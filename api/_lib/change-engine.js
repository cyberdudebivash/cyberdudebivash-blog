/**
 * SENTINEL APEX — Watchlist Change-Detection Engine (Cloudflare D1)
 *
 * Orchestrates one evaluation cycle: for each entity at least one
 * customer watches (api/_lib/watchlist-store.js's reverse index), loads
 * its CURRENT canonical state via the same functions api/v1/intel.js's
 * dossier action already uses (getCVEDetail/getCampaignDetail/loadGraph,
 * called at tier='enterprise' to see the full untiered facts -- this is
 * an internal system read, never returned to a customer directly; any
 * tier-gating a customer sees happens at feed-read time, mirroring
 * intelligence-dossier.js's own tier_info pattern), normalizes it
 * (api/_lib/watchable-state.js), compares its fingerprint against the
 * last-stored snapshot, and on a real semantic change runs the
 * deterministic detector (api/_lib/change-detector.js) to produce typed
 * events, persists each one idempotently, and matches it to watchers.
 *
 * Migrated to Cloudflare D1 as of the Cloudflare-Only Runtime Completion
 * v2 tranche (see watchlist-store.js's own header for the full
 * authorization trail). Snapshots and change events move from Redis
 * STRING/ZSET keys to entity_snapshots/change_events tables in the same
 * D1 database watchlist-store.js and notification-store.js already use
 * (migrations/0002_watchlists_change_detection.sql) -- see that file's
 * design notes for why change_events stores each event as one opaque
 * JSON payload column rather than decomposed fields (nothing in this
 * codebase has ever queried an event by an individual field; this
 * module's own getEventById()/getEventsByIds() have always treated an
 * event as an opaque blob).
 *
 * GLOBAL EVENT vs CUSTOMER MATCH: one event is computed and persisted
 * once per entity change, then fanned out by reference (event_id
 * appended to each watcher's feed) -- not recomputed or duplicated per
 * watching customer. If 100 customers watch the same CVE, the diff runs
 * once. Unchanged from the Redis version -- this property is a function
 * of this module's own logic, not the backing store.
 *
 * Alert Delivery v1: immediately after each watcher's feed append,
 * notification-dispatch.js's dispatchNewEvent() is called (enqueue-only,
 * never blocking on network I/O) so a customer with email/webhook
 * notifications enabled gets a pending delivery queued for the same
 * event, once, at fan-out time -- not recomputed per channel or
 * duplicated on replay (persistEventIfNew's idempotency above already
 * guarantees this loop only runs for a genuinely NEW event). That
 * pending delivery is itself D1-backed since the Cloudflare-Only Alert
 * Runtime v1 tranche (PR #138) -- this module already called into it
 * through the same function signature both before and after that
 * migration, so no change was needed here for that part.
 *
 * Trigger: this module exposes a pure, bounded, cursor-resumable batch
 * function. Invoked today via scripts/evaluate-watchlist-changes.js on
 * GitHub Actions' 30-minute schedule (same workflow, alert-delivery.yml,
 * that bridges alert delivery to D1) -- wiring a live Cloudflare Cron
 * Trigger for evaluation specifically remains a future step, same
 * "cannot prove live execution from this sandbox" constraint documented
 * in the Cloudflare-Only Runtime Completion v2 certification doc.
 */
'use strict';

const d1 = require('./d1');
const store = require('./watchlist-store');
const {
  buildCveWatchableState, buildCampaignWatchableState,
  fingerprintState, WATCHABLE_STATE_SCHEMA_VERSION,
} = require('./watchable-state');
const { detectChanges } = require('./change-detector');
// Safe as a normal top-level require: notification-dispatch.js requires
// THIS module back lazily (inside a function body, not at its own
// top-level), so only one side of the pair needs to defer -- see that
// module's loadChangeEngine() docstring for the full reasoning.
const notificationDispatch = require('./notification-dispatch');

const DEFAULT_BATCH_LIMIT = 200;

function loadIntelLib() {
  // Lazy require: avoids a require-cycle at module-load time (intel.js
  // requires intelligence-dossier.js, which watchable-state.js also
  // requires) and lets tests inject a fake via jest.mock('./intel')
  // without touching the real data-file-backed module cache.
  return require('./intel');
}

function parseJsonSafe(raw) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

/* ───────────────────────── event persistence ───────────────────────── */

// INSERT...ON CONFLICT DO NOTHING makes "already exists" and "just
// created" a single atomic round trip via the affected-row count -- no
// separate EXISTS check, no race between two evaluator runs processing
// the same change. Reuses d1.js's empirically-verified changes()
// mechanism (see that file's header), the same primitive notification-
// store.js's own idempotent enqueue already relies on.
async function persistEventIfNew(event) {
  const nowIso = new Date().toISOString();
  const affected = await d1.runMutationWithChanges(
    `INSERT INTO change_events (event_id, entity_type, entity_id, observed_at, payload, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(event_id) DO NOTHING`,
    [event.event_id, event.entity_type, event.entity_id, event.observed_at, JSON.stringify(event), nowIso]
  );
  return { created: affected > 0 };
}

async function getEventById(eventId) {
  const rows = await d1.query('SELECT payload FROM change_events WHERE event_id = ?', [eventId]);
  return rows[0] ? parseJsonSafe(rows[0].payload) : null;
}

// One query (IN clause) instead of the Redis version's N sequential GETs
// -- preserves the input eventIds' order and silently drops any ID that
// no longer resolves (deleted/corrupt), matching the old loop's
// `if (e) events.push(e)` behavior exactly.
async function getEventsByIds(eventIds) {
  if (!eventIds || eventIds.length === 0) return [];
  const placeholders = eventIds.map(() => '?').join(', ');
  const rows = await d1.query(`SELECT event_id, payload FROM change_events WHERE event_id IN (${placeholders})`, eventIds);
  const byId = new Map(rows.map(r => [r.event_id, parseJsonSafe(r.payload)]));
  return eventIds.map(id => byId.get(id)).filter(Boolean);
}

/* ───────────────────────── snapshots ───────────────────────── */

async function loadSnapshot(entityType, entityId) {
  const rows = await d1.query(
    'SELECT schema_version, fingerprint, state, snapshotted_at FROM entity_snapshots WHERE entity_type = ? AND entity_id = ?',
    [entityType, entityId]
  );
  const row = rows[0];
  if (!row) return null;
  return {
    schema_version: row.schema_version,
    fingerprint: row.fingerprint,
    state: parseJsonSafe(row.state),
    snapshotted_at: row.snapshotted_at,
  };
}

async function saveSnapshot(entityType, entityId, state, fingerprint) {
  const nowIso = new Date().toISOString();
  await d1.run(
    `INSERT INTO entity_snapshots (entity_type, entity_id, schema_version, fingerprint, state, snapshotted_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(entity_type, entity_id) DO UPDATE SET
       schema_version = excluded.schema_version,
       fingerprint = excluded.fingerprint,
       state = excluded.state,
       snapshotted_at = excluded.snapshotted_at`,
    [entityType, entityId, WATCHABLE_STATE_SCHEMA_VERSION, fingerprint, JSON.stringify(state), nowIso]
  );
}

/* ───────────────────────── single-entity evaluation ───────────────────────── */

// Catastrophic data-loss protection: a canonical-load failure
// (found: false) is reported as 'load_failed' and the function returns
// immediately -- the stored snapshot is left untouched and no event is
// emitted. This is deliberate: overwriting the snapshot with an "empty"
// state derived from a failed load would make the *next* successful load
// look like every relationship just disappeared, or (worse, once this
// entity is re-found) like everything just reappeared as "new". Unchanged
// from the Redis version -- this safety property is this function's own
// logic, not a function of the backing store.
async function evaluateEntity({ entityType, entityId, intel, graph, reportsIndexData }) {
  let currentState = null;

  if (entityType === 'cve') {
    const { found, item } = intel.getCVEDetail(entityId, 'enterprise');
    if (!found) return { status: 'load_failed', entityType, entityId, events: [] };
    currentState = buildCveWatchableState({ graph, cveId: entityId, cveItem: item, reportsIndexData });
  } else if (entityType === 'campaign') {
    const { found, campaign } = intel.getCampaignDetail(entityId, 'enterprise');
    if (!found) return { status: 'load_failed', entityType, entityId, events: [] };
    currentState = buildCampaignWatchableState({ campaign, reportsIndexData });
  } else {
    return { status: 'unsupported_type', entityType, entityId, events: [] };
  }

  const fingerprint = fingerprintState(currentState);
  const prior = await loadSnapshot(entityType, entityId);

  // First observation ever -- establish baseline, zero events. A stored
  // snapshot from an older WATCHABLE_STATE_SCHEMA_VERSION is treated
  // identically -- its shape cannot be safely diffed against the current
  // one, and comparing incompatible shapes would either crash or, worse,
  // produce a false mass-change event purely because the *schema*
  // changed, not the intelligence. Re-baseline silently instead.
  if (!prior || prior.schema_version !== WATCHABLE_STATE_SCHEMA_VERSION) {
    await saveSnapshot(entityType, entityId, currentState, fingerprint);
    return { status: 'baseline_established', entityType, entityId, events: [] };
  }

  // Fingerprint-identical -- skip the detailed diff entirely.
  if (prior.fingerprint === fingerprint) {
    return { status: 'unchanged', entityType, entityId, events: [] };
  }

  const { events } = detectChanges({ entityType, before: prior.state, after: currentState });

  const created = [];
  for (const event of events) {
    const result = await persistEventIfNew(event);
    if (!result.created) continue; // replay-safe, no duplicate fan-out
    const watchers = await store.getWatchersForEntity(entityType, entityId);
    for (const w of watchers) {
      await store.appendToOwnerFeed(w.ownerId, event.event_id, Date.parse(event.observed_at) || Date.now());
      // Enqueue-only (see notification-dispatch.js's module docstring) --
      // never blocks change detection on email/webhook network I/O.
      // Failure here must never break the feed fan-out that already
      // succeeded above; a swallowed dispatch error just means this
      // owner's notification isn't enqueued this cycle, not that the
      // watchlist itself is broken.
      await notificationDispatch.dispatchNewEvent({ ownerId: w.ownerId, watchlistId: w.watchlistId, event }).catch(() => {});
    }
    created.push(event);
  }

  await saveSnapshot(entityType, entityId, currentState, fingerprint);
  return { status: created.length ? 'changed' : 'unchanged', entityType, entityId, events: created };
}

/* ───────────────────────── bounded batch driver ───────────────────────── */

// Enumerates ONLY watched entities (never the full corpus), processes a
// bounded slice, and persists a cursor so repeated runs sweep the full
// watched set over time rather than starving alphabetically-later
// entities. The cursor advances before processing completes (not after)
// so one entity that reliably throws can never permanently wedge the
// sweep -- safe because every step here is independently idempotent and
// cheap to simply skip and revisit next run. Unchanged logic from the
// Redis version; only the cursor's own storage moved (a single-row D1
// table, watchlist_eval_state, replacing the watchlist_eval:cursor key).
async function evaluateWatchedEntities({ batchLimit = DEFAULT_BATCH_LIMIT, boundedScan = false } = {}) {
  const intel = loadIntelLib();
  const graph = intel.loadGraph();
  const reportsIndexData = intel.loadJSON(intel.PATHS.reportsIndex);

  let batch = [];
  let watchedTotal = null;
  if (boundedScan) {
    // Hard cap on raw index entries, distinct from the customer-facing
    // batchLimit. An unbounded DISTINCT query would still bill D1 rows.
    if (!Number.isSafeInteger(batchLimit) || batchLimit < 1 || batchLimit > 10) {
      throw new RangeError('SOC bounded scan requires batchLimit 1..10');
    }
    // Deliberately independent from the legacy GitHub publisher's numeric
    // cursor. If migration 0017 is absent, D1 throws and cron fails closed.
    const rows = await d1.query(
      'SELECT entity_type, entity_id FROM watchlist_eval_keyset_state WHERE id = 1', []);
    const saved = rows[0];
    const after = saved ? { entityType: saved.entity_type, entityId: saved.entity_id } : null;
    let window = await store.getWatchedEntityWindow({ after, rowLimit: 128 });
    if (window.length === 0 && after) {
      // Cursor was at the end or its entity was removed. Wrap exactly once.
      window = await store.getWatchedEntityWindow({ rowLimit: 128 });
    }
    const seen = new Set();
    for (const entity of window) {
      const key = JSON.stringify([entity.entityType, entity.entityId]);
      if (seen.has(key)) continue;
      seen.add(key);
      batch.push(entity);
      if (batch.length === batchLimit) break;
    }
    // No full-table COUNT query: unknown rather than a fabricated total.
    // A zero window after wrapping is the only authoritative zero.
    if (batch.length === 0) watchedTotal = 0;
    if (batch.length > 0) {
      const last = batch[batch.length - 1];
      // Persist before evaluation, as with the original skip-on-error
      // cursor, so one failing entity cannot wedge every future cycle.
      await d1.run(
        'INSERT INTO watchlist_eval_keyset_state (id, entity_type, entity_id) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET entity_type = excluded.entity_type, entity_id = excluded.entity_id',
        [last.entityType, last.entityId]
      );
    }
  } else {
    // Keep the existing GitHub alert-delivery publisher's cursor and
    // observability semantics unchanged until separately reviewed.
    const watched = (await store.getAllWatchedEntityKeys())
      .sort((a, b) => (a.entityType + a.entityId).localeCompare(b.entityType + b.entityId));
    watchedTotal = watched.length;
    if (watched.length > 0) {
      const cursorRows = await d1.query('SELECT cursor FROM watchlist_eval_state WHERE id = 1', []);
      let cursor = cursorRows[0] ? cursorRows[0].cursor : 0;
      if (!Number.isFinite(cursor) || cursor < 0) cursor = 0;
      cursor = cursor % watched.length;
      const batchSize = Math.min(batchLimit, watched.length);
      for (let i = 0; i < batchSize; i++) batch.push(watched[(cursor + i) % watched.length]);
      const nextCursor = (cursor + batchSize) % watched.length;
      await d1.run(
        'INSERT INTO watchlist_eval_state (id, cursor) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET cursor = excluded.cursor',
        [nextCursor]
      );
    }
  }

  const results = {
    watched_entities_total: watchedTotal,
    evaluated: 0, changed: 0, baseline: 0, unchanged: 0, load_failed: 0, unsupported: 0,
    events_created: 0, watchlists_touched: 0,
  };
  if (batch.length === 0) return results;

  const touchedWatchlists = new Set();

  for (const { entityType, entityId } of batch) {
    const outcome = await evaluateEntity({ entityType, entityId, intel, graph, reportsIndexData });
    results.evaluated++;
    if (outcome.status === 'load_failed') { results.load_failed++; continue; }
    if (outcome.status === 'unsupported_type') { results.unsupported++; continue; }
    if (outcome.status === 'baseline_established') results.baseline++;
    else if (outcome.status === 'changed') { results.changed++; results.events_created += outcome.events.length; }
    else results.unchanged++;

    const watchers = await store.getWatchersForEntity(entityType, entityId);
    for (const w of watchers) touchedWatchlists.add(w.watchlistId);
  }

  if (touchedWatchlists.size > 0) {
    const nowIso = new Date().toISOString();
    const ids = [...touchedWatchlists];
    const placeholders = ids.map(() => '?').join(', ');
    await d1.run(`UPDATE watchlists SET last_evaluated_at = ? WHERE id IN (${placeholders})`, [nowIso, ...ids]).catch(() => {});
  }
  results.watchlists_touched = touchedWatchlists.size;

  return results;
}

module.exports = {
  evaluateEntity,
  evaluateWatchedEntities,
  persistEventIfNew,
  getEventById,
  getEventsByIds,
  loadSnapshot,
  saveSnapshot,
};
