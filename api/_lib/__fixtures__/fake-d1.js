'use strict';

/**
 * In-memory double implementing the same PUBLIC surface as api/_lib/d1.js
 * (query/run/runMutationWithChanges/setD1Binding/isConfigured), so
 * notification-store.js and notification-dispatch.js can be tested as
 * real sequences of calls against real relational semantics (conditional-
 * UPDATE affected-row counts, INSERT...ON CONFLICT idempotency, ORDER BY
 * id DESC LIMIT trimming) without a live D1 database or wrangler --
 * mirrors fake-redis.js's role/discipline exactly (fake the external
 * store, run the real production logic on top of it), applied to the one
 * D1 database this platform now has.
 *
 * NOT a general SQL engine: this recognizes exactly the fixed set of
 * statement shapes notification-store.js and scripts/migrate-
 * notifications-redis-to-d1.js actually emit (enumerated in this file's
 * dispatch table below, each tied to its real call site in a comment),
 * dispatched by matching a few characteristic substrings rather than by
 * parsing arbitrary SQL. This is intentional, not a shortcut: the
 * production SQL text itself was already empirically verified against a
 * REAL local Cloudflare D1 database (`wrangler d1 execute --local`,
 * documented in the Cloudflare-Only Alert Runtime certification doc) --
 * what this fixture needs to prove is that notification-store.js's own
 * JS logic (retry math, dead-letter thresholds, claim-token threading,
 * disposition strings) behaves correctly given real conditional-mutation
 * semantics, not that D1's SQL engine works (already proven separately).
 * If a new statement shape is ever added to those two files without a
 * matching branch here, every affected test fails loudly (no matching
 * branch = a thrown error), not silently -- there is no silent fallback.
 */

function createFakeD1() {
  const preferences = new Map(); // owner_id -> row
  const jobs = new Map(); // delivery_id -> row
  const deliveryLog = []; // rows with an autoincrement id
  const deadLetters = [];
  const auditLog = [];
  let nextLogId = 1, nextDeadLetterId = 1, nextAuditId = 1;
  let lastAffected = 0;

  // Watchlists / change-detection (Cloudflare-Only Runtime Completion v2)
  const watchlists = new Map(); // id -> row
  const watchlistEntities = []; // { watchlist_id, entity_type, entity_id, created_at }
  const watchlistAuditLog = []; // rows with an autoincrement id
  const entitySnapshots = new Map(); // "type|id" -> row
  const changeEvents = new Map(); // event_id -> row
  const ownerFeed = []; // { owner_id, event_id, observed_at_ms }
  let evalCursor = null; // null until first write, matching "no row yet"
  let evalKeyset = null; // bounded SOC Cron keyset, migration 0017
  let nextWlAuditId = 1;

  // Defense Profiles (Customer Telemetry & Environment-Aware Defense
  // Coverage Fabric v1) -- migrations/0003_defense_profiles.sql
  const defenseProfiles = new Map(); // id -> row
  const defenseProfileTechnologies = []; // { profile_id, category, technology_id, custom_label, created_at }
  const defenseProfileTelemetry = []; // { profile_id, data_source, status, updated_at }
  const defenseProfileAuditLog = []; // rows with an autoincrement id
  let nextDpAuditId = 1;

  // Controlled SIEM Deployment Gateway v1 -- migrations/0004_siem_deployment_gateway.sql
  const siemConnectors = new Map(); // id -> row
  const siemConnectorAuditLog = [];
  let nextConnAuditId = 1;
  const detectionDeployments = new Map(); // deployment_id -> row
  const deploymentApprovals = []; // { approval_id, deployment_id, ..., created_at }
  const deploymentAttempts = []; // { attempt_id, deployment_id, ..., started_at }
  const deploymentAuditLog = [];
  let nextDepAuditId = 1;
  const mockSiemResources = new Map(); // "connectorId|resourceName" -> row

  // Threat Hunting Workspace & Detection Feedback Intelligence v1 --
  // migrations/0005_threat_hunting_workspace.sql
  const hunts = new Map(); // hunt_id -> row
  const huntRefs = []; // { hunt_id, ref_kind, ref_id, created_at }
  const huntQueries = new Map(); // query_id -> row
  const huntObservations = new Map(); // observation_id -> row
  const huntEvidenceLinks = new Map(); // evidence_id -> row
  const huntFindings = new Map(); // finding_id -> row
  const huntTimeline = []; // rows with an autoincrement id
  let nextHuntTimelineId = 1;
  const detectionFeedback = new Map(); // feedback_id -> row

  // Detection Performance Intelligence v1 -- migrations/0006_detection_
  // performance_intelligence.sql
  const detectionVersions = new Map(); // "detection_id|version" -> row

  // Controlled Read-Only SIEM Hunting Connectors v1 --
  // migrations/0007_readonly_siem_hunting.sql
  const huntQueryExecutions = new Map(); // execution_id -> row

  function cloneRow(row) { return row ? { ...row } : row; }

  function trimToNewest(arr, ownerId, limit) {
    const owned = arr.filter(r => r.owner_id === ownerId).sort((a, b) => b.id - a.id);
    const keepIds = new Set(owned.slice(0, limit).map(r => r.id));
    let removed = 0;
    for (let i = arr.length - 1; i >= 0; i--) {
      if (arr[i].owner_id === ownerId && !keepIds.has(arr[i].id)) { arr.splice(i, 1); removed++; }
    }
    return removed;
  }

  function selectByOwnerOrdered(arr, ownerId, limit, mapCols) {
    return arr.filter(r => r.owner_id === ownerId)
      .sort((a, b) => b.id - a.id)
      .slice(0, limit)
      .map(r => mapCols ? mapCols(r) : cloneRow(r));
  }

  // Mirrors d1.js's own query()/run()/runMutationWithChanges() contract
  // exactly -- see that file's header for why runMutationWithChanges
  // never trusts meta.changes/rows_written, only an affected-row count.
  // Here that count is tracked directly as a side effect of each branch
  // below (no literal "SELECT changes()" text is ever parsed -- that's
  // an implementation detail internal to the real d1.js's exec(), not
  // part of the public surface notification-store.js actually calls).
  function exec(sql, params) {
    const p = params || [];

    /* ── notification_preferences ───────────────────────────────── */

    if (sql.includes('SELECT webhook_secret FROM notification_preferences')) {
      const row = preferences.get(p[0]);
      return { rows: row ? [{ webhook_secret: row.webhook_secret != null ? row.webhook_secret : null }] : [] };
    }
    if (sql.includes('SELECT * FROM notification_preferences')) {
      const row = preferences.get(p[0]);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.includes('INSERT INTO notification_preferences')) {
      // Dynamic column list -- extract "(col1, col2, ...)" right after
      // the table name, matching updatePreferences()/rotateWebhookSecret()/
      // the migration script's own dynamic-column-list construction.
      const colsMatch = sql.match(/INSERT INTO notification_preferences \(([^)]+)\)/);
      const cols = colsMatch[1].split(',').map(c => c.trim());
      const ownerId = p[cols.indexOf('owner_id')];
      const existing = preferences.get(ownerId) || {
        owner_id: ownerId, email_enabled: 1, email_override: '', webhook_enabled: 0,
        webhook_url: '', webhook_secret: null, webhook_configured_at: null, updated_at: null,
      };
      const row = { ...existing };
      cols.forEach((col, i) => { row[col] = p[i]; });
      preferences.set(ownerId, row);
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── notification_delivery_log ──────────────────────────────── */

    if (sql.startsWith('INSERT INTO notification_delivery_log')) {
      const [owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at] = p;
      deliveryLog.push({ id: nextLogId++, owner_id, channel, event_id, watchlist_id, status, error, attempt, attempted_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_delivery_log')) {
      const [ownerId, , limit] = p;
      lastAffected = trimToNewest(deliveryLog, ownerId, limit);
      return { rows: [] };
    }
    if (sql.startsWith('SELECT channel, event_id, watchlist_id, status, error, attempt, attempted_at FROM notification_delivery_log')) {
      const [ownerId, limit] = p;
      return { rows: selectByOwnerOrdered(deliveryLog, ownerId, limit, r => ({
        channel: r.channel, event_id: r.event_id, watchlist_id: r.watchlist_id, status: r.status,
        error: r.error, attempt: r.attempt, attempted_at: r.attempted_at,
      })) };
    }

    /* ── notification_dead_letters ──────────────────────────────── */

    if (sql.startsWith('INSERT INTO notification_dead_letters')) {
      const [owner_id, event_id, watchlist_id, channel, attempts, reason, dead_lettered_at] = p;
      deadLetters.push({ id: nextDeadLetterId++, owner_id, event_id, watchlist_id, channel, attempts, reason, dead_lettered_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_dead_letters')) {
      const [ownerId, , limit] = p;
      lastAffected = trimToNewest(deadLetters, ownerId, limit);
      return { rows: [] };
    }
    if (sql.startsWith('SELECT event_id, watchlist_id, channel, attempts, reason, dead_lettered_at FROM notification_dead_letters')) {
      const [ownerId, limit] = p;
      return { rows: selectByOwnerOrdered(deadLetters, ownerId, limit, r => ({
        event_id: r.event_id, watchlist_id: r.watchlist_id, channel: r.channel,
        attempts: r.attempts, reason: r.reason, dead_lettered_at: r.dead_lettered_at,
      })) };
    }

    /* ── notification_audit_log ─────────────────────────────────── */

    if (sql.startsWith('INSERT INTO notification_audit_log')) {
      const [owner_id, action, data, ts] = p;
      auditLog.push({ id: nextAuditId++, owner_id, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_audit_log')) {
      const [ownerId, , limit] = p;
      lastAffected = trimToNewest(auditLog, ownerId, limit);
      return { rows: [] };
    }

    /* ── notification_delivery_jobs ─────────────────────────────── */

    // enqueuePendingDelivery(): literal 'pending'/0 for state/attempt_count.
    if (sql.includes("VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)")) {
      const [delivery_id, event_id, owner_id, watchlist_id, channel, next_attempt_at, schema_version, created_at, updated_at] = p;
      if (jobs.has(delivery_id)) { lastAffected = 0; return { rows: [] }; } // ON CONFLICT DO NOTHING
      jobs.set(delivery_id, {
        delivery_id, event_id, owner_id, watchlist_id, channel, state: 'pending',
        attempt_count: 0, next_attempt_at, claim_token: null, claimed_at: null, lease_expires_at: null,
        schema_version, created_at, updated_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    // migrate-notifications-redis-to-d1.js's enqueue variant: attempt_count
    // is itself a bound param (backfilling a real prior attempt count),
    // not the literal 0 the live enqueue path always uses.
    if (sql.includes("VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)")) {
      const [delivery_id, event_id, owner_id, watchlist_id, channel, attempt_count, next_attempt_at, schema_version, created_at, updated_at] = p;
      if (jobs.has(delivery_id)) { lastAffected = 0; return { rows: [] }; }
      jobs.set(delivery_id, {
        delivery_id, event_id, owner_id, watchlist_id, channel, state: 'pending',
        attempt_count, next_attempt_at, claim_token: null, claimed_at: null, lease_expires_at: null,
        schema_version, created_at, updated_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT MIN(next_attempt_at)')) {
      const values = [...jobs.values()].map(j => j.next_attempt_at);
      return { rows: [{ oldest: values.length ? Math.min(...values) : null }] };
    }
    // Unique discriminator, not startsWith: the real statement's actual
    // template-literal text has a newline between "notification_delivery_
    // jobs" and "WHERE" (see notification-store.js's getDuePendingDeliveries),
    // so a startsWith check assuming a single space there would silently
    // never match. "ORDER BY next_attempt_at ASC" appears in no other
    // statement this fixture handles, so this is safe regardless of
    // surrounding whitespace/line breaks or check ordering below.
    if (sql.includes('ORDER BY next_attempt_at ASC')) {
      const [now1, now2, limit] = p;
      const due = [...jobs.values()].filter(j => {
        if (j.next_attempt_at > now1) return false;
        if (j.state === 'pending' || j.state === 'retry') return true;
        if (j.state === 'claimed' && j.lease_expires_at < now2) return true;
        return false;
      }).sort((a, b) => a.next_attempt_at - b.next_attempt_at).slice(0, limit);
      return { rows: due.map(cloneRow) };
    }
    if (sql.includes("SET state='claimed', claim_token=")) {
      const [claimToken, claimedAt, leaseExpiresAt, deliveryId, now1, now2] = p;
      const job = jobs.get(deliveryId);
      const claimable = job && job.next_attempt_at <= now1 &&
        ((job.state === 'pending' || job.state === 'retry') || (job.state === 'claimed' && job.lease_expires_at < now2));
      if (!claimable) { lastAffected = 0; return { rows: [] }; }
      job.state = 'claimed'; job.claim_token = claimToken; job.claimed_at = claimedAt; job.lease_expires_at = leaseExpiresAt;
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes("SET state='retry', claim_token=NULL, claimed_at=NULL, lease_expires_at=NULL")) {
      const [deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      if (!job || job.claim_token !== claimToken || job.state !== 'claimed') { lastAffected = 0; return { rows: [] }; }
      job.state = 'retry'; job.claim_token = null; job.claimed_at = null; job.lease_expires_at = null;
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes("SET state='retry', attempt_count=")) {
      const [attemptCount, nextAttemptAt, updatedAt, deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      if (!job || job.claim_token !== claimToken || job.state !== 'claimed') { lastAffected = 0; return { rows: [] }; }
      job.state = 'retry'; job.attempt_count = attemptCount; job.next_attempt_at = nextAttemptAt;
      job.claim_token = null; job.claimed_at = null; job.lease_expires_at = null; job.updated_at = updatedAt;
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=?')) {
      const [deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      const match = job && job.claim_token === claimToken && job.state === 'claimed';
      return { rows: match ? [cloneRow(job)] : [] };
    }
    if (sql.startsWith('DELETE FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=?')) {
      const [deliveryId, claimToken] = p;
      const job = jobs.get(deliveryId);
      if (!job || job.claim_token !== claimToken || job.state !== 'claimed') { lastAffected = 0; return { rows: [] }; }
      jobs.delete(deliveryId);
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM notification_delivery_jobs WHERE delivery_id=?')) {
      const [deliveryId] = p;
      lastAffected = jobs.delete(deliveryId) ? 1 : 0;
      return { rows: [] };
    }

    /* ── watchlists ──────────────────────────────────────────────── */

    if (sql.startsWith('SELECT * FROM watchlists WHERE id = ?')) {
      const row = watchlists.get(p[0]);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.startsWith('SELECT COUNT(*) AS cnt FROM watchlists WHERE owner_id = ?')) {
      const cnt = [...watchlists.values()].filter(w => w.owner_id === p[0]).length;
      return { rows: [{ cnt }] };
    }
    if (sql.includes('LEFT JOIN watchlist_entities we ON we.watchlist_id = w.id')) {
      const [ownerId] = p;
      const rows = [...watchlists.values()]
        .filter(w => w.owner_id === ownerId)
        .map(w => ({ ...w, entity_count: watchlistEntities.filter(e => e.watchlist_id === w.id).length }))
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      return { rows };
    }
    if (sql.startsWith('INSERT INTO watchlists (id, owner_id, name, description, status, schema_version, created_at, updated_at)')) {
      const [id, owner_id, name, description, status, schema_version, created_at, updated_at] = p;
      watchlists.set(id, { id, owner_id, name, description, status, schema_version, created_at, updated_at, last_evaluated_at: null });
      lastAffected = 1;
      return { rows: [] };
    }
    // Generic dynamic UPDATE watchlists SET <cols> WHERE id = ? -- handles
    // both updateWatchlist()'s dynamic column list and addEntity()/
    // removeEntity()'s fixed `updated_at = ?` update uniformly: both are
    // the same underlying operation (set some columns, keyed by id), and
    // in the edge case where updateWatchlist() only touches updated_at
    // the two call sites produce textually IDENTICAL SQL -- correct
    // either way since the semantic effect is identical.
    if (sql.startsWith('UPDATE watchlists SET') && !sql.includes('last_evaluated_at')) {
      const setMatch = sql.match(/UPDATE watchlists SET (.+) WHERE id = \?/s);
      const cols = setMatch[1].split(',').map(c => c.trim().replace(/\s*=\s*\?$/, ''));
      const id = p[p.length - 1];
      const row = watchlists.get(id);
      if (row) { cols.forEach((col, i) => { row[col] = p[i]; }); lastAffected = 1; } else { lastAffected = 0; }
      return { rows: [] };
    }
    if (sql.startsWith('UPDATE watchlists SET last_evaluated_at = ? WHERE id IN')) {
      const [nowIso, ...ids] = p;
      let count = 0;
      for (const id of ids) { const row = watchlists.get(id); if (row) { row.last_evaluated_at = nowIso; count++; } }
      lastAffected = count;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlists WHERE id = ?')) {
      lastAffected = watchlists.delete(p[0]) ? 1 : 0;
      return { rows: [] };
    }

    /* ── watchlist_entities ──────────────────────────────────────── */

    if (sql.startsWith('SELECT COUNT(*) AS cnt FROM watchlist_entities WHERE watchlist_id = ?')) {
      const cnt = watchlistEntities.filter(e => e.watchlist_id === p[0]).length;
      return { rows: [{ cnt }] };
    }
    if (sql.startsWith('SELECT entity_type, entity_id FROM watchlist_entities WHERE watchlist_id = ?')) {
      const rows = watchlistEntities
        .filter(e => e.watchlist_id === p[0])
        .sort((a, b) => (a.entity_type + a.entity_id).localeCompare(b.entity_type + b.entity_id))
        .map(e => ({ entity_type: e.entity_type, entity_id: e.entity_id }));
      return { rows };
    }
    if (sql.includes('ON CONFLICT(watchlist_id, entity_type, entity_id) DO NOTHING')) {
      const [watchlist_id, entity_type, entity_id, created_at] = p;
      const exists = watchlistEntities.some(e => e.watchlist_id === watchlist_id && e.entity_type === entity_type && e.entity_id === entity_id);
      if (exists) { lastAffected = 0; return { rows: [] }; }
      watchlistEntities.push({ watchlist_id, entity_type, entity_id, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlist_entities WHERE watchlist_id = ? AND entity_type = ? AND entity_id = ?')) {
      const [watchlist_id, entity_type, entity_id] = p;
      const idx = watchlistEntities.findIndex(e => e.watchlist_id === watchlist_id && e.entity_type === entity_type && e.entity_id === entity_id);
      if (idx === -1) { lastAffected = 0; return { rows: [] }; }
      watchlistEntities.splice(idx, 1);
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlist_entities WHERE watchlist_id = ?')) {
      const before = watchlistEntities.length;
      for (let i = watchlistEntities.length - 1; i >= 0; i--) {
        if (watchlistEntities[i].watchlist_id === p[0]) watchlistEntities.splice(i, 1);
      }
      lastAffected = before - watchlistEntities.length;
      return { rows: [] };
    }
    // SOC cron raw index window; duplicates consume the LIMIT.
    if (sql.startsWith('SELECT entity_type, entity_id FROM watchlist_entities ORDER BY entity_type, entity_id LIMIT ?') ||
        sql.startsWith('SELECT entity_type, entity_id FROM watchlist_entities WHERE (entity_type, entity_id) > (?, ?) ORDER BY entity_type, entity_id LIMIT ?')) {
      const seek = sql.includes(' WHERE (entity_type, entity_id) > (?, ?)');
      const [type, id, limit] = seek ? p : [null, null, p[0]];
      const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
      const rows = watchlistEntities
        .filter(e => !seek || cmp(e.entity_type, type) > 0 ||
          (e.entity_type === type && cmp(e.entity_id, id) > 0))
        .sort((a, b) => cmp(a.entity_type, b.entity_type) || cmp(a.entity_id, b.entity_id))
        .slice(0, limit)
        .map(e => ({ entity_type: e.entity_type, entity_id: e.entity_id }));
      return { rows };
    }
    if (sql.startsWith('SELECT DISTINCT entity_type, entity_id FROM watchlist_entities')) {
      const seen = new Set();
      const rows = [];
      for (const e of watchlistEntities) {
        const key = `${e.entity_type}|${e.entity_id}`;
        if (!seen.has(key)) { seen.add(key); rows.push({ entity_type: e.entity_type, entity_id: e.entity_id }); }
      }
      return { rows };
    }
    if (sql.startsWith('SELECT watchlist_id FROM watchlist_entities WHERE entity_type = ? AND entity_id = ? LIMIT ?')) {
      const [entityType, entityId, limit] = p;
      return { rows: watchlistEntities
        .filter(e => e.entity_type === entityType && e.entity_id === entityId)
        .slice(0, limit).map(e => ({ watchlist_id: e.watchlist_id })) };
    }
    if (sql.includes('JOIN watchlists w ON w.id = we.watchlist_id')) {
      const [entityType, entityId] = p;
      const rows = watchlistEntities
        .filter(e => e.entity_type === entityType && e.entity_id === entityId)
        .map(e => ({ watchlist_id: e.watchlist_id, watchlist: watchlists.get(e.watchlist_id) }))
        .filter(x => x.watchlist && x.watchlist.status !== 'paused')
        .map(x => ({ watchlist_id: x.watchlist_id, owner_id: x.watchlist.owner_id }))
        .slice(0, sql.includes('LIMIT ?') ? p[2] : undefined);
      return { rows };
    }

    /* ── watchlist_audit_log ─────────────────────────────────────── */

    if (sql.startsWith('INSERT INTO watchlist_audit_log')) {
      const [action, data, ts] = p;
      watchlistAuditLog.push({ id: nextWlAuditId++, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM watchlist_audit_log')) {
      const [limit] = p;
      const keepIds = new Set(watchlistAuditLog.slice().sort((a, b) => b.id - a.id).slice(0, limit).map(r => r.id));
      const before = watchlistAuditLog.length;
      for (let i = watchlistAuditLog.length - 1; i >= 0; i--) {
        if (!keepIds.has(watchlistAuditLog[i].id)) watchlistAuditLog.splice(i, 1);
      }
      lastAffected = before - watchlistAuditLog.length;
      return { rows: [] };
    }

    /* ── entity_snapshots ────────────────────────────────────────── */

    if (sql.startsWith('SELECT schema_version, fingerprint, state, snapshotted_at FROM entity_snapshots')) {
      const [entityType, entityId] = p;
      const row = entitySnapshots.get(`${entityType}|${entityId}`);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.includes('ON CONFLICT(entity_type, entity_id) DO UPDATE')) {
      const [entityType, entityId, schema_version, fingerprint, state, snapshotted_at] = p;
      entitySnapshots.set(`${entityType}|${entityId}`, { schema_version, fingerprint, state, snapshotted_at });
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── change_events ───────────────────────────────────────────── */

    if (sql.includes('ON CONFLICT(event_id) DO NOTHING')) {
      const [event_id, entity_type, entity_id, observed_at, payload, created_at] = p;
      if (changeEvents.has(event_id)) { lastAffected = 0; return { rows: [] }; }
      changeEvents.set(event_id, { event_id, entity_type, entity_id, observed_at, payload, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT payload FROM change_events WHERE event_id = ?')) {
      const row = changeEvents.get(p[0]);
      return { rows: row ? [{ payload: row.payload }] : [] };
    }
    if (sql.startsWith('SELECT event_id, payload FROM change_events WHERE event_id IN')) {
      const rows = p.map(id => changeEvents.get(id)).filter(Boolean).map(r => ({ event_id: r.event_id, payload: r.payload }));
      return { rows };
    }

    /* ── owner_feed ──────────────────────────────────────────────── */

    if (sql.includes('ON CONFLICT(owner_id, event_id) DO NOTHING')) {
      const [owner_id, event_id, observed_at_ms] = p;
      const exists = ownerFeed.some(f => f.owner_id === owner_id && f.event_id === event_id);
      if (exists) { lastAffected = 0; return { rows: [] }; }
      ownerFeed.push({ owner_id, event_id, observed_at_ms });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM owner_feed')) {
      const [ownerId, , limit] = p;
      const keep = new Set(
        ownerFeed.filter(f => f.owner_id === ownerId)
          .sort((a, b) => b.observed_at_ms - a.observed_at_ms || b.event_id.localeCompare(a.event_id))
          .slice(0, limit).map(f => f.event_id)
      );
      const before = ownerFeed.length;
      for (let i = ownerFeed.length - 1; i >= 0; i--) {
        if (ownerFeed[i].owner_id === ownerId && !keep.has(ownerFeed[i].event_id)) ownerFeed.splice(i, 1);
      }
      lastAffected = before - ownerFeed.length;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT event_id FROM owner_feed WHERE owner_id = ?')) {
      const [ownerId, limit, offset] = p;
      const rows = ownerFeed.filter(f => f.owner_id === ownerId)
        .sort((a, b) => b.observed_at_ms - a.observed_at_ms || b.event_id.localeCompare(a.event_id))
        .slice(offset, offset + limit)
        .map(f => ({ event_id: f.event_id }));
      return { rows };
    }
    if (sql.startsWith('SELECT COUNT(*) AS cnt FROM owner_feed WHERE owner_id = ?')) {
      const cnt = ownerFeed.filter(f => f.owner_id === p[0]).length;
      return { rows: [{ cnt }] };
    }

    /* ── watchlist_eval_state ────────────────────────────────────── */

    if (sql.startsWith('SELECT entity_type, entity_id FROM watchlist_eval_keyset_state WHERE id = 1')) {
      return { rows: evalKeyset ? [{ ...evalKeyset }] : [] };
    }
    if (sql.startsWith('INSERT INTO watchlist_eval_keyset_state (id, entity_type, entity_id)')) {
      evalKeyset = { entity_type: p[0], entity_id: p[1] };
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT cursor FROM watchlist_eval_state WHERE id = 1')) {
      return { rows: evalCursor === null ? [] : [{ cursor: evalCursor }] };
    }
    if (sql.includes('ON CONFLICT(id) DO UPDATE SET cursor')) {
      evalCursor = p[0];
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── defense_profiles ────────────────────────────────────────── */

    if (sql.startsWith('SELECT * FROM defense_profiles WHERE owner_id = ?')) {
      const row = [...defenseProfiles.values()].find(r => r.owner_id === p[0]);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.startsWith('UPDATE defense_profiles SET name = ?, updated_at = ? WHERE id = ?')) {
      const [name, updated_at, id] = p;
      const row = defenseProfiles.get(id);
      if (row) { row.name = name; row.updated_at = updated_at; lastAffected = 1; } else { lastAffected = 0; }
      return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO defense_profiles (id, owner_id, name, schema_version, created_at, updated_at)')) {
      const [id, owner_id, name, schema_version, created_at, updated_at] = p;
      defenseProfiles.set(id, { id, owner_id, name, schema_version, created_at, updated_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM defense_profiles WHERE id = ?')) {
      lastAffected = defenseProfiles.delete(p[0]) ? 1 : 0;
      return { rows: [] };
    }

    /* ── defense_profile_technologies ───────────────────────────── */

    if (sql.startsWith('SELECT category, technology_id, custom_label FROM defense_profile_technologies WHERE profile_id = ?')) {
      const rows = defenseProfileTechnologies
        .filter(t => t.profile_id === p[0])
        .sort((a, b) => (a.category + a.technology_id).localeCompare(b.category + b.technology_id))
        .map(t => ({ category: t.category, technology_id: t.technology_id, custom_label: t.custom_label }));
      return { rows };
    }
    if (sql.startsWith('DELETE FROM defense_profile_technologies WHERE profile_id = ?')) {
      const before = defenseProfileTechnologies.length;
      for (let i = defenseProfileTechnologies.length - 1; i >= 0; i--) {
        if (defenseProfileTechnologies[i].profile_id === p[0]) defenseProfileTechnologies.splice(i, 1);
      }
      lastAffected = before - defenseProfileTechnologies.length;
      return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO defense_profile_technologies (profile_id, category, technology_id, custom_label, created_at)')) {
      const [profile_id, category, technology_id, custom_label, created_at] = p;
      defenseProfileTechnologies.push({ profile_id, category, technology_id, custom_label, created_at });
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── defense_profile_telemetry ──────────────────────────────── */

    if (sql.startsWith('SELECT data_source, status FROM defense_profile_telemetry WHERE profile_id = ?')) {
      const rows = defenseProfileTelemetry
        .filter(t => t.profile_id === p[0])
        .sort((a, b) => a.data_source.localeCompare(b.data_source))
        .map(t => ({ data_source: t.data_source, status: t.status }));
      return { rows };
    }
    if (sql.startsWith('DELETE FROM defense_profile_telemetry WHERE profile_id = ?')) {
      const before = defenseProfileTelemetry.length;
      for (let i = defenseProfileTelemetry.length - 1; i >= 0; i--) {
        if (defenseProfileTelemetry[i].profile_id === p[0]) defenseProfileTelemetry.splice(i, 1);
      }
      lastAffected = before - defenseProfileTelemetry.length;
      return { rows: [] };
    }
    if (sql.startsWith('INSERT INTO defense_profile_telemetry (profile_id, data_source, status, updated_at)')) {
      const [profile_id, data_source, status, updated_at] = p;
      defenseProfileTelemetry.push({ profile_id, data_source, status, updated_at });
      lastAffected = 1;
      return { rows: [] };
    }

    /* ── defense_profile_audit_log ──────────────────────────────── */

    if (sql.startsWith('INSERT INTO defense_profile_audit_log')) {
      const [action, data, ts] = p;
      defenseProfileAuditLog.push({ id: nextDpAuditId++, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM defense_profile_audit_log')) {
      const [limit] = p;
      const keepIds = new Set(defenseProfileAuditLog.slice().sort((a, b) => b.id - a.id).slice(0, limit).map(r => r.id));
      const before = defenseProfileAuditLog.length;
      for (let i = defenseProfileAuditLog.length - 1; i >= 0; i--) {
        if (!keepIds.has(defenseProfileAuditLog[i].id)) defenseProfileAuditLog.splice(i, 1);
      }
      lastAffected = before - defenseProfileAuditLog.length;
      return { rows: [] };
    }

    /* ── siem_connectors (Controlled SIEM Deployment Gateway v1) ──── */

    if (sql.includes('INSERT INTO siem_connector_audit_log')) {
      const [action, data, ts] = p;
      siemConnectorAuditLog.push({ id: nextConnAuditId++, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes('DELETE FROM siem_connector_audit_log')) {
      const [limit] = p;
      const keepIds = new Set(siemConnectorAuditLog.slice().sort((a, b) => b.id - a.id).slice(0, limit).map(r => r.id));
      const before = siemConnectorAuditLog.length;
      for (let i = siemConnectorAuditLog.length - 1; i >= 0; i--) {
        if (!keepIds.has(siemConnectorAuditLog[i].id)) siemConnectorAuditLog.splice(i, 1);
      }
      lastAffected = before - siemConnectorAuditLog.length;
      return { rows: [] };
    }
    if (sql.includes('SELECT * FROM siem_connectors WHERE owner_id = ?')) {
      const rows = [...siemConnectors.values()].filter(r => r.owner_id === p[0]).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      return { rows: rows.map(cloneRow) };
    }
    if (sql.includes('SELECT * FROM siem_connectors WHERE id = ? AND owner_id = ?')) {
      const [id, ownerId] = p;
      const row = siemConnectors.get(id);
      return { rows: row && row.owner_id === ownerId ? [cloneRow(row)] : [] };
    }
    if (sql.includes('INSERT INTO siem_connectors')) {
      const [id, owner_id, platform, name, target_config, credential_ciphertext, credential_configured, created_at, updated_at] = p;
      siemConnectors.set(id, {
        id, owner_id, platform, name, target_config, credential_ciphertext, credential_configured,
        health_status: 'NEVER_TESTED', last_connection_check_at: null, last_connection_result: null,
        disabled_at: null, created_at, updated_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes('UPDATE siem_connectors SET credential_ciphertext = ?')) {
      const [credential_ciphertext, credential_configured, health_status, updated_at, id, ownerId] = p;
      const row = siemConnectors.get(id);
      if (row && row.owner_id === ownerId) {
        Object.assign(row, { credential_ciphertext, credential_configured, health_status, updated_at });
        lastAffected = 1;
      } else lastAffected = 0;
      return { rows: [] };
    }
    if (sql.includes('UPDATE siem_connectors SET health_status = ?, last_connection_check_at = ?')) {
      const [health_status, last_connection_check_at, last_connection_result, updated_at, id, ownerId] = p;
      const row = siemConnectors.get(id);
      if (row && row.owner_id === ownerId) {
        Object.assign(row, { health_status, last_connection_check_at, last_connection_result, updated_at });
        lastAffected = 1;
      } else lastAffected = 0;
      return { rows: [] };
    }
    if (sql.includes('UPDATE siem_connectors SET disabled_at = ?')) {
      const [disabled_at, updated_at, id, ownerId] = p;
      const row = siemConnectors.get(id);
      if (row && row.owner_id === ownerId) {
        Object.assign(row, { disabled_at, credential_ciphertext: null, credential_configured: 0, health_status: 'DISABLED', updated_at });
        lastAffected = 1;
      } else lastAffected = 0;
      return { rows: [] };
    }

    /* ── detection_deployments / deployment_approvals / deployment_attempts / deployment_audit_log ── */

    if (sql.includes('INSERT INTO deployment_audit_log')) {
      const [action, data, ts] = p;
      deploymentAuditLog.push({ id: nextDepAuditId++, action, data, ts });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes('DELETE FROM deployment_audit_log')) {
      const [limit] = p;
      const keepIds = new Set(deploymentAuditLog.slice().sort((a, b) => b.id - a.id).slice(0, limit).map(r => r.id));
      const before = deploymentAuditLog.length;
      for (let i = deploymentAuditLog.length - 1; i >= 0; i--) {
        if (!keepIds.has(deploymentAuditLog[i].id)) deploymentAuditLog.splice(i, 1);
      }
      lastAffected = before - deploymentAuditLog.length;
      return { rows: [] };
    }
    if (sql.includes('SELECT * FROM detection_deployments WHERE deployment_id = ? AND owner_id = ?')) {
      const [deploymentId, ownerId] = p;
      const row = detectionDeployments.get(deploymentId);
      return { rows: row && row.owner_id === ownerId ? [cloneRow(row)] : [] };
    }
    if (sql.includes('SELECT * FROM detection_deployments WHERE owner_id = ? ORDER BY created_at DESC')) {
      const rows = [...detectionDeployments.values()].filter(r => r.owner_id === p[0]).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      return { rows: rows.map(cloneRow) };
    }
    if (sql.includes('FROM detection_deployments') && sql.includes('AND connector_id = ? AND detection_id = ? AND entity_type = ? AND entity_id = ?')) {
      const [ownerId, connectorId, detectionId, entityType, entityId, ...stateList] = p;
      const rows = [...detectionDeployments.values()]
        .filter(r => r.owner_id === ownerId && r.connector_id === connectorId && r.detection_id === detectionId
          && r.entity_type === entityType && r.entity_id === entityId && stateList.includes(r.state))
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      return { rows: rows.length ? [cloneRow(rows[0])] : [] };
    }
    if (sql.includes('INSERT INTO detection_deployments')) {
      const [deployment_id, owner_id, connector_id, detection_id, detection_version, entity_type, entity_id, format, remote_resource_name, created_at, updated_at] = p;
      detectionDeployments.set(deployment_id, {
        deployment_id, owner_id, connector_id, detection_id, detection_version, entity_type, entity_id,
        format, remote_resource_name, state: 'DRAFT', desired_hash: null, observed_hash: null,
        remote_resource_id: null, remote_etag: null, enabled_desired: 0,
        deployed_intent_snapshot: null, previous_intent_snapshot: null, pending_action: null, last_error: null,
        previous_deployment_id: null, created_at, approved_at: null, deployed_at: null, verified_at: null, updated_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    // Atomic claim (deployment-store.js#claimForExecution) -- distinguished
    // from the generic dynamic-column UPDATE below by its literal state
    // check, which no other detection_deployments UPDATE issues.
    if (sql.includes("UPDATE detection_deployments SET state = 'DEPLOYING'") && sql.includes("state IN ('APPROVED', 'FAILED_RETRYABLE')")) {
      const [updated_at, deploymentId] = p;
      const row = detectionDeployments.get(deploymentId);
      if (row && (row.state === 'APPROVED' || row.state === 'FAILED_RETRYABLE')) {
        row.state = 'DEPLOYING'; row.updated_at = updated_at;
        lastAffected = 1;
      } else lastAffected = 0;
      return { rows: [] };
    }
    // Generic dynamic UPDATE detection_deployments SET <cols>, updated_at = ? WHERE deployment_id = ?
    // (deployment-store.js#updateDeployment()'s only mutation path besides the claim above).
    if (sql.startsWith('UPDATE detection_deployments SET')) {
      const setMatch = sql.match(/UPDATE detection_deployments SET (.+), updated_at = \? WHERE deployment_id = \?/s);
      const cols = setMatch[1].split(',').map(c => c.trim().replace(/\s*=\s*\?$/, ''));
      const updatedAt = p[p.length - 2];
      const deploymentId = p[p.length - 1];
      const row = detectionDeployments.get(deploymentId);
      if (row) {
        cols.forEach((col, i) => { row[col] = p[i]; });
        row.updated_at = updatedAt;
        lastAffected = 1;
      } else lastAffected = 0;
      return { rows: [] };
    }
    if (sql.includes('INSERT INTO deployment_approvals')) {
      const [approval_id, deployment_id, owner_id, detection_version, connector_id, target_config_hash, approved_hash, enabled_requested, created_at] = p;
      deploymentApprovals.push({ approval_id, deployment_id, owner_id, detection_version, connector_id, target_config_hash, approved_hash, enabled_requested, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes('FROM deployment_approvals WHERE deployment_id = ? ORDER BY created_at DESC LIMIT 1')) {
      const rows = deploymentApprovals.filter(a => a.deployment_id === p[0]).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      return { rows: rows.length ? [cloneRow(rows[0])] : [] };
    }
    if (sql.includes('INSERT INTO deployment_attempts')) {
      const [attempt_id, deployment_id, action, result, error_code, http_status, started_at, finished_at] = p;
      deploymentAttempts.push({ attempt_id, deployment_id, action, result, error_code, http_status, started_at, finished_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes('FROM deployment_attempts WHERE deployment_id = ? ORDER BY started_at DESC')) {
      const rows = deploymentAttempts.filter(a => a.deployment_id === p[0]).sort((a, b) => (b.started_at || '').localeCompare(a.started_at || ''));
      return { rows: rows.map(cloneRow) };
    }

    /* ── mock_siem_resources (mock-siem-connector.js) ─────────────── */

    if (sql.includes('SELECT etag FROM mock_siem_resources')) {
      const [connectorId, resourceName] = p;
      const row = mockSiemResources.get(`${connectorId}|${resourceName}`);
      return { rows: row ? [{ etag: row.etag }] : [] };
    }
    if (sql.includes('SELECT payload, etag FROM mock_siem_resources')) {
      const [connectorId, resourceName] = p;
      const row = mockSiemResources.get(`${connectorId}|${resourceName}`);
      return { rows: row ? [{ payload: row.payload, etag: row.etag }] : [] };
    }
    if (sql.includes('SELECT payload FROM mock_siem_resources')) {
      const [connectorId, resourceName] = p;
      const row = mockSiemResources.get(`${connectorId}|${resourceName}`);
      return { rows: row ? [{ payload: row.payload }] : [] };
    }
    if (sql.includes('UPDATE mock_siem_resources SET payload = ?, etag = ?, updated_at = ?')) {
      const [payload, etag, updated_at, connectorId, resourceName] = p;
      const key = `${connectorId}|${resourceName}`;
      const row = mockSiemResources.get(key);
      if (row) { row.payload = payload; row.etag = etag; row.updated_at = updated_at; lastAffected = 1; }
      else lastAffected = 0;
      return { rows: [] };
    }
    if (sql.includes('INSERT INTO mock_siem_resources')) {
      const [connector_id, resource_name, payload, etag, created_at, updated_at] = p;
      mockSiemResources.set(`${connector_id}|${resource_name}`, { connector_id, resource_name, payload, etag, created_at, updated_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes('DELETE FROM mock_siem_resources')) {
      const [connectorId, resourceName] = p;
      lastAffected = mockSiemResources.delete(`${connectorId}|${resourceName}`) ? 1 : 0;
      return { rows: [] };
    }

    /* ── hunts (Threat Hunting Workspace v1) ──────────────────────── */

    if (sql.startsWith('SELECT * FROM hunts WHERE hunt_id = ?')) {
      const [huntId, ownerId] = p;
      const row = hunts.get(huntId);
      return { rows: row && row.owner_id === ownerId ? [cloneRow(row)] : [] };
    }
    if (sql.startsWith('SELECT * FROM hunts WHERE owner_id = ? AND status')) {
      const [ownerId, status, limit] = p;
      const rows = [...hunts.values()].filter((r) => r.owner_id === ownerId && r.status === status)
        .sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }
    if (sql.startsWith('SELECT * FROM hunts WHERE owner_id = ? ORDER')) {
      const [ownerId, limit] = p;
      const rows = [...hunts.values()].filter((r) => r.owner_id === ownerId)
        .sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }
    if (sql.includes('INSERT INTO hunts')) {
      const [hunt_id, owner_id, title, priority, hypothesis, hypothesis_source, created_by, created_at, updated_at] = p;
      hunts.set(hunt_id, {
        hunt_id, owner_id, title, status: 'DRAFT', priority, hypothesis, hypothesis_source,
        linked_case_reference: null, disposition: null, disposition_summary: null, disposition_by: null, disposition_at: null,
        created_by, created_at, updated_at, closed_at: null,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    // Generic dynamic UPDATE hunts SET <cols>, updated_at = ? WHERE hunt_id = ?
    if (sql.startsWith('UPDATE hunts SET')) {
      const setMatch = sql.match(/UPDATE hunts SET (.+), updated_at = \? WHERE hunt_id = \?/s);
      const cols = setMatch[1].split(',').map((c) => c.trim().replace(/\s*=\s*\?$/, ''));
      const updatedAt = p[p.length - 2];
      const huntId = p[p.length - 1];
      const row = hunts.get(huntId);
      if (row) {
        cols.forEach((col, i) => { row[col] = p[i]; });
        row.updated_at = updatedAt;
        lastAffected = 1;
      } else lastAffected = 0;
      return { rows: [] };
    }

    /* ── hunt_refs ─────────────────────────────────────────────────── */

    if (sql.includes('ON CONFLICT (hunt_id, ref_kind, ref_id) DO NOTHING')) {
      const [hunt_id, ref_kind, ref_id, created_at] = p;
      const exists = huntRefs.some((r) => r.hunt_id === hunt_id && r.ref_kind === ref_kind && r.ref_id === ref_id);
      if (exists) { lastAffected = 0; return { rows: [] }; }
      huntRefs.push({ hunt_id, ref_kind, ref_id, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT ref_kind, ref_id, created_at FROM hunt_refs WHERE hunt_id = ?')) {
      const rows = huntRefs.filter((r) => r.hunt_id === p[0]).sort((a, b) => (a.created_at || '').localeCompare(b.created_at || ''));
      return { rows: rows.map((r) => ({ ref_kind: r.ref_kind, ref_id: r.ref_id, created_at: r.created_at })) };
    }
    if (sql.startsWith('SELECT hunt_id FROM hunt_refs WHERE ref_kind = ? AND ref_id = ?')) {
      const [refKind, refId] = p;
      const rows = huntRefs.filter((r) => r.ref_kind === refKind && r.ref_id === refId).map((r) => ({ hunt_id: r.hunt_id }));
      return { rows };
    }

    /* ── hunt_queries ──────────────────────────────────────────────── */

    if (sql.includes('INSERT INTO hunt_queries')) {
      const [query_id, hunt_id, source_detection_id, source_detection_version, format, query_snapshot, validation_status, added_by, created_at] = p;
      huntQueries.set(query_id, { query_id, hunt_id, source_detection_id, source_detection_version, format, query_snapshot, validation_status, added_by, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM hunt_queries WHERE hunt_id = ?')) {
      const [huntId, limit] = p;
      const rows = [...huntQueries.values()].filter((r) => r.hunt_id === huntId).sort((a, b) => (a.created_at || '').localeCompare(b.created_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }

    /* ── hunt_observations ─────────────────────────────────────────── */

    if (sql.includes('INSERT INTO hunt_observations')) {
      const [observation_id, hunt_id, query_id, summary, created_by, created_at, execution_id, selected_fields_json] = p;
      huntObservations.set(observation_id, {
        observation_id, hunt_id, query_id, summary, created_by, created_at,
        execution_id: execution_id === undefined ? null : execution_id,
        selected_fields_json: selected_fields_json === undefined ? null : selected_fields_json,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM hunt_observations WHERE hunt_id = ?')) {
      const [huntId, limit] = p;
      const rows = [...huntObservations.values()].filter((r) => r.hunt_id === huntId).sort((a, b) => (a.created_at || '').localeCompare(b.created_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }

    /* ── hunt_evidence_links ───────────────────────────────────────── */

    if (sql.includes('INSERT INTO hunt_evidence_links')) {
      const [evidence_id, hunt_id, observation_id, description, reference_url, created_by, created_at] = p;
      huntEvidenceLinks.set(evidence_id, { evidence_id, hunt_id, observation_id, description, reference_url, created_by, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM hunt_evidence_links WHERE hunt_id = ?')) {
      const [huntId, limit] = p;
      const rows = [...huntEvidenceLinks.values()].filter((r) => r.hunt_id === huntId).sort((a, b) => (a.created_at || '').localeCompare(b.created_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }

    /* ── hunt_findings ─────────────────────────────────────────────── */

    if (sql.includes('INSERT INTO hunt_findings')) {
      const [finding_id, hunt_id, classification, confidence, summary, evidence_refs, created_by, created_at] = p;
      huntFindings.set(finding_id, { finding_id, hunt_id, classification, confidence, summary, evidence_refs, created_by, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM hunt_findings WHERE hunt_id = ?')) {
      const [huntId, limit] = p;
      const rows = [...huntFindings.values()].filter((r) => r.hunt_id === huntId).sort((a, b) => (a.created_at || '').localeCompare(b.created_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }

    /* ── hunt_timeline ─────────────────────────────────────────────── */

    if (sql.includes('INSERT INTO hunt_timeline')) {
      const [hunt_id, event_type, summary, actor, created_at] = p;
      huntTimeline.push({ id: nextHuntTimelineId++, hunt_id, event_type, summary, actor, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('DELETE FROM hunt_timeline')) {
      const [limit] = p;
      const keepIds = new Set(huntTimeline.slice().sort((a, b) => b.id - a.id).slice(0, limit).map((r) => r.id));
      const before = huntTimeline.length;
      for (let i = huntTimeline.length - 1; i >= 0; i--) {
        if (!keepIds.has(huntTimeline[i].id)) huntTimeline.splice(i, 1);
      }
      lastAffected = before - huntTimeline.length;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT event_type, summary, actor, created_at FROM hunt_timeline WHERE hunt_id = ?')) {
      const [huntId, limit] = p;
      const rows = huntTimeline.filter((r) => r.hunt_id === huntId).sort((a, b) => a.id - b.id).slice(0, limit);
      return { rows: rows.map((r) => ({ event_type: r.event_type, summary: r.summary, actor: r.actor, created_at: r.created_at })) };
    }

    /* ── detection_feedback ────────────────────────────────────────── */

    if (sql.includes('INSERT INTO detection_feedback')) {
      const [feedback_id, owner_id, detection_id, detection_version, hunt_id, deployment_id, classification, summary, created_by, created_at] = p;
      detectionFeedback.set(feedback_id, { feedback_id, owner_id, detection_id, detection_version, hunt_id, deployment_id, classification, summary, created_by, created_at });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM detection_feedback WHERE owner_id = ? AND detection_id = ?')) {
      const [ownerId, detectionId, limit] = p;
      const rows = [...detectionFeedback.values()].filter((r) => r.owner_id === ownerId && r.detection_id === detectionId)
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }
    if (sql.startsWith('SELECT * FROM detection_feedback WHERE owner_id = ? ORDER')) {
      const [ownerId, limit] = p;
      const rows = [...detectionFeedback.values()].filter((r) => r.owner_id === ownerId)
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }
    if (sql.startsWith('SELECT * FROM detection_feedback WHERE hunt_id = ?')) {
      const [huntId, limit] = p;
      const rows = [...detectionFeedback.values()].filter((r) => r.hunt_id === huntId)
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')).slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }
    if (sql.includes('COUNT(DISTINCT owner_id) AS distinct_owners') && sql.includes('GROUP BY classification')) {
      const [detectionId, detectionVersion] = p;
      const matched = [...detectionFeedback.values()].filter((r) => r.detection_id === detectionId && r.detection_version === detectionVersion);
      const byClassification = new Map();
      for (const row of matched) {
        if (!byClassification.has(row.classification)) byClassification.set(row.classification, new Set());
        byClassification.get(row.classification).add(row.owner_id);
      }
      const rows = [...byClassification.entries()].map(([classification, owners]) => ({
        classification,
        distinct_owners: owners.size,
        total: matched.filter((r) => r.classification === classification).length,
      }));
      return { rows };
    }

    /* ── detection_feedback: Detection Performance Intelligence v1 aggregate reads ── */

    // computeTenantPerformance() -- owner-scoped, per-classification counts + last-seen timestamp.
    if (sql.includes('COUNT(*) AS total, MAX(created_at) AS last_at') && sql.includes('GROUP BY classification')) {
      const [ownerId, detectionId, detectionVersion] = p;
      const matched = [...detectionFeedback.values()].filter((r) => r.owner_id === ownerId && r.detection_id === detectionId && r.detection_version === detectionVersion);
      const byClassification = new Map();
      for (const row of matched) {
        if (!byClassification.has(row.classification)) byClassification.set(row.classification, []);
        byClassification.get(row.classification).push(row);
      }
      const rows = [...byClassification.entries()].map(([classification, rowsForClass]) => ({
        classification,
        total: rowsForClass.length,
        last_at: rowsForClass.reduce((max, r) => (!max || r.created_at > max ? r.created_at : max), null),
      }));
      return { rows };
    }
    // computeGlobalReviewMetrics() -- GLOBAL (cross-owner) single-row totals, no GROUP BY.
    if (sql.includes('COUNT(DISTINCT owner_id) AS global_owner_count')) {
      const [detectionId, detectionVersion] = p;
      const matched = [...detectionFeedback.values()].filter((r) => r.detection_id === detectionId && r.detection_version === detectionVersion);
      const owners = new Set(matched.map((r) => r.owner_id));
      const lastFeedbackAt = matched.reduce((max, r) => (!max || r.created_at > max ? r.created_at : max), null);
      return { rows: [{ global_owner_count: owners.size, last_feedback_at: lastFeedbackAt }] };
    }

    /* ── detection_deployments: Detection Performance Intelligence v1 (countDeploymentsByDetection) ── */

    if (sql.includes('COUNT(*) AS total, COUNT(DISTINCT owner_id) AS distinct_owners') && sql.includes('FROM detection_deployments')) {
      const [detectionId, ...stateList] = p;
      const matched = [...detectionDeployments.values()].filter((r) => r.detection_id === detectionId && stateList.includes(r.state));
      const owners = new Set(matched.map((r) => r.owner_id));
      return { rows: [{ total: matched.length, distinct_owners: owners.size }] };
    }

    /* ── detection_versions (Detection Performance Intelligence v1) ──── */

    if (sql.includes('ON CONFLICT(detection_id, version) DO NOTHING')) {
      const [
        detection_id, version, title, technique_id, level, description, data_source,
        platforms_json, suricata_json, governance_status_at_snapshot, confidence_at_snapshot,
        content_hash, snapshot_source, snapshot_reason, snapshot_author, snapshotted_at,
      ] = p;
      const key = `${detection_id}|${version}`;
      if (detectionVersions.has(key)) { lastAffected = 0; return { rows: [] }; }
      detectionVersions.set(key, {
        detection_id, version, title, technique_id, level, description, data_source,
        platforms_json, suricata_json, governance_status_at_snapshot, confidence_at_snapshot,
        content_hash, snapshot_source, snapshot_reason, snapshot_author, snapshotted_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM detection_versions WHERE detection_id = ? AND version = ?')) {
      const [detectionId, version] = p;
      const row = detectionVersions.get(`${detectionId}|${version}`);
      return { rows: row ? [cloneRow(row)] : [] };
    }
    if (sql.startsWith('SELECT * FROM detection_versions WHERE detection_id = ? ORDER BY snapshotted_at ASC')) {
      const [detectionId] = p;
      const rows = [...detectionVersions.values()].filter((r) => r.detection_id === detectionId)
        .sort((a, b) => (a.snapshotted_at || '').localeCompare(b.snapshotted_at || ''));
      return { rows: rows.map(cloneRow) };
    }

    /* ── hunt_query_executions (Controlled Read-Only SIEM Hunting Connectors v1) ── */

    if (sql.includes('INSERT INTO hunt_query_executions')) {
      const [
        execution_id, owner_id, hunt_id, query_id, connector_id, detection_id, detection_version,
        format, time_start, time_end, row_limit, started_at, created_at,
      ] = p;
      huntQueryExecutions.set(execution_id, {
        execution_id, owner_id, hunt_id, query_id, connector_id, detection_id, detection_version,
        format, time_start, time_end, row_limit, state: 'RUNNING',
        result_row_count: null, error_code: null, error_classification: null,
        started_at, completed_at: null, created_at,
      });
      lastAffected = 1;
      return { rows: [] };
    }
    if (sql.includes('UPDATE hunt_query_executions') && sql.includes('SET state = ?')) {
      const [state, result_row_count, error_code, error_classification, completed_at, executionId] = p;
      const row = huntQueryExecutions.get(executionId);
      if (row) {
        Object.assign(row, { state, result_row_count, error_code, error_classification, completed_at });
        lastAffected = 1;
      } else lastAffected = 0;
      return { rows: [] };
    }
    if (sql.startsWith('SELECT * FROM hunt_query_executions WHERE execution_id = ? AND owner_id = ?')) {
      const [executionId, ownerId] = p;
      const row = huntQueryExecutions.get(executionId);
      return { rows: row && row.owner_id === ownerId ? [cloneRow(row)] : [] };
    }
    if (sql.startsWith('SELECT * FROM hunt_query_executions WHERE owner_id = ? AND hunt_id = ?')) {
      const [ownerId, huntId, limit] = p;
      const rows = [...huntQueryExecutions.values()]
        .filter((r) => r.owner_id === ownerId && r.hunt_id === huntId)
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))
        .slice(0, limit);
      return { rows: rows.map(cloneRow) };
    }

    throw new Error(`fake-d1: no matching statement branch for SQL: ${sql}`);
  }

  return {
    query: async (sql, params) => exec(sql, params).rows,
    run: async (sql, params) => { const r = exec(sql, params); return { results: r.rows, success: true, meta: {} }; },
    runMutationWithChanges: async (sql, params) => { exec(sql, params); return lastAffected; },
    setD1Binding: () => {},
    isConfigured: () => true,
    _dump: () => ({
      preferences, jobs, deliveryLog, deadLetters, auditLog,
      watchlists, watchlistEntities, watchlistAuditLog, entitySnapshots, changeEvents, ownerFeed,
      defenseProfiles, defenseProfileTechnologies, defenseProfileTelemetry, defenseProfileAuditLog,
      siemConnectors, siemConnectorAuditLog, detectionDeployments, deploymentApprovals,
      deploymentAttempts, deploymentAuditLog, mockSiemResources,
      hunts, huntRefs, huntQueries, huntObservations, huntEvidenceLinks, huntFindings, huntTimeline, detectionFeedback,
      detectionVersions, huntQueryExecutions,
    }),
    _reset: () => {
      preferences.clear(); jobs.clear();
      deliveryLog.length = 0; deadLetters.length = 0; auditLog.length = 0;
      nextLogId = 1; nextDeadLetterId = 1; nextAuditId = 1; lastAffected = 0;
      watchlists.clear(); watchlistEntities.length = 0; watchlistAuditLog.length = 0;
      entitySnapshots.clear(); changeEvents.clear(); ownerFeed.length = 0;
      evalCursor = null; evalKeyset = null; nextWlAuditId = 1;
      defenseProfiles.clear(); defenseProfileTechnologies.length = 0;
      defenseProfileTelemetry.length = 0; defenseProfileAuditLog.length = 0; nextDpAuditId = 1;
      siemConnectors.clear(); siemConnectorAuditLog.length = 0; nextConnAuditId = 1;
      detectionDeployments.clear(); deploymentApprovals.length = 0; deploymentAttempts.length = 0;
      deploymentAuditLog.length = 0; nextDepAuditId = 1; mockSiemResources.clear();
      hunts.clear(); huntRefs.length = 0; huntQueries.clear(); huntObservations.clear();
      huntEvidenceLinks.clear(); huntFindings.clear(); huntTimeline.length = 0; nextHuntTimelineId = 1;
      detectionFeedback.clear();
      detectionVersions.clear();
      huntQueryExecutions.clear();
    },
  };
}

module.exports = { createFakeD1 };
