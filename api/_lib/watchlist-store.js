/**
 * SENTINEL APEX — Watchlist Persistence (Cloudflare D1)
 *
 * Customer-owned watchlists, their tracked entities, the reverse index
 * used to match a changed entity back to its watchers, and each
 * customer's monitoring feed. Backed by Cloudflare D1 via api/_lib/d1.js
 * -- migrated from Upstash Redis as of the Cloudflare-Only Runtime
 * Completion v2 tranche, per the operator's explicit "Cloudflare Workers
 * is the only production runtime going forward" directive (see
 * docs/architecture/PRODUCTION-RUNTIME-POLICY.md). The prior Redis design
 * is not being replaced because it was wrong -- this module's own header
 * previously documented, correctly, that provisioning new Cloudflare
 * storage was an architectural event requiring separate authorization;
 * that authorization now exists (see docs/audits/SENTINEL-APEX-
 * CLOUDFLARE-ONLY-RUNTIME-COMPLETION-V2-CERTIFICATION.md).
 *
 * Schema: migrations/0002_watchlists_change_detection.sql (same D1
 * database PR #138 introduced for alert delivery, now renamed
 * sentinel-apex-core to reflect the broadened scope -- see wrangler.jsonc's
 * own header for why one database, not two).
 *
 * Design departure from the Redis model, not a mechanical port: the old
 * design needed TWO mirrored Redis sets per (watchlist, entity)
 * relationship -- watchlist:{id}:entities (forward) and
 * entity_watchers:{type}:{id} (reverse) -- because a Redis Set has no
 * secondary index. D1's watchlist_entities table gives both directions
 * over ONE source of truth: the composite PRIMARY KEY (watchlist_id,
 * entity_type, entity_id) serves the forward lookup, and a plain index
 * on (entity_type, entity_id) serves the reverse one. This also collapses
 * getWatchersForEntity()'s old N+1 pattern (SMEMBERS the reverse set,
 * then GET each watchlist hash individually to check pause status) into
 * a single JOIN, and listWatchlists()'s old per-watchlist SCARD call into
 * one query with a LEFT JOIN/GROUP BY.
 *
 * Ownership: every read/write of a specific watchlist ID re-derives
 * ownership from the caller's authenticate()-issued userId and compares
 * it against the stored `owner_id` column -- never trusted from the
 * request body. A missing watchlist and someone else's watchlist return
 * the identical 404, mirroring api/v1/billing.js's handleManageSubscription
 * ownership-check precedent exactly, so a valid watchlist ID can't be
 * enumerated by comparing error responses. Unchanged from the Redis
 * version -- this property does not depend on which store backs it.
 */
'use strict';

const crypto = require('crypto');
const d1 = require('./d1');
const { sanitize } = require('./payment-utils');

const WATCHLIST_SCHEMA_VERSION = '1.0';
const SUPPORTED_ENTITY_TYPES = new Set(['cve', 'campaign']);
const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/i;

// Phase 12 (Watchlists v1): technical hard caps, abuse-prevention only.
// Not tier-differentiated -- unchanged reasoning/limits from the Redis
// version; this migration does not revisit that product decision.
const MAX_WATCHLISTS_PER_OWNER    = 20;
const MAX_ENTITIES_PER_WATCHLIST  = 100;
const MAX_NAME_LENGTH             = 100;
const MAX_DESCRIPTION_LENGTH      = 500;
const FEED_MAX_PER_OWNER          = 500; // bounded retention
const AUDIT_LOG_MAX_ENTRIES       = 10000; // matches payment-utils.js's own bound

function generateWatchlistId() {
  return 'wl_' + crypto.randomBytes(12).toString('hex');
}

// Global trim (not per-owner) -- reproduces the Redis version's own
// ZREMRANGEBYRANK on audit:watchlist:log exactly, which trimmed the
// WHOLE sorted set to the newest AUDIT_LOG_MAX_ENTRIES, not per-owner.
// Signature unchanged: auditWatchlistAction(action, data) -- owner_id/
// watchlist_id/etc. live inside `data`, same as before.
async function auditWatchlistAction(action, data = {}) {
  try {
    await d1.run(
      'INSERT INTO watchlist_audit_log (action, data, ts) VALUES (?, ?, ?)',
      [action, JSON.stringify(data), new Date().toISOString()]
    );
    await d1.run(
      `DELETE FROM watchlist_audit_log WHERE id NOT IN
       (SELECT id FROM watchlist_audit_log ORDER BY id DESC LIMIT ?)`,
      [AUDIT_LOG_MAX_ENTRIES]
    ).catch(() => {});
  } catch (_) {
    // Audit failure must never break the main flow (matches
    // payment-utils.js's auditLog() behavior exactly).
  }
}

/* ───────────────────────── validation ───────────────────────── */

function validateName(name) {
  const clean = sanitize(name, MAX_NAME_LENGTH).trim();
  if (!clean) return { error: true, message: 'name is required (1-' + MAX_NAME_LENGTH + ' characters).' };
  return { value: clean };
}

function validateDescription(description) {
  if (description === undefined || description === null || description === '') return { value: '' };
  return { value: sanitize(description, MAX_DESCRIPTION_LENGTH).trim() };
}

// Reject prototype-pollution keys, unsupported entity types, and
// malformed IDs before anything touches D1. Unchanged from the Redis
// version -- this validation is storage-agnostic.
function validateEntityRef(entityType, entityId) {
  const type = String(entityType || '').toLowerCase().trim();
  if (type === '__proto__' || type === 'constructor' || type === 'prototype') {
    return { error: 'UNSUPPORTED_ENTITY_TYPE', message: 'Unsupported watchlist entity type.' };
  }
  if (!SUPPORTED_ENTITY_TYPES.has(type)) {
    return { error: 'UNSUPPORTED_ENTITY_TYPE', message: `Unsupported watchlist entity type: "${entityType}". Supported: cve, campaign.` };
  }
  if (type === 'cve') {
    const id = String(entityId || '').toUpperCase().trim();
    if (!CVE_ID_RE.test(id)) {
      return { error: 'INVALID_ENTITY_ID', message: `Invalid CVE ID format: "${entityId}". Expected: CVE-YYYY-NNNNN` };
    }
    return { type, id };
  }
  const id = String(entityId || '').trim();
  if (!id || id.length > 200 || !/^[a-zA-Z0-9:_.\-]+$/.test(id)) {
    return { error: 'INVALID_ENTITY_ID', message: `Invalid campaign ID: "${entityId}".` };
  }
  return { type, id };
}

/* ───────────────────────── serialization ───────────────────────── */

function toPublicWatchlist(record, entityCount) {
  return {
    schema_version: record.schema_version || WATCHLIST_SCHEMA_VERSION,
    id: record.id,
    name: record.name,
    description: record.description || '',
    status: record.status || 'active',
    entity_count: entityCount,
    created_at: record.created_at,
    updated_at: record.updated_at,
    last_evaluated_at: record.last_evaluated_at || null,
  };
}

/* ───────────────────────── entitlements ───────────────────────── */
// Deliberately a single function other code calls, not `if (tier===...)`
// scattered across handlers. Flat across tiers -- unchanged product
// posture from the Redis version; see platform/open-issues.md for the
// documented no-centralized-entitlement-layer gap.
function getWatchlistEntitlements(tier) {
  return {
    enabled: true,
    max_watchlists: MAX_WATCHLISTS_PER_OWNER,
    max_entities_per_watchlist: MAX_ENTITIES_PER_WATCHLIST,
    feed_max_entries: FEED_MAX_PER_OWNER,
    email_notifications_enabled: true,
    webhook_notifications_enabled: true,
  };
}

/* ───────────────────────── watchlist CRUD ───────────────────────── */

async function getWatchlistRaw(watchlistId) {
  const rows = await d1.query('SELECT * FROM watchlists WHERE id = ?', [watchlistId]);
  return rows[0] || null;
}

// Ownership check: identical NOT_FOUND for "doesn't exist" and "exists
// but belongs to someone else" -- unchanged from the Redis version.
async function getOwnedWatchlist(watchlistId, ownerId) {
  const record = await getWatchlistRaw(watchlistId);
  if (!record || record.owner_id !== ownerId) return null;
  return record;
}

async function createWatchlist({ ownerId, name, description }) {
  const nameResult = validateName(name);
  if (nameResult.error) return { error: 'INVALID_NAME', message: nameResult.message };
  const descResult = validateDescription(description);

  const [{ cnt }] = await d1.query('SELECT COUNT(*) AS cnt FROM watchlists WHERE owner_id = ?', [ownerId]);
  if (cnt >= MAX_WATCHLISTS_PER_OWNER) {
    return { error: 'LIMIT_REACHED', message: `Maximum of ${MAX_WATCHLISTS_PER_OWNER} watchlists per account reached.` };
  }

  const id = generateWatchlistId();
  const nowIso = new Date().toISOString();
  const record = {
    schema_version: WATCHLIST_SCHEMA_VERSION,
    id, owner_id: ownerId,
    name: nameResult.value,
    description: descResult.value,
    status: 'active',
    created_at: nowIso, updated_at: nowIso, last_evaluated_at: null,
  };
  await d1.run(
    `INSERT INTO watchlists (id, owner_id, name, description, status, schema_version, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, ownerId, record.name, record.description, 'active', WATCHLIST_SCHEMA_VERSION, nowIso, nowIso]
  );
  auditWatchlistAction('WATCHLIST_CREATED', { owner: ownerId, watchlistId: id }).catch(() => {});
  return { watchlist: toPublicWatchlist(record, 0) };
}

// One query (LEFT JOIN + GROUP BY) instead of the Redis version's
// SMEMBERS-then-N-times-SCARD loop -- a genuine simplification the
// relational model gives for free at this bounded scale (max 20
// watchlists per owner).
async function listWatchlists(ownerId) {
  const rows = await d1.query(
    `SELECT w.*, COUNT(we.entity_type) AS entity_count
     FROM watchlists w
     LEFT JOIN watchlist_entities we ON we.watchlist_id = w.id
     WHERE w.owner_id = ?
     GROUP BY w.id
     ORDER BY w.created_at DESC`,
    [ownerId]
  );
  return rows.map(r => toPublicWatchlist(r, r.entity_count));
}

async function getWatchlist(watchlistId, ownerId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const [{ cnt }] = await d1.query('SELECT COUNT(*) AS cnt FROM watchlist_entities WHERE watchlist_id = ?', [watchlistId]);
  return { watchlist: toPublicWatchlist(record, cnt) };
}

async function updateWatchlist(watchlistId, ownerId, updates) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };

  const nowIso = new Date().toISOString();
  const cols = ['updated_at'];
  const vals = [nowIso];
  const patch = { updated_at: nowIso };
  if (updates.name !== undefined) {
    const r = validateName(updates.name);
    if (r.error) return { error: 'INVALID_NAME', message: r.message };
    cols.push('name'); vals.push(r.value); patch.name = r.value;
  }
  if (updates.description !== undefined) {
    const v = validateDescription(updates.description).value;
    cols.push('description'); vals.push(v); patch.description = v;
  }
  if (updates.status !== undefined) {
    const s = String(updates.status).toLowerCase().trim();
    if (!['active', 'paused'].includes(s)) {
      return { error: 'INVALID_STATUS', message: 'status must be "active" or "paused".' };
    }
    cols.push('status'); vals.push(s); patch.status = s;
  }

  const setClause = cols.map(c => `${c} = ?`).join(', ');
  await d1.run(`UPDATE watchlists SET ${setClause} WHERE id = ?`, [...vals, watchlistId]);
  auditWatchlistAction('WATCHLIST_UPDATED', { owner: ownerId, watchlistId, fields: cols }).catch(() => {});
  const [{ cnt }] = await d1.query('SELECT COUNT(*) AS cnt FROM watchlist_entities WHERE watchlist_id = ?', [watchlistId]);
  return { watchlist: toPublicWatchlist({ ...record, ...patch }, cnt) };
}

// Deletes membership rows (both the forward AND reverse index at once --
// they're the same table now, see this module's header) then the
// watchlist row itself. Never touches global change events (change_events/
// owner_feed history already delivered stays visible) and never touches
// canonical intelligence -- only this watchlist's own subscription state.
// Two queries total, versus the Redis version's per-member SREM loop.
async function deleteWatchlist(watchlistId, ownerId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };

  await d1.run('DELETE FROM watchlist_entities WHERE watchlist_id = ?', [watchlistId]).catch(() => {});
  await d1.run('DELETE FROM watchlists WHERE id = ?', [watchlistId]).catch(() => {});
  auditWatchlistAction('WATCHLIST_DELETED', { owner: ownerId, watchlistId }).catch(() => {});
  return { deleted: true };
}

/* ───────────────────────── entity membership ───────────────────────── */

async function listEntities(watchlistId, ownerId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const rows = await d1.query(
    'SELECT entity_type, entity_id FROM watchlist_entities WHERE watchlist_id = ? ORDER BY entity_type, entity_id',
    [watchlistId]
  );
  return { entities: rows.map(r => ({ type: r.entity_type, id: r.entity_id })) };
}

// Adding an already-present entity is a no-op success (idempotent
// membership), even at the cap -- INSERT...ON CONFLICT DO NOTHING is
// naturally idempotent, mirroring SADD. A genuinely new addition once at
// the cap is rolled back and rejected rather than silently exceeding the
// documented limit. Not fully atomic under two concurrent add requests
// for the *same* watchlist (no D1 transaction wraps the count-check and
// insert together) -- unchanged, disclosed limitation carried over
// verbatim from the Redis version: a customer racing themselves could
// transiently land 1 entity over the cap before the next add is
// rejected, a low-severity, self-only race (never cross-customer).
async function addEntity(watchlistId, ownerId, entityType, entityId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const ref = validateEntityRef(entityType, entityId);
  if (ref.error) return ref;

  const nowIso = new Date().toISOString();
  const affected = await d1.runMutationWithChanges(
    `INSERT INTO watchlist_entities (watchlist_id, entity_type, entity_id, created_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(watchlist_id, entity_type, entity_id) DO NOTHING`,
    [watchlistId, ref.type, ref.id, nowIso]
  );
  const wasNew = affected > 0;

  if (wasNew) {
    const [{ cnt }] = await d1.query('SELECT COUNT(*) AS cnt FROM watchlist_entities WHERE watchlist_id = ?', [watchlistId]);
    if (cnt > MAX_ENTITIES_PER_WATCHLIST) {
      await d1.run(
        'DELETE FROM watchlist_entities WHERE watchlist_id = ? AND entity_type = ? AND entity_id = ?',
        [watchlistId, ref.type, ref.id]
      ).catch(() => {});
      return { error: 'LIMIT_REACHED', message: `Maximum of ${MAX_ENTITIES_PER_WATCHLIST} entities per watchlist reached.` };
    }
  }

  await d1.run('UPDATE watchlists SET updated_at = ? WHERE id = ?', [nowIso, watchlistId]);
  if (wasNew) {
    auditWatchlistAction('WATCHLIST_ENTITY_ADDED', { owner: ownerId, watchlistId, entityType: ref.type, entityId: ref.id }).catch(() => {});
  }
  return { added: true, duplicate: !wasNew, entity: { type: ref.type, id: ref.id } };
}

async function removeEntity(watchlistId, ownerId, entityType, entityId) {
  const record = await getOwnedWatchlist(watchlistId, ownerId);
  if (!record) return { error: 'NOT_FOUND' };
  const ref = validateEntityRef(entityType, entityId);
  if (ref.error) return ref;

  await d1.run(
    'DELETE FROM watchlist_entities WHERE watchlist_id = ? AND entity_type = ? AND entity_id = ?',
    [watchlistId, ref.type, ref.id]
  );
  await d1.run('UPDATE watchlists SET updated_at = ? WHERE id = ?', [new Date().toISOString(), watchlistId]);
  auditWatchlistAction('WATCHLIST_ENTITY_REMOVED', { owner: ownerId, watchlistId, entityType: ref.type, entityId: ref.id }).catch(() => {});
  return { removed: true };
}

/* ───────────────────────── change-engine support ─────────────────────────
   Consumed by api/_lib/change-engine.js, not by the customer-facing
   router directly. */

// Enumerate only entities that are actually watched by at least one
// customer -- a single DISTINCT query, replacing the Redis version's
// `KEYS entity_watchers:*` scan.
async function getAllWatchedEntityKeys() {
  const rows = await d1.query('SELECT DISTINCT entity_type, entity_id FROM watchlist_entities', []);
  return rows.map(r => ({ entityType: r.entity_type, entityId: r.entity_id }));
}

// GitHub scheduled evaluator legacy compatibility: retain the numeric
// cursor semantics while bounding RAW index membership reads BEFORE any
// event, cursor or snapshot mutation. LIMIT applies to raw memberships,
// never DISTINCT, COUNT(*), or OFFSET (which can scan unbounded rows).
// 1,024 is a pre-revenue operational ceiling, NOT a bill-free entitlement.
// Over-limit collections MUST fail closed until a separately reviewed
// keyset migration/publisher is commissioned and FinOps attested.
const GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS = 1024;
async function getBoundedLegacyWatchedEntityKeys() {
  const rows = await d1.query(SOC_WATCH_WINDOW_FIRST_SQL,
    [GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS + 1]);
  if (rows.length > GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS) {
    throw new RangeError('GITHUB_WATCHLIST_RAW_MEMBERSHIP_BUDGET_EXCEEDED');
  }
  const seen = new Set();
  const out = [];
  for (const row of rows) {
    const entityType = row.entity_type;
    const entityId = row.entity_id;
    const key = JSON.stringify([entityType, entityId]);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ entityType, entityId });
  }
  return out;
}

// Central SQL contracts: queried by production and by offline native
// SQLite cost-plan tests. A test may inspect the exact SQL used at runtime,
// never a copy that can drift from the deployed query.
const SOC_WATCH_WINDOW_FIRST_SQL =
  'SELECT entity_type, entity_id FROM watchlist_entities ORDER BY entity_type, entity_id LIMIT ?';
const SOC_WATCH_WINDOW_SEEK_SQL =
  'SELECT entity_type, entity_id FROM watchlist_entities WHERE (entity_type, entity_id) > (?, ?) ORDER BY entity_type, entity_id LIMIT ?';
const SOC_CRON_MEMBERSHIP_PROBE_SQL =
  'SELECT watchlist_id FROM watchlist_entities WHERE entity_type = ? AND entity_id = ? LIMIT ?';
const SOC_CRON_ACTIVE_WATCHERS_SQL =
  `SELECT we.watchlist_id, w.owner_id
     FROM watchlist_entities we
     JOIN watchlists w ON w.id = we.watchlist_id
     WHERE we.entity_type = ? AND we.entity_id = ? AND w.status != 'paused'
     LIMIT ?`;

// Fixed-size, index-ordered raw membership window for the optional SOC
// scheduled path. NEVER DISTINCT/GROUP BY or COUNT(*) here: duplicate
// memberships are handled in memory and still count against rowLimit.
// With the existing (entity_type, entity_id) covering index, the query
// can seek past a key without enumerating the full account watchlist.
// This bounds returned/scanned index entries in the window, NOT fan-out
// work later performed for highly popular entities.
async function getWatchedEntityWindow({ after = null, rowLimit = 128 } = {}) {
  if (!Number.isSafeInteger(rowLimit) || rowLimit < 1 || rowLimit > 128) {
    throw new RangeError('SOC watched-entity D1 index window must be 1..128');
  }
  if (after !== null && (!after || typeof after.entityType !== 'string' ||
      !after.entityType || typeof after.entityId !== 'string' || !after.entityId)) {
    throw new TypeError('Invalid SOC watchlist keyset cursor');
  }
  const query = after ? SOC_WATCH_WINDOW_SEEK_SQL : SOC_WATCH_WINDOW_FIRST_SQL;
  const params = after ? [after.entityType, after.entityId, rowLimit] : [rowLimit];
  const rows = await d1.query(query, params);
  return rows.map(r => ({ entityType: r.entity_type, entityId: r.entity_id }));
}

// Optional SOC Cron preflight only. Probe raw membership (including paused
// watchlists) with LIMIT 11 BEFORE joining: a popular/mostly-paused entity
// must not force a potentially large joined read merely to establish that
// it is too expensive for the pre-revenue Cron. Reject >10 without partial
// fan-out. The second join is also LIMIT 11 to detect membership races.
// The existing publisher's unbounded getWatchersForEntity stays unchanged.
const SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS = 10;
async function getSocCronWatchersCostGuard(entityType, entityId) {
  const params = [entityType, entityId, SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS + 1];
  const membership = await d1.query(
    SOC_CRON_MEMBERSHIP_PROBE_SQL,
    params
  );
  if (membership.length > SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS) {
    return { allowed: false, watchers: [], reason: 'membership_limit' };
  }
  if (membership.length === 0) return { allowed: true, watchers: [] };
  const rows = await d1.query(
    SOC_CRON_ACTIVE_WATCHERS_SQL,
    params
  );
  if (rows.length > SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS) {
    return { allowed: false, watchers: [], reason: 'concurrent_membership_growth' };
  }
  return {
    allowed: true,
    watchers: rows.map(w => ({ watchlistId: w.watchlist_id, ownerId: w.owner_id }))
  };
}

// Global event -> customer match. Returns only watchlists whose status is
// not 'paused' -- pausing a watchlist stops new matches without deleting
// membership or history. Never reveals one customer's watch to another
// (only the caller-supplied entity is resolved, and the result is
// consumed internally by the change engine, never echoed back to a
// customer-facing response). A single JOIN, replacing the Redis version's
// SMEMBERS-then-per-watchlist-GET loop.
async function getWatchersForEntity(entityType, entityId) {
  const rows = await d1.query(
    `SELECT we.watchlist_id, w.owner_id
     FROM watchlist_entities we
     JOIN watchlists w ON w.id = we.watchlist_id
     WHERE we.entity_type = ? AND we.entity_id = ? AND w.status != 'paused'`,
    [entityType, entityId]
  );
  return rows.map(r => ({ watchlistId: r.watchlist_id, ownerId: r.owner_id }));
}

async function markEvaluated(entityType, entityId, whenIso) {
  // No-op placeholder (per-entity last-evaluated tracking lives in the
  // snapshot record itself, api/_lib/change-engine.js) -- kept as a named
  // function so callers don't need to know that storage detail. Unchanged
  // from the Redis version, which was already a no-op here too.
  return true;
}

// Idempotent per (owner, event): the SAME owner can watch the SAME entity
// via two different watchlists (getWatchersForEntity() returns one row
// per watchlist_id, not one per distinct owner), so this can legitimately
// be called twice for the same (owner, event) pair in one evaluation
// cycle -- ON CONFLICT DO NOTHING reproduces ZADD's natural per-member
// dedup, not a coincidence of the schema (see the migration file's own
// design note 4).
async function appendToOwnerFeed(ownerId, eventId, observedAtMs) {
  await d1.run(
    `INSERT INTO owner_feed (owner_id, event_id, observed_at_ms) VALUES (?, ?, ?)
     ON CONFLICT(owner_id, event_id) DO NOTHING`,
    [ownerId, eventId, observedAtMs]
  );
  await d1.run(
    `DELETE FROM owner_feed WHERE owner_id = ? AND event_id NOT IN
     (SELECT event_id FROM owner_feed WHERE owner_id = ? ORDER BY observed_at_ms DESC, event_id DESC LIMIT ?)`,
    [ownerId, ownerId, FEED_MAX_PER_OWNER]
  ).catch(() => {});
}

// Paginated, newest-first, stable ordering. `cursor` is a 0-based offset
// -- simple and correct at this feature's bounded-per-owner scale (max
// FEED_MAX_PER_OWNER entries), unchanged semantics from the Redis version.
async function getOwnerFeedPage(ownerId, { limit = 20, cursor = 0 } = {}) {
  const boundedLimit = Math.max(1, Math.min(limit, 100));
  const start = Math.max(0, cursor);
  const rows = await d1.query(
    'SELECT event_id FROM owner_feed WHERE owner_id = ? ORDER BY observed_at_ms DESC, event_id DESC LIMIT ? OFFSET ?',
    [ownerId, boundedLimit, start]
  );
  const [{ cnt }] = await d1.query('SELECT COUNT(*) AS cnt FROM owner_feed WHERE owner_id = ?', [ownerId]);
  const ids = rows.map(r => r.event_id);
  const end = start + ids.length;
  return { eventIds: ids, total: cnt, nextCursor: end < cnt ? end : null };
}

module.exports = {
  WATCHLIST_SCHEMA_VERSION,
  SUPPORTED_ENTITY_TYPES,
  MAX_WATCHLISTS_PER_OWNER,
  MAX_ENTITIES_PER_WATCHLIST,
  getWatchlistEntitlements,
  createWatchlist,
  listWatchlists,
  getWatchlist,
  updateWatchlist,
  deleteWatchlist,
  listEntities,
  addEntity,
  removeEntity,
  getAllWatchedEntityKeys,
  getBoundedLegacyWatchedEntityKeys,
  GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS,
  getWatchedEntityWindow,
  getWatchersForEntity,
  getSocCronWatchersCostGuard,
  SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS,
  SOC_WATCH_WINDOW_FIRST_SQL,
  SOC_WATCH_WINDOW_SEEK_SQL,
  SOC_CRON_MEMBERSHIP_PROBE_SQL,
  SOC_CRON_ACTIVE_WATCHERS_SQL,
  markEvaluated,
  appendToOwnerFeed,
  getOwnerFeedPage,
  auditWatchlistAction,
  validateEntityRef,
};
