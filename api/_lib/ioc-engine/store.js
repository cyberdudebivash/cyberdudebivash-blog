'use strict';

/**
 * Persistent evidence-only IOC store: merge, confidence, aging, revocation
 * and customer-feed publication.
 *
 * Pure functions over plain objects (no network). File I/O is limited to
 * readJsonFile/writeJsonAtomic so the refresh script and tests share one
 * implementation. Design: docs/architecture/IOC-INTELLIGENCE-PIPELINE.md.
 *
 * Invariants enforced here (and re-checked by validateFeed before any write):
 * - every indicator has >= 1 observation from an allowlisted source with a
 *   record URL ("no source = no customer IOC");
 * - values re-pass validateIndicator() on every run, so a value that a newer
 *   safety rule rejects is REVOKED, not silently kept;
 * - absence from a later export never deletes an indicator; it ages by its
 *   own last_seen (ACTIVE -> STALE -> EXPIRED);
 * - confidence is a deterministic function of the observations and age.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { validateIndicator, TYPES } = require('./validate');

const SCHEMA_VERSION = 1;
const CONFIDENCE_LEVELS = Object.freeze(['LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH']);
const CONFIDENCE_SCORE = Object.freeze({ LOW: 15, MEDIUM: 50, HIGH: 85, VERY_HIGH: 95 });
const STATUSES = Object.freeze(['ACTIVE', 'STALE', 'EXPIRED', 'REVOKED']);
const DAY = 86400000;

// Days since the source last observed the value. Network infrastructure
// rotates fast; file hashes never change meaning but lose operational value.
const AGING_DAYS = Object.freeze({
  ipv4:   { stale: 7,  expire: 30 },
  ipv6:   { stale: 7,  expire: 30 },
  url:    { stale: 14, expire: 60 },
  domain: { stale: 30, expire: 90 },
  sha256: { stale: 90, expire: 365 },
  sha1:   { stale: 90, expire: 365 },
  md5:    { stale: 90, expire: 365 },
});
const RETAIN_EXPIRED_DAYS = 30;
const RETAIN_REVOKED_DAYS = 90;
const STORE_CAP = 2000;
// Hard ceiling on the published feed (Worker bundle size / cost guardrail,
// docs/operations/CLOUDFLARE-COST-GUARDRAILS.md). config.feed_cap may lower
// it; raising it requires changing this constant in review.
const FEED_CAP_HARD_LIMIT = 600;
const MAX_OBSERVATIONS = 8;
const MAX_REVOCATIONS_PUBLISHED = 100;

// STIX 2.1 indicator ids are UUIDv5 under a fixed SENTINEL APEX namespace,
// so the same indicator keeps the same id across runs and exports.
const STIX_NAMESPACE = '8f2c6a3e-4b1d-5c7e-9a0f-3d6b2e8c1f47';

function sha256Hex(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function uuidv5(name, namespace = STIX_NAMESPACE) {
  const ns = Buffer.from(namespace.replace(/-/g, ''), 'hex');
  const h = crypto.createHash('sha1').update(Buffer.concat([ns, Buffer.from(String(name), 'utf8')])).digest();
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.subarray(0, 16).toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20, 32)}`;
}

const indicatorKey = (type, value) => `${type}|${value}`;
const indicatorId = (type, value) => `ioc:${type}:${sha256Hex(indicatorKey(type, value)).slice(0, 24)}`;

function emptyStore() {
  return { schema_version: SCHEMA_VERSION, updated_at: null, last_success_at: null, http_cache: {}, indicators: {}, revocations: [] };
}

function levelIndex(level) { return CONFIDENCE_LEVELS.indexOf(level); }
function shiftLevel(level, delta) {
  const i = Math.max(0, Math.min(CONFIDENCE_LEVELS.length - 1, levelIndex(level) + delta));
  return CONFIDENCE_LEVELS[i];
}

// Per-observation confidence from what the source itself asserts.
function observationLevel(obs) {
  switch (obs.source) {
    case 'threatfox':
      return Number(obs.source_confidence) >= 90 ? 'HIGH' : 'MEDIUM';
    case 'urlhaus':
      return obs.source_status === 'online' ? 'HIGH' : 'MEDIUM';
    case 'feodotracker':
      return obs.source_status === 'online' ? 'HIGH' : 'MEDIUM';
    case 'malwarebazaar':
      return 'HIGH';
    default:
      return 'LOW';
  }
}

function lifecycle(type, lastSeen, now) {
  const a = AGING_DAYS[type];
  const age = (now - Date.parse(lastSeen)) / DAY;
  if (Number.isNaN(age)) return { status: 'EXPIRED', expires_at: null };
  const expiresAt = new Date(Date.parse(lastSeen) + a.expire * DAY).toISOString();
  if (age > a.expire) return { status: 'EXPIRED', expires_at: expiresAt };
  if (age > a.stale) return { status: 'STALE', expires_at: expiresAt };
  return { status: 'ACTIVE', expires_at: expiresAt };
}

/**
 * Deterministic confidence: strongest source assertion, +1 level when two or
 * more independent sources corroborate, -1 level once STALE.
 */
function scoreConfidence(observations, status) {
  const basis = [];
  let level = 'LOW';
  for (const o of observations) {
    const l = observationLevel(o);
    if (levelIndex(l) > levelIndex(level)) level = l;
  }
  basis.push(`source_assertion:${level}`);
  const distinct = new Set(observations.map(o => o.source)).size;
  if (distinct >= 2) { level = shiftLevel(level, +1); basis.push(`corroborated_by_${distinct}_sources`); }
  if (status === 'STALE') { level = shiftLevel(level, -1); basis.push('aged_stale'); }
  return { confidence: level, confidence_basis: basis };
}

function recommendedAction(entry) {
  if (entry.status !== 'ACTIVE') return 'hunt';
  if (entry.flags && entry.flags.shared_hosting) return 'alert';
  return levelIndex(entry.confidence) >= levelIndex('HIGH') ? 'block' : 'alert';
}

function provenanceHash(entry) {
  const obs = entry.observations
    .map(o => [o.source, o.source_record_id, o.source_url, o.first_seen, o.last_seen].join('|'))
    .sort();
  return sha256Hex([entry.type, entry.value, ...obs].join('\n'));
}

function union(a, b, max) { return [...new Set([...(a || []), ...(b || [])])].slice(0, max); }

/**
 * Merge one run's candidates (output of adapters.parseSource) into the store.
 * Returns { store, stats }. `sources` is the allowlist config (for names/tiers).
 */
function mergeCandidates(store, candidates, sources, nowIso) {
  const byId = Object.fromEntries(sources.map(s => [s.id, s]));
  const stats = { new: 0, updated: 0, unknown_source: 0 };
  for (const c of candidates) {
    const src = byId[c.observation.source];
    if (!src || !src.enabled) { stats.unknown_source++; continue; }
    const key = indicatorKey(c.type, c.value);
    let e = store.indicators[key];
    if (!e) {
      e = store.indicators[key] = {
        id: indicatorId(c.type, c.value),
        stix_id: `indicator--${uuidv5(key)}`,
        type: c.type, value: c.value, display_value: c.display_value,
        flags: c.flags || {},
        ingested_at: nowIso,
        observations: [],
        context: {}, tags: [], related_cves: [], related_malware: [], related_actors: [],
      };
      stats.new++;
    } else stats.updated++;
    const obs = { ...c.observation, retrieved_at: nowIso };
    const i = e.observations.findIndex(o => o.source === obs.source && o.source_record_id === obs.source_record_id);
    if (i >= 0) {
      const prev = e.observations[i];
      obs.first_seen = [prev.first_seen, obs.first_seen].filter(Boolean).sort()[0];
      obs.last_seen = [prev.last_seen, obs.last_seen].filter(Boolean).sort().pop();
      e.observations[i] = obs;
    } else {
      e.observations.push(obs);
    }
    e.observations.sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || '') || a.source.localeCompare(b.source));
    e.observations = e.observations.slice(0, MAX_OBSERVATIONS);
    e.context = { ...e.context, ...Object.fromEntries(Object.entries(c.context || {}).filter(([, v]) => v != null)) };
    e.tags = union(e.tags, c.tags, 16);
    e.related_cves = union(e.related_cves, c.related_cves, 16);
    e.related_malware = union(e.related_malware, c.related_malware, 8);
    e.flags = { ...e.flags, ...(c.flags || {}) };
    e.updated_at = nowIso;
  }
  return { store, stats };
}

/**
 * Recompute derived fields for every stored indicator (validation, status,
 * confidence, provenance), apply revocations and retention. Idempotent.
 */
function refreshDerived(store, sources, nowIso, revocationList = []) {
  const now = Date.parse(nowIso);
  const byId = Object.fromEntries(sources.map(s => [s.id, s]));
  const revoked = new Map(revocationList.map(r => [indicatorKey(r.type, String(r.value).toLowerCase()), r.reason || 'operator_revocation']));
  for (const [key, e] of Object.entries(store.indicators)) {
    // Drop observations whose source is no longer allowlisted/enabled.
    e.observations = (e.observations || []).filter(o => byId[o.source] && byId[o.source].enabled && o.source_url);
    if (!e.observations.length) { delete store.indicators[key]; continue; }

    const v = validateIndicator(e.type, e.value);
    const revokeReason = !v.ok ? `safety_filter:${v.reason}` : revoked.get(indicatorKey(e.type, String(e.value).toLowerCase()));
    if (revokeReason && e.status !== 'REVOKED') {
      e.status = 'REVOKED';
      e.revoked_at = nowIso;
      e.status_reason = revokeReason;
      store.revocations.push({ id: e.id, stix_id: e.stix_id, type: e.type, value: e.value, revoked_at: nowIso, reason: revokeReason });
    }

    const lastSeen = e.observations.map(o => o.last_seen).filter(Boolean).sort().pop();
    const firstSeen = e.observations.map(o => o.first_seen).filter(Boolean).sort()[0];
    e.first_seen = firstSeen;
    e.last_seen = lastSeen;
    const primary = e.observations[0];
    e.source = primary.source;
    e.source_name = byId[primary.source].name;
    e.source_url = primary.source_url;
    e.source_tier = byId[primary.source].tier;
    e.source_published_at = e.observations.map(o => o.source_published_at).filter(Boolean).sort()[0] || firstSeen;
    e.sources = [...new Set(e.observations.map(o => o.source))].sort();
    e.tlp = 'TLP:CLEAR';
    const syntaxFail = !v.ok && /_syntax$/.test(v.reason);
    const routeFail = !v.ok && /^(url_host_)?ipv[46]_/.test(v.reason);
    e.validation = {
      syntax: syntaxFail ? 'fail' : 'pass',
      public_routability: /^(ipv4|ipv6|url)$/.test(e.type) ? (routeFail ? 'fail' : 'pass') : 'n/a',
      reserved_value: !v.ok && !syntaxFail ? 'fail' : 'pass',
    };

    if (e.status !== 'REVOKED') {
      const lc = lifecycle(e.type, lastSeen, now);
      e.status = lc.status;
      e.expires_at = lc.expires_at;
      delete e.status_reason;
    }
    const conf = scoreConfidence(e.observations, e.status);
    e.confidence = conf.confidence;
    e.confidence_basis = conf.confidence_basis;
    e.confidence_score = CONFIDENCE_SCORE[e.confidence];
    e.detection = { recommended_action: recommendedAction(e) };
    e.provenance_hash = provenanceHash(e);
  }

  // Retention: bounded store, never unbounded growth in the repository.
  for (const [key, e] of Object.entries(store.indicators)) {
    if (e.status === 'EXPIRED' && now - Date.parse(e.expires_at) > RETAIN_EXPIRED_DAYS * DAY) delete store.indicators[key];
    else if (e.status === 'REVOKED' && now - Date.parse(e.revoked_at) > RETAIN_REVOKED_DAYS * DAY) delete store.indicators[key];
  }
  const entries = Object.entries(store.indicators);
  if (entries.length > STORE_CAP) {
    const rank = { ACTIVE: 0, STALE: 1, REVOKED: 2, EXPIRED: 3 };
    entries.sort(([, a], [, b]) => rank[a.status] - rank[b.status] || (b.last_seen || '').localeCompare(a.last_seen || '') || a.id.localeCompare(b.id));
    for (const [key] of entries.slice(STORE_CAP)) delete store.indicators[key];
  }
  store.revocations = store.revocations
    .filter(r => now - Date.parse(r.revoked_at) <= RETAIN_REVOKED_DAYS * DAY)
    .slice(-MAX_REVOCATIONS_PUBLISHED);
  store.updated_at = nowIso;
  return store;
}

// Fields published to customers. Internal bookkeeping (http_cache) stays in
// the store only.
const FEED_FIELDS = ['id', 'stix_id', 'value', 'display_value', 'type', 'source', 'source_name', 'source_url', 'source_tier',
  'source_published_at', 'sources', 'first_seen', 'last_seen', 'ingested_at', 'updated_at', 'confidence', 'confidence_score',
  'confidence_basis', 'status', 'tlp', 'context', 'tags', 'related_cves', 'related_malware', 'related_actors', 'expires_at',
  'provenance_hash', 'validation', 'flags', 'detection', 'observations'];

function pick(e) { return Object.fromEntries(FEED_FIELDS.map(k => [k, e[k] === undefined ? null : e[k]])); }

/**
 * Per-type allocation of the feed cap. Without it, one type with many fresh
 * records (e.g. online URLs) fills the whole cap and pushes out older but
 * still ACTIVE hashes. Pass 1 gives each type up to floor(cap * share) of its
 * best records; pass 2 hands slots a type could not use to the best remaining
 * records of any type, so the cap is never left unfilled. `eligible` must
 * already be in feed order; the result is deterministic.
 */
function selectBalanced(eligible, cap, shares) {
  if (!shares || typeof shares !== 'object') return eligible.slice(0, cap);
  const taken = new Set();
  const used = {};
  for (const e of eligible) {
    const quota = Math.floor(cap * (Number(shares[e.type]) || 0));
    if ((used[e.type] || 0) < quota && taken.size < cap) {
      taken.add(e);
      used[e.type] = (used[e.type] || 0) + 1;
    }
  }
  for (const e of eligible) {
    if (taken.size >= cap) break;
    taken.add(e);
  }
  return [...taken];
}

/** Config check: shares must name known types, be non-negative and sum to <= 1. */
function validateTypeShares(shares) {
  if (shares == null) return [];
  if (typeof shares !== 'object' || Array.isArray(shares)) return ['type_shares must be an object'];
  const problems = [];
  let sum = 0;
  for (const [t, v] of Object.entries(shares)) {
    if (!TYPES.includes(t)) problems.push(`type_shares: unknown type ${t}`);
    if (!(Number(v) >= 0)) problems.push(`type_shares: ${t} must be a non-negative number`);
    sum += Number(v) || 0;
  }
  if (sum > 1 + 1e-9) problems.push(`type_shares sum ${sum} exceeds 1`);
  return problems;
}

/**
 * Build the customer feed. Only ACTIVE/STALE indicators at or above the
 * publication threshold are published. `sourceRuns` is this run's per-source
 * outcome; status is "healthy" only when every enabled source succeeded or
 * was unchanged, independent of how many indicators that produced.
 */
function buildFeed(store, config, sourceRuns, nowIso) {
  const threshold = levelIndex(config.publication_threshold || 'MEDIUM');
  const statusRank = { ACTIVE: 0, STALE: 1 };
  const eligible = Object.values(store.indicators)
    .filter(e => (e.status === 'ACTIVE' || e.status === 'STALE') && levelIndex(e.confidence) >= threshold);
  const order = (a, b) =>
    statusRank[a.status] - statusRank[b.status] ||
    levelIndex(b.confidence) - levelIndex(a.confidence) ||
    (b.last_seen || '').localeCompare(a.last_seen || '') ||
    a.id.localeCompare(b.id);
  eligible.sort(order);
  const cap = Math.min(Number(config.feed_cap) || FEED_CAP_HARD_LIMIT, FEED_CAP_HARD_LIMIT);
  const items = selectBalanced(eligible, cap, config.type_shares).sort(order).map(pick);

  const enabled = config.sources.filter(s => s.enabled);
  const okStates = new Set(['ok', 'not_modified']);
  const failed = enabled.filter(s => !okStates.has((sourceRuns[s.id] || {}).state));
  const status = failed.length === 0 ? 'healthy' : (failed.length === enabled.length && !items.length ? 'unavailable' : 'degraded');

  const count = (arr, f) => arr.reduce((m, x) => { const k = f(x); m[k] = (m[k] || 0) + 1; return m; }, {});
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: nowIso,
    feed_status: {
      status,
      indicator_count: items.length,
      last_success_at: store.last_success_at,
      publication_threshold: config.publication_threshold || 'MEDIUM',
      failed_sources: failed.map(s => s.id),
      sources: enabled.map(s => ({
        id: s.id, name: s.name, tier: s.tier, license: s.license, terms_url: s.terms_url,
        state: (sourceRuns[s.id] || {}).state || 'not_run',
        checked_at: (sourceRuns[s.id] || {}).checked_at || null,
        published: items.filter(i => i.sources.includes(s.id)).length,
      })),
      by_type: count(items, i => i.type),
      by_confidence: count(items, i => i.confidence),
      by_status: count(items, i => i.status),
      store_size: Object.keys(store.indicators).length,
      methodology: '/docs/intelligence/IOC-SOURCE-POLICY.md',
    },
    items,
    revocations: store.revocations.slice(-MAX_REVOCATIONS_PUBLISHED),
  };
}

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/**
 * Schema/invariant gate run before every publish. Returns a list of problems;
 * an empty list means the feed may be written. Re-validates every value so a
 * corrupted or hand-edited store cannot publish a protected/reserved value.
 */
function validateFeed(feed, config) {
  const problems = [];
  const allowed = new Set(config.sources.filter(s => s.enabled).map(s => s.id));
  if (!feed || feed.schema_version !== SCHEMA_VERSION || !Array.isArray(feed.items)) return ['feed shape'];
  if (!feed.feed_status || !['healthy', 'degraded', 'unavailable'].includes(feed.feed_status.status)) problems.push('feed_status');
  if (feed.feed_status && feed.feed_status.indicator_count !== feed.items.length) problems.push('indicator_count mismatch');
  const ids = new Set();
  for (const i of feed.items) {
    const where = i && i.id ? i.id : '(no id)';
    if (!i || !TYPES.includes(i.type)) { problems.push(`${where}: type`); continue; }
    const v = validateIndicator(i.type, i.value);
    if (!v.ok || v.value !== i.value) problems.push(`${where}: value fails validation (${v.reason || 'not normalized'})`);
    if (ids.has(i.id)) problems.push(`${where}: duplicate id`);
    ids.add(i.id);
    if (i.id !== indicatorId(i.type, i.value)) problems.push(`${where}: id not canonical`);
    if (!/^indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(i.stix_id || '')) problems.push(`${where}: stix_id`);
    if (!Array.isArray(i.observations) || !i.observations.length) problems.push(`${where}: no provenance`);
    for (const o of i.observations || []) {
      if (!allowed.has(o.source)) problems.push(`${where}: source ${o.source} not allowlisted`);
      if (!/^https:\/\//.test(o.source_url || '')) problems.push(`${where}: observation without record URL`);
    }
    if (!allowed.has(i.source) || !/^https:\/\//.test(i.source_url || '')) problems.push(`${where}: primary source`);
    if (!CONFIDENCE_LEVELS.includes(i.confidence)) problems.push(`${where}: confidence`);
    if (!['ACTIVE', 'STALE'].includes(i.status)) problems.push(`${where}: unpublishable status ${i.status}`);
    for (const k of ['first_seen', 'last_seen', 'ingested_at', 'updated_at', 'expires_at']) {
      if (!ISO_RE.test(i[k] || '')) problems.push(`${where}: ${k}`);
    }
    if (/^(sha256|sha1|md5)$/.test(i.type) && !(i.related_malware && i.related_malware.length)) problems.push(`${where}: hash without malware context`);
    if (!/^[0-9a-f]{64}$/.test(i.provenance_hash || '')) problems.push(`${where}: provenance_hash`);
  }
  if (feed.items.length > (Number(config.feed_cap) || 600)) problems.push('feed exceeds cap');
  if (Number(config.feed_cap) > FEED_CAP_HARD_LIMIT) problems.push(`feed_cap ${config.feed_cap} exceeds hard limit ${FEED_CAP_HARD_LIMIT}`);
  if (feed.items.length > FEED_CAP_HARD_LIMIT) problems.push('feed exceeds hard limit');
  problems.push(...validateTypeShares(config.type_shares));
  return problems;
}

/** Public, value-free summary written to api/intel/iocs.json (served statically). */
function buildPublicSummary(feed) {
  const fsx = feed.feed_status;
  return {
    generated: feed.generated_at,
    version: '6.0',
    engine: 'SENTINEL APEX evidence-only IOC engine',
    platform: 'CYBERDUDEBIVASH SENTINEL APEX',
    docs: 'https://blog.cyberdudebivash.in/api.html',
    endpoint: '/api/intel/iocs.json',
    description: 'Public status of the evidence-only IOC feed. Indicator values, provenance and STIX 2.1 are served by the authenticated API (/api/v1/intel?action=iocs) on Pro, Team and Enterprise plans.',
    feed_status: {
      status: fsx.status,
      indicator_count: fsx.indicator_count,
      last_success_at: fsx.last_success_at,
      by_type: fsx.by_type,
      by_confidence: fsx.by_confidence,
      sources: fsx.sources.map(s => ({ id: s.id, name: s.name, state: s.state, license: s.license })),
    },
    count: 0,
    items: [],
  };
}

function readJsonFile(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return fallback; }
}

// Write-to-temp then rename: readers never observe a partially written file,
// and a crash mid-write leaves the previous (last-known-good) file intact.
function writeJsonAtomic(file, data, pretty = false) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, pretty ? 1 : 0) + '\n', 'utf8');
  fs.renameSync(tmp, file);
}

module.exports = {
  SCHEMA_VERSION, CONFIDENCE_LEVELS, CONFIDENCE_SCORE, STATUSES, AGING_DAYS, STORE_CAP, FEED_CAP_HARD_LIMIT, STIX_NAMESPACE,
  emptyStore, indicatorId, indicatorKey, uuidv5, observationLevel, lifecycle, scoreConfidence, recommendedAction,
  mergeCandidates, refreshDerived, selectBalanced, validateTypeShares, buildFeed, validateFeed, buildPublicSummary, readJsonFile, writeJsonAtomic,
};
