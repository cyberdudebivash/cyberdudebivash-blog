'use strict';

/**
 * Request-time reader for the evidence-only IOC feed (data/ioc-feed.json).
 *
 * - Workers: the feed is bundled at build time via require() (no filesystem);
 *   it refreshes on each deploy, like every other intel file (api/_lib/intel.js).
 * - Node: read from disk with a 60 s cache.
 * data/ioc-feed.json is NOT in the public asset allowlist
 * (scripts/build-cloudflare-assets.js); indicator values are served only
 * through the authenticated, tier-gated API.
 */

const { isCloudflareWorkers } = require('../runtime-env');
const { TYPES } = require('./validate');

const CONFIDENCE_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH'];
const EMPTY_FEED = Object.freeze({ schema_version: 1, generated_at: null, feed_status: { status: 'unavailable', indicator_count: 0, sources: [] }, items: [], revocations: [] });
const FRESH_HOURS = 6;
const CACHE_TTL_MS = 60000;

let BUNDLED = null;
let FEED_PATH = null;
if (isCloudflareWorkers()) {
  try { BUNDLED = require('../../../data/ioc-feed.json'); } catch (_) { BUNDLED = null; }
} else {
  FEED_PATH = require('path').resolve(__dirname, '../../../data/ioc-feed.json');
}

let _cache = null;
let _cacheTime = 0;
let _override = null;

function getFeed() {
  if (_override) return _override;
  if (BUNDLED) return BUNDLED;
  if (!FEED_PATH) return EMPTY_FEED;
  const now = Date.now();
  if (_cache && now - _cacheTime < CACHE_TTL_MS) return _cache;
  try {
    _cache = JSON.parse(require('fs').readFileSync(FEED_PATH, 'utf8'));
  } catch (_) {
    _cache = EMPTY_FEED;
  }
  _cacheTime = now;
  return _cache;
}

/** Test seam: serve a fixed feed object (null restores normal loading). */
function setFeedForTesting(feed) { _override = feed; _projectionCache = new WeakMap(); }

/**
 * Feed status as seen at request time: the pipeline's own status plus
 * freshness of the published file, so a stalled pipeline is reported as
 * stale instead of silently serving old data as current.
 */
function runtimeFeedStatus(feed = getFeed(), now = Date.now()) {
  const fsx = feed.feed_status || {};
  const generated = Date.parse(feed.generated_at || '');
  const ageHours = Number.isNaN(generated) ? null : Math.round(((now - generated) / 3600000) * 10) / 10;
  return {
    status: fsx.status || 'unavailable',
    freshness: ageHours == null ? 'unknown' : ageHours <= FRESH_HOURS ? 'fresh' : 'stale',
    generated_at: feed.generated_at || null,
    age_hours: ageHours,
    last_success_at: fsx.last_success_at || null,
    indicator_count: fsx.indicator_count || 0,
    publication_threshold: fsx.publication_threshold || 'MEDIUM',
    failed_sources: fsx.failed_sources || [],
    sources: fsx.sources || [],
    by_type: fsx.by_type || {},
    by_confidence: fsx.by_confidence || {},
    methodology: fsx.methodology || null,
  };
}

class QueryError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const MAX_TEXT = 100;
function text(q, name) {
  const v = q[name];
  if (v === undefined || v === '') return null;
  const s = String(v).trim();
  if (s.length > MAX_TEXT) throw new QueryError('INVALID_PARAMETER', `${name} must not exceed ${MAX_TEXT} characters.`);
  return s;
}
function date(q, name) {
  const s = text(q, name);
  if (s == null) return null;
  const t = Date.parse(s);
  if (!/^\d{4}-\d{2}-\d{2}/.test(s) || Number.isNaN(t)) throw new QueryError('INVALID_PARAMETER', `${name} must be an ISO-8601 date.`);
  return new Date(t).toISOString();
}

/**
 * Filter + paginate feed items. Order is the feed's own deterministic order
 * (status, confidence, last_seen, id). Throws QueryError on invalid input.
 */
function queryFeed(items, q = {}) {
  let out = items;
  const type = text(q, 'type');
  if (type) {
    const t = type.toLowerCase();
    if (!TYPES.includes(t)) throw new QueryError('INVALID_PARAMETER', `type must be one of: ${TYPES.join(', ')}.`);
    out = out.filter(i => i.type === t);
  }
  const conf = text(q, 'confidence');
  if (conf) {
    const c = conf.toUpperCase();
    if (!CONFIDENCE_LEVELS.includes(c)) throw new QueryError('INVALID_PARAMETER', `confidence must be one of: ${CONFIDENCE_LEVELS.join(', ')}.`);
    out = out.filter(i => CONFIDENCE_LEVELS.indexOf(i.confidence) >= CONFIDENCE_LEVELS.indexOf(c));
  }
  // Legacy numeric filter (0-1 or 0-100), kept for existing integrations.
  const mc = text(q, 'min_confidence');
  if (mc) {
    const n = Number(mc);
    if (!Number.isFinite(n) || n < 0 || n > 100) throw new QueryError('INVALID_PARAMETER', 'min_confidence must be a number from 0 to 100.');
    const threshold = n <= 1 ? n * 100 : n;
    out = out.filter(i => (i.confidence_score || 0) >= threshold);
  }
  const status = text(q, 'status');
  if (status) {
    const s = status.toUpperCase();
    if (!['ACTIVE', 'STALE'].includes(s)) throw new QueryError('INVALID_PARAMETER', 'status must be active or stale.');
    out = out.filter(i => i.status === s);
  }
  const source = text(q, 'source');
  if (source) out = out.filter(i => (i.sources || []).includes(source.toLowerCase()));
  const cve = text(q, 'cve') || text(q, 'related_id');
  if (cve) out = out.filter(i => (i.related_cves || []).includes(cve.toUpperCase()));
  const malware = text(q, 'malware');
  if (malware) { const m = malware.toLowerCase(); out = out.filter(i => (i.related_malware || []).some(x => x.toLowerCase().includes(m))); }
  const actor = text(q, 'actor');
  if (actor) { const a = actor.toLowerCase(); out = out.filter(i => (i.related_actors || []).some(x => x.toLowerCase().includes(a))); }
  const since = date(q, 'since');
  if (since) out = out.filter(i => (i.last_seen || '') >= since);
  const until = date(q, 'until');
  if (until) out = out.filter(i => (i.last_seen || '') <= until);
  const action = text(q, 'recommended_action');
  if (action) out = out.filter(i => i.detection && i.detection.recommended_action === action.toLowerCase());

  const page = Math.min(10000, Math.max(1, parseInt(q.page || '1', 10) || 1));
  const limit = Math.min(200, Math.max(1, parseInt(q.limit || '50', 10) || 50));
  const offset = (page - 1) * limit;
  return {
    items: out.slice(offset, offset + limit),
    total: out.length,
    page,
    limit,
    total_pages: Math.ceil(out.length / limit),
    has_next: offset + limit < out.length,
    ioc_types: [...new Set(out.map(i => i.type))],
  };
}

/**
 * Serving projection of the threat graph: removes IOC nodes that carry no
 * evidence-engine provenance (the legacy regex-derived nodes; ICF-P0-009)
 * and their edges, then adds the feed's evidence-backed indicators as IOC
 * nodes. The persisted graph file is not modified.
 */
let _projectionCache = new WeakMap();
function hasProvenance(node) {
  const p = node && node.attributes && node.attributes.provenance;
  return Boolean(p && Array.isArray(p.sources) && p.sources.length && p.source_url);
}

function projectGraph(graph, feed = getFeed()) {
  if (!graph || !graph.nodes) return graph;
  const cached = _projectionCache.get(graph);
  if (cached && cached.feed === feed) return cached.projected;
  const nodes = {};
  const removed = new Set();
  for (const [id, n] of Object.entries(graph.nodes)) {
    if (n && n.type === 'IOC' && !hasProvenance(n)) { removed.add(id); continue; }
    nodes[id] = n;
  }
  for (const i of feed.items || []) {
    if (nodes[i.id]) continue;
    nodes[i.id] = {
      id: i.id,
      type: 'IOC',
      name: i.value,
      attributes: {
        ioc_type: i.type,
        confidence: i.confidence,
        confidence_score: i.confidence_score,
        status: i.status,
        first_seen: i.first_seen,
        last_seen: i.last_seen,
        related_malware: i.related_malware,
        provenance: { sources: i.sources, source_url: i.source_url, provenance_hash: i.provenance_hash },
      },
      connections: [],
    };
  }
  const edges = (graph.edges || []).filter(e => !removed.has(e.source) && !removed.has(e.target));
  const all = Object.values(nodes);
  const stats = graph.stats ? {
    ...graph.stats,
    total_nodes: all.length,
    iocs: all.filter(n => n.type === 'IOC').length,
    edges: edges.length,
  } : graph.stats;
  const projected = { ...graph, nodes, edges, stats };
  _projectionCache.set(graph, { feed, projected });
  return projected;
}

module.exports = { getFeed, setFeedForTesting, runtimeFeedStatus, queryFeed, QueryError, projectGraph, hasProvenance, FRESH_HOURS };
