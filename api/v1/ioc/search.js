'use strict';
/**
 * Legacy compatibility endpoint: GET /api/v1/ioc/search
 *
 * SECURITY / DATA-INTEGRITY CONTRACT
 * - Requires the same API-key authentication as the canonical intel router.
 * - IOC access is Pro/Enterprise only, matching action=iocs/action=ioc.
 * - Reads the canonical threat-graph-derived search index; it MUST NOT read
 *   data/ioc-canonical.json (the disconnected two-record legacy store).
 * - Inputs are bounded; errors never echo internal exception messages.
 *
 * New integrations should use:
 *   GET /api/v1/intel?action=iocs
 *   GET /api/v1/intel?action=unified-search&type=ioc&q=...
 */

const sec = require('../../_lib/security');
const { authenticate, apiError } = require('../../_lib/middleware');
const { getSearchIndex } = require('../../_lib/intel');
const { tierAtLeast } = require('../../_lib/tier-entitlements');

const MAX_LIMIT = 100;
const MAX_OFFSET = 100000;
const MAX_QUERY_LENGTH = 200;
const ALLOWED_FORMATS = new Set(['json', 'csv']);
const UNSUPPORTED_LEGACY_FILTERS = ['classification', 'campaign', 'actor', 'min_corroboration', 'status'];

function clampInt(value, fallback, min, max) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function markDeprecated(res) {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Link', '</api/v1/intel?action=iocs>; rel="successor-version"');
  res.setHeader('X-Sentinel-Deprecated-Endpoint', '/api/v1/ioc/search');
}

function csvEscape(value) {
  let s = value === null || value === undefined ? '' : String(value);
  // Prevent spreadsheet formula execution when a downloaded CSV is opened.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

module.exports = async (req, res) => {
  const ok = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'], maxBodyBytes: 2048 });
  if (!ok) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const user = await authenticate(req, res);
  if (!user) return;
  if (!tierAtLeast(user.tier, 'pro')) {
    return apiError(res, 403, 'TIER_RESTRICTED', 'IOC search requires Pro or Enterprise plan.');
  }

  markDeprecated(res);

  try {
    const unsupported = UNSUPPORTED_LEGACY_FILTERS.filter(k => req.query[k] !== undefined && req.query[k] !== '');
    if (unsupported.length) {
      return apiError(
        res,
        400,
        'LEGACY_FILTER_UNSUPPORTED',
        `Legacy filter(s) no longer supported against canonical IOC data: ${unsupported.join(', ')}. Use /api/v1/intel?action=unified-search&type=ioc for canonical search.`
      );
    }

    const format = String(req.query.format || 'json').toLowerCase().trim();
    if (format === 'stix') {
      return apiError(res, 400, 'USE_CANONICAL_STIX_ENDPOINT', 'STIX export is available to Enterprise via /api/v1/intel?action=iocs&format=stix.');
    }
    if (!ALLOWED_FORMATS.has(format)) {
      return apiError(res, 400, 'INVALID_FORMAT', 'format must be json or csv.');
    }

    const query = String(req.query.query || '').trim();
    if (query.length > MAX_QUERY_LENGTH) {
      return apiError(res, 400, 'QUERY_TOO_LONG', `query must not exceed ${MAX_QUERY_LENGTH} characters.`);
    }

    const type = String(req.query.type || '').toLowerCase().trim();
    const value = String(req.query.value || '').trim().toLowerCase();
    const confidence = String(req.query.confidence || '').trim().toLowerCase();
    const limit = clampInt(req.query.limit, 100, 1, MAX_LIMIT);
    const offset = clampInt(req.query.offset, 0, 0, MAX_OFFSET);

    let docs = (getSearchIndex().documents || []).filter(d => d.type === 'ioc');
    if (type) docs = docs.filter(d => String(d.ioc_type || '').toLowerCase() === type);
    if (value) docs = docs.filter(d => String(d.name || '').toLowerCase() === value || String(d.id || '').toLowerCase() === value);
    if (confidence) docs = docs.filter(d => String(d.confidence || '').toLowerCase() === confidence);
    if (query) {
      const q = query.toLowerCase();
      docs = docs.filter(d =>
        String(d.id || '').toLowerCase().includes(q) ||
        String(d.name || '').toLowerCase().includes(q) ||
        String(d.ioc_type || '').toLowerCase().includes(q)
      );
    }

    const total = docs.length;
    const iocs = docs.slice(offset, offset + limit);

    if (format === 'csv') {
      const lines = [
        ['id', 'value', 'type', 'confidence', 'first_seen', 'detail_url'].map(csvEscape).join(','),
        ...iocs.map(i => [i.id, i.name, i.ioc_type, i.confidence, i.first_seen, i.detail_url].map(csvEscape).join(',')),
      ];
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="sentinel-apex-iocs.csv"');
      return res.status(200).send(lines.join('\n'));
    }

    return res.status(200).json({
      success: true,
      count: iocs.length,
      total,
      iocs,
      pagination: { limit, offset, has_next: offset + limit < total },
      deprecated: true,
      successor: '/api/v1/intel?action=iocs',
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error('[IOC API] canonical compatibility search failed:', e && e.message ? e.message : 'unknown');
    return apiError(res, 500, 'IOC_SEARCH_FAILED', 'IOC search is temporarily unavailable.');
  }
};
