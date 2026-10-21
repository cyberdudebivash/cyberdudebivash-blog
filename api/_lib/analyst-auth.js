/**
 * CYBERDUDEBIVASH SENTINEL APEX — Analyst Authentication
 *
 * Real, per-analyst identity for the SOC workbench (investigations, cases,
 * intelligence graph, search). Before this module existed, every
 * workbench/intelligence route either had NO authentication at all, or
 * trusted a caller-supplied `analyst` query parameter / hardcoded
 * 'analyst'/'api' string as the acting identity with zero verification --
 * meaning any request could read or write investigation, case, and
 * intelligence-graph data, and could claim to be any analyst while doing
 * it.
 *
 * Analysts are configured via the ANALYST_KEYS env var (a JSON array of
 * {id, name, role, key}), mirroring ADMIN_SECRET_KEY's single-env-var
 * simplicity for this internal-only round -- but shaped as real, distinct
 * identities (never one shared secret), so a future per-customer access
 * model can extend the exact same {id, name, role, key} shape (e.g. swap
 * the env-var source for a Redis- or database-backed store) without
 * changing any requireAnalyst() call site.
 *
 * Usage in every workbench/intelligence router (mirrors admin.js's own
 * sequential-guard convention -- sec.guardRequest() then
 * sec.adminIpRateLimit() -- rather than inventing a new calling pattern):
 *
 *   const { requireAnalyst } = require('../../_lib/analyst-auth');
 *   ...
 *   const analyst = await requireAnalyst(req, res, fail);
 *   if (!analyst) return; // requireAnalyst already wrote the response
 */
'use strict';
const crypto = require('crypto');
const redis = require('./redis');

const ANALYST_RATE_LIMIT = 120; // req/min per analyst -- trusted internal use,
                                  // higher than the public 10/min global limit
                                  // (security.js) since one workbench page can
                                  // fire several requests (dashboard, timeline,
                                  // evidence, graph) on a single navigation.

function _loadAnalysts() {
  const raw = process.env.ANALYST_KEYS;
  if (!raw) return [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter(a => a && typeof a.id === 'string' && a.id && typeof a.key === 'string' && a.key.length >= 16);
}

function _timingSafeMatch(provided, expected) {
  if (!provided) return false;
  // Fixed 128-char comparison width, matching security.js's verifyAdminKey
  // exactly -- avoids leaking key length via comparison timing.
  const a = expected.padEnd(128).slice(0, 128);
  const b = provided.padEnd(128).slice(0, 128);
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')) && provided === expected;
  } catch (_) {
    return false;
  }
}

/**
 * Verify the X-Analyst-Key header against configured analysts.
 * Returns the matching {id, name, role} or null. Pure -- no response
 * side effects, so it can be unit-tested and reused independent of the
 * rate-limiting/response-writing behavior in requireAnalyst() below.
 */
function verifyAnalystKey(req) {
  const analysts = _loadAnalysts();
  if (!analysts.length) return null; // not configured
  const provided = String((req.headers && req.headers['x-analyst-key']) || '');
  if (!provided) return null;
  const match = analysts.find(a => _timingSafeMatch(provided, a.key));
  if (!match) return null;
  return { id: match.id, name: match.name || match.id, role: match.role || 'analyst' };
}
exports.verifyAnalystKey = verifyAnalystKey;

/**
 * Per-analyst-IP rate limit: 120 req/min. Mirrors security.js's
 * adminIpRateLimit() bucket-key/fail-open pattern exactly, in its own
 * ratelimit:analyst:* namespace so tuning this limit independently never
 * touches the admin or global buckets.
 */
async function analystIpRateLimit(req) {
  const xff = req.headers && req.headers['x-forwarded-for'];
  const ip = xff ? String(xff).split(',')[0].trim().slice(0, 45)
    : String((req.headers && req.headers['x-real-ip']) || (req.socket && req.socket.remoteAddress) || '0.0.0.0').slice(0, 45);
  const minute = Math.floor(Date.now() / 60000);
  const key = `ratelimit:analyst:${ip}:${minute}`;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, 60);
    return count <= ANALYST_RATE_LIMIT;
  } catch (_) {
    // Distinguish a backend outage from a real over-quota analyst. Deny the
    // request rather than silently bypassing the limiter at the worst time.
    return null;
  }
}
exports.analystIpRateLimit = analystIpRateLimit;

/**
 * Full guard for a workbench/intelligence route: verifies the analyst key
 * and applies rate limiting. On failure, writes the response itself via
 * the caller's OWN `fail(res, status, code, message)` function -- every
 * route file already defines one with its own CORS_HEADERS -- so the
 * failure response is byte-consistent with every other error that route
 * already returns, rather than this module guessing at per-file headers.
 * On success returns {id, name, role}; on failure returns null (caller
 * must `if (!analyst) return;` immediately after).
 */
async function requireAnalyst(req, res, fail) {
  const analyst = verifyAnalystKey(req);
  if (!analyst) {
    fail(res, 401, 'UNAUTHORIZED', 'Missing or invalid X-Analyst-Key header. Internal workbench access only.');
    return null;
  }
  const allowed = await analystIpRateLimit(req);
  if (allowed === null) {
    res.setHeader('Retry-After', '60');
    fail(res, 503, 'AUTH_RATE_LIMIT_UNAVAILABLE', 'Analyst authentication protection temporarily unavailable.');
    return null;
  }
  if (!allowed) {
    res.setHeader('Retry-After', '60');
    fail(res, 429, 'RATE_LIMIT_EXCEEDED', `Analyst rate limit: ${ANALYST_RATE_LIMIT} requests/minute`);
    return null;
  }
  return analyst;
}
exports.requireAnalyst = requireAnalyst;
