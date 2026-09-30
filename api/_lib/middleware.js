/**
 * SENTINEL APEX — API Authentication + Rate Limiting Middleware
 * Validates API keys, enforces tier rate limits, logs usage.
 * Phase 1, 4, 8, 11 hardening applied.
 */
'use strict';
const crypto = require('crypto');
const redis  = require('./redis');
const sec    = require('./security');

const RATE_LIMITS = {
  free:       100,
  starter:    5000,
  pro:        25000,
  team:       100000,
  enterprise: 999999,
};

// Canonical ordering lives in ./tier-entitlements; re-exported below so
// existing `middleware.TIERS` consumers keep working unchanged.
const { TIERS } = require('./tier-entitlements');

/* P0 Revenue Conversion v19 — conversion metadata only. This does not alter
 * entitlement order or limits. It turns a real quota-exhaustion event into a
 * deterministic next-tier checkout path while preserving the billing API as
 * the only authority that can accept payment or grant access. */
const NEXT_PAID_TIER = Object.freeze({
  free: 'starter',
  starter: 'pro',
  pro: 'team',
  team: 'enterprise',
  enterprise: null,
});
const DIRECT_CHECKOUT_BASE = 'https://blog.cyberdudebivash.in/buy.html';

function nextPaidTier(tier) {
  return Object.prototype.hasOwnProperty.call(NEXT_PAID_TIER, tier)
    ? NEXT_PAID_TIER[tier]
    : 'starter';
}

function upgradeCheckoutUrl(tier, source = 'api_rate_limit') {
  const nextTier = nextPaidTier(tier);
  if (!nextTier) return null;
  const content = `${String(tier || 'unknown').replace(/[^a-z0-9_.-]/gi, '_')}_quota`;
  const query = new URLSearchParams({
    plan: nextTier,
    checkout: '1',
    utm_source: String(source || 'api_rate_limit').slice(0, 80),
    utm_medium: 'api',
    utm_campaign: 'p0_revenue_conversion_v19',
    utm_content: content.slice(0, 100),
  });
  return `${DIRECT_CHECKOUT_BASE}?${query.toString()}`;
}

function today() {
  return new Date().toISOString().slice(0, 10).replace(/-/g, '');
}

// Best-effort, non-blocking observability for authenticate()'s three
// failure paths -- previously zero visibility into failed auth attempts
// at this platform's single shared authentication chokepoint (GEORP v1
// Phase 5). Mirrors the exact analytics:registrations:* counter pattern
// already established in auth.js's handleRegister(): a running total plus
// a per-day bucket, both fire-and-forget so a Redis hiccup here can never
// affect the actual auth decision already made by the caller.
function recordAuthFailure(reason) {
  redis.incr(`analytics:auth_failures:${reason}:total`).catch(() => {});
  redis.incr(`analytics:auth_failures:${reason}:${today()}`).catch(() => {});
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, X-API-Key, Content-Type, X-Admin-Key',
    'Access-Control-Expose-Headers': 'X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-RateLimit-Tier, X-RateLimit-Upgrade-Tier, X-RateLimit-Upgrade-URL, Link, Retry-After',
    'Access-Control-Max-Age':       '86400',
  };
}

function respond(res, status, body, extra = {}) {
  // Always apply full security headers
  sec.applySecurityHeaders(res);
  res.setHeader('Content-Type', 'application/json');
  Object.entries(extra).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json(body);
}

function apiError(res, status, code, message, extra = {}) {
  respond(res, status, {
    error: { code, message },
    meta:  { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
  }, extra);
}

// Hash API key (SHA-256) for secure storage
function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// Generate a new API key
function generateApiKey() {
  const raw = crypto.randomBytes(32).toString('hex');
  return `sentinel_${raw}`;
}

// Parse API key from request. Credentials in URL query strings are
// deliberately rejected: URLs are routinely captured by access logs,
// browser history, analytics and referrer propagation. Supported transports
// are headers only: Authorization: Bearer or X-API-Key.
function extractApiKey(req) {
  const auth = req.headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  const xkey = req.headers['x-api-key'] || '';
  if (xkey) return xkey.trim();
  return null;
}

// Core auth + rate limit middleware
async function authenticate(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    respond(res, 204, {});
    return null;
  }

  // Fail explicitly when an old integration attempts to put its secret in
  // the URL. This makes migration obvious without ever hashing/logging the
  // query-string value as a credential.
  if (req.query && Object.prototype.hasOwnProperty.call(req.query, 'api_key')) {
    recordAuthFailure('query_key_rejected');
    apiError(res, 400, 'QUERY_API_KEY_REJECTED', 'API keys must not be passed in URLs. Use Authorization: Bearer <key> or X-API-Key header.');
    return null;
  }

  const rawKey = extractApiKey(req);
  if (!rawKey || !rawKey.startsWith('sentinel_')) {
    recordAuthFailure('unauthorized');
    apiError(res, 401, 'UNAUTHORIZED', 'API key required. Pass via Authorization: Bearer <key> or X-API-Key header. Get yours at https://blog.cyberdudebivash.in/api-dashboard.html');
    return null;
  }

  const hash = hashKey(rawKey);
  const userKey = `user:key:${hash}`;

  let userData;
  try {
    const raw = await redis.hgetall(userKey);
    if (!raw || !Array.isArray(raw) || raw.length === 0) {
      recordAuthFailure('invalid_key');
      apiError(res, 401, 'INVALID_KEY', 'API key not found or revoked. Visit https://blog.cyberdudebivash.in/api-dashboard.html to manage your keys.');
      return null;
    }
    // Upstash HGETALL returns flat array [field, value, field, value...]
    userData = {};
    for (let i = 0; i < raw.length; i += 2) userData[raw[i]] = raw[i + 1];
  } catch (e) {
    // Redis unavailable — allow a synthetic dev user ONLY when BOTH
    // NODE_ENV=development AND ALLOW_DEV_AUTH_BYPASS=true are set.
    if (process.env.NODE_ENV === 'development' && process.env.ALLOW_DEV_AUTH_BYPASS === 'true') {
      return { tier: 'pro', userId: 'dev', email: 'dev@local', keyHash: hash };
    }
    // Safe error — never expose Redis internals
    apiError(res, 503, 'SERVICE_UNAVAILABLE', 'Auth service temporarily unavailable. Retry in 30s.');
    return null;
  }

  const tier  = userData.tier || 'free';
  const limit = RATE_LIMITS[tier] || RATE_LIMITS.free;
  const rateKey = `ratelimit:${hash}:${today()}`;

  let used;
  try {
    used = await redis.incr(rateKey);
    if (used === 1) await redis.expire(rateKey, 86400); // expire at end of day

    if (used > limit) {
      recordAuthFailure('rate_limited');
      const nextTier = nextPaidTier(tier);
      const checkoutUrl = upgradeCheckoutUrl(tier);
      const headers = {
        'X-RateLimit-Limit': String(limit),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(Math.ceil(Date.now() / 86400000) * 86400),
        'Retry-After': String(86400 - (Math.floor(Date.now() / 1000) % 86400)),
      };
      if (nextTier && checkoutUrl) {
        headers['X-RateLimit-Upgrade-Tier'] = nextTier;
        headers['X-RateLimit-Upgrade-URL'] = checkoutUrl;
        headers.Link = `<${checkoutUrl}>; rel="upgrade"`;
      }

      respond(res, 429, {
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: nextTier
            ? `Rate limit reached: ${limit} requests/day for ${tier} tier. Upgrade to ${nextTier} for additional capacity.`
            : `Rate limit reached: ${limit} requests/day for enterprise tier. Contact support if you require additional capacity.`,
        },
        ...(nextTier && checkoutUrl ? {
          upgrade: {
            recommended_tier: nextTier,
            checkout_url: checkoutUrl,
            reason: 'daily_api_quota_exhausted',
          },
        } : {}),
        meta: {
          platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0',
          timestamp: new Date().toISOString(),
          revenue_conversion_version: 'v19',
        },
      }, headers);
      return null;
    }

    // Log usage async (don't await — non-blocking)
    logUsage(hash, req, tier).catch(() => {});

    // Update total request count
    redis.hincrby(userKey, 'totalRequests', 1).catch(() => {});
    redis.hset(userKey, 'lastSeen', new Date().toISOString()).catch(() => {});

  } catch (e) {
    // Rate limit service down — fail open for enterprise, fail closed for free
    if (tier === 'enterprise') {
      // continue
    } else {
      apiError(res, 503, 'SERVICE_UNAVAILABLE', 'Rate limit service temporarily unavailable.');
      return null;
    }
  }

  // Set rate limit response headers
  const remaining = Math.max(0, limit - (used || 0));
  res.setHeader('X-RateLimit-Limit', String(limit));
  res.setHeader('X-RateLimit-Remaining', String(remaining));
  res.setHeader('X-RateLimit-Tier', tier);
  res.setHeader('X-Powered-By', 'CYBERDUDEBIVASH SENTINEL APEX v4.0');

  // Near-capacity users are already demonstrating product value. Surface the
  // next paid tier as response metadata before they hard-fail, without changing
  // the response body or consuming additional storage/network services.
  const nextTier = nextPaidTier(tier);
  if (nextTier && limit > 0 && remaining <= Math.ceil(limit * 0.10)) {
    const checkoutUrl = upgradeCheckoutUrl(tier, 'api_capacity_warning');
    if (checkoutUrl) {
      res.setHeader('X-RateLimit-Upgrade-Tier', nextTier);
      res.setHeader('X-RateLimit-Upgrade-URL', checkoutUrl);
      res.setHeader('Link', `<${checkoutUrl}>; rel="upgrade"`);
    }
  }

  return {
    tier,
    userId: userData.userId || hash,
    email:  userData.email || '',
    keyHash: hash,
    requestsUsed: used || 0,
    requestsLimit: limit,
  };
}

// Async usage logger — logs to Redis sorted set for analytics
async function logUsage(keyHash, req, tier) {
  const endpoint = req.url?.split('?')[0] || '/unknown';
  const logKey = `usage:log:${today()}`;
  const entry  = JSON.stringify({
    k: keyHash.slice(0, 8),
    e: endpoint,
    t: tier,
    ts: Date.now(),
    m: req.method,
  });
  await redis.zadd(logKey, Date.now(), entry);
  // Track top endpoints
  await redis.hincrby(`analytics:endpoints:${today()}`, endpoint, 1);
  // Track per-key daily usage in hash
  await redis.hincrby(`analytics:keys:${today()}`, keyHash.slice(0, 16), 1);
}

// Standard success response wrapper
function successResponse(res, data, meta = {}) {
  respond(res, 200, {
    success: true,
    meta: {
      platform:   'CYBERDUDEBIVASH SENTINEL APEX v4.0',
      timestamp:  new Date().toISOString(),
      contact:    'bivash@cyberdudebivash.com',
      docs:       'https://blog.cyberdudebivash.in/api.html',
      ...meta,
    },
    ...data,
  });
}

module.exports = {
  authenticate,
  extractApiKey,
  respond,
  apiError,
  successResponse,
  corsHeaders,
  generateApiKey,
  hashKey,
  RATE_LIMITS,
  TIERS,
  nextPaidTier,
  upgradeCheckoutUrl,
  recordAuthFailure,
  // Re-export security helpers so routers only need one import
  guardRequest:        sec.guardRequest,
  globalIpRateLimit:   sec.globalIpRateLimit,
  applySecurityHeaders:sec.applySecurityHeaders,
  safeError:           sec.safeError,
};
