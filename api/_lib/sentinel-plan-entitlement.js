'use strict';

/**
 * Sentinel APEX plan entitlement for Premium Intelligence (owner decision
 * 2026-10-02: Sentinel APEX is the only payment authority; the Intel Factory
 * delivers premium reports to eligible subscribers).
 *
 * Two credential families reach the premium endpoints:
 *
 *  - `sentinel_…` keys, issued by this blog (Upstash Redis). Their `tier` is
 *    resolved locally by middleware.authenticate(). They also own any legacy
 *    standalone purchase (premium_entitlements.owner_id).
 *  - Sentinel APEX platform credentials (`cdb_…` API keys or a SENTINEL-APEX
 *    JWT), issued by intel.cyberdudebivash.com. Their record lives in the
 *    gateway's API_KEYS_KV and is subject to the gateway's strong-consistency
 *    revocation authority, so the blog never reads that KV directly. It asks
 *    the gateway's existing `/api/auth/validate` through a Cloudflare service
 *    binding (internal, no public hop, no new resource, no shared secret).
 *
 * Fail closed everywhere: an unknown, missing or mis-cased tier is never
 * eligible; an unavailable gateway is an error, never an implicit grant; and
 * nothing a browser sends (?plan=, UTM tags, local storage) is consulted.
 */

const crypto = require('crypto');
const { INTEL_UPGRADE_URL } = require('./payment-utils');
const { tierAtLeast } = require('./tier-entitlements');
const gatewayBinding = require('./sentinel-gateway-binding');

const SENTINEL_UPGRADE_BASE = INTEL_UPGRADE_URL; // https://intel.cyberdudebivash.com/upgrade.html
const DEFAULT_PREMIUM_PLAN = 'pro';
// Sentinel APEX gateway tiers (`TIERS` in sentinel-apex-gateway, exact case)
// that include Premium Intelligence. FREE is preview-only.
const SENTINEL_PREMIUM_TIERS = Object.freeze(['PRO', 'ENTERPRISE', 'MSSP']);
// Blog key tiers (tier-entitlements ladder) at or above this include it.
const BLOG_PREMIUM_MINIMUM_TIER = 'pro';
// The gateway is addressed by path through the binding; the host only has to
// be well-formed and is never resolved over the public internet.
const GATEWAY_VALIDATE_URL = 'https://intel.cyberdudebivash.com/api/auth/validate';
const VALIDATION_CACHE_TTL_MS = 60 * 1000; // bounds revocation lag per isolate
const VALIDATION_CACHE_MAX = 500;

const validationCache = new Map();

function setSentinelGatewayBinding(binding) {
  gatewayBinding.setSentinelGatewayBinding(binding);
  validationCache.clear();
}

function utmValue(value, fallback) {
  const clean = String(value || '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return clean || fallback;
}

/** Canonical Sentinel APEX upgrade URL. Only campaign context goes in it, never a customer identifier. */
function premiumUpgradeUrl({ content = 'premium-intelligence', source = 'intel-factory', medium = 'premium-intelligence', campaign = 'sentinel-apex-conversion' } = {}) {
  const params = new URLSearchParams({
    plan: DEFAULT_PREMIUM_PLAN,
    utm_source: utmValue(source, 'intel-factory'),
    utm_medium: utmValue(medium, 'premium-intelligence'),
    utm_campaign: utmValue(campaign, 'sentinel-apex-conversion'),
    utm_content: utmValue(content, 'premium-intelligence'),
  });
  return `${SENTINEL_UPGRADE_BASE}?${params.toString()}`;
}

function isSentinelPlatformCredential(raw) {
  const key = String(raw || '');
  return key.startsWith('cdb_') || key.split('.').length === 3;
}

function isEligibleSentinelTier(tier) {
  return typeof tier === 'string' && SENTINEL_PREMIUM_TIERS.includes(tier);
}

function isEligibleBlogTier(tier) {
  return tierAtLeast(String(tier || ''), BLOG_PREMIUM_MINIMUM_TIER);
}

function credentialDigest(raw) {
  return crypto.createHash('sha256').update(String(raw), 'utf8').digest('hex');
}

function cacheGet(digest) {
  const hit = validationCache.get(digest);
  if (!hit) return null;
  if (hit.expires <= Date.now()) { validationCache.delete(digest); return null; }
  return hit.value;
}

function cachePut(digest, value) {
  if (validationCache.size >= VALIDATION_CACHE_MAX) validationCache.delete(validationCache.keys().next().value);
  validationCache.set(digest, { value, expires: Date.now() + VALIDATION_CACHE_TTL_MS });
}

/**
 * Resolve a Sentinel APEX platform credential through the gateway.
 * Returns { valid, tier, customerRef, planEligible }. Throws
 * ENTITLEMENT_SERVICE_UNAVAILABLE when the authority cannot answer.
 */
async function resolveSentinelPlatformCredential(raw, { clientIp = '' } = {}) {
  const gateway = gatewayBinding.getSentinelGatewayBinding();
  if (!gateway) {
    throw Object.assign(new Error('Sentinel APEX entitlement service is not configured'), { code: 'ENTITLEMENT_SERVICE_UNAVAILABLE' });
  }
  const digest = credentialDigest(raw);
  const cached = cacheGet(digest);
  if (cached) return cached;

  const headers = { 'X-API-Key': String(raw), Accept: 'application/json' };
  // The gateway buckets brute-force protection by client IP; forward the
  // caller's address so one blog client cannot lock out every other one.
  if (clientIp) { headers['CF-Connecting-IP'] = clientIp; headers['X-Forwarded-For'] = clientIp; }

  let body;
  try {
    const res = await gateway.fetch(GATEWAY_VALIDATE_URL, { method: 'GET', headers });
    if (!res.ok) throw new Error(`gateway HTTP ${res.status}`);
    body = await res.json();
  } catch (_) {
    throw Object.assign(new Error('Sentinel APEX entitlement service unavailable'), { code: 'ENTITLEMENT_SERVICE_UNAVAILABLE' });
  }

  const valid = body && body.valid === true;
  const tier = valid && typeof body.tier === 'string' ? body.tier : 'FREE';
  const sub = valid && body.sub ? String(body.sub) : '';
  const result = {
    valid,
    tier,
    // PII-free audit reference; the gateway's customer id may be an email.
    customerRef: valid ? `sentinel:${credentialDigest(sub || raw).slice(0, 24)}` : null,
    planEligible: valid && isEligibleSentinelTier(tier),
  };
  cachePut(digest, result);
  return result;
}

module.exports = {
  SENTINEL_UPGRADE_BASE,
  DEFAULT_PREMIUM_PLAN,
  SENTINEL_PREMIUM_TIERS,
  BLOG_PREMIUM_MINIMUM_TIER,
  setSentinelGatewayBinding,
  premiumUpgradeUrl,
  isSentinelPlatformCredential,
  isEligibleSentinelTier,
  isEligibleBlogTier,
  resolveSentinelPlatformCredential,
};
