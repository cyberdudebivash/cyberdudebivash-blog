/**
 * SENTINEL APEX — Manual Payment System Utilities
 * Shared helpers for intent/submission/admin endpoints.
 * Phase 1–12 of the CYBERDUDEBIVASH Manual Payment System.
 */
'use strict';
const crypto = require('crypto');
const redis  = require('./redis');

/* ─── PLAN CATALOGUE ─────────────────────────────────────────── */
const PLANS = {
  starter: {
    tier:        'starter',
    label:       'API Starter',
    amount:      999,
    currency:    'INR',
    period:      'month',
    rateLimit:   5000,
    description: 'Starter tier — 5,000 API calls/day, weekly intel digest, single API key',
    upiNote:     'Transfer ₹999 to the UPI ID below. Include your intent ID in remarks.',
  },
  pro: {
    tier:        'pro',
    label:       'SOC Pro',
    amount:      1499,
    currency:    'INR',
    period:      'month',
    rateLimit:   25000,
    description: 'Pro tier — 25,000 API calls/day, IOC access, detection rules, full intel reports',
    upiNote:     'Transfer ₹1,499 to the UPI ID below. Include your intent ID in remarks.',
  },
  team: {
    tier:        'team',
    label:       'Sentinel Team',
    amount:      20699,
    currency:    'INR',
    period:      'month',
    rateLimit:   100000,
    description: 'Sentinel Team tier — 100,000 API calls/day, all Pro capabilities, STIX 2.1 export, SIEM rule export (Splunk SPL / Microsoft Sentinel KQL), live Microsoft Sentinel connector, priority Slack/Discord',
    upiNote:     'Transfer ₹20,699 to the UPI ID below. Include your intent ID in remarks.',
  },
  enterprise: {
    tier:        'enterprise',
    label:       'Enterprise Apex',
    amount:      82999,
    currency:    'INR',
    period:      'month',
    rateLimit:   999999,
    description: 'Enterprise Apex — starting price; unlimited API calls, dedicated analyst, custom SLA, white-label reporting. Custom-scoped deals: contact bivash@cyberdudebivash.com.',
    upiNote:     'Transfer ₹82,999 to the UPI ID below. Include your intent ID in remarks. Custom-scoped Enterprise Apex deals are invoiced directly — contact sales instead of using this flow.',
  },
};

/* ─── PLAN CHECKOUT LOCATION ─────────────────────────────────── */
// Owner decision 2026-10-01: API plans are sold only through the Sentinel
// APEX platform checkout (intel.cyberdudebivash.com/upgrade.html), which
// owns plan prices (/api/pricing there), subscriptions and API keys. The
// blog no longer creates plan orders or subscriptions; PLANS above remains
// the record of what existing blog customers bought and still drives
// in-flight order verification.
const INTEL_UPGRADE_URL = 'https://intel.cyberdudebivash.com/upgrade.html';
// Nearest Sentinel APEX plan for a retired blog plan name. Unknown names get
// no plan parameter, which the intel checkout resolves to the free tier
// (it never upgrades a buyer to a paid plan by default).
const INTEL_PLAN_FOR = { starter: 'pro', pro: 'pro', team: 'enterprise', enterprise: 'enterprise', mssp: 'mssp' };

function intelUpgradeUrl(planType, medium = 'api') {
  const params = new URLSearchParams();
  const plan = INTEL_PLAN_FOR[String(planType || '').toLowerCase()];
  if (plan) params.set('plan', plan);
  params.set('utm_source', 'blog');
  params.set('utm_medium', String(medium).replace(/[^a-z0-9-]/gi, '').slice(0, 30) || 'api');
  params.set('utm_campaign', 'plan-checkout');
  return `${INTEL_UPGRADE_URL}?${params.toString()}`;
}

/* ─── PAYMENT INSTRUCTIONS ───────────────────────────────────── */
// DEPRECATED 2026-10-01: manual UPI/bank transfer is retired and no API
// response serves these details any more (billing action=create-intent
// returns 410). Kept exported for backward compatibility of importers;
// remove together with the manual submit-payment path.
const PAYMENT_INSTRUCTIONS = {
  upi: {
    method:  'UPI',
    upi_id:  process.env.UPI_ID   || 'cyberdudebivash@upi',
    name:    process.env.UPI_NAME  || 'CYBERDUDEBIVASH SENTINEL',
    note:    'Include your Intent ID as payment remarks for faster verification.',
  },
  bank: {
    method:       'Bank Transfer (NEFT/IMPS)',
    account_name: process.env.BANK_NAME    || 'CYBERDUDEBIVASH TECHNOLOGIES',
    account_no:   process.env.BANK_ACCOUNT || 'XXXXXXXXXXXX',
    ifsc:         process.env.BANK_IFSC    || 'XXXXXXXXXX',
    bank:         process.env.BANK_LABEL   || 'Contact support for bank details',
    note:         'Use your Intent ID as transfer narration/remarks.',
  },
};

/* ─── SECURITY CONSTANTS ─────────────────────────────────────── */
const MAX_IP_SUBMISSIONS_PER_DAY = 3;
const MIN_UTR_LENGTH              = 8;       // Minimum for short bank refs
const MAX_UTR_LENGTH              = 64;      // Maximum to prevent padding attacks
const INTENT_TTL_SECONDS          = 86400;   // 24 hours
const SUBMISSION_TTL_SECONDS      = 7776000; // 90 days — fraud guard + retention
const AUDIT_LOG_MAX_ENTRIES       = 10000;

/* ─── HELPERS ────────────────────────────────────────────────── */

/** Generate a UUID v4 intent ID */
function generateIntentId() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = crypto.randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [hex.slice(0,8), hex.slice(8,12), hex.slice(12,16), hex.slice(16,20), hex.slice(20)].join('-');
}

/** Sanitize a string — strip HTML, control chars, trim, truncate */
function sanitize(input, maxLen = 255) {
  if (input === null || input === undefined) return '';
  return String(input)
    .replace(/<[^>]*>/g, '')          // strip HTML tags
    .replace(/[<>"'`]/g, '')          // strip dangerous chars
    .replace(/[\x00-\x1f\x7f]/g, '') // strip control chars
    .trim()
    .slice(0, maxLen);
}

/** Validate email format */
function validateEmail(email) {
  return typeof email === 'string' && /^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,}$/.test(email);
}

/** Normalize email to lowercase */
function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

/** Safe email → Redis key segment */
function emailKey(email) {
  return email.replace(/[^a-z0-9_.-]/g, '_');
}

/** Extract real client IP from request */
function getIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket?.remoteAddress ||
    '0.0.0.0'
  );
}

/** YYYYMMDD string for Redis daily keys */
function today() {
  return new Date().toISOString().slice(0, 10).replace(/-/g, '');
}

/** ISO timestamp */
function now() {
  return new Date().toISOString();
}

/** Verify admin key from request headers.
 *  Only accepts x-admin-key header (NOT Authorization) to prevent header confusion.
 *  Uses timing-safe comparison at fixed width to prevent length-based timing attacks.
 */
function isAdminAuthorized(req) {
  const adminKey = process.env.ADMIN_SECRET_KEY;
  if (!adminKey || adminKey.length < 16) return false; // must be configured + meaningful length
  // Only accept X-Admin-Key — never Authorization (prevents header injection)
  const provided = String(req.headers['x-admin-key'] || '');
  if (!provided || provided.length === 0) return false;
  const WIDTH = 128;
  const expected = adminKey.padEnd(WIDTH).slice(0, WIDTH);
  const actual   = provided.padEnd(WIDTH).slice(0, WIDTH);
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(actual, 'utf8'))
      && provided === adminKey; // exact match also checked (prevents padding bypass)
  } catch (_) {
    return false;
  }
}

/* ─── HGETALL → object ───────────────────────────────────────── */
function parseHash(raw) {
  if (!raw || !Array.isArray(raw) || raw.length === 0) return null;
  const obj = {};
  for (let i = 0; i < raw.length; i += 2) obj[raw[i]] = raw[i + 1];
  return obj;
}

/* ─── RATE LIMIT CHECK ───────────────────────────────────────── */
async function checkIpRateLimit(ip) {
  const key   = `payment:ip_rate:${ip}:${today()}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, 86400);
  return { allowed: count <= MAX_IP_SUBMISSIONS_PER_DAY, count, max: MAX_IP_SUBMISSIONS_PER_DAY };
}

/* ─── AUDIT LOGGER ───────────────────────────────────────────── */
async function auditLog(action, data = {}) {
  try {
    const entry = JSON.stringify({
      action,
      ts: now(),
      ...data,
    });
    await redis.zadd('audit:payment:log', Date.now(), entry);
    // Trim to cap log size
    await redis.pipeline([
      ['ZREMRANGEBYRANK', 'audit:payment:log', '0', String(-(AUDIT_LOG_MAX_ENTRIES + 1))],
    ]).catch(() => {});
  } catch (_) {
    // audit log failure must never break main flow
  }
}

/* ─── USER TIER UPGRADE ─────────────────────────────────────── */
async function upgradeUserTier(email, newTier, meta = {}) {
  const safeEmail = emailKey(email);
  const ek        = `user:email:${safeEmail}`;

  const userId = await redis.get(ek);
  if (!userId) {
    // User not yet registered — store pending tier for when they register
    await redis.set(`user:pending:tier:${safeEmail}`, JSON.stringify({
      tier:        newTier,
      activatedAt: now(),
      ...meta,
    }));
    await redis.expire(`user:pending:tier:${safeEmail}`, 90 * 86400); // 90 day window
    return { upgraded: false, pending: true, reason: 'USER_NOT_REGISTERED' };
  }

  const hash = await redis.get(`user:id:${userId}`);
  if (!hash) return { upgraded: false, pending: false, reason: 'KEY_HASH_NOT_FOUND' };

  await redis.hmset(`user:key:${hash}`, {
    tier:              newTier,
    upgradedAt:        now(),
    upgradedVia:       'manual_payment',
    subscriptionId:    meta.transactionId || '',
    paymentWarning:    '',
    ...( meta.expiresAt ? { tierExpiresAt: meta.expiresAt } : {} ),
  });

  // Also refresh the pending key so register.js can skip it
  await redis.del(`user:pending:tier:${safeEmail}`).catch(() => {});

  await auditLog('TIER_UPGRADED', { email, newTier, ...meta });
  return { upgraded: true, pending: false };
}

/* ─── CORS HEADERS ───────────────────────────────────────────── */
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Key, Authorization');
  res.setHeader('X-Powered-By', 'CYBERDUDEBIVASH SENTINEL APEX v4.0');
}

/* ─── STANDARD RESPONSE ─────────────────────────────────────── */
function ok(res, data, status = 200) {
  res.status(status).json({
    success: true,
    meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: now() },
    ...data,
  });
}

function fail(res, status, code, message, extra = {}) {
  res.status(status).json({
    success: false,
    error:   { code, message },
    meta:    { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: now() },
    ...extra,
  });
}

/* ─── PARSE BODY ─────────────────────────────────────────────── */
async function parseBody(req) {
  if (typeof req.body === 'object' && req.body !== null) return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch (_) { return {}; }
  }
  // Stream body (rare on Vercel but handle it)
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => { try { resolve(JSON.parse(data)); } catch (_) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

/* ─── RAZORPAY PLAN PAYMENT CHECK ───────────────────────────────
   Server-side confirmation of a plan payment fetched from Razorpay
   (GET /payments/{id}), applied before any tier is granted. The checkout
   signature proves the payment belongs to the order; this proves the money
   actually arrived for the authoritative plan price and currency.
   Returns 'captured' (grant), 'authorized' (wait: payment.captured webhook
   completes it), or throws { code } for anything that must never grant. */
function checkPlanPayment(payment, { orderId, planType }) {
  const plan = PLANS[planType];
  const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
  if (!plan) fail('PLAN_UNKNOWN', 'Unknown plan for payment');
  if (!payment || !payment.id) fail('PAYMENT_NOT_FOUND', 'Payment lookup returned no payment');
  if (String(payment.order_id || '') !== String(orderId)) fail('PAYMENT_ORDER_MISMATCH', 'Payment does not belong to this order');
  if (Number(payment.amount) !== plan.amount * 100) fail('PAYMENT_AMOUNT_MISMATCH', 'Payment amount does not match the plan price');
  if (String(payment.currency || '').toUpperCase() !== String(plan.currency).toUpperCase()) fail('PAYMENT_CURRENCY_MISMATCH', 'Payment currency does not match the plan');
  const status = String(payment.status || '').toLowerCase();
  if (status === 'captured') return 'captured';
  if (status === 'authorized') return 'authorized';
  return fail('PAYMENT_NOT_CAPTURED', `Payment status is ${status || 'unknown'}`);
}

module.exports = {
  PLANS,
  PAYMENT_INSTRUCTIONS,
  MIN_UTR_LENGTH,
  MAX_UTR_LENGTH,
  INTENT_TTL_SECONDS,
  SUBMISSION_TTL_SECONDS,
  generateIntentId,
  sanitize,
  validateEmail,
  normalizeEmail,
  emailKey,
  getIp,
  today,
  now,
  isAdminAuthorized,
  parseHash,
  checkIpRateLimit,
  auditLog,
  upgradeUserTier,
  checkPlanPayment,
  INTEL_UPGRADE_URL,
  INTEL_PLAN_FOR,
  intelUpgradeUrl,
  cors,
  ok,
  fail,
  parseBody,
};
