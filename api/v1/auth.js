/**
 * SENTINEL APEX — Consolidated Auth Router
 * Single serverless function handling ALL authentication endpoints.
 *
 * Routing: /api/v1/auth?action={action}
 *
 *  action=register   POST  Create account + generate API key
 *  action=me         GET   Authenticated user profile + tier info
 *  action=usage      GET   Per-key daily usage breakdown (last N days)
 *
 * Backward-compat: vercel.json rewrites old /api/v1/auth/* and
 *   /api/v1/keys/usage paths to this handler.
 */
'use strict';
const crypto  = require('crypto');
const redis   = require('../_lib/redis');
const {
  authenticate, respond, apiError, successResponse, corsHeaders,
  generateApiKey, hashKey, RATE_LIMITS,
} = require('../_lib/middleware');
const sec    = require('../_lib/security');
const resend = require('../_lib/resend');
const { consumePendingTierAfterRegistration } = require('../_lib/pending-tier-registration');

/* ─── Allowed fields for register (Phase 2 whitelist) ─────────── */
const REGISTER_FIELDS = ['email', 'name', 'plan'];

/* ─── Helpers ─────────────────────────────────────────────────── */
function today() { return new Date().toISOString().slice(0,10).replace(/-/g,''); }

function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0,10).replace(/-/g,'');
}

/* ─── Registration welcome email content ───────────────────────
   Kept alongside the handler that owns this specific email, not in
   resend.js (a generic REST client with no content of its own). */
function buildWelcomeEmail({ name, apiKey, tier, rateLimit, dashboardUrl, docsUrl, upgradeUrl }) {
  const greeting = name ? `Hi ${name},` : 'Hi,';
  const subject  = 'Your CYBERDUDEBIVASH Sentinel APEX API key';
  const text = [
    `${greeting}`,
    '',
    `Your Sentinel APEX API key has been created on the ${tier.toUpperCase()} tier (${rateLimit} requests/day).`,
    '',
    `API key: ${apiKey}`,
    'Store this securely — it will not be shown again, including in this email thread if you reply to it.',
    '',
    `Authenticate requests with: Authorization: Bearer ${apiKey}`,
    '',
    `Dashboard: ${dashboardUrl}`,
    `API documentation: ${docsUrl}`,
    `Upgrade plans: ${upgradeUrl}`,
    '',
    'Questions? Reply to this email or contact bivash@cyberdudebivash.com.',
    '',
    '— CYBERDUDEBIVASH Sentinel APEX',
  ].join('\n');
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
<p>${greeting}</p>
<p>Your Sentinel APEX API key has been created on the <strong>${tier.toUpperCase()}</strong> tier
(${rateLimit} requests/day).</p>
<p style="background:#f4f4f5;border:1px solid #e4e4e7;border-radius:8px;padding:12px 16px;font-family:monospace;font-size:14px;word-break:break-all">${apiKey}</p>
<p><strong>Store this securely — it will not be shown again</strong>, including in this email thread if you reply to it.</p>
<p>Authenticate requests with:<br><code>Authorization: Bearer ${apiKey}</code></p>
<p>
<a href="${dashboardUrl}">Dashboard</a> ·
<a href="${docsUrl}">API documentation</a> ·
<a href="${upgradeUrl}">Upgrade plans</a>
</p>
<p>Questions? Reply to this email or contact <a href="mailto:bivash@cyberdudebivash.com">bivash@cyberdudebivash.com</a>.</p>
<p>— CYBERDUDEBIVASH Sentinel APEX</p>
</div>`;
  return { subject, text, html };
}

/* ─── Main Router ─────────────────────────────────────────────── */
module.exports = async (req, res) => {
  /* Phase 1: global guard */
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes:   10240,
  });
  if (!ok_guard) return;

  /* Phase 4: global IP rate limit */
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();

  if (!action) {
    return apiError(res, 400, 'MISSING_ACTION',
      'action parameter required. Valid: register, me, usage.');
  }

  /* ─── Route Dispatcher ──────────────────────────────────────── */
  switch (action) {
    case 'register': return handleRegister(req, res);
    case 'me':       return handleMe(req, res);
    case 'usage':    return handleUsage(req, res);
    default:
      return apiError(res, 400, 'INVALID_ACTION',
        `Unknown action: "${action}". Valid: register, me, usage`);
  }
};

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/auth?action=register
   Create account, generate API key, store in Redis.
   Body: { email, name?, plan? }
═══════════════════════════════════════════════════════════════ */
async function handleRegister(req, res) {
  if (req.method !== 'POST') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'POST required for action=register');
  }

  /* ── Parse + validate body ──────────────────────────────── */
  let body = {};
  try {
    if (typeof req.body === 'object' && req.body !== null) body = req.body;
    else if (typeof req.body === 'string') body = JSON.parse(req.body);
  } catch (_) {
    return apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON: { email, name?, plan? }');
  }

  /* Phase 2: field whitelist */
  const wErr = sec.assertFieldWhitelist(body, REGISTER_FIELDS);
  if (wErr) return apiError(res, 400, 'INVALID_FIELDS', wErr);

  const email = sec.sanitize(String(body.email || ''), 320).trim().toLowerCase();
  const plan  = sec.sanitize(String(body.plan  || 'free'), 20).trim().toLowerCase();
  const name  = sec.sanitize(String(body.name  || ''), 100);

  /* Phase 2: strict email validation */
  if (!sec.validateEmail(email)) {
    return apiError(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  if (!['free', 'starter', 'pro', 'team', 'enterprise'].includes(plan)) {
    return apiError(res, 400, 'INVALID_PLAN', 'plan must be: free, starter, pro, team, or enterprise');
  }
  if (plan !== 'free') {
    return apiError(res, 402, 'PAYMENT_REQUIRED',
      `Plan "${plan}" requires payment. Complete checkout at https://blog.cyberdudebivash.in/api-dashboard.html`);
  }

  try {
    /* ── Duplicate check ────────────────────────────────── */
    const safeEmail = email.replace(/[^a-z0-9_.-]/g, '_');
    const emailKey  = `user:email:${safeEmail}`;
    const existing  = await redis.get(emailKey);

    if (existing) {
      return respond(res, 200, {
        success: false,
        error: { code: 'EMAIL_EXISTS', message: 'Email already registered. Visit /api-dashboard.html to retrieve your key details.' },
        meta:  { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      });
    }

    /* ── Check for pre-approved tier (paid before registering) */
    let activeTier      = 'free';
    let tierActivatedBy = null;
    const pendingTierKey = `user:pending:tier:${safeEmail}`;
    let approvedPendingRaw = null;
    try {
      const pendingRaw = await redis.get(pendingTierKey);
      if (pendingRaw) {
        const pending = JSON.parse(pendingRaw);
        if (pending && pending.tier && ['starter', 'pro', 'team', 'enterprise'].includes(pending.tier)) {
          activeTier      = pending.tier;
          tierActivatedBy = pending.transactionId || 'manual_payment';
          // Do NOT delete yet. Account creation can still fail; its paid
          // entitlement must remain available for an authorized retry.
          approvedPendingRaw = pendingRaw;
        }
      }
    } catch (_) { /* best-effort: no payment status is logged */ }

    /* ── Create user ────────────────────────────────────── */
    const userId = 'usr_' + crypto.randomBytes(12).toString('hex');
    const apiKey = generateApiKey();
    const hash   = hashKey(apiKey);
    const now    = new Date().toISOString();

    await redis.hmset(`user:key:${hash}`, {
      userId,
      email,
      name,
      tier:          activeTier,
      createdAt:     now,
      lastSeen:      now,
      totalRequests: '0',
      keyHash:       hash.slice(0, 16),
      ...(tierActivatedBy ? {
        upgradedAt:     now,
        upgradedVia:    'manual_payment',
        subscriptionId: tierActivatedBy,
      } : {}),
    });

    await redis.set(emailKey,                `${userId}`);
    await redis.set(`user:id:${userId}`,     hash);

    // Both account lookups and the user hash must persist before consuming
    // a pre-approved paid tier. The Lua check deletes ONLY the exact value
    // originally read, never a newer concurrent payment update. Cleanup
    // failure must not hide an already-created one-time customer API key.
    if (approvedPendingRaw !== null) {
      try {
        await consumePendingTierAfterRegistration(redis,pendingTierKey,approvedPendingRaw);
      } catch (_) {
        console.warn('[AUTH] Pending paid-tier cleanup deferred after successful registration');
      }
    }
    await redis.incr('analytics:registrations:total').catch(() => {});
    await redis.incr(`analytics:registrations:${now.slice(0,10)}`).catch(() => {});

    const RATE_MAP = { free: 100, pro: 5000, enterprise: 999999 };
    const dashboardUrl = 'https://blog.cyberdudebivash.in/api-dashboard.html';
    const docsUrl      = 'https://blog.cyberdudebivash.in/api.html';
    const upgradeUrl   = 'https://blog.cyberdudebivash.in/pricing.html';

    if (resend.canSendEmail()) {
      const welcome = buildWelcomeEmail({
        name, apiKey, tier: activeTier,
        rateLimit: RATE_MAP[activeTier] || 100,
        dashboardUrl, docsUrl, upgradeUrl,
      });
      await resend.sendEmail({ to: email, ...welcome }).catch(() => {});
    }

    return respond(res, 201, {
      success: true,
      message: activeTier !== 'free'
        ? `API key generated. Pre-approved ${activeTier.toUpperCase()} tier activated automatically.`
        : 'API key generated successfully. Store this key securely — it will not be shown again.',
      user: {
        user_id:    userId,
        email,
        tier:       activeTier,
        created_at: now,
        ...(tierActivatedBy ? { tier_activated_by: 'manual_payment' } : {}),
      },
      api_key:       apiKey,
      rate_limit:    { requests_per_day: RATE_MAP[activeTier] || 100, tier: activeTier },
      usage:         { endpoint: `Authorization: Bearer ${apiKey}` },
      upgrade_url:   upgradeUrl,
      dashboard_url: dashboardUrl,
      docs_url:      docsUrl,
      meta: {
        platform:  'CYBERDUDEBIVASH SENTINEL APEX v4.0',
        timestamp: now,
        warning:   'This API key is shown only once. Store it in a secure vault.',
      },
    });

  } catch (e) {
    return apiError(res, 500, 'REGISTRATION_FAILED',
      sec.safeError(e, 'Registration failed. Please retry or contact bivash@cyberdudebivash.com'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/auth?action=me
   Authenticated user profile, tier, usage stats.
═══════════════════════════════════════════════════════════════ */
async function handleMe(req, res) {
  if (req.method !== 'GET') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required for action=me');
  }

  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const raw     = await redis.hgetall(`user:key:${user.keyHash}`);
    const userObj = {};
    if (Array.isArray(raw)) {
      for (let i = 0; i < raw.length; i += 2) userObj[raw[i]] = raw[i + 1];
    }

    const rateKey   = `ratelimit:${user.keyHash}:${today()}`;
    const usedToday = parseInt(await redis.get(rateKey) || '0', 10);
    const limit     = RATE_LIMITS[user.tier] || 100;

    return successResponse(res, {
      user: {
        user_id:         userObj.userId       || user.userId,
        email:           userObj.email        || user.email,
        name:            userObj.name         || '',
        tier:            userObj.tier         || user.tier,
        created_at:      userObj.createdAt    || null,
        last_seen:       userObj.lastSeen     || null,
        total_requests:  parseInt(userObj.totalRequests || '0', 10),
      },
      usage: {
        today:        usedToday,
        daily_limit:  limit,
        remaining:    Math.max(0, limit - usedToday),
        reset_at:     new Date(new Date().setUTCHours(24,0,0,0)).toISOString(),
        percent_used: Math.round((usedToday / limit) * 100),
      },
      tier_features: {
        free:       { intel_items: 10, ioc_access: false, detection_rules: false, description_full: false, rate_limit: 100 },
        starter:    { intel_items: 10, ioc_access: false, detection_rules: false, description_full: false, rate_limit: 5000 },
        pro:        { intel_items: 50, ioc_access: true,  detection_rules: true,  description_full: true,  rate_limit: 25000 },
        enterprise: { intel_items: 'unlimited', ioc_access: true, detection_rules: true, description_full: true, rate_limit: 'unlimited', stix_export: true, bulk_export: true },
      }[user.tier] || {},
      upgrade_url: user.tier !== 'enterprise' ? 'https://blog.cyberdudebivash.in/pricing.html' : null,
    }, {
      endpoint: '/api/v1/auth?action=me',
    });

  } catch (e) {
    return apiError(res, 500, 'PROFILE_ERROR', sec.safeError(e, 'Profile unavailable. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/auth?action=usage&days=7
   Per-key daily usage breakdown for the last N days.
═══════════════════════════════════════════════════════════════ */
async function handleUsage(req, res) {
  if (req.method !== 'GET') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required for action=usage');
  }

  const user = await authenticate(req, res);
  if (!user) return;

  try {
    const days  = Math.min(30, Math.max(1, parseInt(req.query.days || '7', 10)));
    const limit = RATE_LIMITS[user.tier] || 100;

    const dateKeys    = Array.from({ length: days }, (_, i) => `ratelimit:${user.keyHash}:${daysAgo(i)}`);
    const usageCounts = await redis.pipeline(dateKeys.map(k => ['GET', k]));

    const dailyUsage = dateKeys.map((k, i) => ({
      date:     daysAgo(i).replace(/(\d{4})(\d{2})(\d{2})/, '$1-$2-$3'),
      requests: parseInt(usageCounts[i] || '0', 10),
      limit,
      percent:  Math.round((parseInt(usageCounts[i] || '0', 10) / limit) * 100),
    })).reverse();

    const totalThisPeriod = dailyUsage.reduce((s, d) => s + d.requests, 0);
    const avgPerDay       = Math.round(totalThisPeriod / days);
    const peakDay         = dailyUsage.reduce((best, d) => d.requests > best.requests ? d : best, dailyUsage[0]);

    return successResponse(res, {
      usage_summary: {
        period_days:    days,
        total_requests: totalThisPeriod,
        avg_per_day:    avgPerDay,
        peak_day:       peakDay,
        daily_limit:    limit,
        tier:           user.tier,
      },
      daily_breakdown: dailyUsage,
      projection: {
        monthly_estimate:     avgPerDay * 30,
        monthly_limit:        limit * 30,
        near_limit:           avgPerDay > limit * 0.7,
        upgrade_recommended:  avgPerDay > limit * 0.7 && user.tier !== 'enterprise',
      },
      upgrade_url: user.tier !== 'enterprise' ? 'https://blog.cyberdudebivash.in/pricing.html' : null,
    }, {
      endpoint: '/api/v1/auth?action=usage',
    });

  } catch (e) {
    return apiError(res, 500, 'USAGE_ERROR', sec.safeError(e, 'Usage data unavailable. Please retry.'));
  }
}

/* Named export for direct unit testing — the default export stays the
 * router, unchanged, for every existing consumer (vercel.json routing). */
module.exports.buildWelcomeEmail = buildWelcomeEmail;
