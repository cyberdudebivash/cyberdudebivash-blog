/**
 * SENTINEL APEX — Consolidated Billing Router
 * Single serverless function handling ALL billing/payment endpoints.
 * Payment rail: Razorpay (INR checkout: cards, UPI, wallets). Manual
 * UPI/bank transfer was retired on 2026-10-01 (OPERATIONS.md: "Do not
 * enable manual payment fallback"). Note: the Razorpay webhook is kept separate
 * (api/v1/billing/razorpay-webhook.js) — requires raw body.
 *
 * Routing: /api/v1/billing?action={action}
 *
 *  action=create-intent          POST  RETIRED 2026-10-01 -> 410 MANUAL_PAYMENT_RETIRED
 *  action=submit-payment         POST  DEPRECATED: accepts UTRs only for intents created before
 *                                      retirement (24h TTL); remove after the pending review queue
 *                                      is empty (see docs/release certification)
 *  action=status                 GET   Status of a submitted manual payment (kept for in-flight reviews)
 *  action=create-razorpay-order  POST  RETIRED 2026-10-01 -> 410 PLAN_CHECKOUT_MOVED (plans are sold
 *                                      on the Sentinel APEX platform checkout; see payment-utils)
 *  action=verify-razorpay-payment POST DEPRECATED: completes plan orders created before retirement
 *  action=create-subscription    POST  RETIRED 2026-10-01 -> 410 PLAN_CHECKOUT_MOVED
 *
 * Backward-compat: vercel.json rewrites old /api/v1/billing/* paths here.
 */
'use strict';
const crypto    = require('crypto');
const redis     = require('../_lib/redis');
const razorpay  = require('../_lib/razorpay');
const {
  authenticate, apiError, respond, corsHeaders,
} = require('../_lib/middleware');
const {
  PLANS,
  MIN_UTR_LENGTH, MAX_UTR_LENGTH,
  INTENT_TTL_SECONDS, SUBMISSION_TTL_SECONDS,
  generateIntentId, sanitize, validateEmail, normalizeEmail, emailKey,
  now, parseHash, ok, fail, parseBody, auditLog, upgradeUserTier, checkPlanPayment, intelUpgradeUrl,
} = require('../_lib/payment-utils');
const sec = require('../_lib/security');
const { getProduct } = require('../_lib/products-catalog');

/* ─── Allowed payment methods ─────────────────────────────────── */
const VALID_PAYMENT_METHODS = new Set(['UPI', 'BANK', 'NEFT', 'IMPS', 'RTGS', 'PHONEPE', 'GPAY', 'PAYTM', 'OTHER']);

/* ─── Allowed fields per action (whitelist) ───────────────────── */
const FIELDS = {
  'create-intent':           ['email', 'plan_type'],
  'submit-payment':          ['email', 'intent_id', 'utr_number', 'transaction_id', 'payment_method'],
  'create-razorpay-order':   ['email', 'plan_type'],
  'verify-razorpay-payment': ['email', 'plan_type', 'razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature'],
  'create-product-checkout': ['email', 'product_id'],
  'verify-product-payment':  ['email', 'product_id', 'razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature'],
  // No 'email' field here, unlike the rest of this table: an existing
  // customer's subscription lifecycle (create/manage, as opposed to their
  // very first payment) is authenticated by API key -- see each handler's
  // own comment for why. list-subscriptions has no entry here at all: it
  // takes no client-supplied fields whatsoever now that it's authenticated.
  'create-subscription':     ['plan_type', 'period'],
  'manage-subscription':     ['subscription_id', 'action'],
};

/* ─── Apex API base URL ────────────────────────────────────────── */
const APEX_API_BASE = process.env.APEX_API_BASE || 'https://intel.cyberdudebivash.com';

/* ─── Main Router ─────────────────────────────────────────────── */
module.exports = async (req, res) => {
  /* Phase 1: global guard — sets security headers, checks method/size */
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes:   10240,
  });
  if (!ok_guard) return;

  /* Phase 4: global IP rate limit */
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();

  const VALID_ACTIONS = 'plans, create-intent, submit-payment, status, create-razorpay-order, verify-razorpay-payment, create-product-checkout, verify-product-payment, create-subscription, manage-subscription, list-subscriptions';

  if (!action) {
    return fail(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);
  }

  /* ─── Route Dispatcher ───────────────────────────────────────── */
  switch (action) {
    case 'plans':                    return handlePlans(req, res);
    case 'create-intent':            return handleCreateIntent(req, res);
    case 'submit-payment':           return handleSubmitPayment(req, res);
    case 'status':                   return handlePaymentStatus(req, res);
    case 'create-razorpay-order':    return handleCreateRazorpayOrder(req, res);
    case 'verify-razorpay-payment':  return handleVerifyRazorpayPayment(req, res);
    case 'create-product-checkout':  return handleCreateProductCheckout(req, res);
    case 'verify-product-payment':   return handleVerifyProductPayment(req, res);
    case 'create-subscription':      return handleCreateSubscription(req, res);
    case 'manage-subscription':      return handleManageSubscription(req, res);
    case 'list-subscriptions':       return handleListSubscriptions(req, res);
    default:
      return fail(res, 400, 'INVALID_ACTION', `Unknown action: "${action}". Valid: ${VALID_ACTIONS}`);
  }
};

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=create-intent  — RETIRED 2026-10-01
   Manual UPI/bank-transfer intents are no longer issued. The action stays
   routed (instead of becoming INVALID_ACTION) so existing clients get an
   explicit, actionable 410. Intents issued before retirement expire within
   24h and can still be completed via action=submit-payment.
═══════════════════════════════════════════════════════════════ */
const MANUAL_PAYMENT_RETIRED_MESSAGE =
  'Manual UPI/bank-transfer payments were retired on 2026-10-01. Buy plans on the CYBERDUDEBIVASH ' +
  'SENTINEL APEX platform (checkout_url) or email bivash@cyberdudebivash.com to purchase.';

async function handleCreateIntent(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');
  await auditLog('MANUAL_INTENT_REJECTED_RETIRED', { ip: sec.getIp(req) });
  return fail(res, 410, 'MANUAL_PAYMENT_RETIRED', MANUAL_PAYMENT_RETIRED_MESSAGE, { checkout_url: intelUpgradeUrl('', 'api') });
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=submit-payment
   Accept UTR submission with fraud protection.
   Body: { email, intent_id, transaction_id, payment_method }
═══════════════════════════════════════════════════════════════ */
async function handleSubmitPayment(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  const ip   = sec.getIp(req);
  const ua   = sanitize(req.headers['user-agent'] || 'unknown', 200);
  const body = await parseBody(req);

  /* Phase 2: field whitelist */
  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS['submit-payment']);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email         = normalizeEmail(body.email);
  const intentId      = sanitize(String(body.intent_id || body.transaction_id?.match?.(/^[0-9a-f-]{36}$/) ? '' : ''), 40);
  const rawUTR        = sec.normalizeUTR(String(body.utr_number || body.transaction_id || ''));
  const paymentMethod = sanitize(String(body.payment_method || 'UPI').toUpperCase(), 20);
  const intentIdRaw   = sanitize(String(body.intent_id || ''), 40);

  /* Phase 2: strict validation */
  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'Valid email address required.');
  }
  if (!sec.validateUUID(intentIdRaw)) {
    return fail(res, 400, 'INVALID_INTENT_ID',
      'intent_id must be a valid UUID v4 (from action=create-intent).');
  }
  if (!sec.validateUTR(rawUTR)) {
    return fail(res, 400, 'INVALID_UTR',
      `UTR must be 8–64 alphanumeric characters only. Example: 427110170556`);
  }
  if (!VALID_PAYMENT_METHODS.has(paymentMethod)) {
    return fail(res, 400, 'INVALID_PAYMENT_METHOD',
      `payment_method must be one of: ${[...VALID_PAYMENT_METHODS].join(', ')}`);
  }

  const txnNorm = rawUTR; // already uppercased + sanitized by normalizeUTR

  /* Phase 4: IP submission rate limit (3/day/IP) */
  if (!(await sec.submissionIpRateLimit(req, res))) {
    await auditLog('RATE_LIMIT_HIT', { ip, email, endpoint: 'submit-payment' });
    return;
  }

  /* ── Phase 5+6: Duplicate UTR Guard (90-day atomic block) ────── */
  const dupKey = `payment:txn:seen:${txnNorm}`;
  try {
    const dup = await redis.exists(dupKey);
    if (dup && parseInt(dup, 10) > 0) {
      await auditLog('DUPLICATE_TXN', { ip, email, transactionId: txnNorm });
      return fail(res, 409, 'DUPLICATE_TRANSACTION',
        'This transaction reference has already been submitted. Each UTR can only be used once.');
    }
  } catch (_) { /* allow if Redis down — approve step also deduplicates */ }

  /* ── Phase 5: Validate Intent ─────────────────────────────────── */
  let intent;
  try {
    intent = parseHash(await redis.hgetall(`payment:intent:${intentIdRaw}`));
    if (!intent) {
      await auditLog('INVALID_INTENT', { ip, email, intentId: intentIdRaw, note: 'not found or expired' });
      return fail(res, 404, 'INTENT_NOT_FOUND',
        'Payment intent not found or expired (24h TTL). ' + MANUAL_PAYMENT_RETIRED_MESSAGE);
    }
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', 'Verification service temporarily unavailable. Retry in 30s.');
  }

  /* Phase 5: email must exactly match intent */
  if (intent.email !== email) {
    await auditLog('EMAIL_MISMATCH', { ip, intentId: intentIdRaw, submittedEmail: email, intentEmail: intent.email });
    return fail(res, 403, 'EMAIL_MISMATCH',
      'Email does not match the intent. Use the same email from payment intent creation.');
  }

  /* Phase 5: intent must be unconsumed */
  if (intent.status === 'submitted' || intent.status === 'completed') {
    return fail(res, 409, 'INTENT_ALREADY_USED',
      `This payment intent has already been submitted (status: ${intent.status}). Each intent is single-use.`);
  }
  if (intent.status === 'rejected') {
    return fail(res, 409, 'INTENT_REJECTED',
      'This intent was rejected. ' + MANUAL_PAYMENT_RETIRED_MESSAGE);
  }
  if (intent.status !== 'pending_payment') {
    return fail(res, 409, 'INVALID_INTENT_STATUS',
      `Intent cannot be used in status "${intent.status}".`);
  }

  /* ── Phase 6: Store Submission with mandatory TTL ─────────────── */
  const submittedAt = now();
  try {
    await redis.hmset(`payment:submission:${txnNorm}`, {
      intentId:      intentIdRaw,
      email,
      transactionId: txnNorm,
      paymentMethod,
      planType:      intent.planType,
      amount:        intent.amount,
      currency:      intent.currency,
      status:        'pending_review',
      submittedAt,
      ip,
      userAgent:     ua,
      reviewedAt:    '',
      reviewedBy:    '',
      rejectionNote: '',
    });

    /* MANDATORY: every Redis write gets a TTL */
    await redis.expire(`payment:submission:${txnNorm}`, SUBMISSION_TTL_SECONDS); // 90 days
    await redis.zadd('payment:pending', Date.now(), txnNorm);
    await redis.setex(dupKey, SUBMISSION_TTL_SECONDS, '1');            // atomic set+TTL
    await redis.hset(`payment:intent:${intentIdRaw}`, 'status', 'submitted');  // consume intent

    await auditLog('PAYMENT_SUBMITTED', {
      email, intentId: intentIdRaw, transactionId: txnNorm, paymentMethod,
      planType: intent.planType, amount: intent.amount, ip,
    });

    return ok(res, {
      message: 'Payment submitted for review. Verification within 2–6 business hours.',
      submission: {
        transaction_id: txnNorm,
        intent_id:      intentIdRaw,
        email,
        plan_type:      intent.planType,
        amount:         parseInt(intent.amount, 10),
        currency:       intent.currency,
        payment_method: paymentMethod,
        status:         'pending_review',
        submitted_at:   submittedAt,
      },
      next_steps: [
        'Your API tier upgrades automatically once payment is verified.',
        `Poll status: GET /api/v1/billing?action=status&transaction_id=${txnNorm}&email=${encodeURIComponent(email)}`,
      ],
      support: 'bivash@cyberdudebivash.com',
    });

  } catch (e) {
    try { await redis.del(`payment:submission:${txnNorm}`); } catch (_) {}
    try { await redis.del(dupKey); } catch (_) {}
    return fail(res, 500, 'SUBMISSION_FAILED', sec.safeError(e, 'Submission failed. Please retry or contact support.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/billing?action=status&transaction_id=XXX&email=xxx
   User self-service payment status check.
═══════════════════════════════════════════════════════════════ */
async function handlePaymentStatus(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const txnRaw = sec.normalizeUTR(String(req.query.transaction_id || ''));
  const email  = normalizeEmail(req.query.email || '');

  if (!sec.validateUTR(txnRaw)) {
    return fail(res, 400, 'INVALID_TRANSACTION_ID',
      'transaction_id must be a valid alphanumeric UTR (8–64 characters).');
  }
  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'email query parameter required.');
  }

  try {
    const sub = parseHash(await redis.hgetall(`payment:submission:${txnRaw}`));
    if (!sub) {
      return fail(res, 404, 'NOT_FOUND',
        'No submission found for this transaction ID. Verify UTR or submit via action=submit-payment');
    }
    if (sub.email !== email) {
      return fail(res, 403, 'FORBIDDEN', 'Email does not match this submission.');
    }

    const STATUS_MESSAGES = {
      pending_review: 'Under review — typical verification time: 2–6 hours on business days.',
      approved:       'Approved! Your API tier has been upgraded. Check GET /api/v1/auth?action=me',
      rejected:       'Payment could not be verified. Contact bivash@cyberdudebivash.com',
    };

    return ok(res, {
      payment_status: {
        transaction_id: txnRaw,
        plan_type:      sub.planType,
        amount:         parseInt(sub.amount || '0', 10),
        currency:       sub.currency,
        payment_method: sub.paymentMethod,
        status:         sub.status,
        status_message: STATUS_MESSAGES[sub.status] || `Status: ${sub.status}`,
        submitted_at:   sub.submittedAt,
        reviewed_at:    sub.reviewedAt   || null,
        rejection_note: sub.status === 'rejected' ? (sub.rejectionNote || null) : null,
      },
    });

  } catch (e) {
    return fail(res, 500, 'STATUS_CHECK_FAILED', sec.safeError(e, 'Status check unavailable. Please retry.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/billing?action=plans
   Canonical, public plan/pricing catalogue. The single authoritative
   source every customer-facing surface (pricing page, checkout modal,
   marketing CTAs) should read from instead of hardcoding its own copy —
   see docs/PRICING.md for the incident this closes.
═══════════════════════════════════════════════════════════════ */
async function handlePlans(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const publicPlans = {};
  for (const [key, plan] of Object.entries(PLANS)) {
    publicPlans[key] = {
      tier: plan.tier, label: plan.label, amount: plan.amount,
      currency: plan.currency, period: plan.period, rateLimit: plan.rateLimit,
      description: plan.description,
    };
  }
  res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=3600');
  // Retained for existing integrations; these blog plans are no longer sold.
  return ok(res, {
    plans: publicPlans,
    on_sale: false,
    checkout_url: intelUpgradeUrl('', 'api'),
    notice: 'Blog API plans are no longer sold. Plans and current prices: Sentinel APEX platform checkout_url.',
  });
}

/* Shared 410 for every retired blog plan-purchase action. */
async function planCheckoutMoved(req, res) {
  let planType = '';
  try {
    const body = await parseBody(req);
    planType = sanitize(String((body && body.plan_type) || '').toLowerCase(), 20);
  } catch (_) { /* no body: link to the platform checkout without a plan */ }
  const checkoutUrl = intelUpgradeUrl(PLANS[planType] ? planType : '', 'api');
  await auditLog('PLAN_CHECKOUT_REDIRECTED', { plan: PLANS[planType] ? planType : null, ip: sec.getIp(req) });
  return fail(res, 410, 'PLAN_CHECKOUT_MOVED',
    'Plans are now purchased on the CYBERDUDEBIVASH SENTINEL APEX platform. Continue at checkout_url.',
    { checkout_url: checkoutUrl });
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=create-razorpay-order  — RETIRED 2026-10-01
   API plans are sold only on the Sentinel APEX platform checkout (owner
   decision). New plan orders are refused with an explicit 410 that carries
   the checkout URL for the nearest platform plan. Orders created before
   retirement still complete via action=verify-razorpay-payment and the
   webhook. Premium reports are unaffected (premium-intelligence checkout).
═══════════════════════════════════════════════════════════════ */
const RAZORPAY_ID_RE = /^[a-zA-Z0-9_]{6,64}$/;

async function handleCreateRazorpayOrder(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');
  return planCheckoutMoved(req, res);
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=verify-razorpay-payment
   Verify the checkout.js post-payment signature and instantly upgrade
   the user's tier — no manual admin review (signature = cryptographic proof).
   Body: { email, plan_type, razorpay_order_id, razorpay_payment_id, razorpay_signature }
═══════════════════════════════════════════════════════════════ */
async function handleVerifyRazorpayPayment(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  if (!razorpay.configured()) {
    return fail(res, 503, 'RAZORPAY_UNAVAILABLE', 'Instant checkout is not configured yet.');
  }

  const ip   = sec.getIp(req);
  const body = await parseBody(req);

  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS['verify-razorpay-payment']);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email     = normalizeEmail(body.email);
  const planType  = sanitize(String(body.plan_type || '').toLowerCase(), 20);
  const orderId   = sanitize(String(body.razorpay_order_id || ''), 64);
  const paymentId = sanitize(String(body.razorpay_payment_id || ''), 64);
  const signature = sanitize(String(body.razorpay_signature || ''), 128);

  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  if (!sec.validatePlan(planType)) {
    return fail(res, 400, 'INVALID_PLAN', 'plan_type must be "starter", "pro", "team" or "enterprise"');
  }
  if (!RAZORPAY_ID_RE.test(orderId) || !RAZORPAY_ID_RE.test(paymentId)) {
    return fail(res, 400, 'INVALID_RAZORPAY_ID', 'razorpay_order_id / razorpay_payment_id are malformed.');
  }
  if (!/^[a-f0-9]{16,128}$/i.test(signature)) {
    return fail(res, 400, 'INVALID_SIGNATURE_FORMAT', 'razorpay_signature must be a hex digest.');
  }

  /* Phase 4: submission-style IP rate limit (3/day/IP) — same budget as manual UTR submission */
  if (!(await sec.submissionIpRateLimit(req, res))) {
    await auditLog('RATE_LIMIT_HIT', { ip, email, endpoint: 'verify-razorpay-payment' });
    return;
  }

  /* ── Cryptographic proof of payment ───────────────────────────── */
  if (!razorpay.verifyPaymentSignature(orderId, paymentId, signature)) {
    await auditLog('RAZORPAY_SIGNATURE_INVALID', { ip, email, orderId, paymentId });
    return fail(res, 403, 'INVALID_SIGNATURE', 'Payment signature verification failed.');
  }

  /* ── Replay guard — each payment_id may only upgrade a tier once ─ */
  const dupKey = `payment:rzp:txn:seen:${paymentId}`;
  try {
    const dup = await redis.exists(dupKey);
    if (dup && parseInt(dup, 10) > 0) {
      return ok(res, {
        message: 'Payment already verified and applied.',
        already_processed: true,
      });
    }
  } catch (_) { /* fall through — order-status check below also guards */ }

  let order;
  try {
    order = parseHash(await redis.hgetall(`payment:rzp:order:${orderId}`));
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', 'Verification service temporarily unavailable. Retry in 30s.');
  }
  if (!order) {
    return fail(res, 404, 'ORDER_NOT_FOUND', 'Razorpay order not found or expired (24h TTL).');
  }
  if (order.email !== email || order.planType !== planType) {
    await auditLog('RAZORPAY_ORDER_MISMATCH', { ip, email, orderId, expectedEmail: order.email, expectedPlan: order.planType });
    return fail(res, 403, 'ORDER_MISMATCH', 'email/plan_type do not match the original order.');
  }
  if (order.status === 'paid') {
    return ok(res, { message: 'Payment already verified and applied.', already_processed: true });
  }

  /* ── Server-side confirmation: the money arrived for this plan ────
     The signature binds payment to order; this confirms with Razorpay that
     the payment is for this order at the authoritative plan amount and
     currency, and is captured. Nothing is granted on any mismatch, and a
     lookup outage fails closed (retryable) rather than trusting the client. */
  let paymentState;
  try {
    const payment = await razorpay.fetchPayment(paymentId);
    paymentState = checkPlanPayment(payment, { orderId, planType: order.planType });
  } catch (e) {
    if (e && e.code) {
      await auditLog('RAZORPAY_PAYMENT_REJECTED', { ip, email, orderId, paymentId, code: e.code });
      return fail(res, 409, e.code, 'Payment could not be confirmed for this plan. Contact bivash@cyberdudebivash.com with your payment ID.');
    }
    return fail(res, 503, 'PAYMENT_LOOKUP_UNAVAILABLE', 'Payment confirmation is temporarily unavailable. Your payment is safe — retry in a minute.');
  }
  if (paymentState === 'authorized') {
    return ok(res, {
      message: 'Payment received and awaiting capture. Your plan activates automatically within a few minutes.',
      pending_capture: true,
      verification: { order_id: orderId, payment_id: paymentId, plan_type: planType },
    }, 202);
  }

  try {
    const tier = (PLANS[planType] || {}).tier || planType;
    // Grant before marking processed (see razorpay-webhook.js): a failure
    // between the two must leave the payment retryable, never "already
    // processed" with no tier applied. upgradeUserTier() is idempotent.
    const result = await upgradeUserTier(email, tier, {
      transactionId: paymentId,
      gateway:       'razorpay',
      orderId,
    });

    await redis.hmset(`payment:rzp:order:${orderId}`, {
      status: 'paid', paymentId, verifiedAt: now(),
    });
    await redis.expire(`payment:rzp:order:${orderId}`, SUBMISSION_TTL_SECONDS);
    await redis.setex(dupKey, SUBMISSION_TTL_SECONDS, '1');

    /* ── W4-P0-003: Bridge — provision APEX API key in Cloudflare KV ─
     * This call carries no auth today beyond being reachable — anyone who
     * can send this exact POST body to APEX_API_BASE gets the same
     * response this backend would. APEX_BRIDGE_SECRET below signs the
     * body so the receiving service (a separate repo, not this one) CAN
     * verify the call genuinely came from here, but it only closes the
     * gap once that service is updated to check it — sending the header
     * from this side alone is necessary but not sufficient. Until then
     * this remains a cross-service trust boundary, not a fixed one. */
    let apexApiKey = null;
    try {
      const apexTier = { starter: 'PRO', pro: 'PRO', team: 'ENTERPRISE', enterprise: 'ENTERPRISE' }[planType] || 'PRO';
      const apexBody = JSON.stringify({
        razorpay_order_id:   orderId,
        razorpay_payment_id: paymentId,
        razorpay_signature:  signature,
        tier:                apexTier,
        email,
      });
      const apexHeaders = { 'Content-Type': 'application/json' };
      if (process.env.APEX_BRIDGE_SECRET) {
        apexHeaders['X-Sentinel-Bridge-Signature'] = crypto
          .createHmac('sha256', process.env.APEX_BRIDGE_SECRET)
          .update(apexBody)
          .digest('hex');
      }
      const apexRes = await fetch(`${APEX_API_BASE}/api/payment/razorpay/verify`, {
        method:  'POST',
        headers: apexHeaders,
        body:    apexBody,
      });
      if (apexRes.ok) {
        const apexData = await apexRes.json();
        apexApiKey = apexData.api_key || null;
      }
    } catch (_) { /* non-fatal — APEX key retrievable via support */ }

    await auditLog('RAZORPAY_PAYMENT_VERIFIED', {
      email, planType, orderId, paymentId, amount: order.amount, ip,
    });

    return ok(res, {
      message: result.upgraded
        ? 'Payment verified. Your tier has been upgraded instantly.'
        : 'Payment verified. Tier will activate automatically once you register with this email.',
      verification: {
        order_id: orderId, payment_id: paymentId, plan_type: planType,
        amount: parseInt(order.amount, 10), currency: order.currency,
        upgraded: result.upgraded, pending_registration: result.pending || false,
      },
      ...(apexApiKey ? {
        apex_api_key: apexApiKey,
        apex_docs:   'https://intel.cyberdudebivash.com/api/docs',
        apex_usage:  `curl -H "X-API-Key: ${apexApiKey}" https://intel.cyberdudebivash.com/api/v1/intel/latest`,
      } : {}),
      support: 'bivash@cyberdudebivash.com',
    });

  } catch (e) {
    return fail(res, 500, 'VERIFICATION_FAILED', sec.safeError(e, 'Verification failed. Please contact support with your payment ID.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=create-product-checkout
   One-time digital product checkout (Razorpay) with automatic fulfillment.
   Used by /products.html "Buy Now" buttons — replaces mailto links.
   Body: { email, product_id }
   Fulfillment is automatic: signed download tokens generated on verification.
═══════════════════════════════════════════════════════════════ */
async function handleCreateProductCheckout(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  if (!razorpay.configured()) {
    return fail(res, 503, 'RAZORPAY_UNAVAILABLE',
      'Instant checkout is not configured yet. Contact bivash@cyberdudebivash.com to order this product.');
  }

  const ip   = sec.getIp(req);
  const body = await parseBody(req);

  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS['create-product-checkout']);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email     = normalizeEmail(body.email);
  const productId = sanitize(String(body.product_id || ''), 64);

  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  const product = getProduct(productId);
  if (!product) {
    return fail(res, 400, 'INVALID_PRODUCT', `Unknown product_id: "${productId}"`);
  }

  /* Same daily intent-creation budget as the manual flow (5/day/IP) */
  if (!(await sec.intentIpRateLimit(req, res))) return;

  try {
    const amountInPaise = product.amount * 100; // Convert USD cents to paise
    const receipt = generateIntentId();
    const order = await razorpay.createOrder(amountInPaise, 'INR', receipt, {
      email, productId, platform: 'CYBERDUDEBIVASH_SENTINEL_APEX',
    });

    await redis.hmset(`payment:product:order:${order.id}`, {
      orderId:   order.id,
      email,
      productId,
      productName: product.name,
      amount:    String(product.amount),
      currency:  product.currency,
      amountInPaise: String(amountInPaise),
      status:    'created',
      createdAt: now(),
      ip,
    });
    await redis.expire(`payment:product:order:${order.id}`, INTENT_TTL_SECONDS);
    await redis.zadd('payment:product:orders', Date.now(), order.id);

    await auditLog('PRODUCT_CHECKOUT_CREATED', { orderId: order.id, email, productId, amount: product.amount, ip });

    return ok(res, {
      message: 'Checkout session created. Complete payment then verify with order ID.',
      order: {
        order_id: order.id,
        amount:   amountInPaise,
        currency: 'INR',
        key_id:   razorpay.KEY_ID,
        product_id: productId,
        product_name: product.name,
        email,
      },
      next_step: {
        endpoint: 'POST /api/v1/billing?action=verify-product-payment',
        payload: { email, product_id: productId, razorpay_order_id: order.id, razorpay_payment_id: '<from checkout.js>', razorpay_signature: '<from checkout.js>' },
      },
      support: 'bivash@cyberdudebivash.com',
    }, 201);

  } catch (e) {
    return fail(res, 500, 'CHECKOUT_FAILED', sec.safeError(e, 'Checkout unavailable. Please retry or contact support.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=verify-product-payment
   Verify product purchase, deliver instantly via signed download token.
   Body: { email, product_id, razorpay_order_id, razorpay_payment_id, razorpay_signature }
═══════════════════════════════════════════════════════════════ */
async function handleVerifyProductPayment(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  if (!razorpay.configured()) {
    return fail(res, 503, 'RAZORPAY_UNAVAILABLE', 'Instant checkout is not configured yet.');
  }

  const deliveryLib = require('../_lib/product-delivery');
  const ip   = sec.getIp(req);
  const body = await parseBody(req);

  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS['verify-product-payment']);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email     = normalizeEmail(body.email);
  const productId = sanitize(String(body.product_id || ''), 64);
  const orderId   = sanitize(String(body.razorpay_order_id || ''), 64);
  const paymentId = sanitize(String(body.razorpay_payment_id || ''), 64);
  const signature = sanitize(String(body.razorpay_signature || ''), 128);

  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'A valid email address is required.');
  }
  const product = getProduct(productId);
  if (!product) {
    return fail(res, 400, 'INVALID_PRODUCT', `Unknown product_id: "${productId}"`);
  }
  if (!RAZORPAY_ID_RE.test(orderId) || !RAZORPAY_ID_RE.test(paymentId)) {
    return fail(res, 400, 'INVALID_RAZORPAY_ID', 'razorpay_order_id / razorpay_payment_id are malformed.');
  }
  if (!/^[a-f0-9]{16,128}$/i.test(signature)) {
    return fail(res, 400, 'INVALID_SIGNATURE_FORMAT', 'razorpay_signature must be a hex digest.');
  }

  /* Same daily submission budget (3/day/IP) */
  if (!(await sec.submissionIpRateLimit(req, res))) {
    await auditLog('RATE_LIMIT_HIT', { ip, email, endpoint: 'verify-product-payment' });
    return;
  }

  /* ── Cryptographic proof of payment ───────────────────────────── */
  if (!razorpay.verifyPaymentSignature(orderId, paymentId, signature)) {
    await auditLog('RAZORPAY_SIGNATURE_INVALID', { ip, email, orderId, paymentId });
    return fail(res, 403, 'INVALID_SIGNATURE', 'Payment signature verification failed.');
  }

  /* ── Replay guard — each payment_id may only complete once ────── */
  const dupKey = `payment:product:txn:seen:${paymentId}`;
  try {
    const dup = await redis.exists(dupKey);
    if (dup && parseInt(dup, 10) > 0) {
      return ok(res, {
        message: 'Product already delivered.',
        already_processed: true,
      });
    }
  } catch (_) { /* fall through — order-status check below also guards */ }

  let order;
  try {
    order = parseHash(await redis.hgetall(`payment:product:order:${orderId}`));
  } catch (e) {
    return fail(res, 503, 'SERVICE_UNAVAILABLE', 'Verification service temporarily unavailable. Retry in 30s.');
  }
  if (!order) {
    return fail(res, 404, 'ORDER_NOT_FOUND', 'Razorpay order not found or expired (24h TTL).');
  }
  if (order.email !== email || order.productId !== productId) {
    await auditLog('PRODUCT_ORDER_MISMATCH', { ip, email, orderId, expectedEmail: order.email, expectedProduct: order.productId });
    return fail(res, 403, 'ORDER_MISMATCH', 'email/product_id do not match the original order.');
  }
  if (order.status === 'paid') {
    return ok(res, { message: 'Product already delivered.', already_processed: true });
  }

  try {
    const purchaseId = generateIntentId();
    await redis.setex(dupKey, SUBMISSION_TTL_SECONDS, '1');
    await redis.hmset(`payment:product:order:${orderId}`, {
      status: 'paid', paymentId, verifiedAt: now(),
    });
    await redis.expire(`payment:product:order:${orderId}`, SUBMISSION_TTL_SECONDS);

    /* ── Automated fulfillment — deliver product instantly ─────── */
    const delivery = await deliveryLib.fulfillProduct(email, productId, purchaseId, redis);

    await auditLog('PRODUCT_PAYMENT_VERIFIED', {
      email, productId, orderId, paymentId, purchaseId, ip,
    });

    return ok(res, {
      message: 'Payment verified. Your product is ready to download.',
      verification: {
        order_id: orderId,
        payment_id: paymentId,
        product_id: productId,
        product_name: product.name,
        purchase_id: purchaseId,
      },
      delivery,
      support: 'bivash@cyberdudebivash.com',
    });

  } catch (e) {
    return fail(res, 500, 'VERIFICATION_FAILED', sec.safeError(e, 'Verification failed. Please contact support with your payment ID.'));
  }
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=create-subscription  — RETIRED 2026-10-01
   Recurring plan billing moved to the Sentinel APEX platform checkout,
   which owns subscriptions. Returns 410 PLAN_CHECKOUT_MOVED with the
   checkout URL. Existing subscriptions are still listed and managed via
   action=list-subscriptions / action=manage-subscription.
═══════════════════════════════════════════════════════════════ */
async function handleCreateSubscription(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');
  return planCheckoutMoved(req, res);
}

/* ═══════════════════════════════════════════════════════════════
   POST /api/v1/billing?action=manage-subscription
   Pause, resume, or cancel a subscription. Requires an API key --
   before this fix, this action trusted a bare client-supplied `email`
   with no verification at all, so anyone who knew or guessed a
   customer's email could cancel their paid subscription. Also verifies
   the target subscription actually belongs to the caller (subscription_id
   itself is still client-supplied) -- authentication alone isn't
   ownership, an authenticated caller could otherwise still act on a
   *different* customer's subscription if they guessed its ID.
   Body: { subscription_id, action: "pause"|"resume"|"cancel" }
═══════════════════════════════════════════════════════════════ */
async function handleManageSubscription(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'POST required');

  if (!razorpay.configured()) {
    return fail(res, 503, 'RAZORPAY_UNAVAILABLE', 'Subscriptions not configured yet.');
  }

  const user = await authenticate(req, res);
  if (!user) return;

  const subLib = require('../_lib/subscriptions');
  const ip   = sec.getIp(req);
  let body = {};
  try {
    body = await parseBody(req);
  } catch (_) {}

  const whitelistErr = sec.assertFieldWhitelist(body, FIELDS['manage-subscription']);
  if (whitelistErr) return fail(res, 400, 'INVALID_FIELDS', whitelistErr);

  const email     = normalizeEmail(user.email);
  const subId     = sanitize(String(body.subscription_id || ''), 64);
  const action    = sanitize(String(body.action || '').toLowerCase(), 20);

  if (!subId) {
    return fail(res, 400, 'MISSING_SUBSCRIPTION_ID', 'subscription_id required.');
  }
  if (!['pause', 'resume', 'cancel'].includes(action)) {
    return fail(res, 400, 'INVALID_ACTION', 'action must be "pause", "resume", or "cancel"');
  }

  // Ownership check: never revealed to the caller whether a subscription
  // simply doesn't exist vs. belongs to someone else -- same NOT_FOUND
  // response either way, to avoid letting a valid subscription_id be
  // enumerated by observing a different error for "not yours".
  const record = await subLib.getSubscriptionRecord(redis, subId);
  if (!record || normalizeEmail(record.email) !== email) {
    return fail(res, 404, 'NOT_FOUND', 'Subscription not found.');
  }

  try {
    let result;
    switch (action) {
      case 'pause':
        result = await subLib.pauseSubscription(razorpay, subId);
        break;
      case 'resume':
        result = await subLib.resumeSubscription(razorpay, subId);
        break;
      case 'cancel':
        result = await subLib.cancelSubscription(razorpay, subId, { cancelAt: 'now' });
        break;
    }

    await auditLog('SUBSCRIPTION_MANAGED', { email, subscriptionId: subId, action, ip });

    return ok(res, {
      message: `Subscription ${action}d successfully.`,
      subscription: {
        subscription_id: result.subscription_id,
        status: result.status,
        action,
      },
      support: 'bivash@cyberdudebivash.com',
    });

  } catch (e) {
    return fail(res, 500, 'SUBSCRIPTION_FAILED', sec.safeError(e, `Failed to ${action} subscription. Please retry or contact support.`));
  }
}

/* ═══════════════════════════════════════════════════════════════
   GET /api/v1/billing?action=list-subscriptions
   List all subscriptions for the authenticated caller. Requires an API
   key -- before this fix, this action returned any email's subscription
   list (subscription_id, plan, amount, billing dates) to any caller who
   supplied that email in the query string, with no verification the
   caller actually owned it.
═══════════════════════════════════════════════════════════════ */
async function handleListSubscriptions(req, res) {
  if (req.method !== 'GET') return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');

  const user = await authenticate(req, res);
  if (!user) return;

  const subLib = require('../_lib/subscriptions');
  const email = normalizeEmail(user.email);

  if (!sec.validateEmail(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'Your account has no valid email on file. Contact support.');
  }

  try {
    const subscriptions = await subLib.getUserSubscriptions(redis, email);

    return ok(res, {
      email,
      subscriptions: subscriptions.map(sub => ({
        subscription_id: sub.subscriptionId,
        plan_type: sub.planType,
        status: sub.status,
        period: sub.period,
        amount: parseInt(sub.amount || '0', 10),
        currency: sub.currency,
        created_at: sub.createdAt,
        next_billing_at: sub.nextBillingAt,
        paused_at: sub.pausedAt || null,
        cancelled_at: sub.cancelledAt || null,
      })),
      total: subscriptions.length,
    });

  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', sec.safeError(e, 'Failed to list subscriptions. Please retry.'));
  }
}
