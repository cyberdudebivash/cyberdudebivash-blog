/**
 * POST /api/v1/billing/razorpay-webhook
 *
 * The blog's Razorpay webhook. Since 2026-10-01 the blog sells only premium
 * intelligence reports; API plans are sold by the Sentinel APEX platform
 * (intel.cyberdudebivash.com), which may share this Razorpay account. Every
 * event therefore goes through an ownership gate before any side effect:
 *
 *   verify HMAC over the exact raw bytes  -> 400, no side effect, on failure
 *   parse those same bytes                 (never a re-serialized body)
 *   classify by the blog's own server-side records, never by amount/email:
 *     - premium order:  D1 premium_orders row for this Razorpay order id
 *                       (created by premium checkout before payment)
 *     - legacy plan:    Redis payment:rzp:order:<id> created by the retired
 *                       blog plan checkout (DEPRECATED; 24h TTL, inert once
 *                       pre-cutover records expire)
 *     - anything else:  foreign (e.g. Sentinel APEX platform) -> 200, logged
 *                       as foreign_platform_webhook_ignored, no writes
 *   premium: validate order/amount/currency/capture -> grant entitlement ->
 *            mark ENTITLED (the replay marker) -> 200
 *
 * Permanent mismatches (wrong amount, currency, order, a second payment for an
 * entitled order, a refunded order) are acknowledged with 200 and logged, so
 * Razorpay does not retry them forever; nothing is granted. Transient failures
 * (D1 / Redis unavailable) return 500 so Razorpay retries. Full premium
 * refunds revoke the entitlement; partial refunds do not. Order and audit
 * records are never deleted. No external lookups: classification costs one
 * indexed D1 read (plus one Redis read for non-premium events).
 */
'use strict';
const redis     = require('../../_lib/redis');
const razorpay  = require('../../_lib/razorpay');
const sec       = require('../../_lib/security');
const premiumCommerce = require('../../_lib/premium-commerce-service');
const {
  PLANS, normalizeEmail, parseHash, now, auditLog, upgradeUserTier,
  SUBMISSION_TTL_SECONDS, checkPlanPayment,
} = require('../../_lib/payment-utils');

// Coded premium errors that no retry can fix: acknowledge, never grant.
const PERMANENT_PREMIUM_CODES = new Set([
  'PAYMENT_NOT_FOUND', 'PAYMENT_NOT_CAPTURED', 'PAYMENT_ORDER_MISMATCH', 'PAYMENT_AMOUNT_MISMATCH', 'PAYMENT_CURRENCY_MISMATCH',
  'PAYMENT_CONFLICT', 'PAYMENT_CLAIM_CONFLICT', 'INVALID_ORDER_STATE',
]);

function logEvent(evt, fields) {
  // Structured, PII-free (no email, no payload): picked up by Workers logs.
  console.log(JSON.stringify({ evt, ...fields }));
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST required' });

  const sig = req.headers['x-razorpay-signature'];
  if (!sig) return res.status(400).json({ error: 'Missing X-Razorpay-Signature' });

  let rawBody;
  try {
    rawBody = await sec.readRawBody(req);
  } catch (_) {
    return res.status(413).json({ error: 'Payload too large or unreadable' });
  }

  if (!razorpay.verifyWebhookSignature(rawBody, sig)) {
    console.error('[RAZORPAY WEBHOOK] Invalid signature');
    return res.status(400).json({ error: 'Invalid signature' });
  }

  // Parse exactly the bytes whose signature was verified, never a body an
  // adapter may have parsed or re-serialized.
  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (_) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }
  if (!event || typeof event !== 'object') return res.status(400).json({ error: 'Invalid JSON' });

  try {
    switch (event.event) {
      case 'payment.captured':
      case 'order.paid': {
        const payment   = event.payload?.payment?.entity || {};
        const orderId   = payment.order_id;
        const paymentId = payment.id;
        if (!orderId || !paymentId) break;

        /* 1. Blog premium-report order? (indexed D1 lookup by order id) */
        let premium;
        try {
          premium = await premiumCommerce.processWebhookPayment(payment);
        } catch (err) {
          if (PERMANENT_PREMIUM_CODES.has(err.code)) {
            logEvent('premium_payment_rejected', { event: event.event, order: orderId, payment: paymentId, code: err.code });
            break; // acknowledged; nothing granted
          }
          throw err; // transient (D1 unavailable): 500 so Razorpay retries
        }
        if (premium.handled) {
          logEvent('premium_payment_verified', { event: event.event, order: premium.order_id, report: premium.report_id, state: premium.state });
          break;
        }

        /* 2. DEPRECATED legacy blog plan order (pre-2026-10-01 cutover).
           Only an order record this blog created itself qualifies; Razorpay
           order notes are never used to recover one, so platform-owned
           orders can never be granted here. */
        let order = parseHash(await redis.hgetall(`payment:rzp:order:${orderId}`));
        if (!order) {
          const notes = payment.notes && typeof payment.notes === 'object' ? payment.notes : {};
          logEvent('foreign_platform_webhook_ignored', {
            event: event.event, order: orderId, platform: String(notes.platform || 'unknown').slice(0, 64),
          });
          break;
        }
        if (order.status === 'paid') break;
        const dupKey = `payment:rzp:txn:seen:${paymentId}`;
        const dup    = await redis.exists(dupKey).catch(() => 0);
        if (dup && parseInt(dup, 10) > 0) break;

        // Same server-side confirmation as the checkout callback: correct
        // order, authoritative plan amount and currency, and captured.
        let paymentState;
        try {
          paymentState = checkPlanPayment(payment, { orderId, planType: order.planType });
        } catch (err) {
          await auditLog('RAZORPAY_WEBHOOK_PAYMENT_REJECTED', { orderId, paymentId, code: err.code || 'UNKNOWN' });
          break; // permanent mismatch: acknowledge so Razorpay stops retrying; never grant
        }
        if (paymentState !== 'captured') break; // payment.captured will follow

        const email = normalizeEmail(order.email);
        const tier  = (PLANS[order.planType] || {}).tier || order.planType;
        // Grant first, then mark processed (an idempotent overwrite), so a
        // retry after a partial failure re-applies the same tier harmlessly.
        await upgradeUserTier(email, tier, {
          transactionId: paymentId,
          gateway: 'razorpay_webhook',
          orderId,
        });
        await redis.hmset(`payment:rzp:order:${orderId}`, {
          status: 'paid', paymentId, verifiedAt: now(),
        });
        await redis.expire(`payment:rzp:order:${orderId}`, SUBMISSION_TTL_SECONDS);
        await redis.setex(dupKey, SUBMISSION_TTL_SECONDS, '1');
        await auditLog('RAZORPAY_WEBHOOK_PAYMENT_CAPTURED', {
          email, planType: order.planType, orderId, paymentId, amount: order.amount,
        });
        break;
      }

      case 'refund.processed': {
        const refund = event.payload?.refund?.entity || {};
        const payment = event.payload?.payment?.entity || {};
        const result = await premiumCommerce.processWebhookRefund(refund, payment);
        if (result.handled) {
          logEvent('premium_refund_processed', { refund: refund.id || null, order: result.order_id, full_refund: Boolean(result.full_refund) });
        } else {
          // Not a blog premium payment: platform-owned, or a historical blog
          // plan payment. Plan refunds never change a tier automatically
          // (operator decision, see docs/runbooks/BLOG-RAZORPAY-WEBHOOK.md),
          // so this is logged only.
          logEvent('foreign_platform_webhook_ignored', { event: event.event, refund: refund.id || null });
        }
        break;
      }

      default:
        logEvent('webhook_event_ignored', { event: String(event.event || '').slice(0, 64) });
    }

    res.status(200).json({ received: true, event: event.event });
  } catch (e) {
    console.error(`[RAZORPAY WEBHOOK] Handler error: ${e.message}`);
    res.status(500).json({ error: 'Webhook handler failed' });
  }
};

module.exports.config = { api: { bodyParser: false } };
