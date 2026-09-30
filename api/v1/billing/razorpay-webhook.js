/**
 * POST /api/v1/billing/razorpay-webhook
 * Razorpay webhook handler — durable backup confirmation path for both API
 * subscription payments and Premium Intelligence one-time report purchases.
 *
 * Premium report orders are D1-backed and idempotently recoverable here if a
 * buyer closes the browser before the checkout callback can call
 * /api/v1/premium-intelligence?action=verify. Processed full refunds revoke the
 * corresponding premium entitlement; partial refunds do not.
 */
'use strict';
const redis     = require('../../_lib/redis');
const razorpay  = require('../../_lib/razorpay');
const sec       = require('../../_lib/security');
const premiumCommerce = require('../../_lib/premium-commerce-service');
const {
  PLANS, normalizeEmail, parseHash, now, auditLog, upgradeUserTier,
  SUBMISSION_TTL_SECONDS,
} = require('../../_lib/payment-utils');

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

  let event;
  try {
    event = typeof req.body === 'object' ? req.body : JSON.parse(rawBody);
  } catch (_) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log(`[RAZORPAY WEBHOOK] Event: ${event.event}`);

  try {
    switch (event.event) {
      case 'payment.captured':
      case 'order.paid': {
        const payment   = event.payload?.payment?.entity || {};
        const orderId   = payment.order_id;
        const paymentId = payment.id;
        if (!orderId || !paymentId) break;

        let remoteOrder = null;
        try {
          remoteOrder = await razorpay.fetchOrder(orderId);
        } catch (err) {
          console.warn(`[RAZORPAY WEBHOOK] Order metadata lookup unavailable for ${orderId}: ${err.message}`);
        }

        const premiumByNotes = remoteOrder && remoteOrder.notes && remoteOrder.notes.commerce === 'premium_intelligence';
        if (premiumByNotes) {
          const result = await premiumCommerce.processWebhookPayment(payment);
          if (!result.handled) throw new Error('Premium order metadata exists but local commerce order was not found');
          console.log(`[RAZORPAY WEBHOOK] Premium entitlement completed: order=${result.order_id} report=${result.report_id}`);
          break;
        }

        if (!remoteOrder) {
          const possiblePremium = await premiumCommerce.processWebhookPayment(payment);
          if (possiblePremium.handled) {
            console.log(`[RAZORPAY WEBHOOK] Premium entitlement completed via D1 fallback: order=${possiblePremium.order_id}`);
            break;
          }
        }

        /* Existing API subscription path (Redis) — intentionally unchanged. */
        const dupKey = `payment:rzp:txn:seen:${paymentId}`;
        const dup    = await redis.exists(dupKey).catch(() => 0);
        if (dup && parseInt(dup, 10) > 0) break;

        const order = parseHash(await redis.hgetall(`payment:rzp:order:${orderId}`));
        if (!order || order.status === 'paid') break;

        const email = normalizeEmail(order.email);
        const tier  = (PLANS[order.planType] || {}).tier || order.planType;
        // Grant first, then mark processed. upgradeUserTier() is an
        // idempotent overwrite, so a Razorpay retry after a partial failure
        // re-applies the same tier harmlessly. Marking first would make every
        // retry short-circuit on the replay markers above: a captured payment
        // with no entitlement and no automatic recovery.
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
        if (result.handled && result.full_refund) {
          console.log(`[RAZORPAY WEBHOOK] Premium entitlement revoked after full refund: order=${result.order_id} report=${result.report_id}`);
        }
        // Legacy subscription refunds are outside this new one-time report
        // commerce store and continue under their existing billing governance.
        break;
      }

      default:
        console.log(`[RAZORPAY WEBHOOK] Unhandled event: ${event.event}`);
    }

    res.status(200).json({ received: true, event: event.event });
  } catch (e) {
    console.error(`[RAZORPAY WEBHOOK] Handler error: ${e.message}`);
    res.status(500).json({ error: 'Webhook handler failed' });
  }
};

module.exports.config = { api: { bodyParser: false } };
