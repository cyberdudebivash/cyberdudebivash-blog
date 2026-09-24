/**
 * POST /api/v1/billing/gumroad-webhook
 * Gumroad Ping webhook — records a Gumroad sale for CyberDudeBivash's
 * standalone digital products (software downloads, rule packs, license-
 * key-fulfilled tools). Payment rails: Razorpay (default -- INR direct
 * checkout, UPI, cards) and Gumroad (optional -- global software
 * downloads, standalone rule packs, license key fulfillment).
 *
 * Auth: Gumroad's Ping mechanism does not sign its payload -- confirmed
 * against the already-live, production Gumroad webhook on
 * intel.cyberdudebivash.com (a separate CyberDudeBivash platform; see
 * that repo's workers/intel-gateway/src/index.js#handleWebhookGumroad's
 * own header comment: "Gumroad doesn't sign payloads, so we use a shared
 * secret in the URL"). This endpoint is secured the same proven way: a
 * shared secret passed as a URL query parameter, checked with a
 * timing-safe comparison. Configure Gumroad -> Settings -> Webhooks with:
 *   https://blog.cyberdudebivash.in/api/v1/billing/gumroad-webhook?secret=YOUR_GUMROAD_WEBHOOK_SECRET
 * Set GUMROAD_WEBHOOK_SECRET in Vercel -- see .env.example.
 *
 * Product mapping: unlike intel.cyberdudebivash.com (which sells the same
 * subscription tiers via Gumroad as an alternate Razorpay rail, and so
 * infers a tier from the product name), this platform's Gumroad catalog
 * is standalone one-time products with no equivalent entries in
 * api/_lib/products-catalog.js yet -- no real Gumroad permalinks/pricing
 * have been supplied as of this writing. This handler therefore records
 * every sale generically, by product_permalink, rather than inferring a
 * tier -- nothing here needs to change once real products are added to
 * the catalog; only a PRODUCTS[permalink] lookup added downstream of this
 * file (e.g. in the admin view or a future fulfillment step) would.
 *
 * Fulfillment: Gumroad delivers the purchased file/license key to the
 * buyer directly (native Gumroad content-delivery / licensing feature) --
 * this webhook exists for CyberDudeBivash's own sale visibility and audit
 * trail (GET /api/v1/admin?action=gumroad-sales), not to gate delivery.
 */
'use strict';
const crypto = require('crypto');
const redis  = require('../../_lib/redis');
const { now, auditLog, SUBMISSION_TTL_SECONDS } = require('../../_lib/payment-utils');

/**
 * Timing-safe shared-secret comparison at a fixed width, mirroring
 * api/_lib/security.js#verifyAdminKey's proven pattern for this exact
 * class of check (a single static secret, not a per-request HMAC) --
 * kept local rather than added to security.js since it's a one-off
 * comparison against a different env var, not a change to shared logic.
 */
function timingSafeSecretMatch(provided, expected) {
  if (!provided || !expected) return false;
  const a = String(provided).padEnd(128).slice(0, 128);
  const b = String(expected).padEnd(128).slice(0, 128);
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
      && provided === expected; // exact match too -- catches length-only attacks
  } catch (_) {
    return false;
  }
}

module.exports = async function handleGumroadWebhook(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST required' });

  const secret = process.env.GUMROAD_WEBHOOK_SECRET;
  if (!secret) return res.status(500).json({ error: 'Webhook secret not configured' });

  const urlToken = (req.query && req.query.secret) || '';
  if (!timingSafeSecretMatch(urlToken, secret)) {
    await auditLog('GUMROAD_WEBHOOK_AUTH_FAIL', {});
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Gumroad Ping sends application/x-www-form-urlencoded -- both Vercel's
  // platform body-parser and the Workers node-compat shim already decode
  // this into req.body (see workers/lib/node-compat.js's
  // application/x-www-form-urlencoded branch), so no raw-body reading or
  // bodyParser:false config is needed here, unlike razorpay-webhook.js
  // (which needs the exact raw bytes for HMAC verification -- this
  // endpoint's URL-token auth above needs no such thing).
  const body = req.body && typeof req.body === 'object' ? req.body : {};

  const saleId          = String(body.sale_id || '');
  const email            = String(body.email || '');
  const productId        = String(body.product_id || '');
  const productPermalink = String(body.product_permalink || body.permalink || '');
  const productName      = String(body.product_name || '');
  const price            = String(body.price || '0');
  const currency         = String(body.currency || 'usd').toLowerCase();
  const refunded         = String(body.refunded || '') === 'true';

  if (!saleId || !email) {
    return res.status(400).json({ error: 'Invalid Gumroad payload: sale_id and email required' });
  }

  try {
    const dedupKey = `payment:gumroad:sale:seen:${saleId}`;
    const dup = await redis.exists(dedupKey);
    if (dup && parseInt(dup, 10) > 0) {
      return res.status(200).json({ received: true, status: 'already_recorded', sale_id: saleId });
    }

    await redis.hmset(`payment:gumroad:sale:${saleId}`, {
      saleId, email, productId, productPermalink, productName,
      price, currency, refunded: String(refunded),
      recordedAt: now(),
    });
    await redis.expire(`payment:gumroad:sale:${saleId}`, SUBMISSION_TTL_SECONDS);
    await redis.zadd('payment:gumroad:sales', Date.now(), saleId);

    await auditLog('GUMROAD_SALE_RECORDED', { saleId, email, productId, productPermalink, price, currency, refunded });

    // Mark complete only after every write succeeds so partial failures retry.
    // Repeated hash and index writes use the same sale ID.
    await redis.setex(dedupKey, SUBMISSION_TTL_SECONDS, '1');
    return res.status(200).json({ received: true, status: 'recorded', sale_id: saleId });
  } catch (e) {
    console.error(`[GUMROAD WEBHOOK] Handler error: ${e.message}`);
    return res.status(500).json({ error: 'Webhook handler failed' });
  }
};
