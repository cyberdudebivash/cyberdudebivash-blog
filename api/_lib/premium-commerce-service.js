'use strict';

const crypto = require('crypto');
const razorpay = require('./razorpay');
const store = require('./premium-commerce-store');
const storage = require('./premium-report-storage');
const { evaluatePremiumCertification } = require('./premium-report-certification');
const { loadReportXBundle } = require('./reportx-adapter');

// Ownership contract written into every premium Razorpay order's notes, so
// the shared Razorpay account (also used by the Sentinel APEX platform) can
// attribute the order in the dashboard and in reconciliation. Derived from the
// server-side catalog row, never from client input. Webhook fulfilment itself
// keys on the D1 order row created below, which is the authoritative record.
const ORDER_PLATFORM = 'CYBERDUDEBIVASH_INTEL_FACTORY';
const ORDER_PRODUCT_TYPE = 'PREMIUM_REPORT';

function logCommerceEvent(evt, fields) {
  console.log(JSON.stringify({ evt, ...fields })); // PII-free: ids only
}

function allowedCurrencies() {
  const raw = String(process.env.PREMIUM_COMMERCE_CURRENCIES || 'INR');
  return new Set(raw.split(',').map(v => v.trim().toUpperCase()).filter(v => /^[A-Z]{3}$/.test(v)));
}

function validateMoney(priceMinor, currency) {
  const amount = Number(priceMinor);
  const code = String(currency || '').trim().toUpperCase();
  if (!Number.isSafeInteger(amount) || amount <= 0 || amount > 100000000) {
    throw Object.assign(new Error('price_minor must be a positive integer in the currency minor unit'), { code: 'INVALID_PRICE' });
  }
  if (!allowedCurrencies().has(code)) {
    throw Object.assign(new Error(`Currency ${code || '(missing)'} is not enabled for premium commerce`), { code: 'UNSUPPORTED_CURRENCY' });
  }
  return { amount, currency: code };
}

function safeSlug(value) {
  const slug = String(value || '').toLowerCase().trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 120);
  if (!slug) throw Object.assign(new Error('A non-empty report slug is required'), { code: 'INVALID_SLUG' });
  return slug;
}

function safeText(value, max) {
  return String(value || '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
}

function publicCatalogShape(row) {
  return {
    report_id: row.report_id,
    slug: row.slug,
    title: row.title,
    report_type: row.report_type,
    summary: row.summary,
    price_minor: Number(row.price_minor),
    currency: row.currency,
    artifact_filename: row.artifact_filename,
    artifact_size_bytes: Number(row.artifact_size_bytes),
    artifact_sha256: row.artifact_sha256, // lets buyers verify the delivered bytes
    published_at: row.published_at,
    updated_at: row.updated_at,
    certification: 'PREMIUM_CERTIFIED',
  };
}

async function publishCertifiedReport(input) {
  const certification = evaluatePremiumCertification(input.reportxExport);
  if (!certification.certified) {
    throw Object.assign(new Error(`ReportX artifact is not PREMIUM_CERTIFIED: ${certification.reasons.join(', ')}`), {
      code: 'REPORT_NOT_PREMIUM_CERTIFIED', reasons: certification.reasons,
    });
  }

  const money = validateMoney(input.priceMinor, input.currency);
  const title = safeText(input.title, 220);
  const reportType = safeText(input.reportType, 80).toUpperCase();
  if (!title || !reportType) throw Object.assign(new Error('title and report_type are required'), { code: 'INVALID_REPORT_METADATA' });

  const filenameBase = safeSlug(input.filename || title || certification.reportId);
  const reportxJson = JSON.stringify(input.reportxExport);
  const evidenceSha256 = crypto.createHash('sha256').update(reportxJson, 'utf8').digest('hex');
  const stored = await storage.putCertifiedArtifact({
    reportId: certification.reportId,
    sha256: certification.artifactSha256,
    renderedText: certification.renderedText,
    filename: filenameBase,
  });

  const evidenceStored = await storage.putCanonicalEvidence({
    reportId: certification.reportId,
    renderedSha256: certification.artifactSha256,
    evidenceSha256,
    reportxJson,
  });
  const evidenceIntegrity = await storage.headCanonicalEvidence({
    key: evidenceStored.key,
    reportId: certification.reportId,
    renderedSha256: certification.artifactSha256,
    evidenceSha256,
    expectedSize: evidenceStored.size,
  });
  if (!evidenceIntegrity.ok) {
    throw Object.assign(new Error(`R2 evidence verification failed: ${evidenceIntegrity.reason}`), { code: 'EVIDENCE_VERIFICATION_FAILED' });
  }

  const integrity = await storage.headCertifiedArtifact({
    key: stored.key,
    reportId: certification.reportId,
    sha256: certification.artifactSha256,
    expectedSize: stored.size,
  });
  if (!integrity.ok) {
    throw Object.assign(new Error(`R2 artifact verification failed: ${integrity.reason}`), { code: 'ARTIFACT_VERIFICATION_FAILED' });
  }

  const report = await store.upsertCertifiedReport({
    reportId: certification.reportId,
    slug: safeSlug(input.slug || certification.reportId),
    title,
    reportType,
    summary: safeText(input.summary, 1200),
    artifactSha256: certification.artifactSha256,
    artifactKey: stored.key,
    artifactFilename: `${filenameBase}.md`,
    artifactContentType: stored.contentType,
    artifactSizeBytes: stored.size,
    priceMinor: money.amount,
    currency: money.currency,
    reviewerIdentity: certification.reviewerIdentity,
    reviewTimestamp: certification.reviewTimestamp,
    publishedAt: input.publishedAt || new Date().toISOString(),
  });
  return publicCatalogShape(report);
}

async function listCatalog(options = {}) {
  return (await store.listSellableReports(options)).map(publicCatalogShape);
}

async function getCatalogItem(reportIdOrSlug) {
  const row = await store.getCatalogReport(reportIdOrSlug);
  if (!row || row.status !== 'SELLABLE' || row.certification_state !== 'PREMIUM_CERTIFIED') return null;
  return publicCatalogShape(row);
}

async function assertSellableArtifact(report) {
  if (!report || report.status !== 'SELLABLE' || report.certification_state !== 'PREMIUM_CERTIFIED') {
    throw Object.assign(new Error('Report is not currently sellable'), { code: 'REPORT_NOT_SELLABLE' });
  }
  validateMoney(Number(report.price_minor), report.currency);
  const integrity = await storage.headCertifiedArtifact({
    key: report.artifact_key,
    reportId: report.report_id,
    sha256: report.artifact_sha256,
    expectedSize: Number(report.artifact_size_bytes),
  });
  if (!integrity.ok) {
    throw Object.assign(new Error(`Certified artifact unavailable: ${integrity.reason}`), { code: 'ARTIFACT_UNAVAILABLE' });
  }
  return true;
}

async function createCheckout({ user, reportId }) {
  if (!user || !user.userId) throw Object.assign(new Error('Authenticated customer required'), { code: 'UNAUTHORIZED' });
  if (!razorpay.configured()) throw Object.assign(new Error('Online purchase temporarily unavailable. Contact bivash@cyberdudebivash.com'), { code: 'PAYMENT_GATEWAY_UNAVAILABLE' });
  const report = await store.getCatalogReport(reportId);
  await assertSellableArtifact(report);

  const receipt = `pir_${crypto.randomUUID().replace(/-/g, '').slice(0, 28)}`;
  const rzpOrder = await razorpay.createOrder(Number(report.price_minor), report.currency, receipt, {
    platform: ORDER_PLATFORM,
    product_type: ORDER_PRODUCT_TYPE,
    sku: report.report_id,
    artifact_sha256: report.artifact_sha256,
    commerce: 'premium_intelligence', // kept for orders/tools created before the contract
    report_id: report.report_id,
  });

  const order = await store.createOrderSnapshot({
    ownerId: user.userId,
    email: user.email || '',
    report,
    razorpayOrderId: rzpOrder.id,
  });
  logCommerceEvent('premium_order_created', { order: order.order_id, report: report.report_id, amount_minor: Number(order.amount_minor), currency: order.currency });

  return {
    order_id: order.order_id,
    razorpay_order_id: rzpOrder.id,
    razorpay_key_id: razorpay.KEY_ID,
    report: publicCatalogShape(report),
    amount_minor: Number(order.amount_minor),
    currency: order.currency,
  };
}

function validateCapturedPayment(payment, order) {
  if (!payment || String(payment.id || '') === '') throw Object.assign(new Error('Payment lookup returned no payment'), { code: 'PAYMENT_NOT_FOUND' });
  if (String(payment.order_id || '') !== String(order.razorpay_order_id)) throw Object.assign(new Error('Payment order mismatch'), { code: 'PAYMENT_ORDER_MISMATCH' });
  if (String(payment.status || '').toLowerCase() !== 'captured') throw Object.assign(new Error('Payment is not captured'), { code: 'PAYMENT_NOT_CAPTURED' });
  if (Number(payment.amount) !== Number(order.amount_minor)) throw Object.assign(new Error('Payment amount mismatch'), { code: 'PAYMENT_AMOUNT_MISMATCH' });
  if (String(payment.currency || '').toUpperCase() !== String(order.currency || '').toUpperCase()) throw Object.assign(new Error('Payment currency mismatch'), { code: 'PAYMENT_CURRENCY_MISMATCH' });
}

async function completeEntitlement(order, paymentId) {
  const current = await store.getOrderByInternalId(order.order_id);
  if (!current) throw Object.assign(new Error('Premium order not found'), { code: 'ORDER_NOT_FOUND' });

  if (current.state === 'ENTITLED') {
    if (String(current.razorpay_payment_id || '') !== String(paymentId)) {
      throw Object.assign(new Error('Order already entitled to a different payment'), { code: 'PAYMENT_CONFLICT' });
    }
    return current;
  }

  if (current.state === 'ORDER_CREATED') {
    const claimed = await store.claimVerifiedPayment({ orderId: current.order_id, paymentId });
    if (claimed !== 1) {
      const raced = await store.getOrderByInternalId(current.order_id);
      if (!raced || !['PAYMENT_VERIFIED', 'ENTITLED'].includes(raced.state) || String(raced.razorpay_payment_id || '') !== String(paymentId)) {
        throw Object.assign(new Error('Payment verification could not acquire the order claim'), { code: 'PAYMENT_CLAIM_CONFLICT' });
      }
      order = raced;
    } else {
      order = await store.getOrderByInternalId(current.order_id);
    }
  } else {
    order = current;
  }

  if (!['PAYMENT_VERIFIED', 'ENTITLED'].includes(order.state)) {
    throw Object.assign(new Error(`Order cannot be fulfilled from state ${order.state}`), { code: 'INVALID_ORDER_STATE' });
  }
  if (String(order.razorpay_payment_id || '') !== String(paymentId)) {
    throw Object.assign(new Error('Payment ID does not match the claimed order'), { code: 'PAYMENT_CONFLICT' });
  }

  await store.grantEntitlement({ ownerId: order.owner_id, reportId: order.report_id, orderId: order.order_id });
  await store.markOrderEntitled(order.order_id);
  logCommerceEvent('premium_entitlement_granted', { order: order.order_id, report: order.report_id });
  return store.getOrderByInternalId(order.order_id);
}

async function verifyCheckout({ user, razorpayOrderId, razorpayPaymentId, razorpaySignature }) {
  const order = await store.getOrderByRazorpayOrderId(razorpayOrderId);
  if (!order || String(order.owner_id) !== String(user && user.userId)) {
    throw Object.assign(new Error('Premium order not found'), { code: 'ORDER_NOT_FOUND' });
  }
  if (!razorpay.verifyPaymentSignature(razorpayOrderId, razorpayPaymentId, razorpaySignature)) {
    throw Object.assign(new Error('Invalid Razorpay payment signature'), { code: 'INVALID_PAYMENT_SIGNATURE' });
  }
  const payment = await razorpay.fetchPayment(razorpayPaymentId);
  if (String(payment.id || '') !== String(razorpayPaymentId)) throw Object.assign(new Error('Payment ID mismatch'), { code: 'PAYMENT_ID_MISMATCH' });
  validateCapturedPayment(payment, order);
  const completed = await completeEntitlement(order, razorpayPaymentId);
  logCommerceEvent('premium_payment_verified', { order: completed.order_id, report: completed.report_id, via: 'checkout_callback' });
  return { order_id: completed.order_id, report_id: completed.report_id, state: completed.state, entitlement: 'ACTIVE' };
}

async function processWebhookPayment(payment) {
  const orderId = payment && payment.order_id;
  if (!orderId) return { handled: false };
  const order = await store.getOrderByRazorpayOrderId(orderId);
  if (!order) return { handled: false };
  validateCapturedPayment(payment, order);
  const completed = await completeEntitlement(order, payment.id);
  return { handled: true, order_id: completed.order_id, report_id: completed.report_id, state: completed.state };
}

async function processWebhookRefund(refund, payment) {
  const paymentId = String((refund && refund.payment_id) || (payment && payment.id) || '');
  if (!paymentId) return { handled: false };
  const order = await store.getOrderByPaymentId(paymentId);
  if (!order) return { handled: false };

  // A partial refund must not revoke access to a purchased report. Razorpay's
  // payment entity exposes amount_refunded; full refunds also transition the
  // payment to `refunded`. Only a processed full refund revokes entitlement.
  const paymentAmount = Number((payment && payment.amount) || order.amount_minor);
  const amountRefunded = Number((payment && payment.amount_refunded) || (refund && refund.amount) || 0);
  const refundStatus = String((refund && refund.status) || '').toLowerCase();
  const paymentStatus = String((payment && payment.status) || '').toLowerCase();
  const fullyRefunded = refundStatus === 'processed' && (paymentStatus === 'refunded' || (paymentAmount > 0 && amountRefunded >= paymentAmount));
  if (!fullyRefunded) return { handled: true, full_refund: false, order_id: order.order_id };

  await store.markFullyRefunded({ orderId: order.order_id, ownerId: order.owner_id, reportId: order.report_id });
  return { handled: true, full_refund: true, order_id: order.order_id, report_id: order.report_id };
}

async function listLibrary(user, limit) {
  if (!user || !user.userId) throw Object.assign(new Error('Authenticated customer required'), { code: 'UNAUTHORIZED' });
  return store.listLibrary(user.userId, limit);
}

async function downloadReport({ user, reportId }) {
  if (!user || !user.userId) throw Object.assign(new Error('Authenticated customer required'), { code: 'UNAUTHORIZED' });
  const entitlement = await store.getEntitlement(user.userId, reportId);
  if (!entitlement) throw Object.assign(new Error('Active entitlement not found'), { code: 'ENTITLEMENT_NOT_FOUND' });

  const integrity = await storage.headCertifiedArtifact({
    key: entitlement.artifact_key,
    reportId,
    sha256: entitlement.artifact_sha256,
    expectedSize: Number(entitlement.artifact_size_bytes),
  });
  if (!integrity.ok) throw Object.assign(new Error(`Purchased artifact unavailable: ${integrity.reason}`), { code: 'ARTIFACT_UNAVAILABLE' });

  const object = await storage.getCertifiedArtifact(entitlement.artifact_key);
  if (!object || typeof object.arrayBuffer !== 'function') throw Object.assign(new Error('Purchased artifact could not be read'), { code: 'ARTIFACT_UNAVAILABLE' });
  const bytes = new Uint8Array(await object.arrayBuffer());
  if (bytes.byteLength !== Number(entitlement.artifact_size_bytes)) throw Object.assign(new Error('Purchased artifact size changed'), { code: 'ARTIFACT_INTEGRITY_ERROR' });

  await store.recordDownload({ ownerId: user.userId, reportId, orderId: entitlement.order_id });
  logCommerceEvent('premium_report_downloaded', { order: entitlement.order_id, report: reportId });
  return {
    bytes,
    filename: entitlement.artifact_filename,
    contentType: entitlement.artifact_content_type || 'application/octet-stream',
    sha256: entitlement.artifact_sha256,
  };
}

async function getEvidenceContract({ user, reportId }) {
  if (!user || !user.userId) throw Object.assign(new Error('Authenticated customer required'), { code: 'UNAUTHORIZED' });
  const id = String(reportId || '').trim();
  if (!id) throw Object.assign(new Error('Report ID required'), { code: 'INVALID_REPORT_ID' });
  const entitlement = await store.getEntitlement(user.userId, id);
  if (!entitlement) throw Object.assign(new Error('Active entitlement not found'), { code: 'ENTITLEMENT_NOT_FOUND' });

  const renderedIntegrity = await storage.headCertifiedArtifact({
    key: entitlement.artifact_key, reportId: id, sha256: entitlement.artifact_sha256,
    expectedSize: Number(entitlement.artifact_size_bytes),
  });
  if (!renderedIntegrity.ok) throw Object.assign(new Error('Purchased artifact unavailable'), { code: 'EVIDENCE_UNAVAILABLE' });

  const evidenceKey = storage.buildEvidenceKey(id, entitlement.artifact_sha256);
  const evidenceHead = await storage.headCanonicalEvidence({
    key: evidenceKey, reportId: id, renderedSha256: entitlement.artifact_sha256,
  });
  if (!evidenceHead.ok || !evidenceHead.evidenceSha256) throw Object.assign(new Error('Canonical evidence unavailable'), { code: 'EVIDENCE_UNAVAILABLE' });

  const object = await storage.getCanonicalEvidence(evidenceKey);
  if (!object || typeof object.arrayBuffer !== 'function') throw Object.assign(new Error('Canonical evidence unreadable'), { code: 'EVIDENCE_UNAVAILABLE' });
  const bytes = new Uint8Array(await object.arrayBuffer());
  if (bytes.byteLength !== evidenceHead.size) throw Object.assign(new Error('Canonical evidence size changed'), { code: 'EVIDENCE_INTEGRITY_ERROR' });
  const json = new TextDecoder().decode(bytes);
  const actualSha = crypto.createHash('sha256').update(json, 'utf8').digest('hex');
  if (actualSha !== evidenceHead.evidenceSha256) throw Object.assign(new Error('Canonical evidence hash mismatch'), { code: 'EVIDENCE_INTEGRITY_ERROR' });

  let bundle;
  try { bundle = loadReportXBundle(json); } catch (_) {
    throw Object.assign(new Error('Canonical evidence is invalid'), { code: 'EVIDENCE_INVALID' });
  }
  if (String(bundle.reportId || '') !== id) throw Object.assign(new Error('Canonical evidence report mismatch'), { code: 'EVIDENCE_INTEGRITY_ERROR' });
  const certification = evaluatePremiumCertification(JSON.parse(json));
  if (!certification.certified || certification.reportId !== id || certification.artifactSha256 !== entitlement.artifact_sha256) {
    throw Object.assign(new Error('Canonical evidence no longer validates against purchased artifact'), { code: 'EVIDENCE_CERTIFICATION_INVALID' });
  }
  return bundle.toSocEvidenceContract();
}

module.exports = {
  ORDER_PLATFORM,
  ORDER_PRODUCT_TYPE,
  allowedCurrencies,
  validateMoney,
  publishCertifiedReport,
  listCatalog,
  getCatalogItem,
  createCheckout,
  verifyCheckout,
  processWebhookPayment,
  processWebhookRefund,
  listLibrary,
  downloadReport,
  getEvidenceContract,
};
