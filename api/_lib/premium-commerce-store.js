'use strict';

const crypto = require('crypto');
const d1 = require('./d1');

function now() { return new Date().toISOString(); }
function newId(prefix) { return `${prefix}_${crypto.randomUUID()}`; }

function clampLimit(value, fallback = 50, max = 100) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(1, Math.trunc(n)));
}

async function upsertCertifiedReport(report) {
  const ts = now();
  await d1.run(`
    INSERT INTO premium_report_catalog (
      report_id, slug, title, report_type, summary, certification_state,
      artifact_sha256, artifact_key, artifact_filename, artifact_content_type,
      artifact_size_bytes, price_minor, currency, status, reviewer_identity,
      review_timestamp, published_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'PREMIUM_CERTIFIED', ?, ?, ?, ?, ?, ?, ?, 'SELLABLE', ?, ?, ?, ?)
    ON CONFLICT(report_id) DO UPDATE SET
      slug=excluded.slug,
      title=excluded.title,
      report_type=excluded.report_type,
      summary=excluded.summary,
      certification_state='PREMIUM_CERTIFIED',
      artifact_sha256=excluded.artifact_sha256,
      artifact_key=excluded.artifact_key,
      artifact_filename=excluded.artifact_filename,
      artifact_content_type=excluded.artifact_content_type,
      artifact_size_bytes=excluded.artifact_size_bytes,
      price_minor=excluded.price_minor,
      currency=excluded.currency,
      status='SELLABLE',
      reviewer_identity=excluded.reviewer_identity,
      review_timestamp=excluded.review_timestamp,
      updated_at=excluded.updated_at
  `, [
    report.reportId, report.slug, report.title, report.reportType, report.summary || '',
    report.artifactSha256, report.artifactKey, report.artifactFilename,
    report.artifactContentType, report.artifactSizeBytes, report.priceMinor,
    report.currency, report.reviewerIdentity, report.reviewTimestamp,
    report.publishedAt || ts, ts,
  ]);
  return getCatalogReport(report.reportId);
}

async function setCatalogStatus(reportId, status) {
  const allowed = new Set(['SELLABLE', 'PAUSED', 'RETIRED']);
  if (!allowed.has(status)) throw new Error('Invalid catalog status');
  const affected = await d1.runMutationWithChanges(
    'UPDATE premium_report_catalog SET status=?, updated_at=? WHERE report_id=?',
    [status, now(), reportId]
  );
  return affected === 1;
}

async function listSellableReports({ reportType = '', limit = 50 } = {}) {
  const bounded = clampLimit(limit);
  if (reportType) {
    return d1.query(`
      SELECT report_id, slug, title, report_type, summary, price_minor, currency,
             artifact_filename, artifact_size_bytes, artifact_sha256, published_at, updated_at
      FROM premium_report_catalog
      WHERE status='SELLABLE' AND certification_state='PREMIUM_CERTIFIED' AND report_type=?
      ORDER BY published_at DESC
      LIMIT ?
    `, [reportType, bounded]);
  }
  return d1.query(`
    SELECT report_id, slug, title, report_type, summary, price_minor, currency,
           artifact_filename, artifact_size_bytes, artifact_sha256, published_at, updated_at
    FROM premium_report_catalog
    WHERE status='SELLABLE' AND certification_state='PREMIUM_CERTIFIED'
    ORDER BY published_at DESC
    LIMIT ?
  `, [bounded]);
}

async function getCatalogReport(reportIdOrSlug) {
  const rows = await d1.query(`
    SELECT * FROM premium_report_catalog
    WHERE report_id=? OR slug=?
    LIMIT 1
  `, [reportIdOrSlug, reportIdOrSlug]);
  return rows[0] || null;
}

async function createOrderSnapshot({ ownerId, email, report, razorpayOrderId }) {
  const orderId = newId('pord');
  const ts = now();
  await d1.run(`
    INSERT INTO premium_orders (
      order_id, owner_id, email, report_id, report_title,
      artifact_sha256, artifact_key, artifact_filename, artifact_content_type,
      artifact_size_bytes, amount_minor, currency, razorpay_order_id,
      state, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ORDER_CREATED', ?, ?)
  `, [
    orderId, ownerId, email, report.report_id, report.title,
    report.artifact_sha256, report.artifact_key, report.artifact_filename,
    report.artifact_content_type, report.artifact_size_bytes,
    report.price_minor, report.currency, razorpayOrderId, ts, ts,
  ]);
  return getOrderByInternalId(orderId);
}

async function getOrderByInternalId(orderId) {
  const rows = await d1.query('SELECT * FROM premium_orders WHERE order_id=? LIMIT 1', [orderId]);
  return rows[0] || null;
}

async function getOrderByRazorpayOrderId(razorpayOrderId) {
  const rows = await d1.query('SELECT * FROM premium_orders WHERE razorpay_order_id=? LIMIT 1', [razorpayOrderId]);
  return rows[0] || null;
}

async function getOrderByPaymentId(paymentId) {
  const rows = await d1.query('SELECT * FROM premium_orders WHERE razorpay_payment_id=? LIMIT 1', [paymentId]);
  return rows[0] || null;
}

async function claimVerifiedPayment({ orderId, paymentId, verifiedAt = now() }) {
  return d1.runMutationWithChanges(`
    UPDATE premium_orders
    SET razorpay_payment_id=?, state='PAYMENT_VERIFIED', verified_at=?, updated_at=?
    WHERE order_id=? AND state='ORDER_CREATED' AND razorpay_payment_id IS NULL
  `, [paymentId, verifiedAt, verifiedAt, orderId]);
}

async function grantEntitlement({ ownerId, reportId, orderId, grantedAt = now() }) {
  const entitlementId = newId('pent');
  await d1.run(`
    INSERT INTO premium_entitlements (
      entitlement_id, owner_id, report_id, order_id, status, granted_at, updated_at
    ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)
    ON CONFLICT(owner_id, report_id) DO UPDATE SET
      order_id=excluded.order_id,
      status='ACTIVE',
      granted_at=excluded.granted_at,
      updated_at=excluded.updated_at
  `, [entitlementId, ownerId, reportId, orderId, grantedAt, grantedAt]);
  return getEntitlement(ownerId, reportId);
}

async function markOrderEntitled(orderId, entitledAt = now()) {
  await d1.runMutationWithChanges(`
    UPDATE premium_orders
    SET state='ENTITLED', entitled_at=COALESCE(entitled_at, ?), updated_at=?
    WHERE order_id=? AND state IN ('PAYMENT_VERIFIED', 'ENTITLED')
  `, [entitledAt, entitledAt, orderId]);
  return getOrderByInternalId(orderId);
}

async function markFullyRefunded({ orderId, ownerId, reportId, refundedAt = now() }) {
  await d1.runMutationWithChanges(`
    UPDATE premium_orders SET state='REFUNDED', updated_at=?
    WHERE order_id=? AND state IN ('PAYMENT_VERIFIED', 'ENTITLED', 'REFUNDED')
  `, [refundedAt, orderId]);
  await d1.runMutationWithChanges(`
    UPDATE premium_entitlements SET status='REFUNDED', updated_at=?
    WHERE owner_id=? AND report_id=? AND order_id=? AND status IN ('ACTIVE', 'REFUNDED')
  `, [refundedAt, ownerId, reportId, orderId]);
  return getOrderByInternalId(orderId);
}

async function getEntitlement(ownerId, reportId) {
  const rows = await d1.query(`
    SELECT e.*, o.report_title, o.artifact_sha256, o.artifact_key,
           o.artifact_filename, o.artifact_content_type, o.artifact_size_bytes,
           o.amount_minor, o.currency, o.razorpay_payment_id, o.entitled_at
    FROM premium_entitlements e
    JOIN premium_orders o ON o.order_id=e.order_id
    WHERE e.owner_id=? AND e.report_id=? AND e.status='ACTIVE'
    LIMIT 1
  `, [ownerId, reportId]);
  return rows[0] || null;
}

async function listLibrary(ownerId, limit = 100) {
  return d1.query(`
    SELECT e.report_id, e.order_id, e.granted_at, e.status,
           o.report_title, o.artifact_filename, o.artifact_size_bytes,
           o.amount_minor, o.currency, o.entitled_at
    FROM premium_entitlements e
    JOIN premium_orders o ON o.order_id=e.order_id
    WHERE e.owner_id=? AND e.status='ACTIVE'
    ORDER BY e.granted_at DESC
    LIMIT ?
  `, [ownerId, clampLimit(limit, 50, 100)]);
}

async function recordDownload({ ownerId, reportId, orderId }) {
  await d1.run(`
    INSERT INTO premium_download_audit (owner_id, report_id, order_id, downloaded_at)
    VALUES (?, ?, ?, ?)
  `, [ownerId, reportId, orderId, now()]);
}

module.exports = {
  upsertCertifiedReport,
  setCatalogStatus,
  listSellableReports,
  getCatalogReport,
  createOrderSnapshot,
  getOrderByInternalId,
  getOrderByRazorpayOrderId,
  getOrderByPaymentId,
  claimVerifiedPayment,
  grantEntitlement,
  markOrderEntitled,
  markFullyRefunded,
  getEntitlement,
  listLibrary,
  recordDownload,
};
