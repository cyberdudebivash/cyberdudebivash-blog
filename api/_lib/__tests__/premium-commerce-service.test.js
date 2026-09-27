'use strict';

jest.mock('../razorpay', () => ({
  configured: jest.fn(),
  createOrder: jest.fn(),
  fetchPayment: jest.fn(),
  verifyPaymentSignature: jest.fn(),
  KEY_ID: 'rzp_test_public',
}));
jest.mock('../premium-commerce-store', () => ({
  upsertCertifiedReport: jest.fn(), listSellableReports: jest.fn(), getCatalogReport: jest.fn(),
  createOrderSnapshot: jest.fn(), getOrderByInternalId: jest.fn(), getOrderByRazorpayOrderId: jest.fn(),
  getOrderByPaymentId: jest.fn(), claimVerifiedPayment: jest.fn(), grantEntitlement: jest.fn(),
  markOrderEntitled: jest.fn(), markFullyRefunded: jest.fn(), getEntitlement: jest.fn(),
  listLibrary: jest.fn(), recordDownload: jest.fn(),
}));
jest.mock('../premium-report-storage', () => ({
  putCertifiedArtifact: jest.fn(), headCertifiedArtifact: jest.fn(), getCertifiedArtifact: jest.fn(),
  putCanonicalEvidence: jest.fn(), headCanonicalEvidence: jest.fn(), getCanonicalEvidence: jest.fn(),
}));
jest.mock('../premium-report-certification', () => ({ evaluatePremiumCertification: jest.fn() }));

const razorpay = require('../razorpay');
const store = require('../premium-commerce-store');
const storage = require('../premium-report-storage');
const cert = require('../premium-report-certification');
const service = require('../premium-commerce-service');

const report = {
  report_id: 'RPT-1', slug: 'rpt-1', title: 'Premium Malware Analysis', report_type: 'MALWARE', summary: 'x',
  certification_state: 'PREMIUM_CERTIFIED', artifact_sha256: 'a'.repeat(64), artifact_key: 'premium-reports/rpt/a.md',
  artifact_filename: 'premium-malware-analysis.md', artifact_content_type: 'text/markdown; charset=utf-8', artifact_size_bytes: 42,
  price_minor: 19900, currency: 'INR', status: 'SELLABLE', published_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
};
const user = { userId: 'usr_1', email: 'buyer@example.com', tier: 'free' };

beforeEach(() => {
  jest.clearAllMocks();
  process.env.PREMIUM_COMMERCE_CURRENCIES = 'INR';
  razorpay.configured.mockReturnValue(true);
  storage.headCertifiedArtifact.mockResolvedValue({ ok: true, size: 42 });
  storage.putCanonicalEvidence.mockResolvedValue({ key: 'premium-reports/rpt/a.reportx.json', size: 128, contentType: 'application/json; charset=utf-8' });
  storage.headCanonicalEvidence.mockResolvedValue({ ok: true, size: 128, evidenceSha256: 'b'.repeat(64) });
  store.getCatalogReport.mockResolvedValue(report);
});

afterAll(() => { delete process.env.PREMIUM_COMMERCE_CURRENCIES; });

describe('certified publication and sellability', () => {
  test('writes and verifies R2 before cataloging a human-certified artifact', async () => {
    cert.evaluatePremiumCertification.mockReturnValue({
      certified: true, reportId: 'RPT-1', artifactSha256: 'a'.repeat(64), renderedText: '# report',
      reviewerIdentity: 'analyst-1', reviewTimestamp: '2026-09-01T00:00:00Z',
    });
    storage.putCertifiedArtifact.mockResolvedValue({ key: report.artifact_key, size: 42, contentType: report.artifact_content_type });
    store.upsertCertifiedReport.mockResolvedValue(report);

    const out = await service.publishCertifiedReport({
      reportxExport: {}, title: report.title, reportType: 'malware', summary: 'x', priceMinor: 19900, currency: 'INR',
    });
    expect(storage.putCertifiedArtifact).toHaveBeenCalledTimes(1);
    expect(storage.putCanonicalEvidence).toHaveBeenCalledTimes(1);
    expect(storage.headCanonicalEvidence).toHaveBeenCalledTimes(1);
    expect(storage.headCertifiedArtifact).toHaveBeenCalledTimes(1);
    expect(store.upsertCertifiedReport).toHaveBeenCalledTimes(1);
    expect(out.certification).toBe('PREMIUM_CERTIFIED');
  });

  test('does not catalog a report if ReportX human certification is absent', async () => {
    cert.evaluatePremiumCertification.mockReturnValue({ certified: false, reasons: ['MISSING_HUMAN_REVIEW'] });
    await expect(service.publishCertifiedReport({ reportxExport: {}, priceMinor: 19900, currency: 'INR' }))
      .rejects.toMatchObject({ code: 'REPORT_NOT_PREMIUM_CERTIFIED' });
    expect(storage.putCertifiedArtifact).not.toHaveBeenCalled();
    expect(store.upsertCertifiedReport).not.toHaveBeenCalled();
  });

  test('does not catalog when canonical evidence cannot be verified in R2', async () => {
    cert.evaluatePremiumCertification.mockReturnValue({ certified: true, reportId: 'RPT-1', artifactSha256: 'a'.repeat(64), renderedText: '# r', reviewerIdentity: 'a', reviewTimestamp: 't' });
    storage.putCertifiedArtifact.mockResolvedValue({ key: report.artifact_key, size: 42, contentType: report.artifact_content_type });
    storage.headCanonicalEvidence.mockResolvedValue({ ok: false, reason: 'EVIDENCE_NOT_FOUND' });
    await expect(service.publishCertifiedReport({ reportxExport: {}, title: 'x', reportType: 'malware', priceMinor: 19900, currency: 'INR' }))
      .rejects.toMatchObject({ code: 'EVIDENCE_VERIFICATION_FAILED' });
    expect(store.upsertCertifiedReport).not.toHaveBeenCalled();
  });

  test('does not catalog when the written artifact cannot be verified in R2', async () => {
    cert.evaluatePremiumCertification.mockReturnValue({ certified: true, reportId: 'RPT-1', artifactSha256: 'a'.repeat(64), renderedText: '# r', reviewerIdentity: 'a', reviewTimestamp: 't' });
    storage.putCertifiedArtifact.mockResolvedValue({ key: report.artifact_key, size: 42, contentType: report.artifact_content_type });
    storage.headCertifiedArtifact.mockResolvedValue({ ok: false, reason: 'ARTIFACT_NOT_FOUND' });
    await expect(service.publishCertifiedReport({ reportxExport: {}, title: 'x', reportType: 'malware', priceMinor: 19900, currency: 'INR' }))
      .rejects.toMatchObject({ code: 'ARTIFACT_VERIFICATION_FAILED' });
    expect(store.upsertCertifiedReport).not.toHaveBeenCalled();
  });
});

describe('checkout money and artifact integrity', () => {
  test('passes catalog price_minor to Razorpay exactly once — no USD/INR conversion', async () => {
    razorpay.createOrder.mockResolvedValue({ id: 'order_rzp_1' });
    store.createOrderSnapshot.mockResolvedValue({ order_id: 'pord_1', amount_minor: 19900, currency: 'INR' });
    const out = await service.createCheckout({ user, reportId: 'RPT-1' });
    expect(razorpay.createOrder).toHaveBeenCalledWith(19900, 'INR', expect.stringMatching(/^pir_/), expect.objectContaining({ commerce: 'premium_intelligence', report_id: 'RPT-1' }));
    expect(out.amount_minor).toBe(19900);
  });

  test('fails before Razorpay order creation when the certified R2 artifact is missing', async () => {
    storage.headCertifiedArtifact.mockResolvedValue({ ok: false, reason: 'ARTIFACT_NOT_FOUND' });
    await expect(service.createCheckout({ user, reportId: 'RPT-1' })).rejects.toMatchObject({ code: 'ARTIFACT_UNAVAILABLE' });
    expect(razorpay.createOrder).not.toHaveBeenCalled();
  });

  test('rejects unsupported currency before accepting payment', async () => {
    store.getCatalogReport.mockResolvedValue({ ...report, currency: 'USD' });
    await expect(service.createCheckout({ user, reportId: 'RPT-1' })).rejects.toMatchObject({ code: 'UNSUPPORTED_CURRENCY' });
    expect(razorpay.createOrder).not.toHaveBeenCalled();
  });
});

describe('payment verification and idempotent fulfillment', () => {
  const order = { ...report, order_id: 'pord_1', owner_id: 'usr_1', email: user.email, report_id: 'RPT-1', amount_minor: 19900, razorpay_order_id: 'order_rzp_1', razorpay_payment_id: null, state: 'ORDER_CREATED' };

  test('requires signature plus server-fetched captured payment with exact amount/currency/order', async () => {
    store.getOrderByRazorpayOrderId.mockResolvedValue(order);
    razorpay.verifyPaymentSignature.mockReturnValue(true);
    razorpay.fetchPayment.mockResolvedValue({ id: 'pay_1', order_id: 'order_rzp_1', status: 'captured', amount: 19900, currency: 'INR' });
    store.getOrderByInternalId
      .mockResolvedValueOnce(order)
      .mockResolvedValueOnce({ ...order, state: 'PAYMENT_VERIFIED', razorpay_payment_id: 'pay_1' })
      .mockResolvedValueOnce({ ...order, state: 'ENTITLED', razorpay_payment_id: 'pay_1' });
    store.claimVerifiedPayment.mockResolvedValue(1);

    const out = await service.verifyCheckout({ user, razorpayOrderId: 'order_rzp_1', razorpayPaymentId: 'pay_1', razorpaySignature: 'sig' });
    expect(store.claimVerifiedPayment).toHaveBeenCalledTimes(1);
    expect(store.grantEntitlement).toHaveBeenCalledWith(expect.objectContaining({ ownerId: 'usr_1', reportId: 'RPT-1', orderId: 'pord_1' }));
    expect(out.entitlement).toBe('ACTIVE');
  });

  test('rejects amount mismatch even with a valid client callback signature', async () => {
    store.getOrderByRazorpayOrderId.mockResolvedValue(order);
    razorpay.verifyPaymentSignature.mockReturnValue(true);
    razorpay.fetchPayment.mockResolvedValue({ id: 'pay_1', order_id: 'order_rzp_1', status: 'captured', amount: 1, currency: 'INR' });
    await expect(service.verifyCheckout({ user, razorpayOrderId: 'order_rzp_1', razorpayPaymentId: 'pay_1', razorpaySignature: 'sig' }))
      .rejects.toMatchObject({ code: 'PAYMENT_AMOUNT_MISMATCH' });
    expect(store.claimVerifiedPayment).not.toHaveBeenCalled();
  });

  test('resumes safely after a prior crash left the order PAYMENT_VERIFIED', async () => {
    const verified = { ...order, state: 'PAYMENT_VERIFIED', razorpay_payment_id: 'pay_1' };
    store.getOrderByRazorpayOrderId.mockResolvedValue(verified);
    razorpay.verifyPaymentSignature.mockReturnValue(true);
    razorpay.fetchPayment.mockResolvedValue({ id: 'pay_1', order_id: 'order_rzp_1', status: 'captured', amount: 19900, currency: 'INR' });
    store.getOrderByInternalId.mockResolvedValueOnce(verified).mockResolvedValueOnce({ ...verified, state: 'ENTITLED' });
    await service.verifyCheckout({ user, razorpayOrderId: 'order_rzp_1', razorpayPaymentId: 'pay_1', razorpaySignature: 'sig' });
    expect(store.claimVerifiedPayment).not.toHaveBeenCalled();
    expect(store.grantEntitlement).toHaveBeenCalledTimes(1);
    expect(store.markOrderEntitled).toHaveBeenCalledTimes(1);
  });

  test('same order owned by another customer is indistinguishable from not found', async () => {
    store.getOrderByRazorpayOrderId.mockResolvedValue({ ...order, owner_id: 'usr_2' });
    await expect(service.verifyCheckout({ user, razorpayOrderId: 'order_rzp_1', razorpayPaymentId: 'pay_1', razorpaySignature: 'sig' }))
      .rejects.toMatchObject({ code: 'ORDER_NOT_FOUND' });
  });
});

describe('fulfillment and refunds', () => {
  test('download requires active entitlement and verifies the purchased pinned artifact', async () => {
    store.getEntitlement.mockResolvedValue({
      owner_id: 'usr_1', report_id: 'RPT-1', order_id: 'pord_1', artifact_key: report.artifact_key,
      artifact_sha256: report.artifact_sha256, artifact_size_bytes: 4, artifact_filename: 'r.md', artifact_content_type: 'text/markdown',
    });
    storage.headCertifiedArtifact.mockResolvedValue({ ok: true, size: 4 });
    storage.getCertifiedArtifact.mockResolvedValue({ arrayBuffer: async () => Uint8Array.from([1,2,3,4]).buffer });
    const out = await service.downloadReport({ user, reportId: 'RPT-1' });
    expect(out.bytes.byteLength).toBe(4);
    expect(store.recordDownload).toHaveBeenCalledWith({ ownerId: 'usr_1', reportId: 'RPT-1', orderId: 'pord_1' });
  });

  test('processed full refund revokes premium entitlement; partial refund does not', async () => {
    store.getOrderByPaymentId.mockResolvedValue({ order_id: 'pord_1', owner_id: 'usr_1', report_id: 'RPT-1', amount_minor: 19900 });
    const partial = await service.processWebhookRefund({ payment_id: 'pay_1', amount: 5000, status: 'processed' }, { id: 'pay_1', amount: 19900, amount_refunded: 5000, status: 'captured' });
    expect(partial.full_refund).toBe(false);
    expect(store.markFullyRefunded).not.toHaveBeenCalled();
    const full = await service.processWebhookRefund({ payment_id: 'pay_1', amount: 19900, status: 'processed' }, { id: 'pay_1', amount: 19900, amount_refunded: 19900, status: 'refunded' });
    expect(full.full_refund).toBe(true);
    expect(store.markFullyRefunded).toHaveBeenCalledWith(expect.objectContaining({ orderId: 'pord_1', ownerId: 'usr_1', reportId: 'RPT-1' }));
  });
});
