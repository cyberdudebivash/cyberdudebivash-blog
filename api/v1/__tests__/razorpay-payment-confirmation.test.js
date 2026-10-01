'use strict';

// Razorpay plan payments: server-side confirmation before any tier grant.
// Drives the real billing router and webhook handler with an in-memory Redis
// and a stubbed Razorpay REST client. Invariants:
//   - no grant unless Razorpay reports a captured payment for this order at
//     the authoritative plan amount and currency;
//   - an authorized-but-uncaptured payment is acknowledged (202), not granted;
//   - a Razorpay lookup outage fails closed (503), never trusts the client;
//   - a client cannot choose the amount;
//   - an expired local order is recovered only from server-set order notes
//     whose amount matches the plan;
//   - refunds are recorded exactly once.

const mem = new Map();
jest.mock('../../_lib/redis', () => ({
  exists: jest.fn(async k => (mem.has(k) ? 1 : 0)),
  hgetall: jest.fn(async k => (mem.has(k) ? Object.entries(mem.get(k)).flat() : null)),
  hmset: jest.fn(async (k, obj) => { mem.set(k, { ...(mem.get(k) || {}), ...obj }); return 'OK'; }),
  setex: jest.fn(async (k, _t, v) => { mem.set(k, v); return 'OK'; }),
  expire: jest.fn(async () => 1),
  zadd: jest.fn(async () => 1),
}));
jest.mock('../../_lib/payment-utils', () => {
  const actual = jest.requireActual('../../_lib/payment-utils');
  return { ...actual, upgradeUserTier: jest.fn(async () => ({ upgraded: true, pending: false })), auditLog: jest.fn(async () => {}) };
});
// Premium-report orders live in D1 (separate suite); here every order is an
// API-plan order, so the premium store reports "not mine".
jest.mock('../../_lib/premium-commerce-service', () => ({
  processWebhookPayment: jest.fn(async () => ({ handled: false })),
  processWebhookRefund: jest.fn(async () => ({ handled: false })),
}));
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return {
    ...actual,
    guardRequest: jest.fn(async () => true),
    globalIpRateLimit: jest.fn(async () => true),
    intentIpRateLimit: jest.fn(async () => true),
    submissionIpRateLimit: jest.fn(async () => true),
    readRawBody: jest.fn(async req => req.__raw),
  };
});

const razorpay = require('../../_lib/razorpay');
const { upgradeUserTier, auditLog, checkPlanPayment, PLANS } = require('../../_lib/payment-utils');
const webhook = require('../billing/razorpay-webhook');
const billing = require('../billing');

const ORDER_ID = 'order_CONF000001';
const PAYMENT_ID = 'pay_CONF000001';
const EMAIL = 'buyer@example.com';
const PRO_PAISE = PLANS.pro.amount * 100;
const goodPayment = (over = {}) => ({ id: PAYMENT_ID, order_id: ORDER_ID, amount: PRO_PAISE, currency: 'INR', status: 'captured', ...over });

function res() {
  const r = { headers: {}, statusCode: null, body: null };
  r.setHeader = jest.fn((k, v) => { r.headers[k] = v; });
  r.status = jest.fn(s => { r.statusCode = s; return r; });
  r.json = jest.fn(b => { r.body = b; return r; });
  r.end = jest.fn(() => r);
  return r;
}
async function verify(body = {}) {
  const r = res();
  await billing({
    method: 'POST', url: '/api/v1/billing', headers: {}, query: { action: 'verify-razorpay-payment' },
    body: { email: EMAIL, plan_type: 'pro', razorpay_order_id: ORDER_ID, razorpay_payment_id: PAYMENT_ID, razorpay_signature: 'ab'.repeat(32), ...body },
  }, r);
  return r;
}
async function hook(event, entity, extra = {}) {
  const body = { event, payload: { payment: { entity }, ...extra } };
  const raw = JSON.stringify(body);
  const r = res();
  await webhook({ method: 'POST', headers: { 'x-razorpay-signature': 'ab'.repeat(32) }, body: raw, __raw: raw, query: {} }, r);
  return r;
}

beforeEach(() => {
  mem.clear();
  mem.set(`payment:rzp:order:${ORDER_ID}`, { email: EMAIL, planType: 'pro', amount: String(PLANS.pro.amount), currency: 'INR', status: 'created' });
  upgradeUserTier.mockClear();
  auditLog.mockClear();
  jest.spyOn(razorpay, 'configured').mockReturnValue(true);
  jest.spyOn(razorpay, 'verifyPaymentSignature').mockReturnValue(true);
  jest.spyOn(razorpay, 'verifyWebhookSignature').mockReturnValue(true);
  jest.spyOn(razorpay, 'fetchPayment').mockResolvedValue(goodPayment());
  jest.spyOn(razorpay, 'fetchOrder').mockResolvedValue({ id: ORDER_ID, amount: PRO_PAISE, currency: 'INR', notes: {} });
  global.fetch = jest.fn(async () => ({ ok: false, json: async () => ({}) }));
});
afterEach(() => { jest.restoreAllMocks(); delete global.fetch; });

describe('checkPlanPayment (unit)', () => {
  test('captured at the plan price and currency → captured', () => {
    expect(checkPlanPayment(goodPayment(), { orderId: ORDER_ID, planType: 'pro' })).toBe('captured');
  });
  test.each([
    [{ amount: PRO_PAISE - 1 }, 'PAYMENT_AMOUNT_MISMATCH'],
    [{ amount: PLANS.pro.amount }, 'PAYMENT_AMOUNT_MISMATCH'], // rupees passed as paise
    [{ currency: 'USD' }, 'PAYMENT_CURRENCY_MISMATCH'],
    [{ order_id: 'order_OTHER' }, 'PAYMENT_ORDER_MISMATCH'],
    [{ status: 'failed' }, 'PAYMENT_NOT_CAPTURED'],
    [{ status: 'refunded' }, 'PAYMENT_NOT_CAPTURED'],
  ])('%j → %s', (over, code) => {
    expect(() => checkPlanPayment(goodPayment(over), { orderId: ORDER_ID, planType: 'pro' })).toThrow(expect.objectContaining({ code }));
  });
  test('unknown plan is refused', () => {
    expect(() => checkPlanPayment(goodPayment(), { orderId: ORDER_ID, planType: 'platinum' })).toThrow(expect.objectContaining({ code: 'PLAN_UNKNOWN' }));
  });
});

describe('checkout callback (verify-razorpay-payment)', () => {
  test('captured payment at the plan price grants the tier', async () => {
    const r = await verify();
    expect(r.statusCode).toBe(200);
    expect(upgradeUserTier).toHaveBeenCalledWith(EMAIL, 'pro', expect.objectContaining({ transactionId: PAYMENT_ID }));
  });

  test.each([
    ['amount mismatch', { amount: 100 }, 'PAYMENT_AMOUNT_MISMATCH'],
    ['currency mismatch', { currency: 'USD' }, 'PAYMENT_CURRENCY_MISMATCH'],
    ['payment for another order', { order_id: 'order_OTHER' }, 'PAYMENT_ORDER_MISMATCH'],
    ['failed payment', { status: 'failed' }, 'PAYMENT_NOT_CAPTURED'],
  ])('%s → 409, no grant, not marked paid', async (_n, over, code) => {
    razorpay.fetchPayment.mockResolvedValue(goodPayment(over));
    const r = await verify();
    expect(r.statusCode).toBe(409);
    expect(r.body.error.code).toBe(code);
    expect(upgradeUserTier).not.toHaveBeenCalled();
    expect(mem.get(`payment:rzp:order:${ORDER_ID}`).status).toBe('created');
    expect(mem.has(`payment:rzp:txn:seen:${PAYMENT_ID}`)).toBe(false);
  });

  test('authorized but not captured → 202 pending, no grant', async () => {
    razorpay.fetchPayment.mockResolvedValue(goodPayment({ status: 'authorized' }));
    const r = await verify();
    expect(r.statusCode).toBe(202);
    expect(r.body.pending_capture).toBe(true);
    expect(upgradeUserTier).not.toHaveBeenCalled();
  });

  test('Razorpay lookup outage fails closed with a retryable 503', async () => {
    razorpay.fetchPayment.mockRejectedValue(new Error('ECONNRESET'));
    const r = await verify();
    expect(r.statusCode).toBe(503);
    expect(r.body.error.code).toBe('PAYMENT_LOOKUP_UNAVAILABLE');
    expect(upgradeUserTier).not.toHaveBeenCalled();
  });

  test('invalid signature is refused before any lookup or grant', async () => {
    razorpay.verifyPaymentSignature.mockReturnValue(false);
    const r = await verify();
    expect(r.statusCode).toBe(403);
    expect(razorpay.fetchPayment).not.toHaveBeenCalled();
    expect(upgradeUserTier).not.toHaveBeenCalled();
  });

  test('client cannot claim a different plan than the server-created order', async () => {
    const r = await verify({ plan_type: 'enterprise' });
    expect(r.statusCode).toBe(403);
    expect(upgradeUserTier).not.toHaveBeenCalled();
  });
});

describe('plan order creation moved to the Sentinel APEX platform checkout', () => {
  test('no plan order is ever created on the blog; the 410 points to the nearest platform plan', async () => {
    jest.spyOn(razorpay, 'createOrder').mockResolvedValue({ id: 'order_NEW0000001' });
    const send = async body => { const r = res(); await billing({ method: 'POST', url: '/api/v1/billing', headers: {}, query: { action: 'create-razorpay-order' }, body }, r); return r; };
    for (const [plan, intelPlan] of [['starter', 'pro'], ['pro', 'pro'], ['team', 'enterprise'], ['enterprise', 'enterprise']]) {
      const r = await send({ email: EMAIL, plan_type: plan });
      expect(r.statusCode).toBe(410);
      expect(r.body.error.code).toBe('PLAN_CHECKOUT_MOVED');
      const url = new URL(r.body.checkout_url);
      expect(url.origin + url.pathname).toBe('https://intel.cyberdudebivash.com/upgrade.html');
      expect(url.searchParams.get('plan')).toBe(intelPlan);
    }
    const tampered = await send({ email: EMAIL, plan_type: 'enterprise', amount: 1 });
    expect(tampered.statusCode).toBe(410);
    const unknown = await send({ email: EMAIL, plan_type: 'platinum' });
    expect(new URL(unknown.body.checkout_url).searchParams.has('plan')).toBe(false); // intel resolves no plan to free
    expect(razorpay.createOrder).not.toHaveBeenCalled();
  });
});

describe('signed webhook (payment.captured / order.paid)', () => {
  test('captured payment at the plan price grants once; redelivery is a no-op', async () => {
    await hook('payment.captured', goodPayment());
    await hook('payment.captured', goodPayment());
    await hook('order.paid', goodPayment());
    expect(upgradeUserTier).toHaveBeenCalledTimes(1);
  });

  test('amount mismatch is acknowledged (no retry storm) but never granted', async () => {
    const r = await hook('payment.captured', goodPayment({ amount: 100 }));
    expect(r.statusCode).toBe(200);
    expect(upgradeUserTier).not.toHaveBeenCalled();
    expect(auditLog).toHaveBeenCalledWith('RAZORPAY_WEBHOOK_PAYMENT_REJECTED', expect.objectContaining({ code: 'PAYMENT_AMOUNT_MISMATCH' }));
  });

  test('expired local order is recovered from server-set order notes at the plan price', async () => {
    mem.delete(`payment:rzp:order:${ORDER_ID}`);
    razorpay.fetchOrder.mockResolvedValue({ id: ORDER_ID, amount: PRO_PAISE, currency: 'INR', notes: { email: EMAIL, planType: 'pro', platform: 'CYBERDUDEBIVASH_SENTINEL_APEX' } });
    const r = await hook('payment.captured', goodPayment());
    expect(r.statusCode).toBe(200);
    expect(upgradeUserTier).toHaveBeenCalledWith(EMAIL, 'pro', expect.objectContaining({ transactionId: PAYMENT_ID }));
    expect(mem.get(`payment:rzp:order:${ORDER_ID}`).status).toBe('paid');
  });

  test.each([
    ['notes from another platform', { email: EMAIL, planType: 'pro', platform: 'OTHER' }, PRO_PAISE],
    ['order amount below plan price', { email: EMAIL, planType: 'pro', platform: 'CYBERDUDEBIVASH_SENTINEL_APEX' }, 100],
    ['unknown plan in notes', { email: EMAIL, planType: 'platinum', platform: 'CYBERDUDEBIVASH_SENTINEL_APEX' }, PRO_PAISE],
  ])('expired local order with %s is not granted', async (_n, notes, amount) => {
    mem.delete(`payment:rzp:order:${ORDER_ID}`);
    razorpay.fetchOrder.mockResolvedValue({ id: ORDER_ID, amount, currency: 'INR', notes });
    // The payment itself carries the plan price, so only the order-notes
    // checks (platform, plan, order amount) can stop this grant.
    await hook('payment.captured', goodPayment());
    expect(upgradeUserTier).not.toHaveBeenCalled();
  });

  test('API-plan refund is recorded once across redeliveries', async () => {
    const refund = { refund: { entity: { id: 'rfnd_CONF000001', payment_id: PAYMENT_ID, amount: PRO_PAISE, currency: 'INR', status: 'processed' } } };
    const a = await hook('refund.processed', goodPayment({ status: 'refunded' }), refund);
    expect(a.statusCode).toBe(200);
    await hook('refund.processed', goodPayment({ status: 'refunded' }), refund);
    const recorded = auditLog.mock.calls.filter(c => c[0] === 'RAZORPAY_REFUND_RECORDED');
    expect(recorded).toHaveLength(1);
    expect(recorded[0][1]).toMatchObject({ refundId: 'rfnd_CONF000001', paymentId: PAYMENT_ID });
  });
});
