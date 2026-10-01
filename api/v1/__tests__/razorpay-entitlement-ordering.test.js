'use strict';

// A captured Razorpay payment must never end up "already processed" with no
// tier applied. Both confirmation paths (the signed webhook and the client
// checkout callback) previously wrote the replay marker and order status
// 'paid' BEFORE calling upgradeUserTier(); one transient failure in between
// made every later retry short-circuit on those markers. These tests drive
// the real handlers against an in-memory Redis with the grant failing once.

const mem = new Map();
jest.mock('../../_lib/redis', () => ({
  exists: jest.fn(async k => (mem.has(k) ? 1 : 0)),
  // Upstash REST shape: flat [field, value, ...] array (see parseHash()).
  hgetall: jest.fn(async k => (mem.has(k) ? Object.entries(mem.get(k)).flat() : null)),
  hmset: jest.fn(async (k, obj) => { mem.set(k, { ...(mem.get(k) || {}), ...obj }); return 'OK'; }),
  setex: jest.fn(async (k, _ttl, v) => { mem.set(k, v); return 'OK'; }),
  expire: jest.fn(async () => 1),
}));
jest.mock('../../_lib/payment-utils', () => {
  const actual = jest.requireActual('../../_lib/payment-utils');
  return { ...actual, upgradeUserTier: jest.fn(), auditLog: jest.fn(async () => {}) };
});
// Plan-order tests: the premium (D1) store reports "not a premium order".
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
    submissionIpRateLimit: jest.fn(async () => true),
    readRawBody: jest.fn(async req => req.__raw),
  };
});

const razorpay = require('../../_lib/razorpay');
const { upgradeUserTier } = require('../../_lib/payment-utils');
const webhook = require('../billing/razorpay-webhook');
const billing = require('../billing');

const ORDER_ID = 'order_TEST000001';
const PAYMENT_ID = 'pay_TEST000001';
const EMAIL = 'buyer@example.com';

function mockRes() {
  const res = { headers: {}, statusCode: null, body: null };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
function webhookReq() {
  const body = { event: 'payment.captured', payload: { payment: { entity: { id: PAYMENT_ID, order_id: ORDER_ID, amount: 2069900, currency: 'INR', status: 'captured' } } } };
  const raw = JSON.stringify(body);
  return { method: 'POST', headers: { 'x-razorpay-signature': 'ab'.repeat(32) }, body: raw, __raw: raw, query: {} };
}
function verifyReq() {
  return {
    method: 'POST', url: '/api/v1/billing', headers: {},
    query: { action: 'verify-razorpay-payment' },
    body: { email: EMAIL, plan_type: 'team', razorpay_order_id: ORDER_ID, razorpay_payment_id: PAYMENT_ID, razorpay_signature: 'ab'.repeat(32) },
  };
}

beforeEach(() => {
  mem.clear();
  // amount is stored in rupees by create-razorpay-order (plan.amount); Razorpay amounts are paise.
  mem.set(`payment:rzp:order:${ORDER_ID}`, { email: EMAIL, planType: 'team', amount: '20699', currency: 'INR', status: 'created' });
  upgradeUserTier.mockReset();
  upgradeUserTier
    .mockRejectedValueOnce(new Error('transient redis write failure'))
    .mockResolvedValue({ upgraded: true, pending: false });
  jest.spyOn(razorpay, 'configured').mockReturnValue(true);
  jest.spyOn(razorpay, 'verifyWebhookSignature').mockReturnValue(true);
  jest.spyOn(razorpay, 'verifyPaymentSignature').mockReturnValue(true);
  jest.spyOn(razorpay, 'fetchOrder').mockResolvedValue({ id: ORDER_ID, notes: {} });
  jest.spyOn(razorpay, 'fetchPayment').mockResolvedValue({ id: PAYMENT_ID, order_id: ORDER_ID, amount: 2069900, currency: 'INR', status: 'captured' });
  global.fetch = jest.fn(async () => ({ ok: false, json: async () => ({}) }));
});

afterEach(() => {
  jest.restoreAllMocks();
  delete global.fetch;
});

describe('signed webhook path', () => {
  test('a retry after a failed grant delivers the tier (payment not stranded)', async () => {
    const first = mockRes();
    await webhook(webhookReq(), first);
    expect(first.statusCode).toBe(500);
    expect(mem.has(`payment:rzp:txn:seen:${PAYMENT_ID}`)).toBe(false);
    expect(mem.get(`payment:rzp:order:${ORDER_ID}`).status).not.toBe('paid');

    const retry = mockRes();
    await webhook(webhookReq(), retry);
    expect(retry.statusCode).toBe(200);
    expect(upgradeUserTier).toHaveBeenCalledTimes(2);
    expect(upgradeUserTier).toHaveBeenLastCalledWith(EMAIL, 'team', expect.objectContaining({ transactionId: PAYMENT_ID }));
    expect(mem.get(`payment:rzp:order:${ORDER_ID}`).status).toBe('paid');
    expect(mem.has(`payment:rzp:txn:seen:${PAYMENT_ID}`)).toBe(true);
  });

  test('replay protection still holds once the grant succeeded', async () => {
    upgradeUserTier.mockReset();
    upgradeUserTier.mockResolvedValue({ upgraded: true, pending: false });
    await webhook(webhookReq(), mockRes());
    await webhook(webhookReq(), mockRes());
    expect(upgradeUserTier).toHaveBeenCalledTimes(1);
  });
});

describe('client checkout-callback path', () => {
  test('a retry after a failed grant upgrades instead of returning already_processed', async () => {
    const first = mockRes();
    await billing(verifyReq(), first);
    expect(first.statusCode).toBe(500);
    expect(mem.has(`payment:rzp:txn:seen:${PAYMENT_ID}`)).toBe(false);

    const retry = mockRes();
    await billing(verifyReq(), retry);
    expect(retry.statusCode).toBe(200);
    expect(retry.body.already_processed).toBeUndefined();
    expect(retry.body.verification).toMatchObject({ upgraded: true, plan_type: 'team' });
    expect(upgradeUserTier).toHaveBeenCalledTimes(2);
  });

  test('a successful payment is applied once; the next call reports already_processed', async () => {
    upgradeUserTier.mockReset();
    upgradeUserTier.mockResolvedValue({ upgraded: true, pending: false });
    await billing(verifyReq(), mockRes());
    const again = mockRes();
    await billing(verifyReq(), again);
    expect(again.body.already_processed).toBe(true);
    expect(upgradeUserTier).toHaveBeenCalledTimes(1);
  });
});
