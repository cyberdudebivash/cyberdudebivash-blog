'use strict';

// Manual UPI/bank-transfer payments were retired on 2026-10-01
// (OPERATIONS.md: "Do not enable manual payment fallback"). These tests run
// the real billing router with Redis mocked, and pin three things:
//   1. no new manual intent can be created, and nothing is written for one;
//   2. intents issued before retirement can still be completed (no customer
//      who already transferred money is stranded);
//   3. no customer-facing surface still offers or starts the manual flow.

const store = new Map();
jest.mock('../../_lib/redis', () => ({
  get: jest.fn(async k => (store.has(k) ? store.get(k) : null)),
  set: jest.fn(async (k, v) => { store.set(k, v); return 'OK'; }),
  exists: jest.fn(async k => (store.has(k) ? 1 : 0)),
  expire: jest.fn(async () => 1),
  // Upstash REST returns hashes as a flat [field, value, ...] array (parseHash expects that).
  hgetall: jest.fn(async k => (store.has(k) ? Object.entries(store.get(k)).flat() : null)),
  hmset: jest.fn(async (k, v) => { store.set(k, { ...(store.get(k) || {}), ...v }); return 'OK'; }),
  hset: jest.fn(async (k, f, v) => { store.set(k, { ...(store.get(k) || {}), [f]: v }); return 1; }),
  setex: jest.fn(async (k, t, v) => { store.set(k, v); return 'OK'; }),
  lpush: jest.fn(async () => 1),
  ltrim: jest.fn(async () => 'OK'),
  incr: jest.fn(async () => 1),
  zadd: jest.fn(async () => 1),
  sadd: jest.fn(async () => 1),
}));
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return {
    ...actual,
    guardRequest: jest.fn(async () => true),
    globalIpRateLimit: jest.fn(async () => true),
    intentIpRateLimit: jest.fn(async () => true),
    submissionIpRateLimit: jest.fn(async () => true),
  };
});

const fs = require('fs');
const path = require('path');
const redis = require('../../_lib/redis');
const razorpay = require('../../_lib/razorpay');
const handler = require('../billing');

const ROOT = path.join(__dirname, '..', '..', '..');

function req(method, action, body) {
  return { method, query: { action }, body, headers: {}, url: '/api/v1/billing' };
}
function res() {
  const r = { headers: {}, statusCode: null, body: null };
  r.setHeader = jest.fn((k, v) => { r.headers[k] = v; });
  r.status = jest.fn(s => { r.statusCode = s; return r; });
  r.json = jest.fn(b => { r.body = b; return r; });
  r.end = jest.fn(() => r);
  return r;
}
async function call(method, action, body) {
  const r = res();
  await handler(req(method, action, body), r);
  return r;
}

beforeEach(() => {
  store.clear();
  jest.clearAllMocks();
});

describe('create-intent is retired', () => {
  test('returns 410 MANUAL_PAYMENT_RETIRED and points to online checkout', async () => {
    const r = await call('POST', 'create-intent', { email: 'buyer@example.com', plan_type: 'pro' });
    expect(r.statusCode).toBe(410);
    expect(r.body.error.code).toBe('MANUAL_PAYMENT_RETIRED');
    expect(r.body.error.message).toMatch(/create-razorpay-order/);
    expect(r.body.error.message).toMatch(/bivash@cyberdudebivash\.com/);
  });

  test('issues no intent, no UPI/bank details, and writes nothing for an intent', async () => {
    const r = await call('POST', 'create-intent', { email: 'buyer@example.com', plan_type: 'pro' });
    const text = JSON.stringify(r.body);
    expect(text).not.toMatch(/intent_id|upi_id|account_no|ifsc|payment_instructions/i);
    expect(redis.hmset).not.toHaveBeenCalled();
    expect([...store.keys()].some(k => k.startsWith('payment:intent:'))).toBe(false);
  });

  test('is still a recognised action (explicit 410, not INVALID_ACTION)', async () => {
    const r = await call('POST', 'create-intent', {});
    expect(r.body.error.code).not.toBe('INVALID_ACTION');
  });
});

describe('payments already in flight are not stranded', () => {
  test('an intent issued before retirement can still be submitted for review', async () => {
    const intentId = '3f2b8c1e-6a4d-4f8e-9b2a-1c3d5e7f9a0b';
    store.set(`payment:intent:${intentId}`, {
      intentId, email: 'buyer@example.com', planType: 'pro', amount: '1499',
      currency: 'INR', status: 'pending_payment', createdAt: '2026-10-01T05:00:00.000Z',
    });
    const r = await call('POST', 'submit-payment', {
      email: 'buyer@example.com', intent_id: intentId, transaction_id: '427110170556', payment_method: 'UPI',
    });
    expect(r.statusCode).not.toBe(410);
    expect(r.body.success).toBe(true);
    expect(store.get(`payment:submission:427110170556`)).toMatchObject({ intentId, planType: 'pro' });
  });

  test('an unknown/expired intent explains the retirement instead of saying "create a new one"', async () => {
    const r = await call('POST', 'submit-payment', {
      email: 'buyer@example.com', intent_id: '3f2b8c1e-6a4d-4f8e-9b2a-1c3d5e7f9a0c', transaction_id: '427110170557', payment_method: 'UPI',
    });
    expect(r.statusCode).toBe(404);
    expect(r.body.error.message).toMatch(/retired/);
    expect(r.body.error.message).not.toMatch(/create a new one/);
  });
});

describe('online checkout unavailable no longer redirects to the manual flow', () => {
  test('RAZORPAY_UNAVAILABLE message does not mention create-intent or manual payment', async () => {
    jest.spyOn(razorpay, 'configured').mockReturnValue(false);
    const r = await call('POST', 'create-razorpay-order', { email: 'buyer@example.com', plan_type: 'pro' });
    expect(r.statusCode).toBe(503);
    expect(r.body.error.code).toBe('RAZORPAY_UNAVAILABLE');
    expect(r.body.error.message).not.toMatch(/create-intent|manual payment/i);
    expect(r.body.error.message).toMatch(/bivash@cyberdudebivash\.com/);
  });
});

describe('customer-facing surfaces', () => {
  const read = f => fs.readFileSync(path.join(ROOT, f), 'utf8');

  test.each(['pricing.html', 'payment-flow.js'])('%s never starts a manual intent and shows no UPI/bank panel', f => {
    const s = read(f);
    expect(s).not.toMatch(/billing\?action=create-intent/);
    expect(s).not.toMatch(/pay manually via UPI\/Bank Transfer/);
    expect(s).not.toMatch(/I've Paid — Submit UTR/);
    expect(s).not.toMatch(/upi:\/\/pay/);
    expect(s).toMatch(/Manual UPI \/ bank transfer has been retired/);
  });

  test.each(['pricing.html', 'faq.html', 'buy.html', 'payment-flow.js'])('%s does not offer manual UPI/bank transfer as a way to pay', f => {
    const s = read(f);
    expect(s).not.toMatch(/Manual UPI and bank transfer \(NEFT\/IMPS\) are (also )?supported/);
    expect(s).not.toMatch(/Verified UPI or bank transfer remains available/);
    expect(s).not.toMatch(/Use manual payment/);
    expect(s).not.toMatch(/Please use UPI\/Bank Transfer below|Try UPI\/Bank below/);
  });

  test('faq.html structured data states the retirement and still parses', () => {
    const s = read('faq.html');
    const blocks = [...s.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map(m => JSON.parse(m[1]));
    const text = JSON.stringify(blocks);
    expect(text).toMatch(/retired on 1 October 2026/);
    expect(text).not.toMatch(/Manual UPI and bank transfer \(NEFT\/IMPS\) are supported/);
  });
});
