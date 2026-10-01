'use strict';

// Premium-report payment integrity, end to end, with no mocked business logic:
// the real webhook handler, premium-commerce service and D1 store run against
// a real SQLite database built from migrations/0008 (node:sqlite behind the
// D1 binding interface), and every webhook is signed with a real HMAC.
// Mocked: Redis (in-memory, write-tracked), R2 artifact storage, and the
// Razorpay REST client's network calls.
//
// Invariants:
//   - signature failure (missing / wrong / tampered bytes) has no side effect;
//   - the handler acts on the signed raw bytes, never on a parsed req.body;
//   - only an order this blog created in D1 is fulfilled; Sentinel APEX (or any
//     other) events are acknowledged with zero writes;
//   - amount/currency mismatches are acknowledged and never granted;
//   - duplicate and mixed payment.captured / order.paid deliveries grant once;
//   - the ENTITLED replay marker is written only after the entitlement exists;
//   - a full refund revokes once, replays are no-ops, a partial refund keeps
//     access, and a late payment event never re-grants a refunded order;
//   - downloads require the caller's own active entitlement.

process.env.RAZORPAY_KEY_ID = 'rzp_test_pwi';
process.env.RAZORPAY_KEY_SECRET = 'pwi_key_secret_for_tests';
process.env.RAZORPAY_WEBHOOK_SECRET = 'pwi_webhook_secret_for_tests';
process.env.PREMIUM_COMMERCE_CURRENCIES = 'INR';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const redisWrites = [];
const mem = new Map();
jest.mock('../../_lib/redis', () => {
  const w = (op) => jest.fn(async (k, ...rest) => { redisWrites.push([op, k]); mem.set(k, rest); return 'OK'; });
  return {
    exists: jest.fn(async k => (mem.has(k) ? 1 : 0)),
    hgetall: jest.fn(async k => (mem.has(k) ? Object.entries(mem.get(k)).flat() : null)),
    hmset: w('hmset'), setex: w('setex'), set: w('set'), zadd: w('zadd'),
    incr: w('incr'), expire: jest.fn(async () => 1), lpush: w('lpush'), ltrim: jest.fn(async () => 'OK'),
  };
});
jest.mock('../../_lib/payment-utils', () => {
  const actual = jest.requireActual('../../_lib/payment-utils');
  return { ...actual, upgradeUserTier: jest.fn(async () => ({ upgraded: true })), auditLog: jest.fn(async () => {}) };
});
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return { ...actual, readRawBody: jest.fn(async req => req.__raw) };
});
const ARTIFACT = Buffer.from('# Premium report body\n', 'utf8');
jest.mock('../../_lib/premium-report-storage', () => ({
  headCertifiedArtifact: jest.fn(async () => ({ ok: true })),
  getCertifiedArtifact: jest.fn(async () => ({ arrayBuffer: async () => Uint8Array.from(Buffer.from('# Premium report body\n', 'utf8')).buffer })),
}));

const d1 = require('../../_lib/d1');
const razorpay = require('../../_lib/razorpay');
const storage = require('../../_lib/premium-report-storage');
const service = require('../../_lib/premium-commerce-service');
const { upgradeUserTier, auditLog } = require('../../_lib/payment-utils');
const webhook = require('../billing/razorpay-webhook');

const SHA = 'c'.repeat(64);
const REPORT = 'rpt-ray-cve';
const BUYER = { userId: 'usr_buyer', email: 'buyer@example.com' };
const OTHER = { userId: 'usr_other', email: 'other@example.com' };
const PRICE = 199900; // ₹1,999 in paise

let db;
let failNextEntitlementInsert = false;

/* D1 binding over node:sqlite: the same prepare/bind/run/batch surface the
   Workers runtime exposes, so api/_lib/d1.js runs its native path. */
function sqliteBinding(database) {
  const prep = (sql, params = []) => ({
    sql, params,
    bind(...p) { return prep(sql, p); },
    async run() {
      if (failNextEntitlementInsert && /INSERT INTO premium_entitlements/.test(sql)) {
        failNextEntitlementInsert = false;
        throw new Error('D1 transient failure');
      }
      const stmt = database.prepare(sql);
      if (/^\s*(SELECT|WITH)/i.test(sql)) return { results: stmt.all(...params), success: true, meta: {} };
      stmt.run(...params);
      return { results: [], success: true, meta: {} };
    },
  });
  return {
    prepare: sql => prep(sql),
    async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
  };
}

const sign = raw => crypto.createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET).update(raw).digest('hex');
function res() {
  const r = { statusCode: null, body: null, headers: {} };
  r.setHeader = (k, v) => { r.headers[k] = v; };
  r.status = s => { r.statusCode = s; return r; };
  r.json = b => { r.body = b; return r; };
  r.end = () => r;
  return r;
}
async function deliver(raw, { signature = sign(raw), parsedBody } = {}) {
  const r = res();
  const headers = signature === null ? {} : { 'x-razorpay-signature': signature };
  await webhook({ method: 'POST', headers, body: parsedBody, __raw: raw, query: {} }, r);
  return r;
}
const paymentEvent = (event, payment) => JSON.stringify({ event, payload: { payment: { entity: payment } } });
const refundEvent = (refund, payment) => JSON.stringify({ event: 'refund.processed', payload: { refund: { entity: refund }, payment: { entity: payment } } });

const orders = () => db.prepare('SELECT * FROM premium_orders').all();
const ents = () => db.prepare('SELECT * FROM premium_entitlements').all();
const order = () => orders()[0];

let rzpSeq = 0;
async function checkout(user = BUYER) {
  const id = `order_PWI${String(++rzpSeq).padStart(6, '0')}`;
  razorpay.createOrder.mockResolvedValueOnce({ id });
  const out = await service.createCheckout({ user, reportId: REPORT });
  return out.razorpay_order_id;
}
const captured = (orderId, over = {}) => ({ id: 'pay_PWI000001', order_id: orderId, amount: PRICE, currency: 'INR', status: 'captured', ...over });

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'migrations', '0008_premium_intelligence_commerce.sql'), 'utf8'));
  db.prepare(`INSERT INTO premium_report_catalog (report_id, slug, title, report_type, summary, certification_state,
    artifact_sha256, artifact_key, artifact_filename, artifact_content_type, artifact_size_bytes, price_minor, currency,
    status, reviewer_identity, review_timestamp, published_at, updated_at)
    VALUES (?, ?, ?, 'VULNERABILITY', '', 'PREMIUM_CERTIFIED', ?, ?, 'ray.md', 'text/markdown; charset=utf-8', ?, ?, 'INR',
    'SELLABLE', 'REVIEWER', '2026-08-18T00:00:00Z', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`)
    .run(REPORT, 'ray-cve', 'Ray CVE', SHA, `premium-reports/${REPORT}/${SHA}.md`, ARTIFACT.length, PRICE);
  d1.setD1Binding(sqliteBinding(db));
  mem.clear();
  redisWrites.length = 0;
  failNextEntitlementInsert = false;
  jest.clearAllMocks();
  jest.spyOn(razorpay, 'createOrder');
  jest.spyOn(razorpay, 'fetchOrder');
  jest.spyOn(razorpay, 'fetchPayment');
  global.fetch = jest.fn(async () => { throw new Error('no network in webhook path'); });
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => { jest.restoreAllMocks(); delete global.fetch; d1.setD1Binding(null); });

const logged = evt => console.log.mock.calls.map(c => String(c[0])).filter(l => l.includes(`"evt":"${evt}"`));

describe('premium checkout order', () => {
  test('price, currency and ownership notes come from the server catalog (₹1,999 = 199900 paise)', async () => {
    await checkout();
    const [amount, currency, receipt, notes] = razorpay.createOrder.mock.calls[0];
    expect(amount).toBe(199900);
    expect(currency).toBe('INR');
    expect(receipt).toMatch(/^pir_/);
    expect(notes).toMatchObject({ platform: 'CYBERDUDEBIVASH_INTEL_FACTORY', product_type: 'PREMIUM_REPORT', sku: REPORT, artifact_sha256: SHA });
    expect(order()).toMatchObject({ amount_minor: 199900, currency: 'INR', state: 'ORDER_CREATED', report_id: REPORT, owner_id: BUYER.userId });
    expect(logged('premium_order_created')).toHaveLength(1);
    expect(logged('premium_order_created')[0]).not.toContain(BUYER.email);
  });

  test('a missing artifact stops checkout before any Razorpay order (no money taken)', async () => {
    storage.headCertifiedArtifact.mockResolvedValueOnce({ ok: false, reason: 'missing' });
    await expect(service.createCheckout({ user: BUYER, reportId: REPORT })).rejects.toMatchObject({ code: 'ARTIFACT_UNAVAILABLE' });
    expect(razorpay.createOrder).not.toHaveBeenCalled();
    expect(orders()).toHaveLength(0);
  });
});

describe('webhook authentication', () => {
  test.each([
    ['missing signature', raw => ({ signature: null })],
    ['wrong signature', raw => ({ signature: 'ab'.repeat(32) })],
    ['payload modified after signing', raw => ({ signature: sign(raw.replace('199900', '199901')) })],
  ])('%s: 400 and no side effect', async (_n, opts) => {
    const orderId = await checkout();
    const raw = paymentEvent('payment.captured', captured(orderId));
    const r = await deliver(raw, opts(raw));
    expect(r.statusCode).toBe(400);
    expect(order().state).toBe('ORDER_CREATED');
    expect(ents()).toHaveLength(0);
    expect(redisWrites).toEqual([]);
  });

  test('acts on the signed raw bytes, never on an adapter-parsed body', async () => {
    const a = await checkout();
    const b = await checkout(OTHER);
    const raw = paymentEvent('payment.captured', captured(a));
    const forged = JSON.parse(paymentEvent('payment.captured', captured(b, { id: 'pay_FORGED00001' })));
    const r = await deliver(raw, { parsedBody: forged });
    expect(r.statusCode).toBe(200);
    expect(ents()).toHaveLength(1);
    expect(ents()[0]).toMatchObject({ owner_id: BUYER.userId, status: 'ACTIVE' });
    expect(orders().find(o => o.razorpay_order_id === b).state).toBe('ORDER_CREATED');
  });
});

describe('fulfilment and idempotency', () => {
  test.each([
    ['payment.captured x3', ['payment.captured', 'payment.captured', 'payment.captured']],
    ['order.paid x3', ['order.paid', 'order.paid', 'order.paid']],
    ['mixed payment.captured + order.paid', ['payment.captured', 'order.paid', 'payment.captured', 'order.paid']],
  ])('%s: exactly one entitlement', async (_n, events) => {
    const orderId = await checkout();
    for (const e of events) expect((await deliver(paymentEvent(e, captured(orderId)))).statusCode).toBe(200);
    expect(ents()).toHaveLength(1);
    expect(ents()[0]).toMatchObject({ owner_id: BUYER.userId, report_id: REPORT, status: 'ACTIVE' });
    expect(order()).toMatchObject({ state: 'ENTITLED', razorpay_payment_id: 'pay_PWI000001' });
    expect(logged('premium_entitlement_granted')).toHaveLength(1); // one logical grant
    expect(redisWrites).toEqual([]); // premium path never touches Redis
    expect(global.fetch).not.toHaveBeenCalled(); // no external lookups
    expect(razorpay.fetchOrder).not.toHaveBeenCalled();
  });

  test.each([
    ['amount below price', { amount: 100 }],
    ['amount in rupees instead of paise', { amount: 1999 }],
    ['wrong currency', { currency: 'USD' }],
    ['not captured', { status: 'authorized' }],
  ])('%s: acknowledged, never granted', async (_n, over) => {
    const orderId = await checkout();
    const r = await deliver(paymentEvent('payment.captured', captured(orderId, over)));
    expect(r.statusCode).toBe(200);
    expect(ents()).toHaveLength(0);
    expect(order().state).toBe('ORDER_CREATED');
    expect(logged('premium_payment_rejected')).toHaveLength(1);
  });

  test('the ENTITLED marker is written only after the entitlement: a failed grant is retried, not stranded', async () => {
    const orderId = await checkout();
    failNextEntitlementInsert = true;
    const first = await deliver(paymentEvent('payment.captured', captured(orderId)));
    expect(first.statusCode).toBe(500); // Razorpay retries
    expect(ents()).toHaveLength(0);
    expect(order().state).not.toBe('ENTITLED');
    const retry = await deliver(paymentEvent('order.paid', captured(orderId)));
    expect(retry.statusCode).toBe(200);
    expect(ents()).toHaveLength(1);
    expect(order().state).toBe('ENTITLED');
  });

  test('a second, different payment for an entitled order is acknowledged and changes nothing', async () => {
    const orderId = await checkout();
    await deliver(paymentEvent('payment.captured', captured(orderId)));
    const r = await deliver(paymentEvent('payment.captured', captured(orderId, { id: 'pay_PWI000002' })));
    expect(r.statusCode).toBe(200);
    expect(order().razorpay_payment_id).toBe('pay_PWI000001');
    expect(ents()).toHaveLength(1);
    expect(logged('premium_payment_rejected')[0]).toContain('PAYMENT_CONFLICT');
  });
});

describe('Sentinel APEX platform isolation', () => {
  test.each([
    ['Sentinel APEX plan payment', { platform: 'CYBERDUDEBIVASH_SENTINEL_APEX', planType: 'pro', email: 'x@example.com' }],
    ['subscription payment without notes', {}],
  ])('%s: acknowledged with zero entitlements, zero order changes, zero Redis writes', async (_n, notes) => {
    const orderId = await checkout();
    const foreign = { id: 'pay_PLAT00001', order_id: 'order_PLATFORM0001', amount: 410000, currency: 'INR', status: 'captured', notes };
    for (const e of ['payment.captured', 'order.paid']) {
      const r = await deliver(paymentEvent(e, foreign));
      expect(r.statusCode).toBe(200);
    }
    expect(ents()).toHaveLength(0);
    expect(orders()).toHaveLength(1);
    expect(order()).toMatchObject({ razorpay_order_id: orderId, state: 'ORDER_CREATED' });
    expect(redisWrites).toEqual([]);
    expect(upgradeUserTier).not.toHaveBeenCalled();
    expect(auditLog).not.toHaveBeenCalled();
    expect(logged('foreign_platform_webhook_ignored')).toHaveLength(2);
  });

  test('a platform refund is acknowledged and changes nothing', async () => {
    const orderId = await checkout();
    await deliver(paymentEvent('payment.captured', captured(orderId)));
    const r = await deliver(refundEvent(
      { id: 'rfnd_PLAT0001', payment_id: 'pay_PLAT00001', amount: 410000, currency: 'INR', status: 'processed' },
      { id: 'pay_PLAT00001', amount: 410000, amount_refunded: 410000, status: 'refunded' }));
    expect(r.statusCode).toBe(200);
    expect(ents()[0].status).toBe('ACTIVE');
    expect(redisWrites).toEqual([]);
  });
});

describe('refunds', () => {
  const refundFor = (over = {}) => refundEvent(
    { id: 'rfnd_PWI0001', payment_id: 'pay_PWI000001', amount: PRICE, currency: 'INR', status: 'processed', ...over },
    { id: 'pay_PWI000001', amount: PRICE, amount_refunded: over.amount || PRICE, status: (over.amount || PRICE) >= PRICE ? 'refunded' : 'captured' });

  test('full refund revokes once; replay is a no-op; a late payment event never re-grants', async () => {
    const orderId = await checkout();
    await deliver(paymentEvent('payment.captured', captured(orderId)));
    expect((await deliver(refundFor())).statusCode).toBe(200);
    expect(order().state).toBe('REFUNDED');
    expect(ents()[0].status).toBe('REFUNDED');
    expect((await deliver(refundFor())).statusCode).toBe(200);
    expect(order().state).toBe('REFUNDED');
    const late = await deliver(paymentEvent('order.paid', captured(orderId)));
    expect(late.statusCode).toBe(200);
    expect(ents()[0].status).toBe('REFUNDED');
    expect(order().state).toBe('REFUNDED');
    expect(orders()).toHaveLength(1); // financial record kept
  });

  test('partial refund keeps access', async () => {
    const orderId = await checkout();
    await deliver(paymentEvent('payment.captured', captured(orderId)));
    await deliver(refundFor({ amount: 50000 }));
    expect(ents()[0].status).toBe('ACTIVE');
    expect(order().state).toBe('ENTITLED');
  });
});

describe('artifact delivery', () => {
  test('only the entitled buyer can download; refunded or other callers never reach R2', async () => {
    const orderId = await checkout();
    await deliver(paymentEvent('payment.captured', captured(orderId)));
    const got = await service.downloadReport({ user: BUYER, reportId: REPORT });
    expect(Buffer.from(got.bytes).toString('utf8')).toBe(ARTIFACT.toString('utf8'));
    expect(logged('premium_report_downloaded')).toHaveLength(1);

    storage.getCertifiedArtifact.mockClear();
    await expect(service.downloadReport({ user: OTHER, reportId: REPORT })).rejects.toMatchObject({ code: 'ENTITLEMENT_NOT_FOUND' });
    await deliver(refundEvent(
      { id: 'rfnd_PWI0001', payment_id: 'pay_PWI000001', amount: PRICE, currency: 'INR', status: 'processed' },
      { id: 'pay_PWI000001', amount: PRICE, amount_refunded: PRICE, status: 'refunded' }));
    await expect(service.downloadReport({ user: BUYER, reportId: REPORT })).rejects.toMatchObject({ code: 'ENTITLEMENT_NOT_FOUND' });
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });
});

describe('checkout unavailable', () => {
  test('tells the buyer to email, never offers a manual UPI/bank fallback, takes no order', async () => {
    jest.spyOn(razorpay, 'configured').mockReturnValue(false);
    const err = await service.createCheckout({ user: BUYER, reportId: REPORT }).catch(e => e);
    expect(err.code).toBe('PAYMENT_GATEWAY_UNAVAILABLE');
    expect(err.message).toBe('Online purchase temporarily unavailable. Contact bivash@cyberdudebivash.com');
    expect(err.message).not.toMatch(/UPI|bank|UTR/i);
    expect(razorpay.createOrder).not.toHaveBeenCalled();
    expect(orders()).toHaveLength(0);
  });
});
