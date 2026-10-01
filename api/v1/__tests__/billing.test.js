'use strict';

// Route-handler tests for billing.js's subscription lifecycle actions
// (create-subscription, manage-subscription, list-subscriptions). Before
// this fix, all three trusted a bare, client-supplied `email` field with
// zero verification -- anyone who knew or guessed a customer's email
// could list their subscription details or cancel their paid
// subscription outright. These tests prove: (a) all three now require a
// real API key, (b) the authenticated caller's own email is used, never
// a client-supplied one, and (c) manage-subscription additionally
// verifies the target subscription actually belongs to the caller
// (subscription_id itself is still client-supplied, so authentication
// alone isn't ownership).
jest.mock('../../_lib/redis', () => ({}));
jest.mock('../../_lib/middleware', () => ({ authenticate: jest.fn() }));
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return {
    ...actual,
    guardRequest: jest.fn(async () => true),
    globalIpRateLimit: jest.fn(async () => true),
    intentIpRateLimit: jest.fn(async () => true),
  };
});

const { authenticate } = require('../../_lib/middleware');
const razorpay = require('../../_lib/razorpay');
const subLib = require('../../_lib/subscriptions');
const handler = require('../billing');

const USER = {
  tier: 'pro', userId: 'u1', email: 'customer@example.com', keyHash: 'h1',
  requestsUsed: 1, requestsLimit: 25000,
};

function mockReq(method, action, { query = {}, body } = {}) {
  return { method, query: { action, ...query }, body, headers: {}, url: '/api/v1/billing' };
}

function mockRes() {
  const res = { headers: {}, statusCode: null, body: null };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}

beforeEach(() => {
  authenticate.mockReset();
  authenticate.mockResolvedValue(USER);
  jest.spyOn(razorpay, 'configured').mockReturnValue(true);
});

afterEach(() => {
  jest.restoreAllMocks();
});

function mockUnauthenticated() {
  authenticate.mockImplementation(async (req, res) => {
    res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'API key required.' } });
    return null;
  });
}

describe('list-subscriptions', () => {
  test('unauthenticated requests are rejected before any subscription lookup', async () => {
    mockUnauthenticated();
    const spy = jest.spyOn(subLib, 'getUserSubscriptions');

    const res = mockRes();
    await handler(mockReq('GET', 'list-subscriptions'), res);

    expect(res.statusCode).toBe(401);
    expect(spy).not.toHaveBeenCalled();
  });

  test('lists the authenticated caller\'s own subscriptions, ignoring any client-supplied email', async () => {
    const spy = jest.spyOn(subLib, 'getUserSubscriptions').mockResolvedValue([
      { subscriptionId: 'sub_1', planType: 'pro', status: 'active', period: 'monthly', amount: '149900', currency: 'INR', createdAt: '2026-08-01T00:00:00Z', nextBillingAt: '2026-09-01T00:00:00Z' },
    ]);

    const res = mockRes();
    // Adversarial: a client-supplied email query param, different from the
    // authenticated account -- must be completely ignored.
    await handler(mockReq('GET', 'list-subscriptions', { query: { email: 'victim@example.com' } }), res);

    expect(spy).toHaveBeenCalledWith({}, 'customer@example.com');
    expect(res.body.email).toBe('customer@example.com');
    expect(res.body.subscriptions).toHaveLength(1);
  });
});

describe('create-subscription (retired: plans are sold on the Sentinel APEX platform)', () => {
  test.each([
    ['unauthenticated', () => mockUnauthenticated()],
    ['authenticated', () => {}],
  ])('%s callers get 410 PLAN_CHECKOUT_MOVED and no subscription is created', async (_label, setup) => {
    setup();
    const spy = jest.spyOn(subLib, 'createSubscription');
    const res = mockRes();
    await handler(mockReq('POST', 'create-subscription', { body: { plan_type: 'team', period: 'monthly' } }), res);
    expect(spy).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(410);
    expect(res.body.error.code).toBe('PLAN_CHECKOUT_MOVED');
    expect(res.body.checkout_url).toMatch(/^https:\/\/intel\.cyberdudebivash\.com\/upgrade\.html\?plan=enterprise&/);
  });
});

describe('manage-subscription', () => {
  test('unauthenticated requests are rejected before any subscription lookup', async () => {
    mockUnauthenticated();
    const recordSpy = jest.spyOn(subLib, 'getSubscriptionRecord');
    const cancelSpy = jest.spyOn(subLib, 'cancelSubscription');

    const res = mockRes();
    await handler(mockReq('POST', 'manage-subscription', { body: { subscription_id: 'sub_1', action: 'cancel' } }), res);

    expect(res.statusCode).toBe(401);
    expect(recordSpy).not.toHaveBeenCalled();
    expect(cancelSpy).not.toHaveBeenCalled();
  });

  test('the exact vulnerability this round fixes: a subscription owned by a different email is never managed, even by an authenticated caller', async () => {
    jest.spyOn(subLib, 'getSubscriptionRecord').mockResolvedValue({
      subscriptionId: 'sub_victim', email: 'victim@example.com', status: 'active',
    });
    const cancelSpy = jest.spyOn(subLib, 'cancelSubscription');

    const res = mockRes();
    await handler(mockReq('POST', 'manage-subscription', {
      body: { subscription_id: 'sub_victim', action: 'cancel' },
    }), res);

    expect(cancelSpy).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('a non-existent subscription_id produces the identical response as one owned by someone else (no enumeration signal)', async () => {
    jest.spyOn(subLib, 'getSubscriptionRecord').mockResolvedValue(null);

    const res = mockRes();
    await handler(mockReq('POST', 'manage-subscription', {
      body: { subscription_id: 'sub_does_not_exist', action: 'cancel' },
    }), res);

    expect(res.statusCode).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
    expect(res.body.error.message).toBe('Subscription not found.');
  });

  test('a subscription genuinely owned by the authenticated caller can be cancelled', async () => {
    jest.spyOn(subLib, 'getSubscriptionRecord').mockResolvedValue({
      subscriptionId: 'sub_mine', email: 'customer@example.com', status: 'active',
    });
    const cancelSpy = jest.spyOn(subLib, 'cancelSubscription').mockResolvedValue({
      subscription_id: 'sub_mine', status: 'cancelled', ended_at: 1234567890,
    });

    const res = mockRes();
    await handler(mockReq('POST', 'manage-subscription', {
      body: { subscription_id: 'sub_mine', action: 'cancel' },
    }), res);

    expect(cancelSpy).toHaveBeenCalledWith(razorpay, 'sub_mine', { cancelAt: 'now' });
    expect(res.statusCode).toBe(200);
    expect(res.body.subscription.status).toBe('cancelled');
  });

  test('ownership comparison is case-insensitive (matches normalizeEmail\'s own normalization)', async () => {
    jest.spyOn(subLib, 'getSubscriptionRecord').mockResolvedValue({
      subscriptionId: 'sub_mine', email: 'Customer@EXAMPLE.com', status: 'active',
    });
    const pauseSpy = jest.spyOn(subLib, 'pauseSubscription').mockResolvedValue({
      subscription_id: 'sub_mine', status: 'paused', paused_at: 1234567890,
    });

    const res = mockRes();
    await handler(mockReq('POST', 'manage-subscription', {
      body: { subscription_id: 'sub_mine', action: 'pause' },
    }), res);

    expect(pauseSpy).toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
  });
});
