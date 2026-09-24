'use strict';

const mockRedis = {
  exists: jest.fn(),
  setex:  jest.fn(),
  hmset:  jest.fn(),
  expire: jest.fn(),
  zadd:   jest.fn(),
};
jest.mock('../../../_lib/redis', () => mockRedis);

const mockAuditLog = jest.fn();
jest.mock('../../../_lib/payment-utils', () => ({
  now: () => '2026-09-10T00:00:00.000Z',
  auditLog: (...args) => mockAuditLog(...args),
  SUBMISSION_TTL_SECONDS: 7776000,
}));

const handleGumroadWebhook = require('../gumroad-webhook');

function response() {
  const r = { statusCode: null, body: null };
  r.status = jest.fn((code) => { r.statusCode = code; return r; });
  r.json = jest.fn((body) => { r.body = body; return r; });
  return r;
}

const SECRET = 'test-gumroad-secret';

function request(overrides = {}) {
  return {
    method: 'POST',
    query: { secret: SECRET },
    body: { sale_id: 'sale_1', email: 'buyer@example.com', product_id: 'p1', product_permalink: 'sessionshield', product_name: 'SessionShield', price: '2900', currency: 'usd' },
    ...overrides,
  };
}

describe('POST /api/v1/billing/gumroad-webhook', () => {
  const originalSecret = process.env.GUMROAD_WEBHOOK_SECRET;

  beforeEach(() => {
    jest.resetAllMocks();
    process.env.GUMROAD_WEBHOOK_SECRET = SECRET;
    mockRedis.exists.mockResolvedValue(0);
  });

  afterAll(() => {
    process.env.GUMROAD_WEBHOOK_SECRET = originalSecret;
  });

  test('rejects non-POST methods', async () => {
    const res = response();
    await handleGumroadWebhook(request({ method: 'GET' }), res);
    expect(res.statusCode).toBe(405);
  });

  test('fails closed with 500 if the webhook secret is not configured', async () => {
    delete process.env.GUMROAD_WEBHOOK_SECRET;
    const res = response();
    await handleGumroadWebhook(request(), res);
    expect(res.statusCode).toBe(500);
    expect(mockRedis.hmset).not.toHaveBeenCalled();
  });

  test('rejects a missing ?secret= query param with 401, without touching redis', async () => {
    const res = response();
    await handleGumroadWebhook(request({ query: {} }), res);
    expect(res.statusCode).toBe(401);
    expect(mockAuditLog).toHaveBeenCalledWith('GUMROAD_WEBHOOK_AUTH_FAIL', {});
    expect(mockRedis.hmset).not.toHaveBeenCalled();
  });

  test('rejects a wrong ?secret= value with 401', async () => {
    const res = response();
    await handleGumroadWebhook(request({ query: { secret: 'wrong' } }), res);
    expect(res.statusCode).toBe(401);
  });

  test('rejects a payload missing sale_id or email with 400', async () => {
    const res = response();
    await handleGumroadWebhook(request({ body: { sale_id: 'sale_1' } }), res);
    expect(res.statusCode).toBe(400);
    expect(mockRedis.hmset).not.toHaveBeenCalled();
  });

  test('records a valid sale, sets the dedup key, and audit-logs it', async () => {
    const res = response();
    await handleGumroadWebhook(request(), res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ received: true, status: 'recorded', sale_id: 'sale_1' });

    expect(mockRedis.setex).toHaveBeenCalledWith('payment:gumroad:sale:seen:sale_1', 7776000, '1');
    expect(mockRedis.hmset).toHaveBeenCalledWith('payment:gumroad:sale:sale_1', expect.objectContaining({
      saleId: 'sale_1', email: 'buyer@example.com', productPermalink: 'sessionshield',
      price: '2900', currency: 'usd', refunded: 'false',
    }));
    expect(mockRedis.expire).toHaveBeenCalledWith('payment:gumroad:sale:sale_1', 7776000);
    expect(mockRedis.zadd).toHaveBeenCalledWith('payment:gumroad:sales', expect.any(Number), 'sale_1');
    expect(mockAuditLog).toHaveBeenCalledWith('GUMROAD_SALE_RECORDED', expect.objectContaining({ saleId: 'sale_1' }));
  });

  test('a duplicate sale_id short-circuits as already_recorded without re-writing redis', async () => {
    mockRedis.exists.mockResolvedValue(1);
    const res = response();
    await handleGumroadWebhook(request(), res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ received: true, status: 'already_recorded', sale_id: 'sale_1' });
    expect(mockRedis.hmset).not.toHaveBeenCalled();
  });

  test('partial storage failure remains retryable and completion is last', async () => {
    mockRedis.hmset.mockRejectedValueOnce(new Error('temporary failure'));
    const first = response();
    await handleGumroadWebhook(request(), first);
    expect(first.statusCode).toBe(500);
    expect(mockRedis.setex).not.toHaveBeenCalled();
    const retry = response();
    await handleGumroadWebhook(request(), retry);
    expect(retry.statusCode).toBe(200);
    expect(mockRedis.setex.mock.invocationCallOrder[0]).toBeGreaterThan(mockRedis.zadd.mock.invocationCallOrder[0]);
  });

  test('dedup storage outage fails closed before writing sale', async () => {
    mockRedis.exists.mockRejectedValueOnce(new Error('unavailable'));
    const res = response();
    await handleGumroadWebhook(request(), res);
    expect(res.statusCode).toBe(500);
    expect(mockRedis.hmset).not.toHaveBeenCalled();
    expect(mockRedis.setex).not.toHaveBeenCalled();
  });

  test('a refunded sale is recorded with refunded: true', async () => {
    const res = response();
    await handleGumroadWebhook(request({ body: { ...request().body, refunded: 'true' } }), res);

    expect(mockRedis.hmset).toHaveBeenCalledWith('payment:gumroad:sale:sale_1', expect.objectContaining({ refunded: 'true' }));
  });

  test('a redis failure returns a clean 500, not an uncaught exception', async () => {
    mockRedis.exists.mockRejectedValue(new Error('redis unavailable'));
    mockRedis.setex.mockRejectedValue(new Error('redis unavailable'));
    const res = response();
    await handleGumroadWebhook(request(), res);
    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: 'Webhook handler failed' });
  });
});
