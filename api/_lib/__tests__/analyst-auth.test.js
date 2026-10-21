'use strict';

// api/_lib/redis.js hits a real Upstash HTTP endpoint at module scope --
// mocked here so analystIpRateLimit()/requireAnalyst() never make a real
// network call, matching the dependency-injection style other _lib tests
// use where the module allows it (publishing-pipeline.test.js), and
// jest.mock() where it doesn't (analyst-auth.js requires ./redis directly,
// like every route handler in this codebase does).
jest.mock('../redis', () => ({
  incr: jest.fn(async () => 1),
  expire: jest.fn(async () => 1),
}));

const redis = require('../redis');
const { verifyAnalystKey, analystIpRateLimit, requireAnalyst } = require('../analyst-auth');

const REAL_KEY_1 = 'a'.repeat(32);
const REAL_KEY_2 = 'b'.repeat(32);

function withAnalysts(json, fn) {
  const prev = process.env.ANALYST_KEYS;
  process.env.ANALYST_KEYS = json;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.ANALYST_KEYS;
    else process.env.ANALYST_KEYS = prev;
  }
}

function req(headers = {}) {
  return { headers, socket: {} };
}

beforeEach(() => {
  redis.incr.mockClear();
  redis.expire.mockClear();
  redis.incr.mockImplementation(async () => 1);
});

describe('verifyAnalystKey', () => {
  test('not configured (no ANALYST_KEYS) always returns null', () => {
    const prev = process.env.ANALYST_KEYS;
    delete process.env.ANALYST_KEYS;
    try {
      expect(verifyAnalystKey(req({ 'x-analyst-key': REAL_KEY_1 }))).toBeNull();
    } finally {
      if (prev !== undefined) process.env.ANALYST_KEYS = prev;
    }
  });

  test('malformed ANALYST_KEYS (not JSON) fails closed, not open', () => {
    withAnalysts('{not valid json', () => {
      expect(verifyAnalystKey(req({ 'x-analyst-key': REAL_KEY_1 }))).toBeNull();
    });
  });

  test('ANALYST_KEYS that is valid JSON but not an array fails closed', () => {
    withAnalysts(JSON.stringify({ id: 'x', key: REAL_KEY_1 }), () => {
      expect(verifyAnalystKey(req({ 'x-analyst-key': REAL_KEY_1 }))).toBeNull();
    });
  });

  test('an analyst entry with a key shorter than 16 chars is never a valid match', () => {
    withAnalysts(JSON.stringify([{ id: 'short', name: 'Short', key: 'tooshort' }]), () => {
      expect(verifyAnalystKey(req({ 'x-analyst-key': 'tooshort' }))).toBeNull();
    });
  });

  test('correct key for a configured analyst resolves to that analyst identity', () => {
    withAnalysts(JSON.stringify([
      { id: 'bivash', name: 'Bivash Kumar Nayak', role: 'lead_analyst', key: REAL_KEY_1 },
      { id: 'analyst2', name: 'Analyst Two', role: 'analyst', key: REAL_KEY_2 },
    ]), () => {
      const analyst = verifyAnalystKey(req({ 'x-analyst-key': REAL_KEY_1 }));
      expect(analyst).toEqual({ id: 'bivash', name: 'Bivash Kumar Nayak', role: 'lead_analyst' });
    });
  });

  test('a key that matches no configured analyst returns null', () => {
    withAnalysts(JSON.stringify([{ id: 'bivash', name: 'Bivash', key: REAL_KEY_1 }]), () => {
      expect(verifyAnalystKey(req({ 'x-analyst-key': 'c'.repeat(32) }))).toBeNull();
    });
  });

  test('missing header entirely returns null', () => {
    withAnalysts(JSON.stringify([{ id: 'bivash', name: 'Bivash', key: REAL_KEY_1 }]), () => {
      expect(verifyAnalystKey(req())).toBeNull();
    });
  });

  test('a second analyst without a name field falls back to id as the display name', () => {
    withAnalysts(JSON.stringify([{ id: 'noname', key: REAL_KEY_1 }]), () => {
      const analyst = verifyAnalystKey(req({ 'x-analyst-key': REAL_KEY_1 }));
      expect(analyst).toEqual({ id: 'noname', name: 'noname', role: 'analyst' });
    });
  });

  test('an entry missing id or key is skipped, not treated as a valid analyst', () => {
    withAnalysts(JSON.stringify([{ name: 'No ID', key: REAL_KEY_1 }, { id: 'no-key' }]), () => {
      expect(verifyAnalystKey(req({ 'x-analyst-key': REAL_KEY_1 }))).toBeNull();
    });
  });
});

describe('analystIpRateLimit', () => {
  test('allows requests under the limit', async () => {
    redis.incr.mockResolvedValue(5);
    const allowed = await analystIpRateLimit(req({ 'x-forwarded-for': '1.2.3.4' }));
    expect(allowed).toBe(true);
  });

  test('blocks requests once the per-minute count exceeds the limit', async () => {
    redis.incr.mockResolvedValue(121);
    const allowed = await analystIpRateLimit(req({ 'x-forwarded-for': '1.2.3.4' }));
    expect(allowed).toBe(false);
  });

  test('fails closed with distinct unavailable state when Redis is down', async () => {
    redis.incr.mockRejectedValue(new Error('redis down'));
    const allowed = await analystIpRateLimit(req({ 'x-forwarded-for': '1.2.3.4' }));
    expect(allowed).toBeNull();
  });

  test('fails closed when Redis bucket expiration fails', async () => {
    redis.incr.mockResolvedValue(1);
    redis.expire.mockRejectedValueOnce(new Error('ttl unavailable'));
    expect(await analystIpRateLimit(req({ 'x-forwarded-for': '1.2.3.4' }))).toBeNull();
  });

  test('sets the bucket TTL only on the first request in a window', async () => {
    redis.incr.mockResolvedValue(1);
    await analystIpRateLimit(req({ 'x-forwarded-for': '1.2.3.4' }));
    expect(redis.expire).toHaveBeenCalledWith(expect.stringContaining('ratelimit:analyst:1.2.3.4:'), 60);
  });
});

describe('requireAnalyst', () => {
  function fakeRes() {
    const res = { headers: {}, statusCode: null, body: null };
    res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
    res.status = jest.fn(s => { res.statusCode = s; return res; });
    res.json = jest.fn(b => { res.body = b; return res; });
    return res;
  }
  function fakeFail(res, status, code, message) {
    res.status(status).json({ success: false, error: { code, message } });
  }

  test('returns the analyst identity and writes nothing on success', async () => {
    await withAnalysts(JSON.stringify([{ id: 'bivash', name: 'Bivash', key: REAL_KEY_1 }]), async () => {
      const res = fakeRes();
      const analyst = await requireAnalyst(req({ 'x-analyst-key': REAL_KEY_1 }), res, fakeFail);
      expect(analyst).toEqual({ id: 'bivash', name: 'Bivash', role: 'analyst' });
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  test('calls the caller-supplied fail() with 401 on a missing/invalid key', async () => {
    await withAnalysts(JSON.stringify([{ id: 'bivash', name: 'Bivash', key: REAL_KEY_1 }]), async () => {
      const res = fakeRes();
      const analyst = await requireAnalyst(req({ 'x-analyst-key': 'wrong-key-wrong-key-wrong-key' }), res, fakeFail);
      expect(analyst).toBeNull();
      expect(res.statusCode).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });
  });


  test('returns 503 and no analyst identity during rate-limit backend outage', async () => {
    redis.incr.mockRejectedValue(new Error('temporary Redis timeout'));
    await withAnalysts(JSON.stringify([{ id: 'bivash', name: 'Bivash', key: REAL_KEY_1 }]), async () => {
      const res = fakeRes();
      const analyst = await requireAnalyst(req({ 'x-analyst-key': REAL_KEY_1 }), res, fakeFail);
      expect(analyst).toBeNull();
      expect(res.statusCode).toBe(503);
      expect(res.body.error.code).toBe('AUTH_RATE_LIMIT_UNAVAILABLE');
      expect(res.headers['Retry-After']).toBe('60');
      expect(JSON.stringify(res.body)).not.toContain('Redis');
    });
  });

  test('calls the caller-supplied fail() with 429 when rate-limited', async () => {
    redis.incr.mockResolvedValue(999);
    await withAnalysts(JSON.stringify([{ id: 'bivash', name: 'Bivash', key: REAL_KEY_1 }]), async () => {
      const res = fakeRes();
      const analyst = await requireAnalyst(req({ 'x-analyst-key': REAL_KEY_1 }), res, fakeFail);
      expect(analyst).toBeNull();
      expect(res.statusCode).toBe(429);
      expect(res.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(res.headers['Retry-After']).toBe('60');
    });
  });
});
