/**
 * SENTINEL APEX — Upstash Redis REST Client
 * Zero npm dependencies. Pure HTTP fetch to Upstash REST API.
 * Required env vars: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
 */
'use strict';

const BASE = process.env.UPSTASH_REDIS_REST_URL || '';
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';

if (!BASE || !TOKEN) {
  console.warn('[REDIS] UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN not set — Redis unavailable.');
}

async function redisCmd(...args) {
  if (!BASE || !TOKEN) throw new Error('Redis not configured');
  const res = await fetch(`${BASE}/${args.map(encodeURIComponent).join('/')}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`Redis HTTP ${res.status}`);
  const json = await res.json();
  // P0: Upstash may return an HTTP 200 containing {"error":"..."}.
  // Never treat that as a missing key, empty backup keyspace, successful HMSET
  // or successful payment audit replay. Redis GET's explicit result:null IS
  // a valid cache miss and must remain supported.
  if (!json || typeof json !== 'object' || Array.isArray(json) ||
      (Object.prototype.hasOwnProperty.call(json, 'error') &&
       json.error !== null && json.error !== undefined) ||
      !Object.prototype.hasOwnProperty.call(json, 'result')) {
    throw new Error('SOC_REDIS_COMMAND_SERVER_REJECTED');
  }
  return json.result;
}

const redis = {
  // Strings
  get:    key           => redisCmd('GET', key),
  set:    (key, val)    => redisCmd('SET', key, val),
  setex:  (key, ttl, v) => redisCmd('SETEX', key, String(ttl), v),
  // SET key val NX -- Upstash returns "OK" if the key was newly set, null
  // if it already existed (no-op). Used for idempotent event creation
  // (watchlist change-detection): the caller does not need a prior EXISTS
  // check -- a truthy return means "this call created it", falsy means
  // "someone/something already had".
  setnx:  (key, val)    => redisCmd('SET', key, val, 'NX'),
  // SET key val NX PX <ms> -- atomic claim-with-lease in one round trip:
  // "OK" if this call created the key (claim acquired), null if it already
  // existed (someone else already holds it). The PX expiry means a worker
  // that claims then dies before releasing self-heals -- no separate
  // "check for expired leases" sweep is needed, Redis expires the claim
  // key itself. Used by notification-store.js's per-channel delivery
  // claim (see that module's docstring for why TTL alone is sufficient).
  setnxpx: (key, val, ttlMs) => redisCmd('SET', key, val, 'NX', 'PX', String(ttlMs)),
  del:    key           => redisCmd('DEL', key),
  exists: key           => redisCmd('EXISTS', key),
  incr:   key           => redisCmd('INCR', key),
  expire: (key, ttl)    => redisCmd('EXPIRE', key, String(ttl)),
  ttl:    key           => redisCmd('TTL', key),
  // KEYS, not SCAN: simple and sufficient at this platform's current key
  // count (registered users, not millions of keys). Revisit with
  // cursor-based SCAN if the keyspace grows large enough for KEYS's
  // single-pass cost to matter -- not needed at today's scale.
  keys:   pattern       => redisCmd('KEYS', pattern),

  // Hashes
  hget:   (key, field)       => redisCmd('HGET', key, field),
  // Redis HSET accepts EITHER a field/value pair OR multiple alternating
  // field/value arguments. Several core SOC managers pass Object.entries(...)
  // .flat() to this adapter; the old fixed-arity implementation sent that
  // entire array as ONE field and an undefined value (P0 write-path defect).
  // Validate the full payload before sending one atomic Redis HSET command.
  hset: (key, field, val) => {
    let pairs;
    if (Array.isArray(field) && val === undefined) {
      pairs = field;
    } else if (typeof field === 'string' && val !== undefined) {
      pairs = [field, val];
    } else {
      throw new TypeError('SOC_REDIS_HSET_INVALID_FIELDS');
    }
    if (!pairs.length || pairs.length % 2 !== 0) {
      throw new TypeError('SOC_REDIS_HSET_INVALID_FIELDS');
    }
    const args = [];
    for (let i = 0; i < pairs.length; i += 2) {
      const name = pairs[i], value = pairs[i + 1];
      if (typeof name !== 'string' || !name ||
          value === undefined ||
          (typeof value === 'number' && !Number.isFinite(value))) {
        throw new TypeError('SOC_REDIS_HSET_INVALID_FIELDS');
      }
      // Structured values must not silently become "[object Object]".
      const encoded = value && typeof value === 'object'
        ? JSON.stringify(value) : String(value);
      if (encoded === undefined) throw new TypeError('SOC_REDIS_HSET_INVALID_FIELDS');
      args.push(name, encoded);
    }
    // Preserve the existing compact GET path for a classic one-field edit.
    if (!Array.isArray(field)) return redisCmd('HSET', key, ...args);
    // A full investigation/report may be too large for URL path parameters.
    // Upstash supports exactly one command as POST [COMMAND, key, field, value...].
    // This is a single atomic Redis HSET, NOT a non-atomic REST pipeline.
    return (async () => {
      if (!BASE || !TOKEN) throw new Error('Redis not configured');
      const res = await fetch(BASE, {
        method: 'POST',
        headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(['HSET', key, ...args]),
        cache: 'no-store',
      });
      if (!res.ok) throw new Error(`Redis HSET HTTP ${res.status}`);
      const json = await res.json();
      if (!json || Object.prototype.hasOwnProperty.call(json, 'error') ||
          !Object.prototype.hasOwnProperty.call(json, 'result')) {
        throw new Error('SOC_REDIS_HSET_SERVER_REJECTED');
      }
      return json.result;
    })();
  },
  hgetall: key               => redisCmd('HGETALL', key),
  // HMSET is still used for customer API keys, paid entitlements,
  // purchase tokens and encrypted-snapshot restoration. Never put those
  // values or potentially long records in a GET URL (proxy/URL-size risk).
  // Preserve Redis HMSET's historic 'OK' response, not HSET's count.
  // One REST POST command is atomic on Redis; do NOT use /pipeline.
  hmset: async (key, obj) => {
    if (typeof key !== 'string' || !key ||
        !obj || typeof obj !== 'object' || Array.isArray(obj)) {
      throw new TypeError('SOC_REDIS_HMSET_INVALID_FIELDS');
    }
    const entries = Object.entries(obj);
    if (!entries.length) throw new TypeError('SOC_REDIS_HMSET_INVALID_FIELDS');
    const pairs = [];
    for (const [field, value] of entries) {
      if (typeof field !== 'string' || !field) {
        throw new TypeError('SOC_REDIS_HMSET_INVALID_FIELDS');
      }
      // Maintain existing String(value) wire encoding for all callers.
      // Validation prevents invalid key/field shape, not a tier remapping.
      pairs.push(field, String(value));
    }
    if (!BASE || !TOKEN) throw new Error('Redis not configured');
    const res = await fetch(BASE, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(['HMSET', key, ...pairs]),
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(`Redis HMSET HTTP ${res.status}`);
    const json = await res.json();
    if (!json || typeof json !== 'object' || Array.isArray(json) ||
        (Object.prototype.hasOwnProperty.call(json, 'error') &&
         json.error !== null && json.error !== undefined) ||
        json.result !== 'OK') {
      throw new Error('SOC_REDIS_HMSET_NOT_CONFIRMED');
    }
    return json.result;
  },
  hincrby: (key, field, n)   => redisCmd('HINCRBY', key, field, String(n)),

  // Sets (entity/relationship indexes -- graph-engine.js, evidence-manager.js)
  sadd:     (key, ...members) => redisCmd('SADD', key, ...members),
  srem:     (key, ...members) => redisCmd('SREM', key, ...members),
  smembers: key                => redisCmd('SMEMBERS', key),
  scard:    key                => redisCmd('SCARD', key),

  // Sorted sets (for usage analytics)
  zadd:     (key, score, member) => redisCmd('ZADD', key, String(score), member),
  zrem:     (key, ...members)    => redisCmd('ZREM', key, ...members),
  zcard:    key                  => redisCmd('ZCARD', key),
  zrange:   (key, start, stop, ws) => ws
    ? redisCmd('ZRANGE', key, String(start), String(stop), 'WITHSCORES')
    : redisCmd('ZRANGE', key, String(start), String(stop)),
  zrevrange:(key, start, stop, ws) => ws
    ? redisCmd('ZREVRANGE', key, String(start), String(stop), 'WITHSCORES')
    : redisCmd('ZREVRANGE', key, String(start), String(stop)),
  // ZRANGEBYSCORE key min max -- the natural primitive for "give me every
  // due item" (notification-store.js's pending-delivery queue, scored by
  // next_attempt_at) that no existing method covers: zrange/zrevrange are
  // rank-based, not score-range-based.
  zrangebyscore: (key, min, max) => redisCmd('ZRANGEBYSCORE', key, String(min), String(max)),

  // Atomic Redis Lua script over Upstash REST. POST keeps the script and
  // arguments out of URL paths. A pipeline is not atomic; do not substitute.
  // Fail closed on response-level errors, including successful HTTP 200 with
  // a Redis error payload.
  eval: async (script, keys = [], args = []) => {
    if (!BASE || !TOKEN) throw new Error('Redis not configured');
    if (typeof script !== 'string' || !script || !Array.isArray(keys) ||
        !Array.isArray(args) || keys.length > 12 || args.length > 32) {
      throw new Error('SOC_REDIS_EVAL_INVALID_ARGUMENTS');
    }
    const res = await fetch(BASE, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['EVAL', script, String(keys.length), ...keys, ...args]),
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(`Redis EVAL HTTP ${res.status}`);
    const json = await res.json();
    if (!json || Object.prototype.hasOwnProperty.call(json, 'error') ||
        !Object.prototype.hasOwnProperty.call(json, 'result')) {
      throw new Error('SOC_REDIS_EVAL_SERVER_REJECTED');
    }
    return json.result;
  },

  // Pipeline: execute multiple commands
  pipeline: async (commands) => {
    const res = await fetch(`${BASE}/pipeline`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(commands),
    });
    if (!res.ok) throw new Error(`Redis pipeline HTTP ${res.status}`);
    const json = await res.json();
    // A pipeline is NOT atomic: a later command can fail after earlier ones
    // executed. Surface every failed/ambiguous receipt to callers. Do not
    // convert a partial failure into an all-green result array.
    if (!Array.isArray(json) || json.length !== commands.length ||
        json.some(r => !r || typeof r !== 'object' || Array.isArray(r) ||
          (Object.prototype.hasOwnProperty.call(r, 'error') &&
           r.error !== null && r.error !== undefined) ||
          !Object.prototype.hasOwnProperty.call(r, 'result'))) {
      throw new Error('SOC_REDIS_PIPELINE_PARTIAL_FAILURE');
    }
    return json.map(r => r.result);
  },
};

module.exports = redis;
