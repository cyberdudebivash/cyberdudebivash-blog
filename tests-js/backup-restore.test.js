'use strict';
// Tests for scripts/backup-customer-data.js and restore-customer-data.js --
// GEORP v1 Phase 3 (Business Continuity). Closes the gap GPEP v1 found:
// customer data (registered API keys, tier assignments, payment audit log)
// lived only in Redis with no export/backup path at all.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const {
  buildSnapshot, encryptSnapshot, decryptSnapshot, fetchAll, KEY_PATTERNS,
} = require(path.join(__dirname, '..', 'scripts', 'backup-customer-data.js'));
const { applySnapshot } = require(path.join(__dirname, '..', 'scripts', 'restore-customer-data.js'));

const VALID_KEY = 'a'.repeat(64); // 32 bytes hex -- a real key would be crypto.randomBytes(32).toString('hex')

/* ─── Encryption round-trip ────────────────────────────────────────────── */

test('encryptSnapshot -> decryptSnapshot round-trips exactly', () => {
  const snapshot = buildSnapshot({
    hashes: { 'user:key:abc123': { email: 'a@example.com', tier: 'pro' } },
    strings: { 'user:email:a_example.com': 'user-1' },
    auditLog: [['TIER_UPGRADED', 1234567890]],
  });

  const encrypted = encryptSnapshot(snapshot, VALID_KEY);
  const decrypted = decryptSnapshot(encrypted, VALID_KEY);

  assert.deepStrictEqual(decrypted, snapshot);
});

test('encryptSnapshot rejects a malformed key', () => {
  const snapshot = buildSnapshot({ hashes: {}, strings: {}, auditLog: [] });
  assert.throws(() => encryptSnapshot(snapshot, 'too-short'), /64-character hex/);
  assert.throws(() => encryptSnapshot(snapshot, null), /64-character hex/);
});

test('decryptSnapshot rejects tampered ciphertext (auth tag mismatch)', () => {
  const snapshot = buildSnapshot({ hashes: {}, strings: { k: 'v' }, auditLog: [] });
  const encrypted = encryptSnapshot(snapshot, VALID_KEY);
  const [iv, tag, data] = encrypted.split(':');
  // Flip one hex character in the ciphertext -- must fail closed, not
  // silently return corrupted-but-parsed data.
  const tampered = [iv, tag, (data[0] === '0' ? '1' : '0') + data.slice(1)].join(':');
  assert.throws(() => decryptSnapshot(tampered, VALID_KEY));
});

test('decryptSnapshot rejects the wrong key', () => {
  const snapshot = buildSnapshot({ hashes: {}, strings: { k: 'v' }, auditLog: [] });
  const encrypted = encryptSnapshot(snapshot, VALID_KEY);
  const wrongKey = 'b'.repeat(64);
  assert.throws(() => decryptSnapshot(encrypted, wrongKey));
});

test('decryptSnapshot rejects a malformed encrypted string', () => {
  assert.throws(() => decryptSnapshot('not-the-right-shape', VALID_KEY), /Malformed/);
});

/* ─── fetchAll — dispatches hash vs. string keys correctly ─────────────── */

function fakeRedis(data) {
  return {
    keys: async (pattern) => {
      const prefix = pattern.replace(/\*$/, '');
      return Object.keys(data).filter(k => k.startsWith(prefix));
    },
    hgetall: async (key) => data[key] || null,
    get: async (key) => data[key] ?? null,
    zrevrange: async () => [['TIER_UPGRADED', '1700000000']],
  };
}

test('fetchAll routes user:key:* through hgetall and everything else through get', async () => {
  const redis = fakeRedis({
    'user:key:hash1': { email: 'a@example.com', tier: 'starter' },
    'user:email:a_example.com': 'user-1',
    'user:id:user-1': 'hash1',
    'user:pending:tier:b_example.com': '{"tier":"pro"}',
  });

  const result = await fetchAll(redis);

  assert.deepStrictEqual(result.hashes['user:key:hash1'], { email: 'a@example.com', tier: 'starter' });
  assert.strictEqual(result.strings['user:email:a_example.com'], 'user-1');
  assert.strictEqual(result.strings['user:id:user-1'], 'hash1');
  assert.strictEqual(result.strings['user:pending:tier:b_example.com'], '{"tier":"pro"}');
  assert.deepStrictEqual(result.auditLog, [['TIER_UPGRADED', '1700000000']]);
});

test('P0 backup rejects failing audit-log reads rather than claiming an incomplete snapshot', async () => {
  const redis = fakeRedis({ 'user:key:hash1': { email: 'a@example.com' } });
  redis.zrevrange = async () => { throw new Error('redis down'); };
  await assert.rejects(fetchAll(redis), /redis down/);
});

test('KEY_PATTERNS excludes ephemeral/regenerable keys by design', () => {
  assert.ok(!KEY_PATTERNS.some(p => p.includes('payment:ip_rate')));
  assert.ok(!KEY_PATTERNS.some(p => p.includes('analytics:')));
});

/* ─── applySnapshot — restore replay ───────────────────────────────────── */

function recordingRedis() {
  const written = { hashes: {}, strings: {}, auditLog: [] };
  return {
    written,
    hmset: async (key, fields) => { written.hashes[key] = fields; },
    set: async (key, value) => { written.strings[key] = value; },
    zadd: async (key, score, member) => {
      assert.strictEqual(key, 'audit:payment:log');
      written.auditLog.push([member, score]);
    },
  };
}

test('applySnapshot replays hashes and strings into redis', async () => {
  const redis = recordingRedis();
  const snapshot = buildSnapshot({
    hashes: { 'user:key:hash1': { email: 'a@example.com', tier: 'pro' } },
    strings: { 'user:email:a_example.com': 'user-1' },
    auditLog: [],
  });

  const { hashesWritten, stringsWritten } = await applySnapshot(redis, snapshot);

  assert.strictEqual(hashesWritten, 1);
  assert.strictEqual(stringsWritten, 1);
  assert.deepStrictEqual(redis.written.hashes['user:key:hash1'], { email: 'a@example.com', tier: 'pro' });
  assert.strictEqual(redis.written.strings['user:email:a_example.com'], 'user-1');
});

test('applySnapshot skips null/undefined string values instead of writing literal "null"', async () => {
  const redis = recordingRedis();
  const snapshot = buildSnapshot({
    hashes: {},
    strings: { 'user:email:missing': null },
    auditLog: [],
  });

  const { stringsWritten } = await applySnapshot(redis, snapshot);

  assert.strictEqual(stringsWritten, 0);
  assert.strictEqual(redis.written.strings['user:email:missing'], undefined);
});

test('full round trip: fetch -> build -> encrypt -> decrypt -> apply', async () => {
  const sourceRedis = fakeRedis({
    'user:key:hash1': { email: 'a@example.com', tier: 'enterprise' },
    'user:email:a_example.com': 'user-1',
  });

  const fetched = await fetchAll(sourceRedis);
  const snapshot = buildSnapshot(fetched);
  const encrypted = encryptSnapshot(snapshot, VALID_KEY);

  // Simulate a real restore: decrypt on the other side, apply to a
  // (different, e.g. freshly-provisioned) redis instance.
  const decrypted = decryptSnapshot(encrypted, VALID_KEY);
  const targetRedis = recordingRedis();
  const { hashesWritten } = await applySnapshot(targetRedis, decrypted);

  assert.strictEqual(hashesWritten, 1);
  assert.deepStrictEqual(targetRedis.written.hashes['user:key:hash1'], { email: 'a@example.com', tier: 'enterprise' });
});
