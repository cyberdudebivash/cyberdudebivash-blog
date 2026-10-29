#!/usr/bin/env node
/**
 * SENTINEL APEX — Customer Data Backup (GEORP v1 / Phase 3)
 *
 * Snapshots the Redis-held customer data that has no other durable copy.
 * Unlike posts/reports (git-versioned, durable by construction), registered
 * API keys, tier assignments, and the payment audit log exist ONLY in
 * Redis (Upstash), with no export path before this script existed
 * (platform/open-issues.md, GPEP v1 finding). Encrypts before writing
 * anywhere the snapshot might land (a local file, a CI artifact), since it
 * contains customer emails and API key hashes.
 *
 * Usage:
 *   BACKUP_ENCRYPTION_KEY=<64-hex-char key> node scripts/backup-customer-data.js [outputPath]
 *
 * Requires UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN (existing env
 * vars, already used throughout api/_lib/redis.js -- no new external
 * resource) and BACKUP_ENCRYPTION_KEY (NEW -- must be provisioned by a
 * human with repo-secrets access before this can run in production; see
 * RUNBOOKS.md "Backup & Restore").
 *
 * Deliberately does NOT upload anywhere beyond the local filesystem --
 * where the encrypted output should durably live long-term (S3/GCS/other)
 * is an infrastructure decision requiring explicit approval, not made
 * here. The scheduled workflow (.github/workflows/backup-customer-data.yml)
 * uses only GitHub's own existing Actions artifact storage as a first
 * safety net, not a long-term archival solution -- see that workflow's own
 * comments and RUNBOOKS.md for the gap this leaves.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// The Redis key patterns that hold data with no other durable copy.
// Deliberately excludes payment:ip_rate:* (self-expiring fraud counters)
// and analytics:registrations:* (regenerable aggregate stats) -- backing
// those up would bloat every snapshot with data that doesn't need
// recovery.
const KEY_PATTERNS = ['user:key:*', 'user:email:*', 'user:id:*', 'user:pending:tier:*'];
const SCHEMA_VERSION = 1;

/** Build a structured snapshot from already-fetched key/value pairs. Pure
 *  -- no I/O, so this is directly unit-testable without live Redis. */
function buildSnapshot({ hashes, strings, auditLog }) {
  return {
    schemaVersion: SCHEMA_VERSION,
    createdAt: new Date().toISOString(),
    hashes,   // { [key]: { field: value, ... }, ... }  (user:key:*)
    strings,  // { [key]: value, ... }                  (user:email:*, user:id:*, user:pending:tier:*)
    auditLog, // [ [member, score], ... ]                (audit:payment:log)
  };
}

function _requireValidKey(keyHex) {
  if (!/^[0-9a-f]{64}$/i.test(keyHex || '')) {
    throw new Error('BACKUP_ENCRYPTION_KEY must be a 64-character hex string (32 bytes / AES-256)');
  }
}

/** AES-256-GCM encrypt. Returns "iv:authTag:ciphertext", all hex -- a
 *  single flat string, easy to store as a plain-text file. */
function encryptSnapshot(snapshot, keyHex) {
  _requireValidKey(keyHex);
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(12); // 96-bit IV, standard for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(snapshot), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv.toString('hex'), authTag.toString('hex'), ciphertext.toString('hex')].join(':');
}

/** Inverse of encryptSnapshot(). Throws if the auth tag doesn't verify --
 *  tampered or corrupted input is rejected, not silently accepted. */
function decryptSnapshot(encrypted, keyHex) {
  _requireValidKey(keyHex);
  const parts = String(encrypted).split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted snapshot (expected iv:authTag:ciphertext)');
  }
  const [ivHex, tagHex, dataHex] = parts;
  const key = Buffer.from(keyHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

/**
 * P0: Upstash REST HGETALL returns alternating [field,value,...], NOT an
 * object. Earlier backups persisted these arrays and restore used hmset with
 * numeric array indexes, risking silent corruption of customer key records.
 * Accept both original legacy flat arrays and object-backed test fixtures,
 * but never invent missing fields or values. This helper has no I/O.
 */
function normalizeHashRecord(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('SOC_BACKUP_INVALID_HASH_RESPONSE');
  }
  let pairs;
  if (Array.isArray(raw)) {
    if (!raw.length || raw.length % 2 !== 0) {
      throw new Error('SOC_BACKUP_INVALID_HASH_RESPONSE');
    }
    pairs = [];
    for (let i = 0; i < raw.length; i += 2) {
      pairs.push([raw[i], raw[i + 1]]);
    }
  } else {
    pairs = Object.entries(raw);
  }
  if (!pairs.length) throw new Error('SOC_BACKUP_INVALID_HASH_RESPONSE');
  const seen = new Set();
  const normalized = [];
  for (const [field, value] of pairs) {
    if (typeof field !== 'string' || !field || seen.has(field) ||
        typeof value !== 'string') {
      throw new Error('SOC_BACKUP_INVALID_HASH_RESPONSE');
    }
    seen.add(field);
    normalized.push([field, value]);
  }
  return Object.fromEntries(normalized);
}

/**
 * Upstash ZREVRANGE WITHSCORES returns a flat [member,score,...] array;
 * existing historical encrypted snapshots sometimes contain already-paired
 * entries from test clients. Preserve both shapes without data loss.
 */
function normalizeAuditLog(raw) {
  if (!Array.isArray(raw)) throw new Error('SOC_BACKUP_INVALID_AUDIT_RESPONSE');
  if (!raw.length) return [];
  let entries;
  if (raw.every(Array.isArray)) {
    entries = raw;
  } else if (raw.some(Array.isArray) || raw.length % 2 !== 0) {
    throw new Error('SOC_BACKUP_INVALID_AUDIT_RESPONSE');
  } else {
    entries = [];
    for (let i = 0; i < raw.length; i += 2) entries.push([raw[i], raw[i + 1]]);
  }
  return entries.map(pair => {
    if (!Array.isArray(pair) || pair.length !== 2 ||
        typeof pair[0] !== 'string' || !pair[0] ||
        (typeof pair[1] !== 'string' && typeof pair[1] !== 'number') ||
        !Number.isFinite(Number(pair[1]))) {
      throw new Error('SOC_BACKUP_INVALID_AUDIT_RESPONSE');
    }
    return [pair[0], String(pair[1])];
  });
}

/** Fetch all data for the configured key patterns from a live redis
 *  client. Isolated from encryption/file-writing so it's the only piece
 *  that actually needs a connection -- takes `redis` as a parameter so
 *  tests can pass a fake client instead of talking to real Upstash. */
async function fetchAll(redis) {
  const hashes = {};
  const strings = {};

  for (const pattern of KEY_PATTERNS) {
    const keys = (await redis.keys(pattern)) || [];
    for (const key of keys) {
      if (key.startsWith('user:key:')) {
        hashes[key] = normalizeHashRecord(await redis.hgetall(key));
      } else {
        strings[key] = await redis.get(key);
      }
    }
  }

  // The payment audit log is durable customer evidence, not an optional
  // cosmetic counter. Fail the entire backup on an unreadable/malformed log
  // rather than emit a successful but silently incomplete encrypted snapshot.
  const auditLog = normalizeAuditLog(
    await redis.zrevrange('audit:payment:log', 0, -1, true)
  );

  return { hashes, strings, auditLog };
}

/**
 * P0 backup artifact safety: do not publish a final backup path until the
 * encrypted contents can be read and successfully authenticated/decrypted.
 * A same-directory hard link installs an already-verified 0600 temp file
 * atomically WITHOUT overwriting an existing artifact. Never fall back to
 * unencrypted output, a partial final artifact or a different storage tier.
 */
function writeVerifiedEncryptedSnapshot(snapshot, keyHex, outputPath) {
  _requireValidKey(keyHex);
  if (typeof outputPath !== 'string' || !outputPath.trim()) {
    throw new Error('SOC_BACKUP_INVALID_OUTPUT_PATH');
  }
  const encrypted = encryptSnapshot(snapshot, keyHex);
  const parent = path.dirname(outputPath);
  fs.mkdirSync(parent, { recursive: true });
  const tempPath = path.join(parent,
    `.${path.basename(outputPath)}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tempPath, 'wx', 0o600);
    fs.writeFileSync(fd, encrypted, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    // Read exactly what was written, not the in-memory encryption output.
    // GCM verification fails closed if the file is incomplete or corrupted.
    const readBack = decryptSnapshot(fs.readFileSync(tempPath, 'utf8'), keyHex);
    if (JSON.stringify(readBack) !== JSON.stringify(snapshot)) {
      throw new Error('SOC_BACKUP_ENCRYPTED_ARTIFACT_MISMATCH');
    }
    // linkSync does NOT replace an existing path (including a symlink).
    // Temp and target share a directory, so this avoids a partial final file.
    fs.linkSync(tempPath, outputPath);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(tempPath); } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }
  return outputPath;
}

async function main() {
  const outputPath = process.argv[2] ||
    path.join(__dirname, '..', 'backups', `customer-data-${new Date().toISOString().replace(/[:.]/g, '-')}.enc`);
  const encryptionKey = process.env.BACKUP_ENCRYPTION_KEY;
  if (!encryptionKey) {
    console.error('[BACKUP] BACKUP_ENCRYPTION_KEY is not set. Refusing to write an unencrypted backup of customer data.');
    console.error('[BACKUP] See RUNBOOKS.md "Backup & Restore" for how to provision this secret.');
    process.exit(1);
    return;
  }

  // P0: validate the key BEFORE opening Redis or consuming any customer-read
  // budget. A present-but-invalid key is not a valid backup prerequisite.
  _requireValidKey(encryptionKey);
  const redis = require('../api/_lib/redis');
  const data = await fetchAll(redis);
  const snapshot = buildSnapshot(data);
  writeVerifiedEncryptedSnapshot(snapshot, encryptionKey, outputPath);

  console.log(`[BACKUP] Snapshot written: ${outputPath}`);
  console.log(`[BACKUP] ${Object.keys(snapshot.hashes).length} user record(s), ${Object.keys(snapshot.strings).length} lookup key(s), ${snapshot.auditLog.length} audit entries.`);
}

// Guards the live-Redis side effect behind require.main so this file stays
// safely requirable for unit testing encryptSnapshot/decryptSnapshot/
// buildSnapshot/fetchAll (the restore script also requires this module for
// decryptSnapshot) without triggering a real backup run.
if (require.main === module) {
  main().catch(err => {
    console.error('[BACKUP] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { buildSnapshot, encryptSnapshot, decryptSnapshot, fetchAll, normalizeHashRecord, normalizeAuditLog, writeVerifiedEncryptedSnapshot, KEY_PATTERNS, SCHEMA_VERSION };
