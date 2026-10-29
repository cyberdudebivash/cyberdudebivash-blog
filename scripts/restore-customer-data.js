#!/usr/bin/env node
/**
 * SENTINEL APEX — Customer Data Restore (GEORP v1 / Phase 3)
 *
 * Companion to backup-customer-data.js. Decrypts a snapshot and replays it
 * into Redis. Defaults to a dry run (prints what WOULD be restored) --
 * requires an explicit --confirm flag to actually write, since replaying
 * data into production Redis should be a deliberate human decision (a
 * "break glass" action performed during an actual incident), never
 * scheduled or triggered automatically the way the backup itself is.
 *
 * Usage:
 *   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file>            # dry run
 *   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file> --confirm   # writes
 *
 * See RUNBOOKS.md "Redis Outage / Data Loss" for the full procedure this
 * script is one step of.
 */
'use strict';

const fs = require('fs');
const { decryptSnapshot, normalizeHashRecord, normalizeAuditLog, SCHEMA_VERSION } = require('./backup-customer-data');

/**
 * Validate the entire decrypted artifact BEFORE any Redis write. A historical
 * v1 snapshot can contain native Upstash HGETALL flattened arrays; normalize
 * these safely into hash objects, not numeric-field HMSET corruption. Never
 * restore keys outside the intended customer lookup namespaces.
 */
function validateSnapshot(snapshot) {
  const isRecord = x => x !== null && typeof x === 'object' &&
    !Array.isArray(x) &&
    (Object.getPrototypeOf(x) === Object.prototype ||
     Object.getPrototypeOf(x) === null);
  if (!isRecord(snapshot) || snapshot.schemaVersion !== SCHEMA_VERSION ||
      typeof snapshot.createdAt !== 'string' ||
      !Number.isFinite(Date.parse(snapshot.createdAt)) ||
      !isRecord(snapshot.hashes) || !isRecord(snapshot.strings) ||
      !Array.isArray(snapshot.auditLog)) {
    throw new Error('SOC_RESTORE_INVALID_SNAPSHOT_SCHEMA');
  }
  const hashes = [];
  const strings = [];
  for (const [key, fields] of Object.entries(snapshot.hashes)) {
    if (!key.startsWith('user:key:') || key.length <= 'user:key:'.length) {
      throw new Error('SOC_RESTORE_KEY_SCOPE_VIOLATION');
    }
    hashes.push([key, normalizeHashRecord(fields)]);
  }
  for (const [key, value] of Object.entries(snapshot.strings)) {
    const isAllowed = ['user:email:', 'user:id:', 'user:pending:tier:']
      .some(prefix => key.startsWith(prefix) && key.length > prefix.length);
    if (!isAllowed) throw new Error('SOC_RESTORE_KEY_SCOPE_VIOLATION');
    if (value !== null && value !== undefined && typeof value !== 'string') {
      throw new Error('SOC_RESTORE_INVALID_STRING_VALUE');
    }
    if (value !== null && value !== undefined) strings.push([key, value]);
  }
  const auditLog = normalizeAuditLog(snapshot.auditLog);
  return {hashes, strings, auditLog};
}

/**
 * Restore only after a full artifact validation pass. Writes remain
 * intentionally explicit and NOT transactional across keys: an operator must
 * rehearse recovery against an isolated Redis instance before --confirm.
 * Payment audit-log scores and members are preserved using idempotent ZADD.
 */
async function applySnapshot(redis, snapshot) {
  const prepared = validateSnapshot(snapshot);
  let hashesWritten = 0;
  let stringsWritten = 0;
  let auditEntriesWritten = 0;

  for (const [key, fields] of prepared.hashes) {
    await redis.hmset(key, fields);
    hashesWritten++;
  }
  for (const [key, value] of prepared.strings) {
    await redis.set(key, value);
    stringsWritten++;
  }
  for (const [member, score] of prepared.auditLog) {
    await redis.zadd('audit:payment:log', Number(score), member);
    auditEntriesWritten++;
  }

  return {hashesWritten, stringsWritten, auditEntriesWritten};
}

async function main() {
  const [, , snapshotPath, flag] = process.argv;
  if (!snapshotPath) {
    console.error('Usage: node restore-customer-data.js <snapshot-file> [--confirm]');
    process.exit(1);
    return;
  }
  const encryptionKey = process.env.BACKUP_ENCRYPTION_KEY;
  if (!encryptionKey) {
    console.error('[RESTORE] BACKUP_ENCRYPTION_KEY is not set — cannot decrypt.');
    process.exit(1);
    return;
  }

  const encrypted = fs.readFileSync(snapshotPath, 'utf8');
  const snapshot = decryptSnapshot(encrypted, encryptionKey);
  // Schema, key-scope and legacy hash/audit validation are required even in
  // dry-run mode: an invalid artifact must never be called restorable.
  const prepared = validateSnapshot(snapshot);

  const userCount = prepared.hashes.length;
  const stringCount = prepared.strings.length;
  console.log(`[RESTORE] Snapshot from ${snapshot.createdAt}: ${userCount} user record(s), ${stringCount} lookup key(s), ${prepared.auditLog.length} audit entries.`);

  if (flag !== '--confirm') {
    console.log('[RESTORE] Dry run only — no data written. Re-run with --confirm to actually restore into Redis.');
    return;
  }

  const redis = require('../api/_lib/redis');
  const { hashesWritten, stringsWritten, auditEntriesWritten } = await applySnapshot(redis, snapshot);
  console.log(`[RESTORE] Wrote ${hashesWritten} hash(es), ${stringsWritten} string key(s), ${auditEntriesWritten} payment audit entry/entries into Redis.`);
}

if (require.main === module) {
  main().catch(err => {
    console.error('[RESTORE] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { applySnapshot, validateSnapshot };
