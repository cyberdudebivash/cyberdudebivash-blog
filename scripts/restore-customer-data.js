#!/usr/bin/env node
/**
 * SENTINEL APEX — Customer Data Restore (GEORP v1 / Phase 3)
 *
 * Companion to backup-customer-data.js. Decrypts a snapshot and replays it
 * into Redis. Defaults to a dry run (prints what WOULD be restored) --
 * requires --confirm for isolated rehearsals or --confirm-production for
 * an actual production recovery; replaying customer data requires a
 * separately authorized break-glass action during an actual incident, never
 * scheduled or triggered automatically the way the backup itself is.
 *
 * Usage:
 *   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file>            # dry run
 *   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file> --confirm   # isolated rehearsal only
 *   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file> --confirm-production   # approved production break-glass only
 *
 * See RUNBOOKS.md "Redis Outage / Data Loss" for the full procedure this
 * script is one step of.
 */
'use strict';

const fs = require('fs');
const { decryptSnapshot, normalizeHashRecord, normalizeAuditLog, SCHEMA_VERSION, PENDING_TIER_PREFIX, MAX_PENDING_TIER_TTL_SECONDS } = require('./backup-customer-data');

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
  // Historical v1 encrypted files can lack this additive metadata.
  // Without the original TTL, restoring a pending payment as a plain SET
  // would resurrect an expired, time-limited entitlement indefinitely.
  const pendingTierExpiry = snapshot.pendingTierExpiry === undefined
    ? {} : snapshot.pendingTierExpiry;
  if (!isRecord(pendingTierExpiry)) {
    throw new Error('SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED');
  }
  for (const key of Object.keys(pendingTierExpiry)) {
    if (!key.startsWith(PENDING_TIER_PREFIX) ||
        !Object.prototype.hasOwnProperty.call(snapshot.strings,key) ||
        typeof snapshot.strings[key] !== 'string') {
      throw new Error('SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED');
    }
  }
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
    if (value !== null && value !== undefined) {
      if (key.startsWith(PENDING_TIER_PREFIX)) {
        const expiresAt = pendingTierExpiry[key];
        const millis = typeof expiresAt === 'string' &&
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(expiresAt)
          ? Date.parse(expiresAt) : NaN;
        const snapshotTime = Date.parse(snapshot.createdAt);
        if (!Number.isFinite(millis) || millis >
            snapshotTime + MAX_PENDING_TIER_TTL_SECONDS * 1000) {
          throw new Error('SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED');
        }
        strings.push([key, value, millis]);
      } else {
        strings.push([key, value]);
      }
    }
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
  let expiredPendingTiers = 0;
  for (const [key, value, expiresAtMillis] of prepared.strings) {
    if (key.startsWith(PENDING_TIER_PREFIX)) {
      // Never resurrect or extend a paid pre-registration TTL.
      // Favor early expiration over the risk of accidentally rearming access.
      const secondsLeft = Math.floor((expiresAtMillis - Date.now()) / 1000);
      if (secondsLeft <= 0) {
        expiredPendingTiers++;
        continue;
      }
      await redis.setex(key, secondsLeft, value);
    } else {
      await redis.set(key, value);
    }
    stringsWritten++;
  }
  for (const [member, score] of prepared.auditLog) {
    await redis.zadd('audit:payment:log', Number(score), member);
    auditEntriesWritten++;
  }

  return expiredPendingTiers
    ? {hashesWritten, stringsWritten, auditEntriesWritten, expiredPendingTiers}
    : {hashesWritten, stringsWritten, auditEntriesWritten};
}

/**
 * P0 CLI write-safety: a --confirm restore must target an explicitly pinned
 * Redis origin, distinct from the owner-declared live origin in rehearsal mode.
 * These environment assertions reduce accidental targeting; they are not a
 * substitute for independently verifying the target or incident approval.
 * Never print URLs, provider tokens, or endpoint fingerprints in diagnostics.
 */
function verifyRestoreTarget(env,flag='--confirm') {
  const invalid = () => { throw new Error('SOC_RESTORE_TARGET_NOT_AUTHORIZED'); };
  const sha = value => typeof value === 'string' &&
    /^[a-f0-9]{64}$/i.test(value) ? value.toLowerCase() : null;
  const hash = value => require('node:crypto')
    .createHash('sha256').update(value).digest('hex');
  let parsed;
  try { parsed = new URL(env.UPSTASH_REDIS_REST_URL || ''); }
  catch (_) { return invalid(); }
  const raw = env.UPSTASH_REDIS_REST_URL;
  // Require an exact, credential-free Upstash HTTPS origin. An endpoint with
  // a path, userinfo, query, fragment or unexpected port is not auditable.
  if (typeof raw !== 'string' || raw !== parsed.origin ||
      parsed.protocol !== 'https:' || parsed.port ||
      parsed.username || parsed.password || parsed.search || parsed.hash ||
      !/^[a-z0-9-]+\.upstash\.io$/i.test(parsed.hostname)) invalid();
  const target = hash(parsed.origin);
  const expected = sha(env.SOC_RESTORE_TARGET_URL_SHA256);
  const live = sha(env.SOC_RESTORE_LIVE_URL_SHA256);
  const approval = env.SOC_RESTORE_APPROVAL_REF;
  if (!expected || !live || expected !== target ||
      typeof approval !== 'string' ||
      !/^CDB-(?:INC|CHG)-20\d{2}-\d{3,8}$/.test(approval)) invalid();
  if (env.SOC_RESTORE_MODE === 'isolated-rehearsal') {
    if (target === live || flag !== '--confirm') invalid();
  } else if (env.SOC_RESTORE_MODE === 'production-break-glass') {
    if (flag !== '--confirm-production' || target !== live ||
        env.SOC_RESTORE_BREAK_GLASS_CONFIRM !==
        'I_AUTHORIZE_PRODUCTION_CUSTOMER_DATA_RESTORE') invalid();
  } else {
    invalid();
  }
  return {mode:env.SOC_RESTORE_MODE, authorized:true};
}

async function main() {
  const [, , snapshotPath, flag] = process.argv;
  if (!snapshotPath) {
    console.error('Usage: node restore-customer-data.js <snapshot-file> [--confirm|--confirm-production]');
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

  if (flag !== '--confirm' && flag !== '--confirm-production') {
    console.log('[RESTORE] Dry run only — no data written. Re-run with the authorized isolated --confirm or break-glass --confirm-production mode.');
    return;
  }

  // Authorization is checked BEFORE loading any live Redis adapter or write.
  // This does not replace private owner approval or a separate isolated rehearsal.
  verifyRestoreTarget(process.env,flag);
  const redis = require('../api/_lib/redis');
  const { hashesWritten, stringsWritten, auditEntriesWritten } = await applySnapshot(redis, snapshot);
  console.log(`[RESTORE] Wrote ${hashesWritten} hash(es), ${stringsWritten} string key(s), ${auditEntriesWritten} payment audit entry/entries into Redis.`);
  console.log('[RESTORE] Pending-tier TTL: captured expiry enforced, expired records never resurrected.');
}

if (require.main === module) {
  main().catch(err => {
    console.error('[RESTORE] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { applySnapshot, validateSnapshot, verifyRestoreTarget };
