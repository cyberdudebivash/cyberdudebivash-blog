'use strict';
/**
 * SENTINEL APEX SOC — disabled-by-default, bounded durable D1 fanout outbox.
 * Intents are staged BEFORE event persistence, so a failed enqueue can
 * recover after a crash. This does NOT backfill historical events.
 * Migration 0018 and account-wide FinOps clearance are manual GO gates.
 */
const crypto = require('node:crypto');
const MAX_WATCHERS = 10;
const MAX_RECONCILE_JOBS = 5;
const MAX_ATTEMPTS = 5;
const LEASE_MS = 90_000;
const BACKOFF_MS = [60_000,300_000,900_000,1_800_000,3_600_000];
const ERROR_CODES = new Set(['EVENT_NOT_AVAILABLE','ENQUEUE_EXCEPTION','ATTEMPTS_EXHAUSTED','DELIVERY_STATE_AMBIGUOUS']);
const INSERT_SQL = "INSERT INTO soc_notification_outbox (event_id,watchlist_id,owner_id,state,attempt_count,next_attempt_ms,created_at_ms,updated_at_ms) VALUES (?, ?, ?, 'pending', 0, ?, ?, ?) ON CONFLICT(event_id,watchlist_id,owner_id) DO NOTHING";
const DUE_SQL = "SELECT event_id,watchlist_id,owner_id FROM soc_notification_outbox WHERE state='pending' AND next_attempt_ms <= ? ORDER BY next_attempt_ms,created_at_ms LIMIT ?";
const EXPIRED_SQL = "SELECT event_id,watchlist_id,owner_id FROM soc_notification_outbox WHERE state='claimed' AND lease_expires_ms <= ? ORDER BY lease_expires_ms LIMIT ?";
const CLAIM_SQL = "UPDATE soc_notification_outbox SET state='claimed',claim_token=?,lease_expires_ms=?,attempt_count=attempt_count+1,updated_at_ms=? WHERE event_id=? AND watchlist_id=? AND owner_id=? AND ((state='pending' AND next_attempt_ms <= ?) OR (state='claimed' AND lease_expires_ms <= ?))";
const COMPLETE_SQL = "UPDATE soc_notification_outbox SET state=?,claim_token=NULL,lease_expires_ms=NULL,last_error_code='',updated_at_ms=? WHERE event_id=? AND watchlist_id=? AND owner_id=? AND state='claimed' AND claim_token=?";
const RETRY_SQL = "UPDATE soc_notification_outbox SET state=?,claim_token=NULL,lease_expires_ms=NULL,next_attempt_ms=?,last_error_code=?,updated_at_ms=? WHERE event_id=? AND watchlist_id=? AND owner_id=? AND state='claimed' AND claim_token=?";
const ATTEMPT_SQL = "SELECT attempt_count FROM soc_notification_outbox WHERE event_id=? AND watchlist_id=? AND owner_id=? AND claim_token=? LIMIT 1";
const PRUNE_SQL = "DELETE FROM soc_notification_outbox WHERE rowid IN (SELECT rowid FROM soc_notification_outbox WHERE state IN ('complete','skipped') AND updated_at_ms < ? ORDER BY updated_at_ms LIMIT ?)";

const validId = x => typeof x === 'string' && x.length > 0 && x.length <= 256;
const key = row => [row.event_id,row.watchlist_id,row.owner_id];
const isEnabled = () => process.env.CDB_SOC_OUTBOX_ENABLED === 'true';
function createOutbox({ d1, getEvent, getWatchlist, listEntities, appendToFeed, dispatch,
  now = () => Date.now(), token = () => crypto.randomBytes(16).toString('hex'),
  enabled = false } = {}) {
  function guard() {
    if (!enabled) throw new Error('SOC_OUTBOX_DISABLED');
    if (!d1 || typeof d1.query !== 'function' ||
        typeof d1.runMutationWithChanges !== 'function')
      throw new Error('SOC_OUTBOX_D1_UNAVAILABLE');
  }
  async function stageEventFanout({ event, watchers }) {
    guard();
    if (!event || !validId(event.event_id) || !Array.isArray(watchers) ||
        watchers.length > MAX_WATCHERS ||
        watchers.some(w => !w || !validId(w.ownerId) || !validId(w.watchlistId)))
      throw new RangeError('SOC_OUTBOX_INVALID_FANOUT');
    const unique = new Map();
    for (const w of watchers) unique.set(JSON.stringify([w.ownerId,w.watchlistId]),w);
    const at = now();
    let created = 0;
    for (const w of unique.values()) {
      // If an insert fails, the caller MUST NOT persist the event.
      // Previously staged rows remain idempotently retryable.
      const affected = await d1.runMutationWithChanges(INSERT_SQL,
        [event.event_id,w.watchlistId,w.ownerId,at,at,at]);
      if (affected > 0) created++;
    }
    return { staged: unique.size, created };
  }
  async function finish(row, claimToken, state) {
    const changed = await d1.runMutationWithChanges(COMPLETE_SQL,
      [state,now(),...key(row),claimToken]);
    if (changed !== 1) throw new Error('SOC_OUTBOX_STALE_CLAIM');
  }
  async function retry(row, claimToken, code, attempts) {
    const state = attempts >= MAX_ATTEMPTS ? 'blocked' : 'pending';
    const backoff = BACKOFF_MS[Math.min(Math.max(attempts-1,0),BACKOFF_MS.length-1)];
    const changed = await d1.runMutationWithChanges(RETRY_SQL,
      [state,now()+backoff,ERROR_CODES.has(code)?code:'ENQUEUE_EXCEPTION',now(),...key(row),claimToken]);
    if (changed !== 1) throw new Error('SOC_OUTBOX_STALE_CLAIM');
    return state;
  }
  // A duplicate delivery job is not proof of delivery: terminal jobs are
  // deleted, so a replay after an external send can recreate the same job.
  // Quarantine ambiguous enqueue outcomes rather than falsely completing
  // the outbox intent or automatically retrying a potential duplicate send.
  async function blockAmbiguous(row, claimToken) {
    const changed = await d1.runMutationWithChanges(RETRY_SQL,
      ['blocked',now(),'DELIVERY_STATE_AMBIGUOUS',now(),...key(row),claimToken]);
    if (changed !== 1) throw new Error('SOC_OUTBOX_STALE_CLAIM');
  }
  async function reconcile({ limit = MAX_RECONCILE_JOBS } = {}) {
    guard();
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_RECONCILE_JOBS)
      throw new RangeError('SOC_OUTBOX_LIMIT_1_TO_5');
    if (![getEvent,getWatchlist,listEntities,appendToFeed,dispatch].every(x => typeof x === 'function'))
      throw new Error('SOC_OUTBOX_DEPENDENCIES_UNAVAILABLE');
    const at = now();
    // Reserve one lease-recovery slot under sustained pending backlog.
    // Otherwise a permanently full due queue can starve crashed claims.
    // Both queries have indexed predicates and preserve the total limit.
    const expired = await d1.query(EXPIRED_SQL,[at,1]);
    const room = limit-expired.length;
    const due = room ? await d1.query(DUE_SQL,[at,room]) : [];
    const rows = [...expired,...due];
    const tally = { selected:rows.length, claimed:0, complete:0, skipped:0,
      retry:0, blocked:0, claim_contended:0, errors:0 };
    for (const row of rows) {
      if (!key(row).every(validId)) throw new Error('SOC_OUTBOX_INVALID_ROW');
      const claimToken = token();
      const claimed = await d1.runMutationWithChanges(CLAIM_SQL,
        [claimToken,now()+LEASE_MS,now(),...key(row),now(),now()]);
      if (claimed !== 1) { tally.claim_contended++; continue; }
      tally.claimed++;
      const saved = await d1.query(ATTEMPT_SQL,[...key(row),claimToken]);
      if (saved.length !== 1) throw new Error('SOC_OUTBOX_STALE_CLAIM');
      const attempts = Number(saved[0].attempt_count);
      if (attempts > MAX_ATTEMPTS) {
        const state = await retry(row,claimToken,'ATTEMPTS_EXHAUSTED',attempts);
        tally[state === 'pending' ? 'retry' : 'blocked']++; tally.errors++; continue;
      }
      try {
        const event = await getEvent(row.event_id);
        if (!event) {
          const state = await retry(row,claimToken,'EVENT_NOT_AVAILABLE',attempts);
          tally[state === 'pending' ? 'retry' : 'blocked']++; tally.errors++; continue;
        }
        const owned = await getWatchlist(row.watchlist_id,row.owner_id);
        if (!owned || !owned.watchlist || owned.watchlist.status !== 'active') {
          await finish(row,claimToken,'skipped'); tally.skipped++; continue;
        }
        const entities = await listEntities(row.watchlist_id,row.owner_id);
        if (!entities || !Array.isArray(entities.entities) ||
            !entities.entities.some(e => e.type === event.entity_type && e.id === event.entity_id)) {
          await finish(row,claimToken,'skipped'); tally.skipped++; continue;
        }
        // Feed insertion itself must be replayed: event persistence may
        // have succeeded before an interrupted per-owner feed write.
        // Existing owner_feed unique key makes repeated inserts idempotent.
        await appendToFeed(row.owner_id,event.event_id,Date.parse(event.observed_at) || now());
        // This enqueues only; external email/webhook receipts are separate.
        // A duplicate delivery_id can mean a pending job OR a job that was
        // already sent and deleted. Without a durable per-channel terminal
        // ledger, a second enqueue is unsafe and must not be called success.
        const result = await dispatch({ ownerId:row.owner_id, watchlistId:row.watchlist_id, event });
        if (result && result.enqueued === true) {
          await finish(row,claimToken,'complete');
          tally.complete++;
        } else if (result && result.enqueued === false &&
                   (!Array.isArray(result.channels) || result.channels.length === 0)) {
          // No eligible channels: no customer send is expected.
          await finish(row,claimToken,'skipped');
          tally.skipped++;
        } else {
          // Includes enqueued=false with eligible channels, and malformed
          // provider responses. Do not retry automatically or assert receipt.
          await blockAmbiguous(row,claimToken);
          tally.blocked++;
          tally.errors++;
        }
      } catch (_) {
        // Crash after creating a delivery job and before COMPLETE is safe:
        // recovery uses the same per-(owner,event,channel) delivery ID.
        const state = await retry(row,claimToken,'ENQUEUE_EXCEPTION',attempts);
        tally[state === 'pending' ? 'retry' : 'blocked']++; tally.errors++;
      }
    }
    return tally;
  }
  async function pruneCompleted({ days = 30, limit = MAX_RECONCILE_JOBS } = {}) {
    guard();
    if (!Number.isSafeInteger(days) || days < 30 || days > 365 ||
        !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_RECONCILE_JOBS)
      throw new RangeError('SOC_OUTBOX_RETENTION_RANGE');
    // Never delete pending, claimed or blocked incident evidence automatically.
    return d1.runMutationWithChanges(PRUNE_SQL,[now()-days*86400000,limit]);
  }
  return { stageEventFanout, reconcile, pruneCompleted };
}
// Resolve lazily; change-engine and notification-dispatch import each other.
function productionOutbox() {
  const store = require('./watchlist-store');
  const notifier = require('./notification-dispatch');
  return createOutbox({
    enabled:isEnabled(), d1:require('./d1'),
    getEvent:eventId => require('./change-engine').getEventById(eventId),
    getWatchlist:(watchlistId,ownerId) => store.getWatchlist(watchlistId,ownerId),
    listEntities:(watchlistId,ownerId) => store.listEntities(watchlistId,ownerId),
    appendToFeed:(ownerId,eventId,atMs) => store.appendToOwnerFeed(ownerId,eventId,atMs),
    dispatch:args => notifier.dispatchNewEvent(args),
  });
}
module.exports = { isEnabled, createOutbox, productionOutbox, MAX_WATCHERS,
  MAX_RECONCILE_JOBS, MAX_ATTEMPTS, INSERT_SQL, DUE_SQL, EXPIRED_SQL, CLAIM_SQL,
  COMPLETE_SQL, RETRY_SQL, ATTEMPT_SQL, PRUNE_SQL };
