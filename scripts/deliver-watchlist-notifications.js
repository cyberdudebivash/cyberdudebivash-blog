#!/usr/bin/env node
/**
 * SENTINEL APEX — Watchlist Notification Delivery
 *
 * Thin CLI wrapper around api/_lib/notification-dispatch.js's
 * processDueDeliveries(). Delivery state moved off Redis onto Cloudflare
 * D1 as of the Cloudflare-Only Alert Runtime tranche (see
 * api/_lib/d1.js and api/_lib/notification-store.js's module headers) --
 * this script now talks to D1 via d1.js's REST API transport (it runs
 * under plain Node, never inside a Cloudflare Worker, so there is no
 * native env.DB binding available to it; see d1.js's own two-transport
 * design). Runs on a real autonomous schedule:
 * .github/workflows/alert-delivery.yml's native GitHub Actions
 * `schedule:` trigger (every 30 minutes -- see that workflow's header for
 * why that cadence) remains the PROVEN scheduler this sandbox can attest
 * to; workers/entry.js's `scheduled` export now also exists as the
 * Cloudflare-native path once an operator with real credentials runs
 * `wrangler deploy` (see that file's header) -- both paths read/write the
 * SAME D1 database, so there is one source of delivery truth regardless
 * of which trigger actually fires. Still safe to run manually or via any
 * other external scheduler too -- processDueDeliveries()'s atomic D1
 * claim/lease makes concurrent/repeated invocations safe by construction,
 * not just by convention. Run AFTER evaluate-watchlist-changes.js in the
 * same cycle (the scheduled workflow already does this in order) — it
 * only ever processes already-enqueued pending deliveries, it does not
 * detect changes itself. evaluate-watchlist-changes.js is a SEPARATE
 * script and still requires UPSTASH_REDIS_REST_URL/TOKEN — change
 * detection/watchlists are explicitly out of scope for this D1 migration
 * (see the Cloudflare Runtime Dependency Inventory doc §0).
 *
 * Usage:
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_D1_DATABASE_ID=... CLOUDFLARE_API_TOKEN=... \
 *   RESEND_API_KEY=... \
 *     node scripts/deliver-watchlist-notifications.js [--limit=100]\n * Strict CLI range 1..100. Invalid/duplicated inputs fail closed.
 *
 * RESEND_API_KEY is optional here in the sense that the script still runs
 * without it — email deliveries will simply fail with EMAIL_NOT_CONFIGURED
 * (logged and retried/dead-lettered like any other failure) rather than
 * the script refusing to start; webhook deliveries need no email
 * configuration at all.
 */
'use strict';

// Operator workload limit: never silently clamp oversized CLI batches.
// Preserve the existing 100-job no-argument default.
const MAX_GITHUB_DELIVERY_LIMIT = 100;
function parseLimitArg(argv) {
  const matches = argv.filter(a => a === '--limit' || a.startsWith('--limit='));
  if (matches.length === 0) return undefined;
  if (matches.length !== 1 || !/^--limit=[1-9][0-9]*$/.test(matches[0])) {
    throw new RangeError('Invalid --limit; expected a single integer from 1 to 100');
  }
  const value = Number(matches[0].slice('--limit='.length));
  if (!Number.isSafeInteger(value) || value > MAX_GITHUB_DELIVERY_LIMIT) {
    throw new RangeError('Invalid --limit; expected a single integer from 1 to 100');
  }
  return value;
}

async function main() {
  const { isConfigured } = require('../api/_lib/d1');
  if (!isConfigured()) {
    console.error('[NOTIFY-DELIVER] CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_D1_DATABASE_ID / CLOUDFLARE_API_TOKEN must be set.');
    process.exit(1);
    return;
  }

  const { processDueDeliveries } = require('../api/_lib/notification-dispatch');
  const { getOldestPendingAgeSeconds } = require('../api/_lib/notification-store');
  const limit = parseLimitArg(process.argv.slice(2));

  const startedAt = Date.now();
  const results = await processDueDeliveries(limit ? { limit } : {});
  // A failed D1 backlog-age query must never masquerade as an empty
  // queue in a green GitHub Actions delivery job.
  const oldestPendingAgeSeconds = await getOldestPendingAgeSeconds();
  const elapsedMs = Date.now() - startedAt;

  console.log('[NOTIFY-DELIVER] Run complete.');
  console.log(`[NOTIFY-DELIVER]   pending records processed: ${results.records_processed}`);
  console.log(`[NOTIFY-DELIVER]   channels claimed:          ${results.claimed}`);
  console.log(`[NOTIFY-DELIVER]   skipped (claimed elsewhere): ${results.skipped_claimed_elsewhere}`);
  console.log(`[NOTIFY-DELIVER]   cancelled (channel disabled): ${results.cancelled}`);
  console.log(`[NOTIFY-DELIVER]   delivery attempts:         ${results.attempts}`);
  console.log(`[NOTIFY-DELIVER]   delivered:                 ${results.delivered}`);
  console.log(`[NOTIFY-DELIVER]   scheduled for retry:       ${results.retried}`);
  console.log(`[NOTIFY-DELIVER]   dead-lettered:             ${results.dead_lettered}`);
  console.log(`[NOTIFY-DELIVER]   oldest pending age (sec):  ${oldestPendingAgeSeconds === null ? 'n/a (queue empty)' : oldestPendingAgeSeconds}`);
  console.log(`[NOTIFY-DELIVER]   elapsed: ${elapsedMs}ms`);

  // Compact structured run summary (orchestration mandate Phase 55) --
  // one machine-parseable line, no secrets, safe to grep out of GitHub
  // Actions logs or pipe into whatever external monitoring is wired up
  // later without needing to reformat the human-readable lines above.
  console.log('[NOTIFY-DELIVER-SUMMARY]', JSON.stringify({
    records_processed: results.records_processed,
    claimed: results.claimed,
    skipped_claimed_elsewhere: results.skipped_claimed_elsewhere,
    cancelled: results.cancelled,
    attempts: results.attempts,
    delivered: results.delivered,
    retrying: results.retried,
    terminal: results.dead_lettered,
    oldest_pending_delivery_age_seconds: oldestPendingAgeSeconds,
    elapsed_ms: elapsedMs,
  }));
}

if (require.main === module) {
  main().catch(err => {
    console.error('[NOTIFY-DELIVER] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { parseLimitArg, MAX_GITHUB_DELIVERY_LIMIT };
