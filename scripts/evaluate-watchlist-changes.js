#!/usr/bin/env node
/**
 * SENTINEL APEX — Watchlist Change Evaluation
 *
 * Thin CLI wrapper around api/_lib/change-engine.js's evaluateWatchedEntities().
 * Runs on a real autonomous schedule: .github/workflows/alert-delivery.yml's
 * native GitHub Actions `schedule:` trigger (every 30 minutes, immediately
 * followed by scripts/deliver-watchlist-notifications.js in the same run
 * — see that workflow's header for the cadence reasoning). Still safe to
 * run manually or via any other external scheduler too — this function's
 * own idempotent/replay-safe event creation (see change-engine.js) does
 * not depend on any particular caller.
 *
 * Storage: watchlists/entities/snapshots/events moved from Redis to
 * Cloudflare D1 as of the Cloudflare-Only Runtime Completion v2 tranche
 * (see watchlist-store.js's own header). This script's own dependency
 * check reflects that -- D1 REST env vars, not Redis. A live Cloudflare
 * Cron Trigger for evaluation specifically remains future work; this
 * sandbox cannot prove live execution (see that tranche's certification
 * doc).
 *
 * Usage:
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_D1_DATABASE_ID=... CLOUDFLARE_API_TOKEN=... \
 *     node scripts/evaluate-watchlist-changes.js [--batch=200]
 *
 * Bounded and cursor-resumable (see change-engine.js's own header): a run
 * only processes up to --batch watched entities before persisting its
 * cursor and exiting, so repeated invocations sweep the full watched set
 * over time without ever scanning the full intelligence corpus.
 */
'use strict';

const MAX_GITHUB_EVALUATION_BATCH = 200;
function parseBatchArg(argv) {
  const matches = argv.filter(arg => arg === '--batch' || arg.startsWith('--batch='));
  if (matches.length === 0) return undefined;
  if (matches.length !== 1 || !/^--batch=[1-9][0-9]*$/.test(matches[0])) {
    throw new RangeError('Invalid --batch; expected a single integer from 1 to 200');
  }
  const value = Number(matches[0].slice('--batch='.length));
  if (!Number.isSafeInteger(value) || value > MAX_GITHUB_EVALUATION_BATCH) {
    throw new RangeError('Invalid --batch; expected a single integer from 1 to 200');
  }
  return value;
}

async function main() {
  const { isConfigured } = require('../api/_lib/d1');
  if (!isConfigured()) {
    console.error('[WATCHLIST-EVAL] CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_D1_DATABASE_ID / CLOUDFLARE_API_TOKEN must be set.');
    process.exit(1);
    return;
  }

  const { evaluateWatchedEntities } = require('../api/_lib/change-engine');
  const batchLimit = parseBatchArg(process.argv.slice(2));

  const startedAt = Date.now();
  const results = await evaluateWatchedEntities(batchLimit ? { batchLimit } : {});
  const elapsedMs = Date.now() - startedAt;

  console.log('[WATCHLIST-EVAL] Run complete.');
  console.log(`[WATCHLIST-EVAL]   watched entities total: ${results.watched_entities_total}`);
  console.log(`[WATCHLIST-EVAL]   evaluated this run:      ${results.evaluated}`);
  console.log(`[WATCHLIST-EVAL]   baseline established:    ${results.baseline}`);
  console.log(`[WATCHLIST-EVAL]   unchanged:               ${results.unchanged}`);
  console.log(`[WATCHLIST-EVAL]   changed:                 ${results.changed}`);
  console.log(`[WATCHLIST-EVAL]   events created:          ${results.events_created}`);
  console.log(`[WATCHLIST-EVAL]   load failures (skipped): ${results.load_failed}`);
  console.log(`[WATCHLIST-EVAL]   watchlists touched:      ${results.watchlists_touched}`);
  console.log(`[WATCHLIST-EVAL]   elapsed: ${elapsedMs}ms`);
}

if (require.main === module) {
  main().catch(err => {
    console.error('[WATCHLIST-EVAL] Failed:', err.message);
    process.exit(1);
  });
}

module.exports = { parseBatchArg, MAX_GITHUB_EVALUATION_BATCH };
