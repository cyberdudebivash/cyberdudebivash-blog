#!/usr/bin/env node
/**
 * Manual-only SOC outbox reconciler. This script is deliberately NOT wired
 * to any Cron, GitHub Actions or Worker trigger. Running with no arguments
 * must do zero D1 or network work. Requires explicit operator controls.
 */
'use strict';
function parse(argv) {
  const flags = new Set(argv);
  const options = argv.filter(x => x.startsWith('--limit='));
  // No destructive retention CLI until replay-safe tombstones exist (#418).
  const accepted = new Set(['--apply',...options]);
  if (argv.some(x => !accepted.has(x)) || options.length > 1)
    throw new RangeError('SOC_OUTBOX_INVALID_ARGUMENTS');
  const limit = options.length ? Number(options[0].slice('--limit='.length)) : 5;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5 ||
      (options.length && !/^--limit=[1-5]$/.test(options[0])))
    throw new RangeError('SOC_OUTBOX_LIMIT_1_TO_5');
  return { apply:flags.has('--apply'), prune:false, limit };
}
async function main(argv = process.argv.slice(2)) {
  const args = parse(argv);
  if (!args.apply) {
    console.log('[SOC-OUTBOX] READINESS ONLY: no database access or notifications. Manual --apply required.');
    return { noAction:true };
  }
  if (process.env.CDB_SOC_OUTBOX_ENABLED !== 'true' ||
      process.env.CDB_SOC_OUTBOX_OPERATOR_APPROVED !== 'true')
    throw new Error('SOC_OUTBOX_NOT_AUTHORIZED');
  const d1 = require('../api/_lib/d1');
  if (!d1.isConfigured()) throw new Error('SOC_OUTBOX_D1_UNAVAILABLE');
  const o = require('../api/_lib/soc-notification-outbox').productionOutbox();
  const result = await o.reconcile({ limit:args.limit });
  console.log('[SOC-OUTBOX] Totals (no tenant IDs, payload or delivery secrets):', JSON.stringify(result));
  // Processing an incomplete outbox should never be counted as a clean
  // customer-delivery success. This does not prove email/webhook receipt.
  if (result.errors > 0 || result.blocked > 0)
    throw new Error('SOC_OUTBOX_INCOMPLETE: requires manual incident review');
  return result;
}
if (require.main === module) {
  main().catch(e => {
    console.error('[SOC-OUTBOX] FAIL:', e.message);
    process.exitCode = 1;
  });
}
module.exports = { parse, main };
