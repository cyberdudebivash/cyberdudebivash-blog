'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../api/_lib/change-engine.js'), 'utf8');

test('both publisher modes use the indexed watcher cost guard before evaluation', () => {
  const driver = source.slice(source.indexOf('async function evaluateWatchedEntities('));
  const preflight = driver.indexOf('await store.getSocCronWatchersCostGuard(entityType, entityId)');
  const mutate = driver.indexOf('const outcome = await evaluateEntity({');
  assert.ok(preflight >= 0 && mutate > preflight);
  assert.doesNotMatch(driver.slice(0, mutate), /if \(boundedScan\) \{\s*const guard/);
});

test('every batch enforces shared fanout event budget and preflight rejection', () => {
  const driver = source.slice(source.indexOf('async function evaluateWatchedEntities('));
  assert.match(driver, /if \(!guard\.allowed\) \{ results\.fanout_blocked\+\+; continue; \}/);
  assert.match(driver, /socCronRemainingPairs: SOC_CRON_MAX_FANOUT_PAIRS_PER_RUN - results\.fanout_pairs/);
  assert.match(driver, /if \(outcome\.status === 'cost_blocked'\) \{ results\.event_budget_blocked\+\+; continue; \}/);
  assert.match(driver, /results\.fanout_pairs \+= outcome\.fanout_pairs \|\| 0/);
  assert.doesNotMatch(driver, /await store\.getWatchersForEntity\(entityType, entityId\)/);
});

test('cost-blocked entities cannot advance fingerprint snapshot or persist change events', () => {
  const entity = source.slice(source.indexOf('async function evaluateEntity('),
    source.indexOf('/* ───────────────────────── bounded batch driver'));
  const block = entity.indexOf("status: 'cost_blocked'");
  const persist = entity.indexOf('await persistEventIfNew(event)');
  const snapshot = entity.lastIndexOf('await saveSnapshot(entityType, entityId, currentState, fingerprint)');
  assert.ok(block >= 0 && block < persist && snapshot > persist);
});

test('legacy scan remains bounded and preserves numeric cursor', () => {
  assert.match(source, /await store\.getBoundedLegacyWatchedEntityKeys\(\)/);
  assert.match(source, /SELECT cursor FROM watchlist_eval_state WHERE id = 1/);
  assert.match(source, /fanout_pairs: 0, fanout_blocked: 0, event_budget_blocked: 0, skipped_no_active_watchers: 0/);
});
