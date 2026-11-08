'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Exercise the actual browser selection function without triggering DOM boot.
const source = fs.readFileSync(require('node:path').join(__dirname, '..', 'live-feed-widget.js'), 'utf8');
const start = source.indexOf('  function selectLocalItems(');
const end = source.indexOf('  /* ── MAIN FETCH PIPELINE', start);
assert.ok(start > 0 && end > start, 'selector must exist');
const context = vm.createContext({ CFG: { LOOKBACK_DAYS: 1, MAX_CARDS: 15 }, Date, Number, Object,
  normaliseLocal: raw => ({ id: raw.id, published: raw.published, link: raw.link }) });
vm.runInContext(source.slice(start, end), context);
const select = context.selectLocalItems;
const now = Date.parse('2026-11-08T12:00:00Z');
const record = (id, stamp) => ({ id, _addedAt: stamp, published: stamp });
const ids = rows => Array.from(rows, row => row.id);

test('rejects old, future, missing and invalid timestamps', () => {
  const got = select([
    record('recent', '2026-11-08T11:00:00Z'),
    record('old', '2026-11-06T11:00:00Z'),
    record('future', '2026-11-08T12:06:00Z'),
    {id:'missing'}, record('invalid', 'not-a-date')
  ], now);
  assert.deepEqual(ids(got), ['recent']);
});

test('never substitutes archive when no fresh records exist', () => {
  assert.deepEqual(ids(select([record('old', '2026-04-22T10:00:00Z')], now)), []);
});

test('deduplicates identifiers and sorts newest first', () => {
  const got = select([
    record('a', '2026-11-08T10:00:00Z'),
    record('b', '2026-11-08T11:00:00Z'),
    record('a', '2026-11-08T09:00:00Z')
  ], now);
  assert.deepEqual(ids(got), ['b','a']);
});

test('enforces 15-card limit and 24h boundary', () => {
  const rows = Array.from({length:20}, (_,i) => record('id'+i, '2026-11-08T11:00:00Z'));
  rows.push(record('boundary','2026-11-07T12:00:00Z'));
  assert.equal(select(rows,now).length,15);
  assert.deepEqual(ids(select([rows[20]],now)),['boundary']);
});

test('requires fresh first-party source before displaying live items', () => {
  assert.match(source, /classifyFeedTimestamp\(generated\)\.state !== 'current'/);
  assert.match(source, /classifyFeedTimestamp\(cached\[0\]\._feedGenerated\)\.state === 'current'/);
});
