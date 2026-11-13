'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const RS = require('../runtime-state.js');

// Exercise the actual browser selection function without triggering DOM boot.
const source = fs.readFileSync(require('node:path').join(__dirname, '..', 'live-feed-widget.js'), 'utf8');
const start = source.indexOf('  function sharedLiveAuthority(');
const end = source.indexOf('  /* ── MAIN FETCH PIPELINE', start);
assert.ok(start > 0 && end > start, 'selector must exist');
const context = vm.createContext({ CFG: { LOOKBACK_DAYS: 1, MAX_CARDS: 15 },
  Date, Number, Object, window: {SentinelRuntimeState: RS},
  normaliseLocal: raw => ({ id: raw.id, published: raw.published, link: raw.link }) });
vm.runInContext(source.slice(start, end), context);
const timestampStart=source.indexOf('  function classifyFeedTimestamp(');
const timestampEnd=source.indexOf('  function esc(',timestampStart);
assert.ok(timestampStart > 0 && timestampEnd > timestampStart,'source timestamp classifier exists');
vm.runInContext(source.slice(timestampStart,timestampEnd),context);
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

test('requires shared model for ingestion and publication clocks', () => {
  assert.match(source, /if \(!shared\.isLiveRecord\(raw, now\)\) return null/);
  assert.match(source, /if \(cached && verifiedLiveItems\(cached\)\)/);
  const previous = context.window;
  context.window = undefined;
  assert.deepEqual(ids(select([record('no-model','2026-11-08T11:00:00Z')],now)),[]);
  context.window = previous;
});
test('newly ingested OLD source and missing ingestion cannot appear live', () => {
  const newAt='2026-11-08T11:00:00Z';
  assert.deepEqual(ids(select([
    {id:'old',_addedAt:newAt,published:'2026-04-22T10:00:00Z'},
    {id:'zone-less',_addedAt:'2026-11-08T11:00:00',published:newAt},
    {id:'no-ingest',published:newAt},
    {id:'recent',_addedAt:newAt,published:newAt},
  ],now)),['recent']);
});
test('source publication date remains distinct from first-ingestion time',()=>{
  const recordAdded='2026-11-08T11:00:00Z';
  const sourcePublished='2026-11-07T12:00:00Z';
  const got=select([{id:'recent',_addedAt:recordAdded,published:sourcePublished}],now);
  assert.equal(got[0].published,sourcePublished);
  assert.equal(got[0]._sourcePublishedAt,sourcePublished);
  assert.equal(got[0]._reportAddedAt,new Date(recordAdded).toISOString());
});
test('render and cached card eligibility reject stale feed and expired reports',()=>{
  const added='2026-11-08T11:00:00Z';
  const rows=select([{id:'fresh',_addedAt:added,published:added}],now);
  rows[0]._feedGenerated='2026-11-08T11:30:00Z';
  assert.equal(context.verifiedLiveItems(rows,now),true);
  const tampered=Object.assign({},rows[0],{_sourcePublishedAt:'2026-04-22T10:00:00Z'});
  assert.equal(context.verifiedLiveItems([tampered],now),false);
  const stale=Object.assign({},rows[0],{_feedGenerated:'2026-11-08T08:59:00Z'});
  assert.equal(context.verifiedLiveItems([stale],now),false);
  const future=Object.assign({},rows[0],{_feedGenerated:'2026-11-08T12:01:00Z'});
  assert.equal(context.verifiedLiveItems([future],now),false);
  assert.equal(context.verifiedLiveItems(rows,now+25*3600000),false);
  assert.equal(context.verifiedLiveItems([Object.assign({},rows[0],{_contentArchived:true})],now),false);
});
test('no third-party fallback enters the first-party live card grid',()=>{
  assert.doesNotMatch(source,/xhrFetch\(CFG\.CISA_DIRECT/);
  assert.match(source,/function render\(items, container, animate\) \{\s*if \(!verifiedLiveItems\(items\)\)/);
  assert.match(source,/if \(container && _displayedItems\.length && !verifiedLiveItems\(_displayedItems\)\)/);
});

test('truncated HTML image injection fragments are never displayed as report prose',()=>{
  const begin=source.indexOf('  function stripEntities(');
  const end=source.indexOf('  function card(',begin);
  assert.ok(begin>0 && end>begin,'description sanitizer must exist');
  const ctx=vm.createContext({});
  vm.runInContext(source.slice(begin,end),ctx);
  assert.equal(ctx.stripEntities('Report &lt;img src=&quot;https://external.invalid'),
    'Report');
  assert.equal(ctx.stripEntities('Valid <strong>source</strong> context'),
    'Valid source context');
});
