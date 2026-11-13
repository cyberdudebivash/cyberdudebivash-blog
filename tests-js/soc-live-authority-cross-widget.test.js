'use strict';
// One meaning of "live" across every customer-facing record list.
//
// Four surfaces select records for customers. They were fixed one at a time and could disagree:
//   homepage triage  (apex-command-center.js)   homepage widget (live-feed-widget.js)
//   SOC intelligence desk (soc-intelligence-desk.js)
//   SOC global incidents (soc-global-incidents.js) -- a DIFFERENT category, see the last tests
// The three RECORD surfaces must apply exactly the policy in runtime-state.js (first added <= 24 h
// AND source-published <= 72 h; anything missing, malformed, zone-less or future is not live), so
// the same record is either live on all of them or on none. A stale pipeline exposes nothing.
// Fixtures are SYNTHETIC. No network.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const RS = require('../runtime-state.js');
const desk = require('../soc-intelligence-desk.js');
const read = f => fs.readFileSync(path.join(ROOT, f), 'utf8');

// homepage triage: the real function, extracted exactly as the other suites do
const ccSrc = read('apex-command-center.js');
const ccFrom = ccSrc.indexOf('function selectTriageFeed(');
const ccTo = ccSrc.indexOf('function emptyFeedRow(', ccFrom);
const triage = vm.runInNewContext('(function(){' + ccSrc.slice(ccFrom, ccTo) + 'return selectTriageFeed;})()',
  { Date, Number, Array, RS }, { timeout: 1000 });

// homepage widget: the real selector with the shared model present
const wSrc = read('live-feed-widget.js');
const wFrom = wSrc.indexOf('  function sharedLiveAuthority(');
const wTo = wSrc.indexOf('  /* ── MAIN FETCH PIPELINE', wFrom);
function widgetSelector(win) {
  const ctx = vm.createContext({ ...(win ? { window: win } : {}), CFG: { LOOKBACK_DAYS: 1, MAX_CARDS: 15 }, Date, Number, Object, Array,
    normaliseLocal: raw => ({ id: raw.id, published: raw.published, link: raw.link }) });
  vm.runInContext(wSrc.slice(wFrom, wTo), ctx);
  return ctx.selectLocalItems;
}
const widget = widgetSelector({ SentinelRuntimeState: RS });

const NOW = Date.parse('2026-11-12T12:00:00Z');
const H = 3600000;
const at = h => new Date(NOW - h * H).toISOString();
const day = h => at(h).slice(0, 10);
const rec = (id, extra) => ({ id, title: 'T-' + id, source: 'nvd', priority: 1, threatLevel: 'HIGH', ...extra });

const FIXTURE = [
  rec('RECENT-BOTH',        { _addedAt: at(2),  pubDate: day(2) }),                 // new here, new at source
  rec('REINGESTED-OLD-PUB', { _addedAt: at(1),  pubDate: '2026-07-05' }),           // ingested late: NOT new
  rec('NO-PUBLICATION',     { _addedAt: at(1) }),                                   // missing original date
  rec('OLD-INGEST-NEW-PUB', { _addedAt: at(30), pubDate: day(1) }),                 // source recent, we added it >24 h ago
  rec('FUTURE-ADDED',       { _addedAt: new Date(NOW + 2 * H).toISOString(), pubDate: day(0) }),
  rec('FUTURE-PUB',         { _addedAt: at(1),  pubDate: '2099-01-01' }),
  rec('ZONELESS-ADDED',     { _addedAt: '2026-11-12T11:00:00', pubDate: day(1) }),  // instant is browser-dependent
  rec('DATE-ONLY-ADDED',    { _addedAt: day(1), pubDate: day(1) }),                 // a machine timestamp must be a full date-time
  rec('INVALID',            { _addedAt: 'soon', pubDate: day(1) }),
  rec('ARCHIVE-HIGH',       { _addedAt: at(24 * 40), pubDate: day(24 * 40), priority: 100, cisaKev: true, exploited: true }),
  rec('RECENT-BOTH',        { _addedAt: at(5),  pubDate: day(5) }),                 // duplicate id, older copy
  rec('RECENT-LATER',       { _addedAt: at(1),  pubDate: day(1) }),
];
const EXPECTED = ['RECENT-LATER', 'RECENT-BOTH'];                                   // newest ingestion first, de-duplicated
const feed = items => ({ generatedAt: at(0.2),
  metadata: { lastPipelineRun: at(0.2), lastReportGeneratedAt: at(0.2) }, items });
const healthy = () => RS.classifyFeed({ ok: true, feed: feed([]), nowMs: NOW });

const homepageIds = items => Array.from(triage(items, NOW, healthy()).items, i => i.id);
const widgetIds = items => Array.from(widget(items, NOW), i => i.id);
const deskIds = items => desk.selectRecentRecords(feed(items), NOW).map(r => r.id);
const dedupe = ids => ids.filter((id, i) => ids.indexOf(id) === i);

test('the shared authority alone defines the expected live set for the fixture', () => {
  assert.deepEqual(dedupe(RS.selectLiveRecords(FIXTURE, NOW).items.map(i => i.id)), EXPECTED);
});

test('homepage triage, homepage widget and SOC desk select the same live records', () => {
  const sets = { homepage: dedupe(homepageIds(FIXTURE)), widget: widgetIds(FIXTURE), desk: deskIds(FIXTURE) };
  assert.deepEqual(sets.homepage, EXPECTED, 'homepage triage');
  assert.deepEqual(sets.widget, EXPECTED, 'homepage widget');
  assert.deepEqual(sets.desk, EXPECTED, 'SOC desk');
});

test('every disqualifying case is excluded by all three surfaces, individually', () => {
  const excluded = ['REINGESTED-OLD-PUB', 'NO-PUBLICATION', 'OLD-INGEST-NEW-PUB', 'FUTURE-ADDED', 'FUTURE-PUB',
    'ZONELESS-ADDED', 'DATE-ONLY-ADDED', 'INVALID', 'ARCHIVE-HIGH'];
  for (const id of excluded) {
    const one = FIXTURE.filter(r => r.id === id);
    assert.deepEqual(homepageIds(one), [], 'homepage triage must exclude ' + id);
    assert.deepEqual(widgetIds(one), [], 'homepage widget must exclude ' + id);
    assert.deepEqual(deskIds(one), [], 'SOC desk must exclude ' + id);
  }
});

test('an old advisory ingested today is NOT a newly published advisory (reingestion does not reset its age)', () => {
  const reingested = [rec('CVE-OLD', { _addedAt: at(0.5), pubDate: '2026-05-22', cisaKev: true, exploited: true, priority: 100 })];
  assert.deepEqual(homepageIds(reingested), []);
  assert.deepEqual(widgetIds(reingested), []);
  assert.deepEqual(deskIds(reingested), []);
});

test('archive-only data and zero recent records yield empty lists everywhere', () => {
  const archive = Array.from({ length: 20 }, (_, i) => rec('A' + i, { _addedAt: at(24 * (40 + i)), pubDate: day(24 * (40 + i)) }));
  for (const items of [archive, []]) {
    assert.deepEqual(homepageIds(items), []);
    assert.deepEqual(widgetIds(items), []);
    assert.deepEqual(deskIds(items), []);
  }
  assert.deepEqual(desk.selectRecentRecords(null, NOW), []);
  assert.deepEqual(desk.selectRecentRecords({ items: 'nope' }, NOW), []);
});

test('a stale, unavailable or unverifiable pipeline exposes no record on any surface', () => {
  const stale = RS.classifyFeed({ ok: true, feed: { generatedAt: at(24 * 20),
    metadata: { lastPipelineRun: at(24 * 20), lastReportGeneratedAt: at(24 * 20) }, items: FIXTURE }, nowMs: NOW });
  const down = RS.classifyFeed({ ok: false, error: 'timeout', nowMs: NOW });
  const noClock = RS.classifyFeed({ ok: true, feed: { items: FIXTURE }, nowMs: NOW });
  for (const cls of [stale, down, noClock, { state: 'CHECKING' }]) {
    assert.deepEqual(desk.availableRecords(feed(FIXTURE), cls, NOW), [], 'desk ' + cls.state);
    const t = triage(FIXTURE, NOW, cls);
    assert.equal(t.items.length, 0, 'homepage ' + cls.state);
    assert.equal(t.withheld, true);
  }
  const ok = triage(FIXTURE, NOW, healthy());
  assert.equal(ok.withheld, false);
  assert.ok(ok.items.length > 0);
});

test('if the shared model is missing, every surface fails closed instead of improvising a window', () => {
  const noModelTriage = vm.runInNewContext('(function(){var RS=null;' + ccSrc.slice(ccFrom, ccTo) + 'return selectTriageFeed;})()',
    { Date, Number, Array }, { timeout: 1000 });
  assert.equal(noModelTriage(FIXTURE, NOW).items.length, 0);
  assert.equal(noModelTriage(FIXTURE, NOW).unavailable, true);
  // The desk resolves its authority from window first, then from runtime-state.js; with neither it returns [].
  const deskSrc = read('soc-intelligence-desk.js').replace("require('./runtime-state.js')", "(function(){throw new Error('absent');})()");
  const sandbox = { module: { exports: {} }, window: undefined, Date, Number, Array, Set, URL, Object, String, isFinite, require: undefined };
  vm.runInNewContext(deskSrc, sandbox, { timeout: 1000 });
  assert.equal(Array.from(sandbox.module.exports.selectRecentRecords(feed(FIXTURE), NOW)).length, 0);
});

test('the three record surfaces contain no private window rule of their own', () => {
  assert.doesNotMatch(read('soc-intelligence-desk.js'), /RECENT_WINDOW_MS|86400000|24\s*\*\s*60\s*\*\s*60\s*\*\s*1000/, 'desk must not carry its own 24 h constant');
  assert.match(read('soc-intelligence-desk.js'), /RS\.isLiveRecord\(/);
  assert.match(ccSrc, /RS\.selectLiveRecords\(/);
  assert.match(wSrc, /shared\.isLiveRecord\(/);
});

// ── a distinct, documented category ──────────────────────────────────────────
test('global incidents are a DIFFERENT category: ACTIVITY (updated_utc) not first publication', () => {
  const ctx = { window: {}, URL, Set, Date, Number, Object };
  vm.runInNewContext(read('soc-global-incidents.js'), ctx);
  const incidents = ctx.window.CDBGlobalIncidents;
  const stamp = at(0.5);
  const url = 'https://example.org/advisory';
  const incident = (id, first, updated) => ({ id, title: id, category: 'breach', first_seen_utc: first, updated_utc: updated,
    status: 'investigating', severity: 'high', confidence: 'medium',
    sources: [{ url, publisher: 'Example CERT', published_at_utc: stamp, retrieved_at_utc: stamp }],
    claims: [{ text: 'c', source_urls: [url], verification_state: 'reported' }] });
  const gcii = { schema: 'cdb.global-incidents.v1', generated_at_utc: stamp, sha256: 'a'.repeat(64),
    incidents: [incident('OLD-BUT-ACTIVE', at(24 * 30), at(1)), incident('OLD-AND-QUIET', at(24 * 30), at(24 * 5))] };
  const fresh = incidents.selectFreshIncidents(gcii, NOW);
  assert.deepEqual(Array.from(fresh, i => i.id), ['OLD-BUT-ACTIVE'], 'an incident first seen long ago but updated within 24 h is current activity');
  // The same shape of fact is NOT live in a record list: a record's age is its ingestion + publication.
  assert.deepEqual(homepageIds([rec('OLD-BUT-ACTIVE', { _addedAt: at(24 * 30), pubDate: day(24 * 30), updatedAt: at(1), lastUpdated: at(1) })]), []);
  // A stale incident publication withholds all incidents (null = freshness cannot be certified).
  assert.equal(incidents.selectFreshIncidents({ ...gcii, generated_at_utc: at(5) }, NOW), null);
});

test('an otherwise recent source heartbeat with an expired report receipt is denied by every surface',()=>{
  const heartbeat={...feed(FIXTURE),metadata:{
    lastPipelineRun:at(0.01),lastReportGeneratedAt:at(24)
  }};
  const c=RS.classifyFeed({ok:true,feed:heartbeat,nowMs:NOW});
  assert.equal(c.state,'STALE');
  assert.equal(RS.pipelineAllowsLive(c,NOW),false);
  assert.deepEqual(desk.selectRecentRecords(heartbeat,NOW),[]);
  assert.deepEqual(triage(FIXTURE,NOW,c).items,[]);
});
