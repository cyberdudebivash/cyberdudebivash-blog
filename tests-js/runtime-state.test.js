'use strict';

// Public runtime state model (runtime-state.js) and its consumers. Protects
// three production defects: (1) customer pages could sit in "VERIFYING"
// forever because no fetch had a deadline; (2) the homepage/status page called
// a feed "LIVE"/"ok" for up to 6h while the CI freshness monitor treats >180
// min as down; (3) status "AVAILABLE" was derived from a SOC 2 flag rather
// than from what actually responded.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const RS = require('../runtime-state.js');
const monitor = require('../scripts/check-intel-freshness.js');

const NOW = Date.parse('2026-09-30T17:00:00Z');
const minutesAgo = m => new Date(NOW - m * 60000).toISOString();
const feedAt = iso => ({ metadata: { lastPipelineRun: iso, lastReportGeneratedAt: iso }, generatedAt: iso, items: [], stats: {} });

describe('classifier', () => {
  test('thresholds are the CI freshness monitor thresholds (single source of truth)', () => {
    assert.equal(RS.THRESHOLDS.healthyMaxMinutes, monitor.WARN_RUNTIME_MINUTES);
    assert.equal(RS.THRESHOLDS.staleAfterMinutes, monitor.DOWN_RUNTIME_MINUTES);
  });

  test('state boundaries', () => {
    const at = m => RS.classifyFeed({ ok: true, feed: feedAt(minutesAgo(m)), nowMs: NOW }).state;
    assert.equal(at(0), 'HEALTHY');
    assert.equal(at(90), 'HEALTHY');
    assert.equal(at(91), 'DEGRADED');
    assert.equal(at(180), 'DEGRADED');
    assert.equal(at(181), 'STALE');
    assert.equal(at(20 * 60), 'STALE');
  });

  test('unprovable freshness is never HEALTHY', () => {
    assert.equal(RS.classifyFeed({ ok: true, feed: { items: [] }, nowMs: NOW }).state, 'DEGRADED');
    assert.equal(RS.classifyFeed({ ok: true, feed: feedAt('not-a-date'), nowMs: NOW }).state, 'DEGRADED');
    assert.equal(RS.classifyFeed({ ok: true, feed: feedAt(minutesAgo(-30)), nowMs: NOW }).state, 'DEGRADED');
    assert.equal(RS.classifyFeed({ ok: true, feed: null, nowMs: NOW }).state, 'DEGRADED');
  });

  test('failed retrieval is UNAVAILABLE and says why', () => {
    const r = RS.classifyFeed({ ok: false, error: 'timeout', nowMs: NOW });
    assert.equal(r.state, 'UNAVAILABLE');
    assert.equal(r.reachable, false);
    assert.match(r.reason, /timeout/);
  });

  test('a new heartbeat never makes an old genuine report LIVE', () => {
    const feed = { generatedAt: minutesAgo(10), metadata: {
      lastPipelineRun: minutesAgo(1), lastReportGeneratedAt: minutesAgo(300)
    } };
    const result = RS.classifyFeed({ ok: true, feed, nowMs: NOW });
    assert.equal(result.state, 'STALE');
    assert.equal(RS.pipelineAllowsLive(result, NOW), false);
    assert.notEqual(RS.badgeFor(result).text, 'LIVE');
    assert.equal(RS.feedTimestamp(feed), minutesAgo(300));
  });

  test('missing genuine report receipt and future generated clock cannot display LIVE', () => {
    const absent={generatedAt:minutesAgo(1), metadata:{lastPipelineRun:minutesAgo(1)}};
    assert.equal(RS.classifyFeed({ok:true,feed:absent,nowMs:NOW}).state,'DEGRADED');
    const forged={generatedAt:minutesAgo(-30),metadata:{lastReportGeneratedAt:minutesAgo(1)}};
    assert.equal(RS.classifyFeed({ok:true,feed:forged,nowMs:NOW}).state,'DEGRADED');
  });

  test('the committed production feed shape classifies from its own timestamps', () => {
    const feed = JSON.parse(fs.readFileSync(path.join(ROOT, 'live-intel.json'), 'utf8'));
    const stamp = Date.parse(RS.feedTimestamp(feed));
    assert.ok(Number.isFinite(stamp), 'live-intel.json must carry a parseable pipeline timestamp');
    const observedAt=Date.parse(feed.generatedAt)+10*60000;
    const reportAge=observedAt-Date.parse(feed.metadata.lastReportGeneratedAt);
    const expected=reportAge>180*60000?'STALE':reportAge>90*60000?'DEGRADED':'HEALTHY';
    assert.equal(RS.classifyFeed({ok:true,feed,nowMs:observedAt}).state,expected);
    assert.equal(RS.classifyFeed({ ok: true, feed, nowMs: stamp + 24 * 3600000 }).state, 'STALE');
  });
});

describe('status badge (badgeFor): LIVE only with evidence', () => {
  const badge = m => RS.badgeFor(RS.classifyFeed({ ok: true, feed: feedAt(minutesAgo(m)), nowMs: NOW }));

  test('LIVE is claimed only while the feed is HEALTHY', () => {
    assert.deepEqual(badge(12), { text: 'LIVE', tone: 'live', hidden: false });
    assert.deepEqual(badge(90), { text: 'LIVE', tone: 'live', hidden: false });
    for (const m of [91, 120, 180, 181, 300, 20 * 1440]) {
      assert.notEqual(badge(m).text, 'LIVE', m + ' minutes old must not read LIVE');
      assert.notEqual(badge(m).tone, 'live', m + ' minutes old must not carry the live tone');
    }
  });

  test('delayed and stale feeds name their observed age', () => {
    assert.deepEqual(badge(120), { text: 'DELAYED · 2h 0m', tone: 'warn', hidden: false });
    assert.deepEqual(badge(181), { text: 'STALE · 3h 1m', tone: 'warn', hidden: false });
    assert.equal(badge(20 * 1440 + 3 * 60).text, 'STALE · 20d 3h');
  });

  test('unprovable freshness reads UNVERIFIED, never LIVE or DELAYED', () => {
    const b = RS.badgeFor(RS.classifyFeed({ ok: true, feed: { items: [] }, nowMs: NOW }));
    assert.deepEqual(b, { text: 'UNVERIFIED', tone: 'warn', hidden: false });
    const future = RS.badgeFor(RS.classifyFeed({ ok: true, feed: feedAt(minutesAgo(-30)), nowMs: NOW }));
    assert.equal(future.text, 'UNVERIFIED');
  });

  test('an unreachable feed reads UNAVAILABLE with the bad tone', () => {
    const b = RS.badgeFor(RS.classifyFeed({ ok: false, error: 'timeout', nowMs: NOW }));
    assert.deepEqual(b, { text: 'UNAVAILABLE', tone: 'bad', hidden: false });
  });

  test('CHECKING, unknown and missing input produce no badge at all', () => {
    for (const input of [{ state: 'CHECKING' }, { state: 'SOMETHING_ELSE' }, {}, null, undefined]) {
      assert.deepEqual(RS.badgeFor(input), { text: '', tone: 'warn', hidden: true }, JSON.stringify(input));
    }
  });
});

describe('fetchJson deadline', () => {
  test('resolves JSON on 2xx', async () => {
    const v = await RS.fetchJson('/x', { fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ a: 1 }) }) });
    assert.deepEqual(v, { a: 1 });
  });

  test('rejects non-2xx with the status', async () => {
    await assert.rejects(RS.fetchJson('/x', { fetchImpl: async () => ({ ok: false, status: 503 }) }), /http 503/);
  });

  test('a hanging request rejects with timeout and aborts the request', async () => {
    let signal;
    const hang = (_u, init) => { signal = init.signal; return new Promise(() => {}); };
    await assert.rejects(RS.fetchJson('/x', { fetchImpl: hang, timeoutMs: 20 }), /timeout/);
    assert.equal(signal.aborted, true);
  });
});

// Run the real apex-command-center.js against a minimal DOM.
function runCommandCenter(fetchImpl, mutateRs, opts = {}) {
  const els = new Map();
  const el = id => {
    if (!els.has(id)) els.set(id, { id, textContent: '', innerHTML: '', dataset: {}, addEventListener() {} });
    return els.get(id);
  };
  const rs = { ...RS, fetchJson: url => RS.fetchJson(url, { fetchImpl, timeoutMs: 25 }) };
  if (mutateRs) mutateRs(rs);
  const window = { SentinelRuntimeState: opts.noModel ? undefined : rs, addEventListener() {}, location: { origin: 'https://blog.cyberdudebivash.in', reload() {} }, matchMedia: () => ({ matches: true }), devicePixelRatio: 1 };
  const document = { getElementById: id => (id === 'cdbSignalCanvas' ? null : el(id)) };
  const ctx = vm.createContext({ window, document, Intl, URL, Promise, setTimeout, clearTimeout, setInterval: () => 1, clearInterval: () => {}, Date, Math, Number, String, Object, Array, JSON, isFinite, fetch: fetchImpl });
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'apex-command-center.js'), 'utf8'), ctx);
  return { text: id => el(id).textContent, html: id => el(id).innerHTML, state: id => el(id).dataset.state,
    hidden: id => el(id).hidden, title: id => el(id).title };
}
const settle = ms => new Promise(r => setTimeout(r, ms));

describe('homepage command center wiring', () => {
  test('a hanging network resolves to UNAVAILABLE instead of staying in CHECKING', async () => {
    const page = runCommandCenter(() => new Promise(() => {}));
    await settle(80);
    assert.equal(page.text('homepage-feed-state'), 'UNAVAILABLE');
    assert.equal(page.text('homepage-priority-runtime'), 'UNAVAILABLE');
    assert.match(page.html('cdb-edge-state'), /PRODUCTION EDGE · UNAVAILABLE/);
    assert.equal(page.state('cdb-runtime-pill'), 'bad');
  });

  test('a reachable but 5h-old feed reads STALE with a verified edge, never LIVE', async () => {
    const stale = { ...feedAt(new Date(Date.now() - 300 * 60000).toISOString()), totalPublished: 5, stats: { critical: 1 } };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => stale }));
    await settle(80);
    assert.equal(page.text('homepage-feed-state'), 'STALE');
    assert.match(page.text('cdb-runtime-text'), /^STALE · FEED AGE 5h 0m$/);
    assert.match(page.html('cdb-edge-state'), /PRODUCTION EDGE · VERIFIED/);
    assert.doesNotMatch(page.text('cdb-runtime-text'), /LIVE/);
  });

  test('a fresh feed reads HEALTHY', async () => {
    const fresh = { ...feedAt(new Date(Date.now() - 12 * 60000).toISOString()), totalPublished: 5, stats: {} };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => fresh }));
    await settle(80);
    assert.equal(page.text('homepage-feed-state'), 'HEALTHY');
    assert.equal(page.state('cdb-runtime-pill'), 'live');
  });
});

describe('homepage Intelligence Hub badge wiring', () => {
  const settleMs = 80;

  test('a 20-day-old feed (the real production state) reads STALE with its age, never LIVE', async () => {
    const stale = { ...feedAt(new Date(Date.now() - (20 * 1440 + 3 * 60) * 60000).toISOString()), totalPublished: 6466, stats: {} };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => stale }));
    await settle(settleMs);
    assert.match(page.text('cdb-live-badge'), /^STALE · 20d 3h$/);
    assert.equal(page.state('cdb-live-badge'), 'warn');
    assert.equal(page.hidden('cdb-live-badge'), false);
    assert.match(page.title('cdb-live-badge'), /out of date/);
    assert.doesNotMatch(page.text('cdb-live-badge'), /LIVE/);
  });

  test('a fresh feed is the only case that reads LIVE', async () => {
    const fresh = { ...feedAt(new Date(Date.now() - 12 * 60000).toISOString()), totalPublished: 5, stats: {} };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => fresh }));
    await settle(settleMs);
    assert.equal(page.text('cdb-live-badge'), 'LIVE');
    assert.equal(page.state('cdb-live-badge'), 'live');
    assert.equal(page.hidden('cdb-live-badge'), false);
  });

  test('a feed behind cadence reads DELAYED, not LIVE', async () => {
    const behind = { ...feedAt(new Date(Date.now() - 120 * 60000).toISOString()), totalPublished: 5, stats: {} };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => behind }));
    await settle(settleMs);
    assert.match(page.text('cdb-live-badge'), /^DELAYED · 2h \d+m$/);
    assert.equal(page.state('cdb-live-badge'), 'warn');
  });

  test('an unreachable feed reads UNAVAILABLE with the bad tone', async () => {
    const page = runCommandCenter(() => new Promise(() => {}));
    await settle(settleMs);
    assert.equal(page.text('cdb-live-badge'), 'UNAVAILABLE');
    assert.equal(page.state('cdb-live-badge'), 'bad');
    assert.equal(page.hidden('cdb-live-badge'), false);
  });

  test('version skew: an older cached runtime-state.js without badgeFor leaves the badge hidden and empty', async () => {
    const fresh = { ...feedAt(new Date(Date.now() - 12 * 60000).toISOString()), totalPublished: 5, stats: {} };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => fresh }), rs => { delete rs.badgeFor; });
    await settle(settleMs);
    assert.equal(page.hidden('cdb-live-badge'), true);
    assert.equal(page.text('cdb-live-badge'), '');
    assert.equal(page.text('homepage-feed-state'), 'HEALTHY', 'the rest of the command center is unaffected');
  });
});

describe('consumer pages', () => {
  const index = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  const status = fs.readFileSync(path.join(ROOT, 'service-status.html'), 'utf8');

  test('runtime-state.js loads before the command center and is part of the public build', () => {
    const rsAt = index.indexOf('<script src="/runtime-state.js');
    const ccAt = index.indexOf('<script src="/apex-command-center.js');
    assert.ok(rsAt > 0 && ccAt > rsAt, 'runtime-state.js must precede apex-command-center.js');
    assert.ok(status.includes('<script src="/runtime-state.js'), 'status page must load the shared model');
    const { PUBLIC_ROOT_FILES } = require('../scripts/build-cloudflare-assets.js');
    assert.ok(PUBLIC_ROOT_FILES.includes('runtime-state.js'));
  });

  test('the sidebar badge ships hidden and empty: LIVE is never hard-coded in markup', () => {
    assert.doesNotMatch(index, /<span class="ihw-live"[^>]*>\s*LIVE\s*<\/span>/, 'no static LIVE text in the badge');
    const badge = index.match(/<span class="ihw-live"[^>]*>[\s\S]*?<\/span>/);
    assert.ok(badge, 'the badge element must exist');
    assert.match(badge[0], /id="cdb-live-badge"/);
    assert.match(badge[0], /\bhidden\b/, 'hidden until the feed state is proven');
    assert.match(badge[0], />\s*<\/span>$/, 'no text until the feed state is proven');
    assert.match(index, /\.ihw-live\[data-state="warn"\]\s*\{[^}]*animation:\s*none/, 'only the live state may blink');
    assert.match(index, /\.ihw-live\[data-state="bad"\]\s*\{[^}]*animation:\s*none/);
  });

  test('changed scripts are cache-busted together on the homepage', () => {
    const rsV = index.match(/\/runtime-state\.js\?v=([^"']+)/);
    const ccV = index.match(/\/apex-command-center\.js\?v=([^"']+)/);
    assert.ok(rsV && ccV, 'both scripts carry a version query');
    assert.equal(rsV[1], ccV[1], 'runtime-state.js and apex-command-center.js must be bumped together');
  });

  test('no customer page ships an unbounded VERIFYING state or a LIVE label for batch data', () => {
    for (const [name, html] of [['index.html', index], ['service-status.html', status]]) {
      assert.doesNotMatch(html, /VERIFYING/, name);
    }
    assert.doesNotMatch(fs.readFileSync(path.join(ROOT, 'apex-command-center.js'), 'utf8'), /PRODUCTION DATA LIVE/);
  });

  test('homepage does not pull intelligence through third-party CORS proxies or CSP-blocked origins', () => {
    const scripts = (index.match(/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi) || []).join('\n');
    assert.doesNotMatch(scripts, /fetch\([^)]*(?:allorigins|corsproxy|thingproxy)/i);
    assert.doesNotMatch(scripts, /fetch\(CISA_URL/);
  });

  test('status page reachability is derived from responses, not from a SOC 2 flag', () => {
    assert.doesNotMatch(status, /soc2_certified===false\?'AVAILABLE'/);
    assert.match(status, /Promise\.allSettled\(\[RS\.fetchJson\('\/api\/intel\/customer-assurance\.json'\),RS\.fetchJson\('\/live-intel\.json'\)\]\)/);
  });
});

// ── Live-record window policy ────────────────────────────────────────────────
// Product requirement: a live list never silently repopulates itself with historical
// reports. A record is LIVE only if the pipeline first added it within 24 h AND the
// source published it within 72 h. A fresh feed timestamp proves nothing about its
// records, and re-ingesting an old advisory does not make it new. Historical content
// stays reachable through the Intelligence Archive, never through a live list.
describe('live record freshness: historical records are never presented as live', () => {
  const NOWMS = Date.parse('2026-11-12T12:00:00Z');
  const hrs = h => new Date(NOWMS - h * 3600000).toISOString();
  const dayOf = h => hrs(h).slice(0, 10);
  const rec = (id, addedH, pubH, extra = {}) => ({ id, title: 'T-' + id, priority: 1, _addedAt: hrs(addedH), pubDate: dayOf(pubH), ...extra });
  const pick = items => RS.selectLiveRecords(items, NOWMS);
  const ids = sel => sel.items.map(i => i.id);
  const why = (item, now = NOWMS) => RS.classifyRecord(item, now).reason;

  test('the policy is explicit and immutable: 24 h ingestion, 72 h publication', () => {
    assert.equal(RS.LIVE_WINDOWS.ingestMaxHours, 24);
    assert.equal(RS.LIVE_WINDOWS.publicationMaxHours, 72);
    assert.ok(Object.isFrozen(RS.LIVE_WINDOWS));
  });

  test('recent valid intelligence is live', () => {
    const sel = pick([rec('NEW', 2, 2)]);
    assert.deepEqual(ids(sel), ['NEW']);
    assert.equal(why(rec('NEW', 2, 2)), 'LIVE');
    assert.deepEqual(sel.windowHours, { ingest: 24, publication: 72 });
  });

  test('old high-severity reports are not live, whatever their priority or flags', () => {
    const old = rec('OLD-CRIT', 24 * 40, 24 * 40, { priority: 100, threatLevel: 'CRITICAL', cvss: 9.8, cisaKev: true, exploited: true, ransomware: true });
    assert.equal(why(old), 'NOT_RECENTLY_INGESTED');
    assert.deepEqual(ids(pick([old])), []);
  });

  test('an old advisory re-ingested today is NOT live (re-ingestion does not reset age)', () => {
    const reingested = rec('REINGESTED', 1, 24 * 30, { priority: 100, exploited: true, cisaKev: true });
    assert.equal(why(reingested), 'PUBLISHED_BEFORE_WINDOW');
    assert.deepEqual(ids(pick([reingested])), []);
  });

  test('window boundaries: 24 h ingestion (inclusive) and 72 h publication, including date-only values', () => {
    assert.equal(why({ id: 'a', _addedAt: hrs(24), pubDate: hrs(24) }), 'LIVE');
    assert.equal(why({ id: 'b', _addedAt: new Date(NOWMS - 24 * 3600000 - 60000).toISOString(), pubDate: hrs(1) }), 'NOT_RECENTLY_INGESTED');
    assert.equal(why({ id: 'c', _addedAt: hrs(1), pubDate: hrs(72) }), 'LIVE');
    assert.equal(why({ id: 'd', _addedAt: hrs(1), pubDate: new Date(NOWMS - 72 * 3600000 - 60000).toISOString() }), 'PUBLISHED_BEFORE_WINDOW');
    // A date-only value may be published any time that UTC day, so its latest possible time is end of day.
    assert.equal(why({ id: 'e', _addedAt: hrs(1), pubDate: '2026-11-09' }), 'LIVE', 'ends 2026-11-09T23:59:59Z = 60 h ago');
    assert.equal(why({ id: 'f', _addedAt: hrs(1), pubDate: '2026-11-08' }), 'PUBLISHED_BEFORE_WINDOW', 'ends 2026-11-08T23:59:59Z = 84 h ago');
  });

  test('mixed recent and archival records: only recent ones, newest ingestion first, priority breaks ties', () => {
    const sel = pick([
      rec('OLD', 24 * 90, 24 * 90, { priority: 100 }),
      rec('NEW-5H', 5, 5),
      rec('NEW-1H-LOW', 1, 1, { priority: 1 }),
      rec('NEW-1H-HIGH', 1, 1, { priority: 50 }),
      rec('REINGESTED', 2, 24 * 20),
    ]);
    assert.deepEqual(ids(sel), ['NEW-1H-HIGH', 'NEW-1H-LOW', 'NEW-5H']);
    assert.equal(sel.considered, 5);
    assert.deepEqual(sel.excluded, { NOT_RECENTLY_INGESTED: 1, PUBLISHED_BEFORE_WINDOW: 1 });
  });

  test('all reports historical: the live selection is empty and accounts for every record', () => {
    const sel = pick(Array.from({ length: 12 }, (_, i) => rec('H' + i, 24 * (40 + i), 24 * (40 + i), { priority: 100 - i })));
    assert.deepEqual(ids(sel), []);
    assert.equal(Object.values(sel.excluded).reduce((a, b) => a + b, 0), 12);
  });

  test('missing, blank, malformed or wrongly typed timestamps are never live', () => {
    assert.equal(why({ id: 'x', pubDate: dayOf(1) }), 'NO_INGEST_TIME');
    assert.equal(why({ id: 'x', _addedAt: '', pubDate: dayOf(1) }), 'NO_INGEST_TIME');
    assert.equal(why({ id: 'x', _addedAt: null, pubDate: dayOf(1) }), 'NO_INGEST_TIME');
    assert.equal(why({ id: 'x', _addedAt: hrs(1) }), 'NO_PUBLICATION_DATE');
    assert.equal(why({ id: 'x', _addedAt: '   ', pubDate: dayOf(1) }), 'INVALID_TIMESTAMP');
    assert.equal(why({ id: 'x', _addedAt: 'not-a-date', pubDate: dayOf(1) }), 'INVALID_TIMESTAMP');
    assert.equal(why({ id: 'x', _addedAt: hrs(1), pubDate: 'soon' }), 'INVALID_TIMESTAMP');
    assert.equal(why({ id: 'x', _addedAt: NOWMS - 1000, pubDate: dayOf(1) }), 'INVALID_TIMESTAMP', 'numbers are not accepted as timestamps');
    for (const bad of [null, undefined, 'str', 7, [], [{ id: 'nested' }]]) assert.equal(why(bad), 'INVALID_RECORD');
    assert.deepEqual(ids(pick(null)), []);
    assert.deepEqual(ids(pick({ items: [] })), []);
  });

  test('future timestamps are rejected beyond a 5 minute clock-skew tolerance', () => {
    const at = ms => new Date(NOWMS + ms).toISOString();
    assert.equal(why({ id: 'f1', _addedAt: at(24 * 3600000), pubDate: dayOf(1) }), 'FUTURE_TIMESTAMP');
    assert.equal(why({ id: 'f2', _addedAt: hrs(1), pubDate: '2099-01-01' }), 'FUTURE_TIMESTAMP');
    assert.equal(why({ id: 'f3', _addedAt: hrs(1), pubDate: '2026-11-13' }), 'FUTURE_TIMESTAMP', 'a date-only value for tomorrow');
    assert.equal(why({ id: 'f4', _addedAt: at(6 * 60000), pubDate: dayOf(0) }), 'FUTURE_TIMESTAMP');
    assert.equal(why({ id: 'f5', _addedAt: at(4 * 60000), pubDate: dayOf(0) }), 'LIVE', 'within clock-skew tolerance');
    assert.deepEqual(ids(pick([{ id: 'f2', _addedAt: hrs(1), pubDate: '2099-01-01' }])), []);
  });

  test('an old record with a "recent update" is NOT revived: the feed has no trusted confirmation timestamp', () => {
    // fetch-live-intel.js emits only _addedAt and pubDate. Other date-like fields are not
    // evidence, so they must not make an old incident live. Showing a genuinely
    // re-confirmed old incident needs a pipeline-side confirmation field first.
    const old = rec('OLD-BUT-ACTIVE', 24 * 45, 24 * 45, {
      lastUpdated: hrs(1), updatedAt: hrs(1), modified: hrs(1), lastConfirmedAt: hrs(1), kevDateAdded: dayOf(1), dateAdded: undefined,
      exploited: true, cisaKev: true,
    });
    assert.equal(why(old), 'NOT_RECENTLY_INGESTED');
    assert.deepEqual(ids(pick([old])), []);
  });

  test('the real source feed: nothing in the live selection is older than the policy allows', () => {
    const feed = JSON.parse(fs.readFileSync(path.join(ROOT, 'live-intel.json'), 'utf8'));
    const now = Date.parse(feed.generatedAt) + 1000;
    const sel = RS.selectLiveRecords(feed.items, now);
    for (const item of sel.items) {
      assert.ok(now - Date.parse(item._addedAt) <= 24 * 3600000, item.id + ' ingested within 24 h');
      assert.ok(now - (Date.parse(item.pubDate) + (/^\d{4}-\d{2}-\d{2}$/.test(item.pubDate) ? 86399999 : 0)) <= 72 * 3600000, item.id + ' published within 72 h');
    }
    assert.equal(sel.considered, feed.items.length);
    assert.ok(Object.values(sel.excluded).reduce((a, b) => a + b, 0) + sel.items.length === feed.items.length, 'every record is accounted for');
  });
});

describe('live record freshness: what the homepage command center renders', () => {
  const settle2 = 80;
  const HOUR = 3600000;
  const iso = h => new Date(Date.now() - h * HOUR).toISOString();
  const day = h => iso(h).slice(0, 10);
  const item = (id, addedH, pubH, extra = {}) => ({ id, title: 'Title ' + id, source: 'nvd', priority: 1, threatLevel: 'HIGH', _addedAt: iso(addedH), pubDate: day(pubH), ...extra });
  const feed = (pipelineAgeMin, items) => ({ metadata: {
    lastPipelineRun: new Date(Date.now() - pipelineAgeMin * 60000).toISOString(),
    lastReportGeneratedAt: new Date(Date.now() - pipelineAgeMin * 60000).toISOString()
  }, generatedAt: new Date(Date.now() - pipelineAgeMin * 60000).toISOString(),
  totalPublished: items.length, items, stats: {} });
  const serve = body => async () => ({ ok: true, status: 200, json: async () => body });
  const EMPTY = 'No newly verified intelligence available in the selected live window.';

  test('healthy pipeline with no recent reports: explicit empty state, genuine sync time shown separately, no archival rows', async () => {
    const old = Array.from({ length: 8 }, (_, i) => item('OLD-' + i, 24 * 40, 24 * 40, { priority: 100 - i, cisaKev: true, exploited: true }));
    const page = runCommandCenter(serve(feed(12, old)));
    await settle(settle2);
    const html = page.html('cdb-triage-feed');
    assert.ok(html.includes(EMPTY), 'required empty-state text');
    assert.match(html, /Feed state: HEALTHY\./, 'pipeline health is reported separately from record freshness');
    assert.match(html, /Last feed synchronisation: \d{4}-\d\d-\d\dT[\d:.]+Z \(12m ago\)/);
    assert.match(html, /<a href="\/archive\.html">open the Intelligence Archive<\/a>/);
    assert.doesNotMatch(html, /OLD-\d|Title OLD|ARCHIVAL/);
    assert.equal(page.text('homepage-feed-state'), 'HEALTHY', 'an empty live window must not turn a healthy pipeline red');
    assert.equal(page.text('cdb-live-badge'), 'LIVE', 'badge describes pipeline freshness; the list describes record freshness');
  });

  test('mixed feed: only records proven new are rendered, historical high-priority rows are not', async () => {
    const page = runCommandCenter(serve(feed(12, [
      item('OLD-CRIT', 24 * 60, 24 * 60, { priority: 100, threatLevel: 'CRITICAL' }),
      item('REINGESTED', 1, 24 * 25, { priority: 100, threatLevel: 'CRITICAL' }),
      item('NEW-A', 3, 3), item('NEW-B', 6, 6),
    ])));
    await settle(settle2);
    const html = page.html('cdb-triage-feed');
    assert.match(html, /Title NEW-A/);
    assert.match(html, /Title NEW-B/);
    assert.doesNotMatch(html, /OLD-CRIT|REINGESTED|ARCHIVAL/);
    assert.ok(html.indexOf('NEW-A') < html.indexOf('NEW-B'), 'newest ingestion first');
    assert.ok(!html.includes(EMPTY));
  });

  test('stale generated timestamp: STALE is visible everywhere and no historical row is presented as current', async () => {
    const old = [item('OLD-1', 24 * 20, 24 * 20, { priority: 100 }), item('OLD-2', 24 * 21, 24 * 21)];
    const page = runCommandCenter(serve(feed(20 * 24 * 60 + 180, old)));
    await settle(settle2);
    assert.equal(page.text('homepage-feed-state'), 'STALE');
    assert.match(page.text('cdb-runtime-text'), /^STALE · FEED AGE 20d 3h$/);
    assert.match(page.text('cdb-live-badge'), /^STALE · 20d 3h$/);
    const html = page.html('cdb-triage-feed');
    assert.ok(html.includes(EMPTY));
    assert.match(html, /Feed state: STALE\./);
    assert.doesNotMatch(html, /OLD-\d|LIVE/);
  });

  test('invalid JSON: the list says unavailable, never stays on "Loading", never shows records', async () => {
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected token < in JSON'); } }));
    await settle(settle2);
    const html = page.html('cdb-triage-feed');
    assert.match(html, /Live intelligence feed unavailable/);
    assert.match(html, /\(unreadable response\)/);
    assert.doesNotMatch(html, /Loading|Unexpected token|Title/);
    assert.equal(page.text('homepage-feed-state'), 'UNAVAILABLE');
    assert.equal(page.text('cdb-live-badge'), 'UNAVAILABLE');
  });

  test('unreachable feed (network failure and HTTP 503): visible UNAVAILABLE, no records', async () => {
    for (const [impl, detail] of [[async () => { throw new Error('network down'); }, 'unreadable response'], [async () => ({ ok: false, status: 503, json: async () => ({}) }), 'http 503']]) {
      const page = runCommandCenter(impl);
      await settle(settle2);
      const html = page.html('cdb-triage-feed');
      assert.match(html, /Live intelligence feed unavailable/);
      assert.ok(html.includes('(' + detail + ')'), detail);
      assert.equal(page.text('homepage-feed-state'), 'UNAVAILABLE');
    }
  });

  test('client fallback: if runtime-state.js never loads, nothing is shown as live', async () => {
    const page = runCommandCenter(serve(feed(12, [item('NEW-A', 3, 3), item('OLD-1', 24 * 40, 24 * 40)])), null, { noModel: true });
    await settle(settle2);
    const html = page.html('cdb-triage-feed');
    assert.match(html, /Live intelligence list unavailable/);
    assert.doesNotMatch(html, /Title NEW-A|Title OLD-1|ARCHIVAL/);
    assert.equal(page.hidden('cdb-live-badge'), true, 'no badge without the freshness model');
  });

  test('cross-domain divergence: each host renders only its own feed, never a blend', async () => {
    const soc = runCommandCenter(serve(feed(30, [item('SOC-NEW', 2, 2)])));
    const blog = runCommandCenter(serve(feed(20 * 24 * 60, [item('BLOG-OLD', 24 * 20, 24 * 20)])));
    await settle(settle2);
    assert.equal(soc.text('homepage-feed-state'), 'HEALTHY');
    assert.match(soc.html('cdb-triage-feed'), /Title SOC-NEW/);
    assert.equal(blog.text('homepage-feed-state'), 'STALE');
    assert.ok(blog.html('cdb-triage-feed').includes(EMPTY));
    assert.doesNotMatch(blog.html('cdb-triage-feed'), /SOC-NEW/);
    assert.doesNotMatch(soc.html('cdb-triage-feed'), /BLOG-OLD/);
  });

  test('item text is escaped: a hostile title cannot inject markup into the live list', async () => {
    const page = runCommandCenter(serve(feed(10, [item('NEW-X', 1, 1, { title: '<img src=x onerror=alert(1)>' })])));
    await settle(settle2);
    const html = page.html('cdb-triage-feed');
    assert.doesNotMatch(html, /<img/);
    assert.match(html, /&lt;img/);
  });
});

describe('live record freshness: shared policy, widget agreement and markup', () => {
  const widgetSrc = fs.readFileSync(path.join(ROOT, 'live-feed-widget.js'), 'utf8');
  const start = widgetSrc.indexOf('  function sharedLiveAuthority(');
  const end = widgetSrc.indexOf('  /* ── MAIN FETCH PIPELINE', start);
  const select = (win) => {
    const ctx = vm.createContext({ ...(win ? { window: win } : {}), CFG: { LOOKBACK_DAYS: 1, MAX_CARDS: 15 }, Date, Number, Object, Array,
      normaliseLocal: raw => ({ id: raw.id, published: raw.published, link: raw.link }) });
    vm.runInContext(widgetSrc.slice(start, end), ctx);
    return ctx.selectLocalItems;
  };
  const NOWMS = Date.parse('2026-11-12T12:00:00Z');
  const hrs = h => new Date(NOWMS - h * 3600000).toISOString();

  test('the live widget applies the same shared policy: a re-ingested old advisory is excluded', () => {
    const rows = [
      { id: 'NEW', _addedAt: hrs(2), pubDate: hrs(2) },
      { id: 'REINGESTED', _addedAt: hrs(1), pubDate: '2026-07-05' },
    ];
    assert.deepEqual(Array.from(select({ SentinelRuntimeState: RS })(rows, NOWMS), x => x.id), ['NEW']);
  });

  test('missing shared freshness authority withholds ALL live cards, including otherwise recent reports', () => {
    const rows = [{ id: 'NEW', _addedAt: hrs(2), pubDate: hrs(2) }, { id: 'ARCHIVE', _addedAt: hrs(24 * 40), pubDate: hrs(24 * 40) }];
    assert.deepEqual(Array.from(select(undefined)(rows, NOWMS), x => x.id), []);
    assert.deepEqual(Array.from(select({ SentinelRuntimeState: undefined })(rows, NOWMS), x => x.id), []);
  });

  test('neither live surface contains an archival fallback or its label', () => {
    const cc = fs.readFileSync(path.join(ROOT, 'apex-command-center.js'), 'utf8');
    assert.doesNotMatch(cc, /ARCHIVAL/, 'command center');
    for (const [name, src] of [['apex-command-center.js', cc], ['live-feed-widget.js', widgetSrc]]) {
      assert.doesNotMatch(src, /archived\s*\?\s*dated/, name);
    }
    // The widget keeps a legacy "archival" heading branch for items flagged _contentArchived,
    // but nothing may ever set that flag: selectLocalItems always emits false.
    assert.doesNotMatch(widgetSrc, /_contentArchived\s*=\s*true/, 'no code path may flag an item as archival-but-live');
    assert.doesNotMatch(cc, /30\s*\*\s*86400000|cutoff/, 'command center must not re-implement or widen the window rule');
    assert.match(cc, /RS\.selectLiveRecords\(/);
  });

  test('the empty state points at an Intelligence Archive that ships in the public build', () => {
    const { PUBLIC_ROOT_FILES } = require('../scripts/build-cloudflare-assets.js');
    assert.ok(PUBLIC_ROOT_FILES.includes('archive.html'));
    assert.ok(fs.existsSync(path.join(ROOT, 'archive.html')));
  });

  test('the live list is a polite live region so state changes are announced', () => {
    const index = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
    const open = index.match(/<div[^>]*id="cdb-triage-feed"[^>]*>/);
    assert.ok(open, 'container exists');
    assert.match(open[0], /aria-live="polite"/);
  });

  test('the empty and unavailable states wrap instead of truncating, and the stylesheet is cache-busted with the scripts', () => {
    const css = fs.readFileSync(path.join(ROOT, 'apex-command-center.css'), 'utf8');
    const rule = css.match(/\.cdb-feed-empty \.cdb-feed-title,\.cdb-feed-empty \.cdb-feed-sub\{([^}]*)\}/);
    assert.ok(rule, 'dedicated wrap rule exists');
    assert.match(rule[1], /white-space:normal/);
    assert.doesNotMatch(rule[1], /text-overflow:\s*ellipsis/, 'the customer-facing explanation must never be ellipsised');
    const cc = fs.readFileSync(path.join(ROOT, 'apex-command-center.js'), 'utf8');
    assert.match(cc, /class="cdb-feed-row cdb-feed-empty" role="status"/);
    const index = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
    const cssV = index.match(/\/apex-command-center\.css\?v=([^"']+)/);
    const jsV = index.match(/\/apex-command-center\.js\?v=([^"']+)/);
    assert.ok(cssV && jsV);
    assert.equal(cssV[1], jsV[1], 'stylesheet and script that depend on each other are bumped together');
  });
});

describe('shared live authority: timestamp strictness and pipeline evidence', () => {
  const NOWMS = Date.parse('2026-11-12T12:00:00Z');
  const rec = (added, pub) => ({ id: 'x', title: 't', _addedAt: added, pubDate: pub });
  const why = (item) => RS.classifyRecord(item, NOWMS).reason;

  test('a machine timestamp must be a full date-time WITH an offset', () => {
    assert.equal(why(rec('2026-11-12T11:00:00Z', '2026-11-12')), 'LIVE');
    assert.equal(why(rec('2026-11-12T11:00:00.123Z', '2026-11-12')), 'LIVE');
    assert.equal(why(rec('2026-11-12T16:30:00+05:30', '2026-11-12')), 'LIVE', 'an explicit offset is an unambiguous instant');
    assert.equal(why(rec('2026-11-12T11:00:00', '2026-11-12')), 'INVALID_TIMESTAMP', 'zone-less = local time in the browser');
    assert.equal(why(rec('2026-11-12T11:00', '2026-11-12')), 'INVALID_TIMESTAMP');
    assert.equal(why(rec('2026-11-12', '2026-11-12')), 'INVALID_TIMESTAMP', 'a date alone is not a report-addition instant');
    assert.equal(why(rec('Thu, 12 Nov 2026 11:00:00 GMT', '2026-11-12')), 'INVALID_TIMESTAMP', 'only ISO-8601 is accepted');
  });

  test('a source publication date may be date-only or a zoned date-time, never zone-less', () => {
    assert.equal(why(rec('2026-11-12T11:00:00Z', '2026-11-12')), 'LIVE');
    assert.equal(why(rec('2026-11-12T11:00:00Z', '2026-11-12T09:00:00Z')), 'LIVE');
    assert.equal(why(rec('2026-11-12T11:00:00Z', '2026-11-12T09:00:00')), 'INVALID_TIMESTAMP');
    assert.equal(why(rec('2026-11-12T11:00:00Z', 'November 12 2026')), 'INVALID_TIMESTAMP');
  });

  test('pipelineAllowsLive: only HEALTHY or a MEASURED, evidenced delay may show records', () => {
    const iso = m => new Date(NOWMS - m * 60000).toISOString();
    const ok = (state, ageMinutes, timestamp) => RS.pipelineAllowsLive({ state, ageMinutes, timestamp }, NOWMS);
    assert.equal(ok('HEALTHY', 30, iso(30)), true);
    assert.equal(ok('DEGRADED', 120, iso(120)), true, 'a measured 2 h delay');
    assert.equal(ok('DEGRADED', 180, iso(180)), true, 'the stale limit is inclusive');
    assert.equal(ok('DEGRADED', 181, iso(181)), false);
    assert.equal(ok('DEGRADED', null, null), false, 'DEGRADED without a clock is absence of evidence');
    assert.equal(ok('DEGRADED', null, iso(60)), false);
    assert.equal(ok('DEGRADED', 60, null), false);
    assert.equal(ok('HEALTHY', 30, new Date(NOWMS + 3600000).toISOString()), false, 'future timestamp');
    assert.equal(ok('HEALTHY', 30, iso(600)), false, 'age and timestamp must agree');
    assert.equal(ok('HEALTHY', -5, iso(0)), false);
    for (const state of ['STALE', 'UNAVAILABLE', 'CHECKING', 'UNVERIFIED', undefined]) assert.equal(ok(state, 10, iso(10)), false, String(state));
    for (const bad of [null, undefined, {}, 'HEALTHY', 7]) assert.equal(RS.pipelineAllowsLive(bad, NOWMS), false);
  });

  test('every real classification the model can produce is judged consistently', () => {
    const feedAt = ageMin => {
      const stamp=new Date(NOWMS - ageMin * 60000).toISOString();
      return { generatedAt:stamp, metadata:{lastPipelineRun:stamp,lastReportGeneratedAt:stamp},items:[] };
    };
    const allowed = ageMin => RS.pipelineAllowsLive(RS.classifyFeed({ ok: true, feed: feedAt(ageMin), nowMs: NOWMS }), NOWMS);
    assert.equal(allowed(10), true);
    assert.equal(allowed(150), true);
    assert.equal(allowed(181), false);
    assert.equal(allowed(60 * 24 * 20), false);
    assert.equal(RS.pipelineAllowsLive(RS.classifyFeed({ ok: true, feed: { items: [] }, nowMs: NOWMS }), NOWMS), false);
    assert.equal(RS.pipelineAllowsLive(RS.classifyFeed({ ok: false, error: 'timeout', nowMs: NOWMS }), NOWMS), false);
  });
});
