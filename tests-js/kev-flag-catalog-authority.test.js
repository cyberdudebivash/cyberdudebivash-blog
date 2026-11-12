'use strict';
// Regression: the live feed carried cisaKev=true on records the CISA KEV catalog does not
// contain. Verified 2026-11-12 against the real catalog (version 2026.11.10, 1779 entries):
// 37 of the 150 feed records claimed KEV membership; 33 are in the catalog, 4 are not --
// three are news/social ARTICLE records keyed SECURITYWEEK-*/REDDIT_CYBER-* (an article id
// can never be a KEV member) and one is a reddit-sourced CVE record absent from the catalog.
// All four were created in May-July by an older pipeline version and kept alive by the
// rolling-window merge (`existing.cisaKev || item.cisaKev`), then counted in the customer
// KPI "CISA KEV-confirmed records" (stats.cisaKev).
//
// Fix under test: KEV membership is a property of the authoritative catalog only.
// fetchCISAKev() remembers the FULL catalog it parsed; the live feed writer reconciles every
// record's flag against it before computing stats. All fixtures are SYNTHETIC (CVE-2099-*).
// No network is used: the https transport is stubbed.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const mod = require(path.join(__dirname, '..', 'fetch-live-intel.js'));
const { reconcileKevFlags, getKevCatalogIds, fetchCISAKev } = mod;

const rec = (id, source, extra = {}) => ({ id, source, cisaKev: false, exploited: false, ...extra });
const cat = (...ids) => new Set(ids);

test('a record in the authoritative catalog keeps / gains cisaKev=true', () => {
  const r = reconcileKevFlags([rec('CVE-2099-0001', 'cisa_kev', { cisaKev: true }), rec('CVE-2099-0002', 'thehackernews')], cat('CVE-2099-0001', 'CVE-2099-0002'));
  assert.deepEqual(r.items.map(i => i.cisaKev), [true, true]);
  assert.equal(r.confirmed, 1, 'only the previously-false record is a correction');
  assert.deepEqual(r.cleared, []);
});

test('news / social ARTICLE records can never be KEV members: the claim is cleared', () => {
  const claims = [rec('SECURITYWEEK-6906104d8606997d', 'securityweek', { cisaKev: true, exploited: true }),
    rec('REDDIT_CYBER-28e83926b85eda37', 'reddit_cyber', { cisaKev: true, exploited: true })];
  const r = reconcileKevFlags(claims, cat('CVE-2099-0001'));
  assert.deepEqual(r.items.map(i => i.cisaKev), [false, false]);
  assert.deepEqual(r.cleared, ['SECURITYWEEK-6906104d8606997d', 'REDDIT_CYBER-28e83926b85eda37']);
});

test('a CVE record claiming KEV that the catalog does not list is cleared, but a listed one is kept', () => {
  const r = reconcileKevFlags([rec('CVE-2099-0100', 'reddit_cyber', { cisaKev: true }), rec('CVE-2099-0001', 'sans_isc', { cisaKev: true })], cat('CVE-2099-0001'));
  assert.deepEqual(r.items.map(i => [i.id, i.cisaKev]), [['CVE-2099-0100', false], ['CVE-2099-0001', true]]);
});

test('exploited is never touched: it has its own evidence rules', () => {
  const r = reconcileKevFlags([rec('CVE-2099-0100', 'reddit_cyber', { cisaKev: true, exploited: true })], cat('CVE-2099-0001'));
  assert.equal(r.items[0].exploited, true);
  assert.equal(r.items[0].cisaKev, false);
});

test('an unknown catalog (null / empty / not a Set) changes nothing: an outage must not erase real KEV flags', () => {
  const input = [rec('CVE-2099-0001', 'cisa_kev', { cisaKev: true }), rec('SECURITYWEEK-x', 'securityweek', { cisaKev: true })];
  for (const unknown of [null, undefined, new Set(), [], {}]) {
    const r = reconcileKevFlags(input, unknown);
    assert.deepEqual(r.items.map(i => i.cisaKev), [true, true], String(unknown));
    assert.deepEqual(r.cleared, []);
  }
});

test('ids are matched case-insensitively and the input is never mutated', () => {
  const input = [rec('cve-2099-0001', 'x', { cisaKev: false })];
  const frozen = JSON.stringify(input);
  const r = reconcileKevFlags(input, cat('CVE-2099-0001'));
  assert.equal(r.items[0].cisaKev, true);
  assert.equal(JSON.stringify(input), frozen);
  assert.notEqual(r.items[0], input[0]);
});

test('malformed entries pass through untouched instead of throwing', () => {
  const r = reconcileKevFlags([null, undefined, 'str', 7, rec('CVE-2099-0001', 'x')], cat('CVE-2099-0001'));
  assert.deepEqual(r.items.slice(0, 4), [null, undefined, 'str', 7]);
  assert.equal(r.items[4].cisaKev, true);
  assert.deepEqual(reconcileKevFlags(null, cat('A')).items, []);
});

// ── adapter: remembers the FULL catalog, not just the incremental additions ─────
function stubTransport(t, body) {
  return t.mock.method(https, 'request', (_o, cb) => {
    const req = new EventEmitter(); req.write = () => {}; req.destroy = () => {};
    req.end = () => setImmediate(() => { const res = new EventEmitter(); res.statusCode = 200; res.headers = {}; res.setEncoding = () => {}; res.resume = () => {}; cb(res); res.emit('data', body); res.emit('end'); });
    return req;
  });
}
const entry = (id, dateAdded) => ({ cveID: id, vendorProject: 'V', product: 'P', vulnerabilityName: 'SYNTHETIC', dateAdded, shortDescription: 'SYNTHETIC FIXTURE', requiredAction: 'none', dueDate: '2099-12-31', knownRansomwareCampaignUse: 'Unknown', notes: '' });
const body = v => JSON.stringify({ title: 'SYNTHETIC KEV-shaped fixture', catalogVersion: 'test', vulnerabilities: v });

test('the adapter keeps every catalog id (including entries older than its incremental cutoff), upper-cased', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.parse('2026-11-12T12:00:00Z') });
  stubTransport(t, body([entry('CVE-2099-0001', '2026-11-12'), entry('cve-2099-0002', '2020-01-01')]));
  const returned = await fetchCISAKev({ sourceFetchState: {} });
  const ids = getKevCatalogIds();
  assert.ok(ids instanceof Set);
  assert.ok(ids.has('CVE-2099-0001') && ids.has('CVE-2099-0002'), 'old entries are part of the authority set');
  assert.ok(returned.every(i => i.id !== 'cve-2099-0002' && i.id !== 'CVE-2099-0002'), 'incremental output is unchanged: old entries are not re-published');
});

test('an empty or unparseable catalog never replaces a good one', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.parse('2026-11-12T12:00:00Z') });
  stubTransport(t, body([entry('CVE-2099-0007', '2026-11-12')]));
  await fetchCISAKev({ sourceFetchState: {} });
  const good = getKevCatalogIds();
  assert.ok(good.has('CVE-2099-0007'));
  t.mock.restoreAll();
  stubTransport(t, body([]));
  await fetchCISAKev({ sourceFetchState: {} });
  assert.equal(getKevCatalogIds(), good, 'empty catalog is "unknown", not "nothing is KEV"');
  t.mock.restoreAll();
  stubTransport(t, '<html>not json');
  await assert.rejects(fetchCISAKev({ sourceFetchState: {} }));
  assert.equal(getKevCatalogIds(), good);
});

// ── wiring: reconcile BEFORE stats, and a bug here must never stop publication ───
test('the live feed writer reconciles before computing stats, and fails open', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'fetch-live-intel.js'), 'utf8');
  const call = src.indexOf('reconcileKevFlags(liveItems, lastKevCatalogIds)');
  const stats = src.indexOf('cisaKev:    liveItems.filter(i=>i.cisaKev).length');
  assert.ok(call > 0 && stats > call, 'stats.cisaKev must be computed from reconciled items');
  const block = src.slice(src.lastIndexOf('try {', call), src.indexOf('catch (e)', call) + 120);
  assert.match(block, /KEV reconciliation skipped/, 'a failure is logged and publication continues');
});
