'use strict';
// CISA KEV catalog adoption must be validated, and its provenance recorded.
//
// #564 made KEV membership catalog-authoritative. A catalog that is merely non-empty is not
// enough: a partial or truncated (but syntactically valid) response would be adopted as
// "the" authority and reconciliation would then clear every real flag it happens to omit.
// This suite pins the fail-closed behaviour and the auditable provenance written to
// live-intel.json metadata.kevCatalog. Fixtures are SYNTHETIC (CVE-2099-*). No network.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const mod = require(path.join(__dirname, '..', 'fetch-live-intel.js'));
const { parseKevCatalog, reconcileKevFlags, fetchCISAKev, getKevCatalogIds, getKevCatalogMeta, resetKevCatalogState } = mod;

const entry = (id, dateAdded = '2026-11-12') => ({ cveID: id, vendorProject: 'V', product: 'P', vulnerabilityName: 'SYNTHETIC',
  dateAdded, shortDescription: 'SYNTHETIC FIXTURE', requiredAction: 'none', dueDate: '2099-12-31', knownRansomwareCampaignUse: 'Unknown', notes: '' });
const many = n => Array.from({ length: n }, (_, i) => entry('CVE-2099-' + String(10000 + i)));
const doc = (vulns, extra = {}) => ({ title: 'SYNTHETIC KEV-shaped fixture', catalogVersion: '2099.01.01', dateReleased: '2099-01-01T00:00:00Z',
  count: vulns.length, vulnerabilities: vulns, ...extra });

// ── parseKevCatalog (pure) ───────────────────────────────────────────────────
test('a complete catalog above the floor is adopted, with version and counts', () => {
  const r = parseKevCatalog(doc(many(1200)));
  assert.equal(r.ok, true);
  assert.equal(r.entries, 1200);
  assert.equal(r.catalogVersion, '2099.01.01');
  assert.equal(r.dateReleased, '2099-01-01T00:00:00Z');
  assert.ok(r.ids instanceof Set && r.ids.has('CVE-2099-10000'));
});

test('partial catalog: a count that disagrees with the array is rejected (truncated but valid JSON)', () => {
  const full = many(1200);
  const partial = doc(full.slice(0, 5), { count: 1200 });
  const r = parseKevCatalog(partial, 1);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'COUNT_MISMATCH');
  assert.equal(r.declared, 1200);
  assert.equal(r.received, 5);
});

test('partial catalog: a tiny array is rejected even when its own count is consistent', () => {
  const r = parseKevCatalog(doc(many(40)));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'CATALOG_TOO_SMALL');
  assert.equal(r.minimum, 1000);
});

test('duplicates are de-duplicated and counted, never double-counted toward the floor', () => {
  const v = [...many(1100), ...many(50)];
  const r = parseKevCatalog(doc(v));
  assert.equal(r.ok, true);
  assert.equal(r.entries, 1100);
  assert.equal(r.duplicates, 50);
  assert.equal(parseKevCatalog(doc([...many(990), ...many(990)])).reason, 'CATALOG_TOO_SMALL', '1980 rows but only 990 distinct ids');
});

test('invalid identifiers are ignored, counted, and never become authority', () => {
  const v = [...many(1100), entry('NOT-A-CVE'), entry('CVE-2099-12'), entry(''), { cveID: null }, null, 'x', entry('SECURITYWEEK-6906104d8606997d')];
  const r = parseKevCatalog(doc(v));
  assert.equal(r.ok, true);
  assert.equal(r.entries, 1100);
  assert.equal(r.invalid, 7);
  assert.equal(r.ids.has('NOT-A-CVE'), false);
  assert.equal(r.ids.has('SECURITYWEEK-6906104D8606997D'), false);
});

test('ids are normalised to upper case', () => {
  const v = many(1100); v.push(entry('cve-2099-77777'));
  assert.equal(parseKevCatalog(doc(v)).ids.has('CVE-2099-77777'), true);
});

test('missing or malformed documents are rejected, never adopted', () => {
  for (const bad of [null, undefined, 'str', 7, [], {}, { vulnerabilities: 'x' }, { vulnerabilities: {} }]) {
    const r = parseKevCatalog(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
    assert.equal(r.reason, 'NO_VULNERABILITIES_ARRAY');
  }
  assert.equal(parseKevCatalog(doc(many(1100), { count: 'twelve' })).reason, 'COUNT_MISMATCH');
});

test('a catalog without a count field is still judged by the size floor', () => {
  const noCount = { catalogVersion: 'x', vulnerabilities: many(1100) };
  assert.equal(parseKevCatalog(noCount).ok, true);
  assert.equal(parseKevCatalog({ vulnerabilities: many(10) }).reason, 'CATALOG_TOO_SMALL');
});

// ── reconciliation never runs on an unadopted catalog ────────────────────────
test('a rejected catalog leaves every flag untouched (nothing is "confirmed absent")', () => {
  const rec = (id, k) => ({ id, source: 'x', cisaKev: k });
  const items = [rec('CVE-2099-10000', true), rec('CVE-2099-99999', true), rec('SECURITYWEEK-x', false)];
  const rejected = parseKevCatalog(doc(many(5), { count: 1200 }), 1);
  assert.equal(rejected.ok, false);
  const out = reconcileKevFlags(items, rejected.ok ? rejected.ids : null);
  assert.deepEqual(out.items.map(i => i.cisaKev), [true, true, false]);
  assert.deepEqual(out.cleared, []);
});

// ── adapter: adoption, retention and provenance ──────────────────────────────
function stubTransport(t, body) {
  return t.mock.method(https, 'request', (_o, cb) => {
    const req = new EventEmitter(); req.write = () => {}; req.destroy = () => {};
    req.end = () => setImmediate(() => { const res = new EventEmitter(); res.statusCode = 200; res.headers = {}; res.setEncoding = () => {}; res.resume = () => {}; cb(res); res.emit('data', body); res.emit('end'); });
    return req;
  });
}
const freeze = t => t.mock.timers.enable({ apis: ['Date'], now: Date.parse('2026-11-12T12:00:00Z') });

test('no fetch yet: provenance is UNVERIFIED with an explicit reason', () => {
  resetKevCatalogState();
  assert.equal(getKevCatalogIds(), null);
  assert.deepEqual(getKevCatalogMeta(), { status: 'UNVERIFIED', reason: 'CATALOG_NOT_FETCHED_THIS_RUN' });
});

test('a complete catalog is adopted and its provenance is VERIFIED with version and time', async (t) => {
  resetKevCatalogState(); freeze(t);
  stubTransport(t, JSON.stringify(doc(many(1200))));
  await fetchCISAKev({ sourceFetchState: {} });
  assert.equal(getKevCatalogIds().size, 1200);
  const m = getKevCatalogMeta();
  assert.equal(m.status, 'VERIFIED');
  assert.equal(m.catalogVersion, '2099.01.01');
  assert.equal(m.entries, 1200);
  assert.equal(m.verifiedAt, '2026-11-12T12:00:00.000Z');
});

test('a partial catalog is not adopted: provenance UNVERIFIED, no authority, reason recorded', async (t) => {
  resetKevCatalogState(); freeze(t);
  stubTransport(t, JSON.stringify(doc(many(5), { count: 1200 })));
  await fetchCISAKev({ sourceFetchState: {} });
  assert.equal(getKevCatalogIds(), null);
  const m = getKevCatalogMeta();
  assert.equal(m.status, 'UNVERIFIED');
  assert.equal(m.reason, 'COUNT_MISMATCH');
});

test('a later bad catalog never downgrades or re-stamps an already verified snapshot', async (t) => {
  resetKevCatalogState(); freeze(t);
  stubTransport(t, JSON.stringify(doc(many(1200))));
  await fetchCISAKev({ sourceFetchState: {} });
  const good = getKevCatalogIds(), goodMeta = { ...getKevCatalogMeta() };
  t.mock.restoreAll();
  stubTransport(t, JSON.stringify(doc(many(3), { count: 3 })));
  await fetchCISAKev({ sourceFetchState: {} });
  assert.equal(getKevCatalogIds(), good, 'authority snapshot retained');
  assert.deepEqual(getKevCatalogMeta(), goodMeta, 'provenance not re-certified or altered');
});

test('an unparseable response fails the adapter and leaves provenance untouched', async (t) => {
  resetKevCatalogState(); freeze(t);
  stubTransport(t, '<html>not json');
  await assert.rejects(fetchCISAKev({ sourceFetchState: {} }));
  assert.equal(getKevCatalogIds(), null);
  assert.equal(getKevCatalogMeta().status, 'UNVERIFIED');
});

// ── wiring: provenance is part of the published feed contract ────────────────
test('live-intel.json metadata carries kevCatalog provenance, computed after reconciliation inputs exist', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'fetch-live-intel.js'), 'utf8');
  assert.match(src, /metadata: \{ generated: _liveGenTs, version: '5\.0', pipeline: 'SENTINEL APEX v5\.0', platform: 'blog\.cyberdudebivash\.in', kevCatalog: getKevCatalogMeta\(\) \}/);
  assert.match(src, /KEV_MIN_CATALOG_ENTRIES = 1000/);
  assert.doesNotMatch(src, /catalogIds\.size > 0\) lastKevCatalogIds/, 'the bare non-empty check must not return');
});
