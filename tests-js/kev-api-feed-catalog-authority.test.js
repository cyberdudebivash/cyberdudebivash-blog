'use strict';
// Regression: the customer API feeds carried `cisa_kev: false` on records whose CVE the authoritative
// CISA KEV catalog lists. Measured 2026-11-14 against catalog 2026.11.13 (1781 entries) on blog main
// 331a5962:
//   api/intel/live.json       35 of 100 items had their own CVE in the catalog but cisa_kev=false
//   api/intel/raw.json        37 of 118  (the paid Enterprise feed)
//   api/intel/ransomware.json  3 of 3
//   33 of the 35 live.json cases had KEV dateAdded on or before the item's first_seen, i.e. the flag
//   was already wrong when generated, not merely stale.
// Root cause: reconcileKevFlags() (catalog authority) is applied to the ROOT feed live-intel.json only.
// The API block took cisa_kev from the S2N output as-is, and the rolling window re-read from the previous
// api/intel/live.json carried every earlier wrong `false` forward indefinitely.
//
// Fix under test: the same authority (via reconcileApiKevFlags, a thin snake_case adapter over
// reconcileKevFlags) is applied at the S2N output boundary to every API feed and to the rolled-in window.
// An absent/empty catalog changes nothing ("unknown", never "zero"). All fixtures are SYNTHETIC
// (CVE-2099-*); no network is used.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

process.env.CDB_KEV_MIN_CATALOG_ENTRIES = '1';
const SRC_PATH = path.join(__dirname, '..', 'fetch-live-intel.js');
const mod = require(SRC_PATH);
const { reconcileApiKevFlags } = mod;
const cat = (...ids) => new Set(ids);
const api = (id, extra = {}) => ({ id, title: 't-' + id, final_ps: 70, cisa_kev: false, ...extra });

test('the helper is exported (the structural test below depends on the same name)', () => {
  assert.equal(typeof reconcileApiKevFlags, 'function');
});

test('an item whose id is in the catalog but is flagged false is corrected to true; the input is not mutated', () => {
  const input = [api('CVE-2099-0001'), api('CVE-2099-0002')];
  const snapshot = JSON.parse(JSON.stringify(input));
  const r = reconcileApiKevFlags(input, cat('CVE-2099-0001'));
  assert.deepEqual(r.items.map(i => i.cisa_kev), [true, false]);
  assert.deepEqual(r.confirmedIds, ['CVE-2099-0001']);
  assert.deepEqual(r.cleared, []);
  assert.deepEqual(input, snapshot, 'input array and records are untouched');
});

test('an item with no cisa_kev field at all and an id in the catalog gains cisa_kev=true', () => {
  const r = reconcileApiKevFlags([{ id: 'CVE-2099-0003', title: 'x' }], cat('CVE-2099-0003'));
  assert.equal(r.items[0].cisa_kev, true);
  assert.equal(r.items[0].title, 'x');
});

test('a KEV claim whose id is not in the catalog is cleared (news/social article ids can never be members)', () => {
  const r = reconcileApiKevFlags([api('SECURITYWEEK-abc123', { cisa_kev: true }), api('CVE-2099-0009', { cisa_kev: true })], cat('CVE-2099-0001'));
  assert.deepEqual(r.items.map(i => i.cisa_kev), [false, false]);
  assert.deepEqual(r.cleared, ['SECURITYWEEK-abc123', 'CVE-2099-0009']);
});

test('records that are already correct are returned as the same objects (no copy, no new fields)', () => {
  const a = api('CVE-2099-0001', { cisa_kev: true }); const b = api('CVE-2099-0002'); const c = { id: 'CVE-2099-0003' };
  const r = reconcileApiKevFlags([a, b, c], cat('CVE-2099-0001'));
  assert.equal(r.items[0], a); assert.equal(r.items[1], b); assert.equal(r.items[2], c);
  assert.equal('cisa_kev' in r.items[2], false, 'an absent flag on a non-member stays absent');
  assert.deepEqual(r.confirmedIds, []); assert.deepEqual(r.cleared, []);
});

test('id matching is case-insensitive, like the root feed', () => {
  const r = reconcileApiKevFlags([api('cve-2099-0001')], cat('CVE-2099-0001'));
  assert.equal(r.items[0].cisa_kev, true);
});

test('an absent, empty or invalid catalog changes nothing: unknown is never treated as zero', () => {
  const items = [api('CVE-2099-0001'), api('CVE-2099-0002', { cisa_kev: true })];
  for (const catalog of [null, undefined, new Set(), {}, 'nope']) {
    const r = reconcileApiKevFlags(items, catalog);
    assert.deepEqual(r.items, items);
    assert.deepEqual(r.confirmedIds, []); assert.deepEqual(r.cleared, []);
  }
});

test('non-object elements and a non-array input are tolerated', () => {
  const r = reconcileApiKevFlags([null, 'x', 7, api('CVE-2099-0001')], cat('CVE-2099-0001'));
  assert.deepEqual(r.items.slice(0, 3), [null, 'x', 7]);
  assert.equal(r.items[3].cisa_kev, true);
  assert.deepEqual(reconcileApiKevFlags(undefined, cat('CVE-2099-0001')).items, []);
});

test('the camelCase working field never leaks into a customer record, and every other field is preserved', () => {
  const rec = api('CVE-2099-0001', { vendor: 'V', cvss: 9.8, merged_sources: ['nvd'], explanation: 'e' });
  const out = reconcileApiKevFlags([rec], cat('CVE-2099-0001')).items[0];
  assert.equal('cisaKev' in out, false);
  assert.deepEqual({ ...out, cisa_kev: false }, rec);
});

test('production-shaped case: a ransomware feed whose every CVE is a catalog member is fully flagged', () => {
  const feed = ['CVE-2099-0101', 'CVE-2099-0102', 'CVE-2099-0103'].map(id => api(id, { ransomware: true }));
  const r = reconcileApiKevFlags(feed, cat('CVE-2099-0101', 'CVE-2099-0102', 'CVE-2099-0103'));
  assert.deepEqual(r.items.map(i => i.cisa_kev), [true, true, true]);
  assert.equal(r.confirmedIds.length, 3);
});

// ---- the API generation block must route EVERY feed through the catalog authority ----
const src = fs.readFileSync(SRC_PATH, 'utf8');
const start = src.indexOf('formatForFeed(s2nResult)');
const end = src.indexOf('API files written:');
const block = src.slice(start, end);

test('structural: the API block locates and is non-trivial', () => {
  assert.ok(start > 0 && end > start && block.length > 2000);
});

test('structural: live, top-threats, raw, the passed list (ransomware + per-CVE) and the rolled-in window are each reconciled', () => {
  assert.equal((block.match(/\bkevApi\(/g) || []).length, 5);
  for (const name of ['s2nLive', 's2nTop', 's2nRaw', 's2nResult.passed', 'windowItems']) {
    assert.ok(block.includes(`kevApi(${name})`), `kevApi(${name}) missing`);
  }
});

test('structural: no feed is built from an unreconciled source any more', () => {
  assert.equal((block.match(/s2nResult\.passed/g) || []).length, 1, 's2nResult.passed is read only inside kevApi()');
  assert.equal((block.match(/\bwindowItems\.forEach/g) || []).length, 0, 'the unreconciled window must not be merged');
  assert.ok(/windowKevItems\.forEach/.test(block));
  assert.ok(/const ransomItems = passedItems\.filter/.test(block));
  assert.ok(/const cveCandidates = passedItems/.test(block));
  assert.ok(/items: rawItems,/.test(block) && /items: topItems,/.test(block) && /items: rolledLiveItems,/.test(block));
});

test('structural: an unverified catalog is reported loudly, never silently treated as "zero KEV"', () => {
  assert.ok(/KEV\(api\): authoritative catalog not verified this run; cisa_kev left as produced upstream \(UNKNOWN, not zero\)/.test(block));
});
