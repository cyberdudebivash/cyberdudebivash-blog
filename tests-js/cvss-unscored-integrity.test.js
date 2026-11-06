'use strict';
// Regression: an UNSCORED vulnerability was published as "CVSS 0" / severity LOW.
//
// Real case (main 78aa576b): CVE-2024-27834 was added to CISA KEV on 2026-11-04,
// before NVD had analysed it (NVD scored it 5.5 MEDIUM a day later). The KEV adapter
// correctly emits `cvss: null`, and generatePostHTML() correctly renders `null` as
// "Not assigned"/UNASSESSED (see static-cti-cvss-integrity.test.js). But the
// enrichment stage in between rewrote `cvss: parseFloat(item.cvss || item.cvssScore || 0) || 0`,
// so null/undefined became the NUMBER 0 -- indistinguishable from a genuine, source-verified
// 0.0 -- and the published post, its description/OG/Twitter text, its OG image URL
// (`severity=LOW&cvss=0`) and live-intel.json all carried the false zero.
//
// The existing renderer test could not catch this because it feeds `cvss: null` straight to
// the renderer and skips the enrichment stage. These tests span BOTH layers.
//
// All records are SYNTHETIC (CVE-2099-*). No network. Hermetic: the enrichment pipeline
// persists api/intel/threat-graph.json and api/intel/campaigns.json as a side effect, so
// exactly those two writes are intercepted below (every other write passes through) and the
// test never modifies tracked repository files.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { runEnrichmentPipeline } = require(path.join(__dirname, '..', 'api', '_lib', 'enrichment-pipeline.js'));
const { generatePostHTML } = require(path.join(__dirname, '..', 'fetch-live-intel.js'));

function kev(id, extra = {}) {
  return {
    source: 'cisa_kev', type: 'CVE_REPORT', id,
    title: `${id}: Synthetic Vendor Product Improper Authentication Vulnerability — CISA KEV Active Exploitation`,
    desc: 'SYNTHETIC FIXTURE: an improper authentication vulnerability in a synthetic product.',
    refs: ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog'], pubDate: '2026-11-04',
    vendor: 'SyntheticVendor', product: 'SyntheticProduct', vulnName: 'Synthetic improper authentication',
    exploited: true, cisaKev: true, ransomware: false, iocs: [], cves: [id], sourceCount: 1, daysOld: 0,
    priority: 81, threatLevel: 'HIGH',
    ...extra,
  };
}

// One pipeline run for every case (the enrichment graph load is the slow part).
const CASES = {
  null_score:        kev('CVE-2099-1001', { cvss: null }),
  missing_score:     (() => { const x = kev('CVE-2099-1002'); delete x.cvss; return x; })(),
  empty_string:      kev('CVE-2099-1003', { cvss: '' }),
  not_a_number:      kev('CVE-2099-1004', { cvss: 'n/a' }),
  nan:               kev('CVE-2099-1005', { cvss: NaN }),
  too_high:          kev('CVE-2099-1006', { cvss: 11 }),
  negative:          kev('CVE-2099-1007', { cvss: -1 }),
  infinity:          kev('CVE-2099-1008', { cvss: Infinity }),
  boolean:           kev('CVE-2099-1009', { cvss: true }),
  real_zero:         kev('CVE-2099-1010', { cvss: 0 }),
  scored:            kev('CVE-2099-1011', { cvss: 5.5 }),
  numeric_string:    kev('CVE-2099-1012', { cvss: '7.5' }),
  alias_fallback:    kev('CVE-2099-1013', { cvss: null, cvssScore: 6.1 }),
  legacy_placeholder:kev('CVE-2099-1014', { cvss: 0, cvssScore: 5.5 }),
};
const origLog = console.log;
const realWriteFileSync = fs.writeFileSync;
const PIPELINE_OUTPUTS = /api[\\/]intel[\\/](?:campaigns|threat-graph)\.json$/;
const interceptedWrites = [];
console.log = () => {};                       // the pipeline is very chatty
fs.writeFileSync = function (target, ...rest) {
  if (PIPELINE_OUTPUTS.test(String(target))) { interceptedWrites.push(path.basename(String(target))); return undefined; }
  return realWriteFileSync.call(this, target, ...rest);
};
let enriched;
try {
  enriched = Object.fromEntries(
    runEnrichmentPipeline(Object.values(CASES)).enrichedItems.map((e) => [e.id, e]),
  );
} finally { console.log = origLog; fs.writeFileSync = realWriteFileSync; }
const after = (name) => enriched[CASES[name].id];

test('hermetic: the pipeline side-effect writes were intercepted, not written to the repo', () => {
  assert.deepEqual([...new Set(interceptedWrites)].sort(), ['campaigns.json', 'threat-graph.json']);
  assert.equal(fs.writeFileSync, realWriteFileSync, 'fs.writeFileSync must be restored');
});

test('enrichment preserves "no score" as null, never as the number 0', () => {
  for (const name of ['null_score', 'missing_score', 'empty_string', 'not_a_number']) {
    assert.equal(after(name).cvss, null, `${name} must stay unscored (null), got ${after(name).cvss}`);
  }
});

test('enrichment rejects invalid numeric values instead of inventing a score', () => {
  for (const name of ['nan', 'too_high', 'negative', 'infinity', 'boolean']) {
    assert.equal(after(name).cvss, null, `${name} must not become a score, got ${after(name).cvss}`);
  }
});

test('a genuine source-verified 0.0 is preserved as numeric zero (distinct from unscored)', () => {
  assert.equal(after('real_zero').cvss, 0);
  assert.notEqual(after('real_zero').cvss, after('null_score').cvss);
});

test('real scores pass through unchanged, including numeric strings', () => {
  assert.equal(after('scored').cvss, 5.5);
  assert.equal(after('numeric_string').cvss, 7.5);
});

test('cvssScore alias is used only when cvss is absent or a legacy 0 placeholder (backward compatible)', () => {
  assert.equal(after('alias_fallback').cvss, 6.1);
  assert.equal(after('legacy_placeholder').cvss, 5.5);
});

test('END-TO-END: an unscored KEV record is published as "Not assigned", never "CVSS 0" / LOW', () => {
  const { html } = generatePostHTML(after('null_score'));
  assert.match(html, /CVSS Not assigned/);
  assert.doesNotMatch(html, /CVSS 0(?![.\d])/, 'no false "CVSS 0" anywhere in the page');
  assert.doesNotMatch(html, /\(CVSS 0\)/);
  const og = html.match(/<meta property="og:image" content="([^"]+)"/)[1];
  assert.match(og, /severity=UNASSESSED/);
  assert.doesNotMatch(og, /severity=LOW/);
  assert.doesNotMatch(og, /cvss=0(?!\.)/, 'OG image URL must not carry cvss=0');
  assert.doesNotMatch(html, /CVSS LOW/);
});

test('END-TO-END: an unscored record is not mislabelled by CISA KEV / editorial priority either', () => {
  const { html } = generatePostHTML(after('missing_score'));
  assert.match(html, /CVSS Not assigned/);
  assert.match(html, /CISA KEV/, 'KEV status is still shown, as its own signal');
  assert.doesNotMatch(html, /CVSS (?:CRITICAL|HIGH|MEDIUM|LOW)\b/, 'no CVSS severity derived from a missing score');
});

test('END-TO-END: a scored record still renders its score and the matching technical severity', () => {
  const { html } = generatePostHTML(after('scored'));
  assert.match(html, /CVSS 5\.5/);
  assert.match(html, /MEDIUM/);
  const og = html.match(/<meta property="og:image" content="([^"]+)"/)[1];
  assert.match(og, /severity=MEDIUM/);
  assert.match(og, /cvss=5\.5/);
});

test('END-TO-END: a genuine 0.0 is treated as a scored record, not as "Not assigned"', () => {
  const { html } = generatePostHTML(after('real_zero'));
  assert.doesNotMatch(html, /CVSS Not assigned/);
  assert.match(html, /CVSS 0(?![.\d])/);
});
