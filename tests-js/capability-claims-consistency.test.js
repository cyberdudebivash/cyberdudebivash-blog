'use strict';
// Regression test for a real customer-facing overclaim found while auditing
// the intelligence pipeline (GIOP v1): six live locations across
// index.html, api.html, enterprise.html, contact.html, and fetch-live-intel.js's
// generated post/API templates advertised "STIX/TAXII", "MISP formats", and
// "CSV" export — none of which exist anywhere in the codebase (confirmed by
// full-repo search). Only STIX 2.1 (api/v1/intel.js:buildSTIXBundle()) and
// JSON are real export formats. Fixed all six by removing the unimplemented
// claims, not by inventing a "corrected" replacement capability.
//
// This guards the narrowest, highest-confidence part of that fix: "TAXII" is
// a distinctive enough term that it has no legitimate unrelated use anywhere
// on this site, so a bare substring check is safe (unlike "MISP"/"CSV",
// which could plausibly appear in unrelated prose elsewhere and would need a
// more careful, context-aware check to avoid false positives).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

function readFile(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

const PAGES_THAT_MUST_NOT_CLAIM_TAXII = [
  'index.html', 'api.html', 'enterprise.html', 'contact.html',
];

for (const file of PAGES_THAT_MUST_NOT_CLAIM_TAXII) {
  test(`${file} does not claim TAXII support (no TAXII endpoint exists anywhere in the repo)`, () => {
    const src = readFile(file);
    assert.ok(!/TAXII/i.test(src), `${file} still mentions TAXII`);
  });
}

test('fetch-live-intel.js\'s generated templates do not claim TAXII support', () => {
  const src = readFile('fetch-live-intel.js');
  assert.ok(!/TAXII/i.test(src), 'fetch-live-intel.js still mentions TAXII in a template string');
});

// Paid-plan offer integrity (gap register ICF-P0-005). The Sentinel Team /
// Enterprise offer advertised capabilities with no implementation: team seats
// (one API key per account exists), Elastic SIEM export (only Splunk SPL and
// Sentinel KQL rule formats plus the live Microsoft Sentinel connector
// exist), per-tier response latency (one Worker serves every tier), "no rate
// limit" on a 100,000/day plan, and "priority data freshness" (one pipeline).
const OFFER_SURFACES = [
  'pricing.html', 'faq.html', 'api-dashboard.html', 'api.html',
  'revenue-conversion-v19.js', 'api/_lib/payment-utils.js',
];
const UNDELIVERED_OFFER_CLAIMS = [
  /\b\d+\s+(?:team\s+)?seats\b/i,
  /Unlimited team seats/i,
  /Splunk\s*\/\s*Sentinel\s*\/\s*Elastic/i,
  /Response latency/i,
  /no rate limit/i,
  /Priority data freshness/i,
];
for (const file of OFFER_SURFACES) {
  test(`${file} does not sell plan capabilities that no code delivers`, () => {
    const text = readFile(file);
    for (const re of UNDELIVERED_OFFER_CLAIMS) assert.doesNotMatch(text, re, `${file}: ${re}`);
  });
}

test('the SIEM export formats the offer names are real detection-download formats', () => {
  const intel = readFile('api/v1/intel.js');
  assert.match(intel, /format=sigma\|kql\|splunk/);
  const taxonomy = require('../api/_lib/siem-connector-taxonomy');
  const liveDeployable = Object.entries(taxonomy.KNOWN_PLATFORMS)
    .filter(([, p]) => p.capabilities.deploy_supported && !p.is_sandbox).map(([id]) => id);
  assert.ok(liveDeployable.length >= 1, 'offer names a live connector; at least one non-sandbox platform must be deployable');
});
