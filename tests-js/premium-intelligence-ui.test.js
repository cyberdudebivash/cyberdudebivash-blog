'use strict';
// Premium Intelligence storefront and library (2026-10-02 owner decision:
// Sentinel APEX is the only payment authority). Guards that no page sells a
// report on its own again, that every conversion link goes to the Sentinel
// APEX platform, and that the plan price is never hardcoded here.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = f => fs.readFileSync(path.join(ROOT, f), 'utf8');
const store = read('intelligence-store.html');
const library = read('customer-library.html');

test('the store loads no Razorpay script and never calls standalone checkout or verify', () => {
  assert.doesNotMatch(store, /checkout\.razorpay\.com|new Razorpay|typeof Razorpay/);
  assert.doesNotMatch(store, /action=(checkout|verify)/);
});

test('no per-report price or buy button on the store', () => {
  assert.doesNotMatch(store, /price_minor|Intl\.NumberFormat|money\(/);
  assert.doesNotMatch(store, /\bBuy\b/); // visible copy; the .buy CSS class is styling only
  assert.doesNotMatch(store, /purchase|one-time sale|secure checkout/i);
  assert.doesNotMatch(store, /₹\s?\d|INR\s?\d|\$\s?\d/);
  assert.match(store, /Unlock with Sentinel APEX/);
  assert.match(store, /Included with Sentinel APEX PRO/);
});

test('every upgrade link on the store and library stays on intel.cyberdudebivash.com', () => {
  for (const page of [store, library]) {
    const links = [...page.matchAll(/https:\/\/[^'"`\s)]*upgrade\.html[^'"`\s)]*/g)].map(m => m[0]);
    assert.ok(links.length > 0);
    for (const l of links) assert.ok(l.startsWith('https://intel.cyberdudebivash.com/upgrade.html'), l);
    assert.match(page, /UPGRADE_ORIGIN='https:\/\/intel\.cyberdudebivash\.com\/'/);
  }
  assert.match(store, /startsWith\(UPGRADE_ORIGIN\)\?u:FALLBACK_UPGRADE/);
});

test('the plan price comes only from the Sentinel APEX pricing API (intel-plans.js), with a neutral fallback', () => {
  assert.match(store, /<script src="\/intel-plans\.js" defer><\/script>/);
  assert.match(store, /data-intel-price="PRO"[^>]*>see Sentinel APEX pricing</);
});

test('the store shows the report SHA-256, version, evidence cut-off and sources', () => {
  assert.match(store, /SHA-256 \$\{r\.artifact_sha256\}/);
  assert.match(store, /Version \$\{v\.version\} · evidence cut-off \$\{v\.evidence_cutoff\} · \$\{s\.sources\} sources/);
});

test('the library accepts Sentinel APEX (cdb_) and earlier blog (sentinel_) keys, sent only in a header', () => {
  assert.match(library, /startsWith\('sentinel_'\)&&!key\.startsWith\('cdb_'\)/);
  assert.match(library, /Authorization:`Bearer \$\{key\}`/);
  assert.doesNotMatch(library, /[?&]api_key=/);
  assert.match(library, /INCLUDED WITH SENTINEL APEX/);
});
