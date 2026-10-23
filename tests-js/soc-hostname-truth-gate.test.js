'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {ORIGIN, ROUTES, assess} = require('../scripts/soc-hostname-truth-gate.cjs');

function fixture(route, {canonical = ORIGIN + route, og = ORIGIN + route, extra = ''} = {}) {
  return '<!doctype html><html><head><title>SENTINEL APEX SOC</title>' +
    '<link rel="canonical" href="' + canonical + '">' +
    '<meta property="og:url" content="' + og + '">' +
    '</head><body>CYBERDUDEBIVASH ECOSYSTEM ' +
    'not an active 24/7 monitoring service contact@cyberdudebivash.in ' +
    extra + '</body></html>';
}
test('approved SOC identity fixtures pass on all routes', () => {
  for (const route of ROUTES) assert.deepEqual(assess(route, fixture(route)), []);
});
test('legacy blog canonical fails even when page otherwise appears healthy', () => {
  const route = '/soc-readiness-assessment.html';
  assert.deepEqual(assess(route, fixture(route, {
    canonical:'https://blog.cyberdudebivash.in' + route,
    og:'https://blog.cyberdudebivash.in' + route
  })), ['SOC_CANONICAL_MISMATCH','SOC_OG_URL_MISMATCH']);
});
test('missing and duplicated canonical/OG identity fail closed', () => {
  const html = fixture('/').replace(/<link rel="canonical"[^>]*>/, '');
  assert.ok(assess('/', html).includes('SOC_CANONICAL_MISMATCH'));
  const duplicated = fixture('/') + '<meta property="og:url" content="' + ORIGIN + '/">';
  assert.ok(assess('/', duplicated).includes('SOC_OG_URL_MISMATCH'));
});
test('legacy legal seller and false incorporation are rejected', () => {
  const html = fixture('/terms.html', {extra:'CyberDudeBivash Private Limited'})
    .replace('CYBERDUDEBIVASH ECOSYSTEM', 'SENTINEL APEX ECOSYSTEM');
  const errors = assess('/terms.html', html);
  assert.ok(errors.includes('SELLER_IDENTITY_MISSING'));
  assert.ok(errors.includes('UNSUPPORTED_INCORPORATION'));
});
test('assessment must not silently omit commercial availability boundary or contact', () => {
  const html = fixture('/soc-readiness-assessment.html')
    .replace('not an active 24/7 monitoring service', '')
    .replace('contact@cyberdudebivash.in', '');
  assert.deepEqual(assess('/soc-readiness-assessment.html', html),
    ['SERVICE_BOUNDARY_MISSING','ENQUIRY_CONTACT_MISSING']);
});
test('oversized, empty and unsupported routes are rejected', () => {
  assert.deepEqual(assess('/', ''), ['INVALID_HTML']);
  assert.deepEqual(assess('/unapproved', fixture('/')), ['INVALID_HTML']);
  assert.deepEqual(assess('/', 'a'.repeat(2_000_001)), ['INVALID_HTML']);
});
test('unsupported SOC service and certification statements are rejected', () => {
  const errors = assess('/', fixture('/', {extra:'SOC 2 Type II certified'}));
  assert.ok(errors.includes('UNSUPPORTED_SERVICE_OR_CERTIFICATION'));
});
