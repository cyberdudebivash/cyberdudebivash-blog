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

test('visible Terms legacy hostname blocks release while historical image URL remains allowed', () => {
  const clean = fixture('/terms.html', {extra:'<img src="https://blog.cyberdudebivash.in/og-image.png" alt="Legacy CTI artwork">'});
  assert.deepEqual(assess('/terms.html', clean), []);
  const stale = fixture('/terms.html', {extra:'<p class="sub">Effective date · blog.cyberdudebivash.in</p>'});
  assert.ok(assess('/terms.html', stale).includes('LEGACY_VISIBLE_LEGAL_HOST'));
});
test('About page must not assert unsupported around-the-clock monitoring or retired social identity', () => {
  const stale = fixture('/about.html', {
    extra:'<p>We monitor official vulnerability authorities and global security reporting around the clock.</p>' +
      '<p>X / Twitter: @cdbsentinelapex</p>'
  });
  const errors = assess('/about.html', stale);
  assert.ok(errors.includes('UNVERIFIED_CONTINUOUS_MONITORING_COPY'));
  assert.ok(errors.includes('RETIRED_SOCIAL_IDENTITY'));
});
test('About page must explicitly bound managed customer monitoring availability', () => {
  const stale = fixture('/about.html').replace('not an active 24/7 monitoring service', '');
  assert.ok(assess('/about.html', stale).includes('MANAGED_SERVICE_BOUNDARY_MISSING'));
  const scoped = fixture('/about.html', {
    extra:'Continuous managed customer monitoring and incident response are not offered without a separately approved service agreement and operational acceptance.'
  }).replace('not an active 24/7 monitoring service', '');
  assert.ok(!assess('/about.html', scoped).includes('MANAGED_SERVICE_BOUNDARY_MISSING'));
});

test('missing body or head-only legal response fails closed', () => {
  const terms = fixture('/terms.html');
  const headOnly = terms.replace(/<body>[\s\S]*?<\/body>/, '');
  const errors = assess('/terms.html', headOnly);
  assert.ok(errors.includes('VISIBLE_BODY_MISSING'));
  assert.ok(errors.includes('SELLER_IDENTITY_MISSING'));
});

test('legal seller must appear in visible copy, not just hidden markup', () => {
  const terms = fixture('/terms.html');
  const hidden = terms.replace('CYBERDUDEBIVASH ECOSYSTEM',
    '<script type="application/ld+json">{"name":"CYBERDUDEBIVASH ECOSYSTEM"}</script>');
  const errors = assess('/terms.html', hidden);
  assert.ok(errors.includes('SELLER_IDENTITY_MISSING'));
  assert.ok(!errors.includes('VISIBLE_BODY_MISSING'));
});

test('all SOC routes reject missing visible body independently of metadata', () => {
  for (const route of ROUTES) {
    const html = fixture(route).replace(/<body>[\s\S]*?<\/body>/, '');
    assert.ok(assess(route, html).includes('VISIBLE_BODY_MISSING'), route);
  }
});
