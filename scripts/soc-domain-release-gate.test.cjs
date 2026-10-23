'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readSources, evaluate } = require('./soc-domain-release-gate.cjs');

test('staged SOC Custom Domain preserves existing Worker and critical API routes', () => {
  const report = evaluate(readSources(), 'stage');
  assert.equal(report.passed, true, report.issues.join('; '));
  assert.ok(report.pendingOperatorAcceptance.length >= 4);
});

test('removing the new SOC Custom Domain blocks stage', () => {
  const sources = readSources();
  sources.wrangler = sources.wrangler.replace(
    '"pattern": "soc.cyberdudebivash.in"',
    '"pattern": "nonexistent.invalid"');
  const report = evaluate(sources, 'stage');
  assert.equal(report.passed, false);
  assert.match(report.issues.join('\n'), /Missing production Custom Domain: soc/);
});

test('removing the legacy blog Custom Domain blocks stage', () => {
  const sources = readSources();
  sources.wrangler = sources.wrangler.replace(
    '"pattern": "blog.cyberdudebivash.in"',
    '"pattern": "nonexistent.invalid"');
  const report = evaluate(sources, 'stage');
  assert.equal(report.passed, false);
  assert.match(report.issues.join('\n'), /Missing production Custom Domain: blog/);
});

test('missing legacy payment webhook mapping blocks stage', () => {
  const sources = readSources();
  sources.router = sources.router.replace(
    "'api/v1/billing/razorpay-webhook'",
    "'removed-razorpay-webhook'");
  const report = evaluate(sources, 'stage');
  assert.equal(report.passed, false);
  assert.match(report.issues.join('\n'), /Legacy API dispatch mapping missing: api\/v1\/billing\/razorpay-webhook/);
});

test('SOC canonical source gate passes but never certifies customer release by itself', () => {
  const report = evaluate(readSources(), 'cutover');
  assert.equal(report.passed, true, report.issues.join('; '));
  assert.ok(report.pendingOperatorAcceptance.length > 0,
    'Source gate is never sufficient for live production acceptance');
});

test('restoring old canonical references individually blocks SOC cutover', () => {
  const failures = [
    ['homepage', '<link rel="canonical" href="https://soc.cyberdudebivash.in/">',
      '<link rel="canonical" href="https://blog.cyberdudebivash.in/">', /homepage canonical/i],
    ['homepage', '<meta property="og:url" content="https://soc.cyberdudebivash.in/">',
      '<meta property="og:url" content="https://blog.cyberdudebivash.in/">', /open graph/i],
    ['robots', 'Sitemap: https://soc.cyberdudebivash.in/sitemap.xml',
      'Sitemap: https://blog.cyberdudebivash.in/sitemap.xml', /robots.txt/i],
    ['builder', "const canonicalHost = 'https://soc.cyberdudebivash.in'",
      "const canonicalHost = 'https://blog.cyberdudebivash.in'", /sitemap builder/i],
    ['seoEngine', "const SITE = 'https://soc.cyberdudebivash.in'",
      "const SITE = 'https://blog.cyberdudebivash.in'", /seo engine/i],
  ];
  for (const [file, current, legacy, reason] of failures) {
    const sources = readSources();
    assert.ok(sources[file].includes(current), 'source fixture missing: ' + file);
    sources[file] = sources[file].replace(current, legacy);
    const report = evaluate(sources, 'cutover');
    assert.equal(report.passed, false, 'legacy canonical change not detected: ' + file);
    assert.match(report.issues.join('\n'), reason);
  }
});

test('unknown release phase fails closed', () => {
  assert.throws(() => evaluate(readSources(), 'deploy'), /stage or cutover/);
});
