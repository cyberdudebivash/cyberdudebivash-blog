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

test('canonical cutover fails closed while old SEO sources remain', () => {
  const report = evaluate(readSources(), 'cutover');
  assert.equal(report.passed, false);
  assert.ok(report.issues.some(s => /canonical|sitemap/i.test(s)));
});

test('source cutover checks accept an internally consistent synthetic fixture', () => {
  const sources = readSources();
  sources.homepage = sources.homepage
    .replace('<link rel="canonical" href="https://blog.cyberdudebivash.in/">',
      '<link rel="canonical" href="https://soc.cyberdudebivash.in/">')
    .replace('<meta property="og:url" content="https://blog.cyberdudebivash.in/">',
      '<meta property="og:url" content="https://soc.cyberdudebivash.in/">');
  sources.robots = sources.robots.replace(
    'Sitemap: https://blog.cyberdudebivash.in/sitemap.xml',
    'Sitemap: https://soc.cyberdudebivash.in/sitemap.xml');
  sources.builder = sources.builder.replace(
    "const canonicalHost = 'https://blog.cyberdudebivash.in'",
    "const canonicalHost = 'https://soc.cyberdudebivash.in'");
  sources.seoEngine = sources.seoEngine.replace(
    "const SITE = 'https://blog.cyberdudebivash.in'",
    "const SITE = 'https://soc.cyberdudebivash.in'");
  const report = evaluate(sources, 'cutover');
  assert.equal(report.passed, true, report.issues.join('; '));
  assert.ok(report.pendingOperatorAcceptance.length > 0,
    'Source gate is never sufficient for live production acceptance');
});

test('unknown release phase fails closed', () => {
  assert.throws(() => evaluate(readSources(), 'deploy'), /stage or cutover/);
});
