'use strict';

/**
 * SENTINEL APEX SOC — read-only hostname release gate.
 *
 * --stage   : certify source-level dual-host compatibility prerequisites.
 * --cutover : additionally demand the core SEO source migration. This DOES NOT
 *             certify browser sessions, checkout, callbacks, or Cloudflare costs.
 *
 * Never mutates files, DNS, Cloudflare, deployments, or customer records.
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const SOURCE_FILES = Object.freeze({
  wrangler: 'wrangler.jsonc',
  router: 'workers/lib/router.js',
  routeTable: 'workers/lib/route-table.js',
  homepage: 'index.html',
  robots: 'robots.txt',
  builder: 'scripts/build-cloudflare-assets.js',
  seoEngine: 'seo-engine.js',
});

function readSources(root = ROOT) {
  return Object.fromEntries(Object.entries(SOURCE_FILES).map(([key, name]) => [
    key, fs.readFileSync(path.join(root, name), 'utf8'),
  ]));
}

function evaluate(sources, phase = 'stage') {
  if (!['stage', 'cutover'].includes(phase)) {
    throw new TypeError('phase must be stage or cutover');
  }
  const issues = [];
  const requireCheck = (condition, message) => {
    if (!condition) issues.push(message);
  };
  const wrangler = sources.wrangler || '';
  const router = sources.router || '';
  const routeTable = sources.routeTable || '';

  // The Worker name and its two Custom Domains are intentionally preserved.
  // A migrated canonical hostname must not imply removal of the old API origin.
  requireCheck(/"name"\s*:\s*"cyberdudebivash-blog"/.test(wrangler),
    'Existing Worker identity must be preserved');
  for (const host of ['blog.cyberdudebivash.in', 'soc.cyberdudebivash.in']) {
    const escaped = host.replace(/[.*+?^\u0024{}()|[\]\\]/g, '\\$&');
    const binding = new RegExp('"pattern"\\s*:\\s*"' + escaped +
      '"\\s*,\\s*"custom_domain"\\s*:\\s*true');
    requireCheck(binding.test(wrangler), 'Missing production Custom Domain: ' + host);
  }

  for (const endpoint of [
    'api/v1/billing/razorpay-webhook',
    'api/v1/billing/gumroad-webhook',
    'api/v1/auth',
    'api/v1/billing',
  ]) {
    requireCheck(router.includes("'" + endpoint + "'") && routeTable.includes("'" + endpoint + "'"),
      'Legacy API dispatch mapping missing: ' + endpoint);
  }

  if (phase === 'cutover') {
    const home = sources.homepage || '';
    requireCheck(home.includes('<link rel="canonical" href="https://soc.cyberdudebivash.in/">'),
      'Homepage canonical URL has not migrated to SOC');
    requireCheck(home.includes('<meta property="og:url" content="https://soc.cyberdudebivash.in/">'),
      'Homepage Open Graph URL has not migrated to SOC');
    requireCheck((sources.robots || '').includes('Sitemap: https://soc.cyberdudebivash.in/sitemap.xml'),
      'robots.txt does not advertise SOC sitemap');
    requireCheck((sources.builder || '').includes("const canonicalHost = 'https://soc.cyberdudebivash.in'"),
      'Cloudflare sitemap builder still uses the old canonical host');
    requireCheck((sources.seoEngine || '').includes("const SITE = 'https://soc.cyberdudebivash.in'"),
      'Client-side SEO engine still uses the old origin');
  }

  return {
    phase,
    passed: issues.length === 0,
    issues,
    // Passing the source gate alone is never full production authorization.
    pendingOperatorAcceptance: [
      'Generated HTML and sitemap canonical parity',
      'Authenticated sessions and customer/API flows on both hosts',
      'Live Razorpay/Gumroad callback compatibility without real charges',
      'Cloudflare shared-account usage and SOC cron control',
      'Manual deployment, HTTP acceptance and rollback verification',
    ],
  };
}

if (require.main === module) {
  const phase = process.argv.includes('--cutover') ? 'cutover' : 'stage';
  try {
    const report = evaluate(readSources(), phase);
    console.log(JSON.stringify(report, null, 2));
    if (!report.passed) process.exitCode = 1;
  } catch (error) {
    console.error('SOC_DOMAIN_GATE_ERROR:', error.message);
    process.exitCode = 1;
  }
}

module.exports = { readSources, evaluate, SOURCE_FILES };
