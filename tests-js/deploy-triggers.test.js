'use strict';
// Deploy-trigger coverage (release-control invariant): any merge to main that
// changes production runtime behaviour must trigger the Cloudflare production
// deploy on push. PR #318 (webhook security fix in api/_lib + api/v1) merged
// and then waited for the 30-minute drift reconciler because the push path
// filter covered only some front-end files. The required inputs are derived
// from the real Worker module graph + the static-asset build allowlist.
const test = require('node:test');
const assert = require('node:assert');
const {
  workflowPushPaths, requiredInputs, uncovered, matchesAny, workerModuleGraph,
} = require('../scripts/deploy-trigger-inputs.js');

const paths = workflowPushPaths();

test('the production deploy push filter covers every production runtime input', () => {
  const missing = uncovered(paths);
  assert.deepStrictEqual(missing, [], `uncovered runtime inputs:\n${missing.join('\n')}`);
});

test('actual .cjs branding module is covered without an invented .cjs.js path', () => {
  const inputs = requiredInputs();
  assert.ok(inputs.includes('scripts/sentinel-branding.cjs'));
  assert.ok(!inputs.includes('scripts/sentinel-branding.cjs.js'));
});

test('the Worker module graph is real and includes the payment/webhook modules', () => {
  const graph = workerModuleGraph();
  for (const f of ['workers/entry.js', 'api/v1/billing/razorpay-webhook.js', 'api/_lib/premium-commerce-service.js', 'api/_lib/payment-utils.js']) {
    assert.ok(graph.includes(f), `${f} missing from the esbuild graph`);
  }
  assert.ok(graph.length > 100, `implausibly small graph (${graph.length})`);
});


for (const [file, expected] of [
  ['api/v1/billing.js', true],
  ['api/v1/billing/razorpay-webhook.js', true],
  ['api/_lib/premium-commerce-service.js', true],
  ['api/_lib/some-future-module.js', true],
  ['workers/lib/router.js', true],
  ['pricing.html', true],
  ['intel-plans.js', true],
  ['posts/some-new-post.html', true],
  ['package-lock.json', true],
  ['wrangler.jsonc', true],
  ['docs/audits/anything.md', false],
  ['docs/runbooks/BLOG-RAZORPAY-WEBHOOK.md', false],
  ['README.md', false],
  ['CLAUDE.md', false],
  ['tests/test_x.py', false],
]) {
  test(`${file} ${expected ? 'MUST deploy' : 'does not deploy'}`, () => {
    assert.strictEqual(matchesAny(file, paths), expected);
  });
}

test('negative control: dropping api/** (covers api/_lib and api/v1) is detected', () => {
  const without = paths.filter(p => p !== 'api/**');
  const missing = uncovered(without);
  assert.ok(missing.some(f => f.startsWith('api/_lib/')), 'api/_lib gap not detected');
  assert.ok(missing.some(f => f.startsWith('api/v1/')), 'api/v1 gap not detected');
});

test('negative control: the pre-fix filter (front-end files only) is detected as incomplete', () => {
  const preFix = ['index.html', 'pricing.html', 'api.html', 'api/v1/intel.js', 'api/v1/customer/assurance.js', 'api/intel/**', 'workers/**', 'scripts/build-cloudflare-assets.js', 'wrangler.jsonc'];
  const missing = uncovered(preFix);
  assert.ok(missing.includes('api/v1/billing/razorpay-webhook.js'), 'the #318 gap must be reproduced');
  assert.ok(missing.includes('api/_lib/premium-commerce-service.js'));
});

test('docs-only changes stay out of the deploy trigger (no deployment storms)', () => {
  assert.ok(!paths.some(p => p === '**' || p === '**/*' || /^docs\//.test(p) || /\*\.md$/.test(p)));
  assert.ok(requiredInputs().every(f => !f.startsWith('docs/')));
});

const { classify } = require('../scripts/production-drift-policy.js');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

test('drift gate skips only explicitly approved non-production changes', () => {
  assert.strictEqual(classify(['docs/release.md', 'tests-js/check.test.js', 'README.md']).decision, 'skip');
  assert.strictEqual(classify(['.github/workflows/test.yml', 'scripts/soc-native-d1-local-certify.cjs']).decision, 'skip');
});
test('drift gate identifies production source and mixed source changes', () => {
  for (const file of ['workers/entry.js', 'api/v1/billing.js', 'index.html', 'posts/new.html', 'wrangler.jsonc', 'package-lock.json', '.github/workflows/cloudflare-production-deploy.yml', 'scripts/production-drift-policy.js']) {
    assert.strictEqual(classify([file]).decision, 'deploy', file);
  }
  assert.strictEqual(classify(['docs/audit.md', 'workers/entry.js']).decision, 'deploy');
});
test('drift gate blocks unknown paths even when production files also changed', () => {
  for (const changed of [[], ['unexpected-source.txt'], ['docs/audit.md', 'unknown.js'], ['workers/entry.js', 'unknown.js'], ['../unexpected']]) {
    assert.strictEqual(classify(changed).decision, 'blocked', changed.join(','));
  }
});
test('drift monitor is read-only and a push cannot execute Cloudflare deployment', () => {
  const yaml = readFileSync(join(__dirname, '..', '.github/workflows/production-drift-reconcile.yml'), 'utf8');
  const deployment = readFileSync(join(__dirname, '..', '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');
  assert.match(yaml, /node scripts\/production-drift-policy\.cjs/);
  assert.match(yaml, /permissions:\s*\n  contents: read/);
  assert.doesNotMatch(yaml, /actions: write|\/dispatches|Dispatch Cloudflare production deployment/);
  assert.match(deployment, /jobs:\s*\n  deploy:[\s\S]{0,350}?if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs/heads/main' \}\}/);
  assert.match(deployment, /environment: production/);
});
