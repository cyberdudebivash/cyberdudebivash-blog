'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const policy = require('../scripts/production-drift-policy.cjs');

const root = path.resolve(__dirname, '..');
const deploy = fs.readFileSync(path.join(root, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');
const monitor = fs.readFileSync(path.join(root, '.github/workflows/production-drift-reconcile.yml'), 'utf8');
const patterns = policy.deployPaths(deploy);
const BASE = 'a'.repeat(40);
const HEAD = 'b'.repeat(40);
const reviewed = [
  '.github/workflows/production-drift-reconcile.yml',
  'api/_lib/__tests__/d1-worker-native-fail-closed.test.js',
];

function classify(files) {
  return policy.classify({
    status: 'ahead',
    base_commit: { sha: BASE },
    merge_base_commit: { sha: BASE },
    ahead_by: 1,
    behind_by: 0,
    total_commits: 1,
    commits: [{ sha: HEAD }],
    files,
  }, BASE, HEAD, patterns);
}
function changed(paths) {
  return paths.map(filename => ({ filename, status: 'modified' }));
}

test('P0 #433: both observed drift inputs require human operational review, never benign release', () => {
  for (const file of reviewed) {
    assert.equal(policy.isReviewedOperationalPath(file), true, file);
    assert.equal(policy.isKnownBenignPath(file), false, file);
    const result = classify(changed([file]));
    assert.equal(result.state, 'manual_release_required', file);
    assert.deepEqual(result.operational, [file]);
    assert.deepEqual(result.unknown, []);
    assert.deepEqual(result.benign, []);
  }
  const combined = classify(changed([...reviewed, 'README.md']));
  assert.equal(combined.state, 'manual_release_required');
  assert.deepEqual(combined.operational, [...reviewed].sort());
  assert.deepEqual(combined.benign, ['README.md']);
  assert.deepEqual(combined.unknown, []);
});

test('P0 #433: renamed-away reviewed controls still require manual release', () => {
  for (const file of reviewed) {
    const result = classify([{
      filename: 'docs/retired-' + path.basename(file) + '.md',
      previous_filename: file,
      status: 'renamed',
    }]);
    assert.equal(result.state, 'manual_release_required', file);
    assert.ok(result.operational.includes(file), file);
    assert.deepEqual(result.unknown, []);
  }
});

test('P0 #433: future unreviewed workflow or D1 authorization test fails closed', () => {
  for (const unknown of [
    '.github/workflows/unauthorized-deploy.yml',
    'api/_lib/__tests__/new-tenant-authorization-bypass.test.js',
  ]) {
    const result = classify(changed([...reviewed, unknown]));
    assert.equal(result.state, 'blocked', unknown);
    assert.ok(result.unknown.includes(unknown), unknown);
    for (const file of reviewed) assert.ok(result.operational.includes(file), file);
  }
});

test('P0 #433: classification repair cannot enable unattended deployment or write-capable reconciliation', () => {
  assert.match(monitor, /permissions:\s*\n  contents: read\n  actions: read/);
  assert.doesNotMatch(monitor, /actions: write|\/dispatches/);
  assert.match(deploy, /if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
  const result = classify(changed(reviewed));
  const summary = policy.renderDriftSummary(HEAD, BASE, result);
  assert.match(summary, /decision: \*\*manual_release_required\*\*/);
  assert.match(summary, /No deployment or workflow dispatch/);
});
