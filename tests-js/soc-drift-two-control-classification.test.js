'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const build = require('../scripts/build-cloudflare-assets.js');
const drift = require('../scripts/production-drift-policy.cjs');

const ROOT = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'soc.html'), 'utf8');
const deploy = fs.readFileSync(path.join(ROOT, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');
const patterns = drift.deployPaths(deploy);
const SCRIPTS = ['soc-global-incidents.js', 'soc-global-incidents-loader.js'];
const BASE = 'a'.repeat(40), HEAD = 'b'.repeat(40);

function compare(files) {
  return {
    status: 'ahead',
    base_commit: { sha: BASE },
    merge_base_commit: { sha: BASE },
    ahead_by: 1, behind_by: 0, total_commits: 1,
    commits: [{ sha: HEAD }],
    files: files.map(filename => ({ filename, status: 'modified' })),
  };
}

test('P0 #433: SOC GCII source scripts referenced by customer page are both shipped', () => {
  for (const script of SCRIPTS) {
    assert.equal(fs.existsSync(path.join(ROOT, script)), true, script);
    assert.equal(build.PUBLIC_ROOT_FILES.filter(x => x === script).length, 1, script);
    assert.ok(html.includes('src="/' + script + '?'), script);
  }
  assert.ok(html.indexOf('src="/soc-global-incidents.js?') <
            html.indexOf('src="/soc-global-incidents-loader.js?'),
            'renderer must be loaded before its fetch-driven consumer');
});

test('P0 #433: changing either GCII script triggers a protected manual release assessment', () => {
  for (const script of SCRIPTS) {
    assert.ok(patterns.some(p => drift.pathMatches(script, p)), script);
    assert.equal(drift.isKnownBenignPath(script), false, script);
    const result = drift.classify(compare([script]), BASE, HEAD, patterns);
    assert.equal(result.state, 'manual_release_required', script);
    assert.deepEqual(result.production, [script]);
    assert.deepEqual(result.unknown, []);
    assert.deepEqual(result.benign, []);
  }
  const both = drift.classify(compare(SCRIPTS), BASE, HEAD, patterns);
  assert.equal(both.state, 'manual_release_required');
  assert.deepEqual(both.production, [...SCRIPTS].sort());
  assert.deepEqual(both.unknown, []);
});

test('P0 #433 negative: arbitrary root scripts remain excluded and unclassified', () => {
  const unexpected = 'soc-unreviewed-incident-override.js';
  assert.equal(build.PUBLIC_ROOT_FILES.includes(unexpected), false);
  assert.equal(patterns.some(p => drift.pathMatches(unexpected, p)), false);
  const result = drift.classify(compare([...SCRIPTS, unexpected]), BASE, HEAD, patterns);
  assert.equal(result.state, 'blocked');
  assert.deepEqual(result.unknown, [unexpected]);
  assert.deepEqual(result.production, [...SCRIPTS].sort());
});

test('P0 #433: GCII fix does not add unattended Cloudflare deployment', () => {
  assert.match(deploy, /if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(deploy, /environment: production/);
  const source = fs.readFileSync(path.join(ROOT, 'soc-global-incidents-loader.js'), 'utf8');
  assert.match(source, /credentials: 'omit'/);
  assert.match(source, /cache: 'no-store'/);
  assert.match(source, /Global incident feed unavailable or invalid/);
});
