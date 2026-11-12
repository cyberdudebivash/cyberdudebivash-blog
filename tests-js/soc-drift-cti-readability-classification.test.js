'use strict';
// P0 #433: the read-only production drift monitor (run 43230308160, main 0207cff1) reported
// two paths from #552 as UNKNOWN, keeping the release decision `blocked`:
//   automation/cti_readability_v13.py, automation/tests/test_cti_readability_v13.py
// Inspected: a pure BeautifulSoup HTML post-processor (no network, subprocess, env, secret or
// file I/O) imported by automation/premium_main.py, so it shapes public Blogger CTI dossiers.
// They are classified OPERATIONAL -- still requiring an operator-reviewed release -- never
// benign, and never via an automation/** wildcard.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const drift = require('../scripts/production-drift-policy.cjs');

const ROOT = path.resolve(__dirname, '..');
const deploy = fs.readFileSync(path.join(ROOT, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');
const patterns = drift.deployPaths(deploy);
const BASE = 'a'.repeat(40), HEAD = 'b'.repeat(40);
const compare = files => ({ status: 'ahead', base_commit: { sha: BASE }, merge_base_commit: { sha: BASE }, ahead_by: 1, behind_by: 0, total_commits: 1,
  commits: [{ sha: HEAD }], files: files.map(filename => ({ filename, status: 'modified' })) });
const PATHS = ['automation/cti_readability_v13.py', 'automation/tests/test_cti_readability_v13.py'];

test('both #552 paths are reviewed OPERATIONAL changes: not unknown, not benign', () => {
  for (const p of PATHS) {
    assert.equal(drift.isKnownBenignPath(p), false, p);
    const r = drift.classify(compare([p]), BASE, HEAD, patterns);
    assert.deepEqual(r.unknown, [], p + ' must no longer be unknown');
    assert.deepEqual(r.operational, [p], p);
    assert.deepEqual(r.benign, [], p);
    assert.equal(r.state, 'manual_release_required', 'still requires a manual, operator-reviewed release');
  }
});

test('negative: a new, unreviewed automation module is still UNKNOWN and still blocks (no wildcard)', () => {
  for (const unexpected of ['automation/unreviewed_new_module.py', 'automation/cti_readability_v14.py', 'automation/tests/test_unreviewed.py']) {
    const r = drift.classify(compare([...PATHS, unexpected]), BASE, HEAD, patterns);
    assert.deepEqual(r.unknown, [unexpected], unexpected);
    assert.equal(r.state, 'blocked', unexpected);
  }
});

test('the classification entries are exact paths, not a pattern', () => {
  const src = fs.readFileSync(path.join(ROOT, 'scripts/production-drift-policy.cjs'), 'utf8');
  for (const p of PATHS) assert.equal(src.split("'" + p + "'").length - 1, 1, p + ' listed exactly once');
  assert.doesNotMatch(src, /'automation\/\*\*?'/);
});
