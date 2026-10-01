'use strict';

// The required status checks for `main` must be checks that report on every
// PR; otherwise branch protection deadlocks merges. Also covers the verifier
// that confirms GitHub actually enforces the policy.

const fs = require('fs');
const os = require('os');
const path = require('path');
const policy = require('../verify-branch-protection');

describe('main branch protection policy', () => {
  test('required checks are the merge-gate jobs plus GitGuardian, by their real names', () => {
    expect(policy.requiredChecks()).toEqual([
      'Jest Test Suite', 'Build Verification', 'End-to-End Tests', 'Governance Tests',
      'Performance Tests', 'Resilience Tests', 'Coverage Verification', 'GitGuardian Security Checks',
    ]);
  });

  test('every merge-gate workflow reports on every PR to main (no path filter)', () => {
    for (const w of policy.GATE_WORKFLOWS) expect([w, policy.runsOnEveryPr(w)]).toEqual([w, true]);
  });

  test('negative control: a path-filtered workflow is detected as not reporting on every PR', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bp-'));
    fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
    const write = (name, body) => fs.writeFileSync(path.join(root, '.github', 'workflows', name), body);
    write('filtered.yml', 'on:\n  pull_request:\n    branches: [main]\n    paths: ["api/**"]\njobs:\n  a: {runs-on: x}\n');
    write('ignored.yml', 'on:\n  pull_request:\n    paths-ignore: ["docs/**"]\njobs:\n  a: {runs-on: x}\n');
    write('other-branch.yml', 'on:\n  pull_request:\n    branches: [develop]\njobs:\n  a: {runs-on: x}\n');
    write('push-only.yml', 'on:\n  push: {}\njobs:\n  a: {runs-on: x}\n');
    write('ok.yml', 'on:\n  pull_request:\n    branches: [main]\njobs:\n  a: {runs-on: x}\n');
    for (const f of ['filtered.yml', 'ignored.yml', 'other-branch.yml', 'push-only.yml']) {
      expect(policy.runsOnEveryPr(`.github/workflows/${f}`, 'main', root)).toBe(false);
    }
    expect(policy.runsOnEveryPr('.github/workflows/ok.yml', 'main', root)).toBe(true);
  });

  const rules = (...types) => types.map(t => (typeof t === 'string' ? { type: t } : t));
  const checksRule = names => ({ type: 'required_status_checks', parameters: { required_status_checks: names.map(context => ({ context })) } });

  test('phase 1 requires force-push and deletion blocks', () => {
    expect(policy.evaluate(rules('non_fast_forward', 'deletion'), { phase: 1 })).toEqual({ ok: true, missing: [] });
    expect(policy.evaluate(rules('deletion'), { phase: 1 }).missing).toEqual(['BLOCK_FORCE_PUSH']);
    expect(policy.evaluate([], { phase: 1 }).missing).toEqual(['BLOCK_FORCE_PUSH', 'BLOCK_DELETION']);
  });

  test('phase 2 also requires a PR and every required check', () => {
    const all = policy.requiredChecks();
    expect(policy.evaluate(rules('non_fast_forward', 'deletion', 'pull_request', checksRule(all)), { phase: 2 }).ok).toBe(true);
    const r = policy.evaluate(rules('non_fast_forward', 'deletion', checksRule(all.slice(1))), { phase: 2 });
    expect(r.missing).toEqual(['REQUIRE_PULL_REQUEST', 'REQUIRE_CHECK:Jest Test Suite']);
  });
});
