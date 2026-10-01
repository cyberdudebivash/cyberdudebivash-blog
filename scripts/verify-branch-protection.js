#!/usr/bin/env node
'use strict';

/**
 * Policy and verifier for protection of `main`
 * (docs/runbooks/MAIN-BRANCH-PROTECTION.md).
 *
 *   GITHUB_TOKEN=... node scripts/verify-branch-protection.js [--phase 1|2]
 *
 * Reads the rules GitHub actually applies to `main`
 * (GET /repos/{owner}/{repo}/rules/branches/main, which merges rulesets and
 * classic protection) and exits 1 if the phase's policy is not met. Read-only.
 *
 * Required check names are derived from the workflows, not hand-listed: every
 * job of a workflow whose pull_request trigger has no path filter, plus the
 * GitGuardian app check. A required check that a path filter can skip never
 * reports, and the PR deadlocks; tests-js/branch-protection-policy.test.js
 * fails if the policy ever requires such a check.
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const ROOT = path.resolve(__dirname, '..');
const OWNER = 'cyberdudebivash';
const REPO = 'cyberdudebivash-blog';
const BRANCH = 'main';
// Workflows whose jobs are the merge gate. Each must run on every PR to main.
const GATE_WORKFLOWS = ['.github/workflows/test.yml'];
// Checks posted by installed GitHub Apps (not workflows) that run on every PR.
const APP_CHECKS = ['GitGuardian Security Checks'];

function readWorkflow(rel, root = ROOT) {
  const doc = yaml.load(fs.readFileSync(path.join(root, rel), 'utf8'));
  return { doc, on: doc.on || doc[true] || {} };
}

/** Whether a workflow reports on every PR targeting `branch`. */
function runsOnEveryPr(rel, branch = BRANCH, root = ROOT) {
  const { on } = readWorkflow(rel, root);
  if (!on || !Object.prototype.hasOwnProperty.call(on, 'pull_request')) return false;
  const pr = on.pull_request || {};
  if (pr.paths || pr['paths-ignore']) return false;
  return !pr.branches || pr.branches.includes(branch);
}

function jobNames(rel, root = ROOT) {
  const { doc } = readWorkflow(rel, root);
  return Object.entries(doc.jobs || {}).map(([id, job]) => (job && job.name) || id);
}

function requiredChecks(root = ROOT) {
  return [...GATE_WORKFLOWS.flatMap(w => jobNames(w, root)), ...APP_CHECKS];
}

/**
 * Phase 1 (safe with today's direct pipeline pushes): no force push, no deletion.
 * Phase 2 (after pipelines push through a bypass-listed GitHub App): also PR
 * required and every required check enforced.
 */
function evaluate(rules, { phase = 1, checks = requiredChecks() } = {}) {
  const list = Array.isArray(rules) ? rules : [];
  const has = type => list.some(r => r && r.type === type);
  const missing = [];
  if (!has('non_fast_forward')) missing.push('BLOCK_FORCE_PUSH');
  if (!has('deletion')) missing.push('BLOCK_DELETION');
  if (phase >= 2) {
    if (!has('pull_request')) missing.push('REQUIRE_PULL_REQUEST');
    const enforced = new Set(list.filter(r => r && r.type === 'required_status_checks')
      .flatMap(r => ((r.parameters || {}).required_status_checks || []).map(c => c.context)));
    for (const c of checks) if (!enforced.has(c)) missing.push(`REQUIRE_CHECK:${c}`);
  }
  return { ok: missing.length === 0, missing };
}

async function main() {
  const args = process.argv.slice(2);
  const phaseIdx = args.indexOf('--phase');
  const phase = phaseIdx >= 0 ? Number(args[phaseIdx + 1]) : 1;
  const token = process.env.GITHUB_TOKEN || '';
  const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/rules/branches/${BRANCH}`, { headers });
  if (!res.ok) { console.error(`GitHub API HTTP ${res.status}`); process.exit(2); }
  const result = evaluate(await res.json(), { phase });
  console.log(`required checks: ${requiredChecks().join(', ')}`);
  console.log(result.ok ? `main protection: phase ${phase} ENFORCED` : `main protection: phase ${phase} MISSING ${result.missing.join(', ')}`);
  process.exit(result.ok ? 0 : 1);
}

if (require.main === module) main().catch(e => { console.error(String(e.message || e)); process.exit(2); });

module.exports = { GATE_WORKFLOWS, APP_CHECKS, runsOnEveryPr, jobNames, requiredChecks, evaluate };
