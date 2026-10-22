#!/usr/bin/env node
'use strict';

/**
 * P0 release safety (issue #381).
 * Read-only drift monitor. It never dispatches or deploys production.
 * Default: every production-affecting change requires an operator-reviewed
 * workflow_dispatch or an independently authorized local deployment.
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const DEPLOY_WORKFLOW = path.join(ROOT, '.github/workflows/cloudflare-production-deploy.yml');
const BENIGN_PREFIXES = Object.freeze(['docs/', 'tests/', 'tests-js/']);
const BENIGN_FILES = new Set([
  'README.md', 'CLAUDE.md', 'CHANGELOG.md',
  '.github/workflows/test.yml',
  'scripts/soc-native-d1-local-certify.cjs',
  'scripts/production-drift-policy.cjs',
]);
const BENIGN_SCRIPT_TEST = /^scripts\/[A-Za-z0-9._/-]+\.(?:test|spec)\.(?:cjs|mjs|js)$/;

function deployPaths(source) {
  const lines = source.split(/\r?\n/);
  let foundPush = false;
  let withinPaths = false;
  const patterns = [];
  for (const line of lines) {
    if (line === '  push:') foundPush = true;
    if (foundPush && line === '    paths:') { withinPaths = true; continue; }
    if (!withinPaths) continue;
    const match = line.match(/^      - '([^']+)'\s*$/);
    if (match) { patterns.push(match[1]); continue; }
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    break;
  }
  if (!foundPush || !withinPaths || patterns.length < 20 ||
      patterns.some(p => p.startsWith('!') || !/^[\w./*-]+$/.test(p))) {
    throw new Error('PRODUCTION_DEPLOY_PATH_POLICY_UNREADABLE');
  }
  return patterns;
}

function pathMatches(file, pattern) {
  if (pattern.endsWith('/**')) return file.startsWith(pattern.slice(0, -2));
  return file === pattern;
}

function isProductionPath(file, patterns) {
  return patterns.some(pattern => pathMatches(file, pattern));
}

function isKnownBenignPath(file) {
  return BENIGN_FILES.has(file) ||
    BENIGN_PREFIXES.some(prefix => file.startsWith(prefix)) ||
    BENIGN_SCRIPT_TEST.test(file);
}

function classify(compare, expectedBase, expectedHead, patterns) {
  if (!compare || typeof compare !== 'object' ||
      !/^[a-f0-9]{40}$/.test(expectedBase || '') ||
      !/^[a-f0-9]{40}$/.test(expectedHead || '') ||
      !Array.isArray(patterns) || patterns.length < 20) {
    return { state: 'blocked', reason: 'comparison inputs invalid' };
  }
  if (expectedBase === expectedHead) return { state: 'no_drift', files: 0 };
  if (compare.status !== 'ahead' ||
      compare.base_commit?.sha !== expectedBase ||
      compare.merge_base_commit?.sha !== expectedBase ||
      compare.commits?.at(-1)?.sha !== expectedHead ||
      compare.ahead_by !== compare.total_commits ||
      compare.behind_by !== 0 ||
      !Number.isSafeInteger(compare.total_commits) ||
      compare.total_commits < 1 || compare.total_commits >= 250 ||
      !Array.isArray(compare.commits) ||
      compare.commits.length !== compare.total_commits ||
      !Array.isArray(compare.files) || compare.files.length === 0 ||
      compare.files.length >= 300) {
    return { state: 'blocked', reason: 'comparison incomplete, divergent, or truncated' };
  }
  const affected = [];
  const unknown = [];
  const benign = [];
  for (const file of compare.files) {
    if (!file || typeof file.filename !== 'string' ||
        !/^(added|modified|removed|renamed|changed|copied)$/.test(file.status) ||
        (file.status === 'renamed' && typeof file.previous_filename !== 'string')) {
      return { state: 'blocked', reason: 'unrecognized file-change structure' };
    }
    const names = file.status === 'renamed' ?
      [file.filename, file.previous_filename] : [file.filename];
    for (const name of names) {
      if (!/^(?!\/)(?!.*\.\.)(?!.*\\)[\w.@+/-]+$/.test(name)) {
        return { state: 'blocked', reason: 'unsafe filename in comparison' };
      }
      if (isProductionPath(name, patterns)) affected.push(name);
      else if (isKnownBenignPath(name)) benign.push(name);
      else unknown.push(name);
    }
  }
  // A hard release block must NEVER suppress the already-detected
  // production changes. Previous code reported "production-affecting: 0"
  // when even one unknown path existed, despite dozens of changed Worker
  // and customer-facing files. Preserve every category for the operator.
  const reviewed = {
    compared_files: compare.files.length,
    production: [...new Set(affected)].sort(),
    benign: [...new Set(benign)].sort(),
    unknown: [...new Set(unknown)].sort(),
  };
  if (reviewed.unknown.length) return {
    state: 'blocked', reason: 'unrecognized changed files require source review',
    ...reviewed,
  };
  if (reviewed.production.length) return {
    state: 'manual_release_required', ...reviewed,
  };
  return { state: 'nonproduction_only', ...reviewed };
}

async function apiRead(route, token, repository) {
  const response = await fetch(
    'https://api.github.com/repos/' + repository + route, {
      headers: {
        Authorization: 'Bearer ' + token,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      signal: AbortSignal.timeout(15000),
    }
  );
  if (!response.ok) throw new Error('GitHub API status ' + response.status);
  return response.json();
}

async function run() {
  const token = process.env.GH_TOKEN || '';
  const repository = process.env.GITHUB_REPOSITORY || '';
  if (!token || !/^[\w.-]+\/[\w.-]+$/.test(repository)) {
    throw new Error('GitHub read-only context missing');
  }
  const paths = deployPaths(fs.readFileSync(DEPLOY_WORKFLOW, 'utf8'));
  const main = await apiRead('/commits/main', token, repository);
  const head = main.sha;
  if (!/^[a-f0-9]{40}$/.test(head || '')) throw new Error('Main SHA not trustworthy');

  const runs = await apiRead(
    '/actions/workflows/cloudflare-production-deploy.yml/runs?branch=main&per_page=100',
    token, repository
  );
  if (!Array.isArray(runs.workflow_runs)) throw new Error('Deploy runs unavailable');
  // A successful skipped push workflow is not a certified deployment.
  // Only operator-triggered completed runs may establish a new baseline.
  const manual = runs.workflow_runs.filter(run => run.event === 'workflow_dispatch' &&
    run.status === 'completed');
  const latest = manual[0];
  let result;
  let base = '';
  if (!latest) {
    result = { state: 'blocked', reason: 'no independently certified manual-deploy baseline' };
  } else if (latest.conclusion !== 'success') {
    result = { state: 'blocked', reason: 'last manual production certification failed' };
  } else {
    base = latest.head_sha || '';
    if (!/^[a-f0-9]{40}$/.test(base)) {
      result = { state: 'blocked', reason: 'certified deploy SHA missing' };
    } else if (head === base) {
      result = { state: 'no_drift', files: 0 };
    } else {
      const compare = await apiRead('/compare/' + base + '...' + head, token, repository);
      result = classify(compare, base, head, paths);
    }
  }
  const summary = [
    '### SENTINEL APEX production drift — read-only release control',
    '- main commit: `' + head + '`',
    '- last successful approved deploy: `' + (base || 'unavailable') + '`',
    '- decision: **' + result.state + '**',
    '- reason: ' + (result.reason || 'complete commit/file comparison evaluated'),
    '- production-affecting files: ' + (result.production?.length || 0),
    '- known nonproduction files: ' + (result.benign?.length || 0),
    '- unknown files: ' + (result.unknown?.length || 0),
    '- total compared changed files: ' + (result.compared_files ?? 'not certified'),
    // Evidence listing is deliberately bounded, not a broad GitHub API
    // dump. All filenames here already passed the safe-path parser.
    ...(result.unknown?.length ? [
      '- **Unclassified path review required:**',
      ...result.unknown.slice(0, 30).map(name => '  - `' + name + '`'),
      ...(result.unknown.length > 30
        ? ['  - ... plus ' + (result.unknown.length - 30) + ' additional unclassified paths'] : []),
    ] : []),
    ...(result.production?.length ? [
      '- **Production changes detected (sample, never a deployment approval):**',
      ...result.production.slice(0, 12).map(name => '  - `' + name + '`'),
      ...(result.production.length > 12
        ? ['  - ... plus ' + (result.production.length - 12) + ' additional production paths'] : []),
    ] : []),
    '- **No deployment or workflow dispatch is performed by this monitor.**',
    '- Manual release and independent postdeploy certification required.',
    '',
  ].join('\n');
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
  }
  process.stdout.write(summary);
  if (result.state === 'blocked') process.exitCode = 1;
}

if (require.main === module) {
  run().catch(err => {
    console.error('::error::Production drift HOLD: ' + String(err.message).slice(0, 180));
    process.exitCode = 1;
  });
}
module.exports = { deployPaths, pathMatches, isKnownBenignPath, classify };
