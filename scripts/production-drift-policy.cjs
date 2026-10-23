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

/**
 * Audited 2026-10-23 against COMPLETE, independently verified immutable Git
 * trees (base 365c89f3, main c77ec9a4). These are operational/CTI pipeline,
 * scheduler, migration, customer-delivery and release-gate inputs.
 *
 * They do not all ship inside a Cloudflare Worker bundle. They MUST NOT be
 * downgraded to documentation, test fixtures or successful deployment proof.
 * Changes require operator-reviewed acceptance, even if no Worker deploy is
 * appropriate. Future unlisted scripts, workflows or migrations remain BLOCKED.
 */
const REVIEWED_OPERATIONAL_FILES = new Set([
  '.github/workflows/alert-delivery.yml',
  '.github/workflows/intelligence-hub.yml',
  '.github/workflows/workflow-security-gate.yml',
  'OPERATIONS.md',
  'ai-security-intel-memory.json',
  'ai-security-intel-state.json',
  'intel-memory.json',
  'data/ioc-store.json',
  'data/published_posts.json',
  'build-detections-page.js',
  'build-evi-page.js',
  'build-research.js',
  'generate-intelligence-hub.js',
  'generate-rss.js',
  'migrations/0017_soc_bounded_watchlist_eval.sql',
  'migrations/0018_soc_notification_outbox.sql',
  'scripts/alert-delivery-execution-gate.cjs',
  'scripts/audit-soc-published-ui.cjs',
  'scripts/check-cloudflare-runtime.js',
  'scripts/cloudflare-account-zero-overage-gate.cjs',
  'scripts/deliver-watchlist-notifications.js',
  'scripts/evaluate-watchlist-changes.js',
  'scripts/publish-intelligence-hub.sh',
  'scripts/reconcile-soc-notification-outbox.js',
  'scripts/soc-domain-release-gate.cjs',
  'scripts/soc-hostname-truth-gate.cjs',
  'scripts/soc-live-release-parity.cjs',
  'scripts/soc-readiness-delivery-gate.cjs',
  'scripts/verify-existing-cloudflare-domain.cjs',
]);

/**
 * Exact historical execution evidence inspected as JSON under logs/. Do not
 * allowlist logs/** or arbitrary newly written logs: unexpected artifacts
 * might include operational state, private values or production inputs.
 */
const REVIEWED_HISTORICAL_LOGS = new Set([
  'logs/run-20261022-073736.json',
  'logs/run-20261022-100859.json',
  'logs/run-20261022-131441.json',
  'logs/run-20261022-151526.json',
  'logs/run-20261022-180407.json',
  'logs/run-20261022-191412.json',
  'logs/run-20261022-214114.json',
  'logs/run-20261022-221856.json',
  'logs/run-20261023-001210.json',
  'logs/run-20261023-012847.json',
  'logs/run-20261023-072845.json',
  'logs/run-20261023-132648.json',
]);

function isReviewedOperationalPath(file) {
  return REVIEWED_OPERATIONAL_FILES.has(file);
}

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
  return BENIGN_FILES.has(file) || REVIEWED_HISTORICAL_LOGS.has(file) ||
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
  return classifyChangedFiles(compare.files, patterns);
}

/**
 * Shared strict filename classification for GitHub Compare and VERIFIED full
 * tree diffs. Renames in a tree diff appear as remove+add, classifying both
 * old and new paths. Never silently downgrade an unknown source file.
 */
function classifyChangedFiles(files, patterns) {
  if (!Array.isArray(files)) return {
    state: 'blocked', reason: 'changed file list unavailable'
  };
  const affected=[], operational=[], unknown=[], benign=[];
  for (const file of files) {
    if (!file || typeof file.filename !== 'string' ||
        !/^(added|modified|removed|renamed|changed|copied)$/.test(file.status) ||
        (file.status === 'renamed' && typeof file.previous_filename !== 'string'))
      return {state:'blocked',reason:'unrecognized file-change structure'};
    const names = file.status==='renamed' ?
      [file.filename,file.previous_filename] : [file.filename];
    for (const name of names) {
      if (!/^(?!\/)(?!.*\.\.)(?!.*\\)[\w.@+/-]+$/.test(name))
        return {state:'blocked',reason:'unsafe filename in comparison'};
      if (isProductionPath(name,patterns)) affected.push(name);
      else if (isReviewedOperationalPath(name)) operational.push(name);
      else if (isKnownBenignPath(name)) benign.push(name);
      else unknown.push(name);
    }
  }
  const reviewed = {
    compared_files:files.length,
    production:[...new Set(affected)].sort(),
    operational:[...new Set(operational)].sort(),
    benign:[...new Set(benign)].sort(),
    unknown:[...new Set(unknown)].sort(),
  };
  if (reviewed.unknown.length)
    return {state:'blocked',reason:'unrecognized changed files require source review',...reviewed};
  if (reviewed.production.length || reviewed.operational.length)
    return {state:'manual_release_required',...reviewed};
  return {state:'nonproduction_only',...reviewed};
}

/**
 * GitHub Compare limits files to 300 and may not provide the complete
 * history near its 250-commit page ceiling. Trust its lineage ONLY after
 * validating exact base, merge-base, end SHA and complete commit listing.
 * Whole-tree fallback is forbidden for incomplete ancestry.
 */
function verifiedAncestry(compare, base, head) {
  return !!(compare && compare.status === 'ahead' &&
    compare.base_commit?.sha === base &&
    compare.merge_base_commit?.sha === base &&
    compare.commits?.at(-1)?.sha === head &&
    compare.ahead_by === compare.total_commits &&
    compare.behind_by === 0 &&
    Number.isSafeInteger(compare.total_commits) &&
    compare.total_commits >= 1 && compare.total_commits < 250 &&
    Array.isArray(compare.commits) &&
    compare.commits.length === compare.total_commits);
}

function classifyVerifiedGitTrees(compare, base, head, patterns, baseTree, headTree) {
  const blocked = reason => ({state:'blocked',reason});
  if (!/^[a-f0-9]{40}$/.test(base||'') ||
      !/^[a-f0-9]{40}$/.test(head||'') ||
      !Array.isArray(patterns) || patterns.length < 20 ||
      !verifiedAncestry(compare,base,head))
    return blocked('full-tree ancestry not independently verified');
  const expectedOld = compare.base_commit?.commit?.tree?.sha;
  const expectedNew = compare.commits?.at(-1)?.commit?.tree?.sha;
  const isSha = value => /^[a-f0-9]{40}$/.test(value||'');
  if (!isSha(expectedOld) || !isSha(expectedNew) ||
      baseTree?.sha !== expectedOld || headTree?.sha !== expectedNew)
    return blocked('full-tree object SHA does not match verified commits');
  const read = tree => {
    if (tree.truncated !== false || !Array.isArray(tree.tree) ||
        !tree.tree.length || tree.tree.length > 100000) return null;
    const blobs=new Map();
    const paths=new Set();
    for (const item of tree.tree) {
      if (!item || typeof item.path !== 'string' || !item.path ||
          paths.has(item.path) || !isSha(item.sha) ||
          !/^(?:040000|100644|100755|120000|160000)$/.test(item.mode) ||
          !['tree','blob','commit'].includes(item.type) ||
          (item.type==='tree') !== (item.mode==='040000') ||
          (item.type==='commit') !== (item.mode==='160000'))
        return null;
      paths.add(item.path);
      if (item.type!=='tree') blobs.set(item.path,item.mode+':'+item.sha);
    }
    return blobs;
  };
  const older=read(baseTree),newer=read(headTree);
  if (!older || !newer) return blocked('full-tree payload truncated or malformed');
  const changed=[];
  for (const [name,identity] of older)
    if (!newer.has(name)) changed.push({filename:name,status:'removed'});
    else if (newer.get(name)!==identity) changed.push({filename:name,status:'modified'});
  for (const name of newer.keys())
    if (!older.has(name)) changed.push({filename:name,status:'added'});
  // Never use the 300-file response to classify a large release.
  const result=classifyChangedFiles(changed,patterns);
  return {...result,comparison_source:'verified_full_git_trees',
    baseline_tree_files:older.size,current_tree_files:newer.size};
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

function renderDriftSummary(head, base, result) {
  return [
    '### SENTINEL APEX production drift — read-only release control',
    '- main commit: `' + head + '`',
    '- last successful approved deploy: `' + (base || 'unavailable') + '`',
    '- decision: **' + result.state + '**',
    '- reason: ' + (result.reason || 'complete commit/file comparison evaluated'),
    '- production-affecting files: ' + (result.production?.length || 0),
    '- reviewed operational/release-control changes: ' + (result.operational?.length || 0),
    '- known nonproduction files: ' + (result.benign?.length || 0),
    '- unknown files: ' + (result.unknown?.length || 0),
    '- total compared changed files: ' + (result.compared_files ?? 'not certified'),
    '- comparison source: ' + (result.comparison_source || 'GitHub Compare API'),
    // Evidence listing is deliberately bounded, not a broad GitHub API
    // dump. All filenames here already passed the safe-path parser.
    ...(result.unknown?.length ? [
      '- **Unclassified path review required:**',
      ...result.unknown.slice(0, 30).map(name => '  - `' + name + '`'),
      ...(result.unknown.length > 30
        ? ['  - ... plus ' + (result.unknown.length - 30) + ' additional unclassified paths'] : []),
    ] : []),
    ...(result.operational?.length ? [
      '- **Operational/release-control changes (operator review required):**',
      ...result.operational.slice(0, 12).map(name => '  - \x60' + name + '\x60'),
      ...(result.operational.length > 12
        ? ['  - ... plus ' + (result.operational.length - 12) + ' additional operational paths'] : []),
    ] : []),
    ...(result.production?.length ? [
      '- **Production changes detected (sample, never a deployment approval):**',
      ...result.production.slice(0, 12).map(name => '  - `' + name + '`'),
      ...(result.production.length > 12
        ? ['  - ... plus ' + (result.production.length - 12) + ' additional production paths'] : []),
    ] : []),
    '- **No deployment or workflow dispatch is performed by this monitor.**',
    '- Monitoring completed; status manual_release_required is NOT proof of deployment.',
    '- Manual release and independent postdeploy certification required.',
    '',
  ].join('\n');
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
      if (Array.isArray(compare.files) && compare.files.length >= 300) {
        // GitHub Compare cannot certify a 300-file inventory. Get both
        // immutable commit trees. Any truncated/malformed tree fails closed.
        const oldSha = compare.base_commit?.commit?.tree?.sha;
        const newSha = compare.commits?.at(-1)?.commit?.tree?.sha;
        if (!verifiedAncestry(compare,base,head) ||
            !/^[a-f0-9]{40}$/.test(oldSha||'') ||
            !/^[a-f0-9]{40}$/.test(newSha||'')) {
          result = {state:'blocked',reason:'full-tree fallback ancestry invalid'};
        } else {
          const [older,newer] = await Promise.all([
            apiRead('/git/trees/' + oldSha + '?recursive=1',token,repository),
            apiRead('/git/trees/' + newSha + '?recursive=1',token,repository),
          ]);
          result = classifyVerifiedGitTrees(compare,base,head,paths,older,newer);
        }
      } else {
        result = classify(compare,base,head,paths);
      }
    }
  }
  const summary = renderDriftSummary(head, base, result);
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
module.exports = { deployPaths, pathMatches, isKnownBenignPath, isReviewedOperationalPath,
  classify, classifyVerifiedGitTrees, renderDriftSummary };
