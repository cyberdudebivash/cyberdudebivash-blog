'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { deployPaths, classify } = require('../scripts/production-drift-policy.cjs');

const root = path.resolve(__dirname, '..');
const deploy = fs.readFileSync(path.join(root,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');
const monitor = fs.readFileSync(path.join(root,'.github/workflows/production-drift-reconcile.yml'),'utf8');
const paths = deployPaths(deploy);
const BASE = 'a'.repeat(40), HEAD = 'b'.repeat(40);
function compare(files) {
  return { status: 'ahead', base_commit: {sha: BASE}, merge_base_commit: {sha: BASE},
    ahead_by: 1, behind_by: 0, total_commits: 1, commits: [{sha:HEAD}],
    files: files.map(filename => ({filename, status:'modified'})) };
}
function state(files) { return classify(compare(files), BASE, HEAD, paths).state; }

test('production workflow cannot deploy on push or schedule', () => {
  assert.match(deploy,/\n  deploy:[\s\S]{0,350}?if: \$\{\{ github\.event_name == 'workflow_dispatch' \}\}/);
});
test('reconciler has no write permission or dispatch operation', () => {
  assert.match(monitor,/permissions:\s*\n  contents: read\n  actions: read/);
  assert.doesNotMatch(monitor,/actions: write|\/dispatches|workflow_dispatch.*ref.*main/);
  assert.match(monitor,/node scripts\/production-drift-policy\.cjs/);
});
test('source graph comes from actual production deploy push paths', () => {
  assert.ok(paths.length >= 20);
  for (const pathName of ['workers/entry.js','api/v1/billing.js','index.html','wrangler.jsonc','package-lock.json']) {
    assert.ok(paths.some(p => p === pathName || (p.endsWith('/**') && pathName.startsWith(p.slice(0,-2)))),pathName);
  }
});
for(const [label,files,expected] of [
  ['documentation only',['docs/runbooks/SOC.md','README.md'],'nonproduction_only'],
  ['unit tests and native rehearsal',['tests-js/soc-native-d1-local-certify.test.js','scripts/soc-native-d1-local-certify.cjs','.github/workflows/test.yml'],'nonproduction_only'],
  ['changed Worker',['workers/entry.js'],'manual_release_required'],
  ['changed router',['api/v1/billing.js'],'manual_release_required'],
  ['generated CTI',['posts/CVE-2026-123.html'],'manual_release_required'],
  ['homepage',['index.html'],'manual_release_required'],
  ['build and lockfile',['scripts/build-cloudflare-assets.js','package-lock.json'],'manual_release_required'],
  ['mixed production plus docs',['index.html','docs/readme.md'],'manual_release_required'],
  ['unexpected root file',['scripts/unknown-builder.js'],'blocked'],
]) test(label,()=>assert.equal(state(files),expected));
test('renaming a production file requires a release', () => {
  const c=compare([]); c.files=[{filename:'docs/retired.md',previous_filename:'index.html',status:'renamed'}];
  assert.equal(classify(c,BASE,HEAD,paths).state,'manual_release_required');
});
test('renaming to an unknown file blocks', () => {
  const c=compare([]); c.files=[{filename:'unreviewed.js',previous_filename:'docs/a.md',status:'renamed'}];
  assert.equal(classify(c,BASE,HEAD,paths).state,'blocked');
});
test('diverged and incomplete comparisons fail closed', () => {
  const c=compare(['index.html']);
  for(const mutation of [
    x=>x.status='diverged',x=>x.total_commits=251,
    x=>x.files=Array(300).fill({filename:'README.md',status:'modified'}),
    x=>x.commits=[],x=>x.base_commit.sha='c'.repeat(40),
  ]) {
    const input=structuredClone(c);mutation(input);
    assert.equal(classify(input,BASE,HEAD,paths).state,'blocked');
  }
});
test('comparison API file list cannot disappear silently', () => {
  const c=compare(['docs/readme.md']);delete c.files;
  assert.equal(classify(c,BASE,HEAD,paths).state,'blocked');
});
