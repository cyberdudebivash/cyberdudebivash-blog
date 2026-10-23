'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { deployPaths, classify, classifyVerifiedGitTrees, renderDriftSummary } = require('../scripts/production-drift-policy.cjs');

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
  assert.match(deploy,/\n  deploy:[\s\S]{0,350}?if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
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

test('negative control: feature-branch dispatch must not reach production', () => {
  const jobBlock = deploy.slice(deploy.indexOf('\n  deploy:'), deploy.indexOf('\n    steps:',deploy.indexOf('\n  deploy:')));
  assert.ok(jobBlock.includes("github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"));
  assert.ok(jobBlock.includes('environment: production'));
  assert.doesNotMatch(jobBlock,/refs\/tags\//);
});


test('P0 regression: mixed 288-file drift retains 228 production, 31 benign and 29 unknown paths', () => {
  const production = Array.from({ length: 228 }, (_, i) => 'api/intel/cve/fixture-' + i + '.json');
  const benign = Array.from({ length: 31 }, (_, i) => 'docs/release-evidence/fixture-' + i + '.md');
  const unknown = Array.from({ length: 29 }, (_, i) => 'scripts/operator-unclassified-' + i + '.cjs');
  const files = [...production, ...benign, ...unknown];
  const r = classify(compare(files), BASE, HEAD, paths);
  assert.equal(r.state, 'blocked');
  assert.equal(r.reason, 'unrecognized changed files require source review');
  assert.equal(r.compared_files, 288);
  assert.equal(r.production.length, 228);
  assert.equal(r.benign.length, 31);
  assert.equal(r.unknown.length, 29);
  assert.equal(r.production[0], 'api/intel/cve/fixture-0.json');
  const summary = renderDriftSummary(HEAD, BASE, r);
  assert.match(summary, /decision: \*\*blocked\*\*/);
  assert.match(summary, /production-affecting files: 228/);
  assert.match(summary, /known nonproduction files: 31/);
  assert.match(summary, /unknown files: 29/);
  assert.match(summary, /total compared changed files: 288/);
  assert.match(summary, /scripts\/operator-unclassified-0\.cjs/);
  assert.match(summary, /api\/intel\/cve\/fixture-0\.json/);
  assert.match(summary, /plus 216 additional production paths/);
  assert.match(summary, /No deployment or workflow dispatch/);
});

test('P0 negative control: unknown review cannot authorize deployment or conceal production changes', () => {
  const files = ['workers/entry.js', 'index.html', 'scripts/unknown-sensitive.cjs', 'docs/runbook.md'];
  const initial = classify(compare(files), BASE, HEAD, paths);
  assert.equal(initial.state, 'blocked');
  assert.deepEqual(initial.production, ['index.html', 'workers/entry.js']);
  assert.deepEqual(initial.unknown, ['scripts/unknown-sensitive.cjs']);
  assert.deepEqual(initial.benign, ['docs/runbook.md']);
  // Even after an explicitly reviewed path becomes known-nonproduction,
  // the existing changes to Worker and homepage REQUIRE manual release.
  const reviewed = classify(compare(['workers/entry.js', 'index.html', 'docs/reviewed.md', 'docs/runbook.md']),
    BASE, HEAD, paths);
  assert.equal(reviewed.state, 'manual_release_required');
  assert.equal(reviewed.production.length, 2);
  assert.equal(reviewed.unknown.length, 0);
  assert.match(renderDriftSummary(HEAD, BASE, reviewed), /production-affecting files: 2/);
});

test('P0 summary bounds large unclassified path lists without hiding the total', () => {
  const unknown = Array.from({ length: 60 }, (_, i) => 'unclassified-fixture-' + i + '.cjs');
  const result = classify(compare(unknown), BASE, HEAD, paths);
  assert.equal(result.state, 'blocked');
  const summary = renderDriftSummary(HEAD, BASE, result);
  assert.match(summary, /unknown files: 60/);
  assert.match(summary, /plus 30 additional unclassified paths/);
  assert.doesNotMatch(summary, /unclassified-fixture-59\.cjs/);
});

test('P0 incomplete comparison still hard blocks and never represents a verified zero baseline', () => {
  const bad = compare(['index.html']); delete bad.files;
  const result = classify(bad, BASE, HEAD, paths);
  assert.equal(result.state, 'blocked');
  const summary = renderDriftSummary(HEAD, BASE, result);
  assert.match(summary, /total compared changed files: not certified/);
  assert.match(summary, /decision: \*\*blocked\*\*/);
});


const TREE_OLD = 'c'.repeat(40), TREE_NEW = 'd'.repeat(40);
const BLOB_OLD = 'e'.repeat(40), BLOB_NEW = 'f'.repeat(40);
function blob(name,sha=BLOB_OLD,mode='100644') {
  return {path:name,type:'blob',mode,sha};
}
function treeFixtures(oldEntries,newEntries) {
  const comparison = compare(Array.from({length:300},(_,i)=>'docs/compare-truncated-'+i+'.md'));
  comparison.base_commit.commit={tree:{sha:TREE_OLD}};
  comparison.commits.at(-1).commit={tree:{sha:TREE_NEW}};
  return {
    comparison,
    previous:{sha:TREE_OLD,truncated:false,tree:oldEntries},
    current:{sha:TREE_NEW,truncated:false,tree:newEntries},
  };
}
function verifyTrees(f) {
  return classifyVerifiedGitTrees(f.comparison,BASE,HEAD,paths,f.previous,f.current);
}
test('P0: 300-file GitHub compare truncation is independently reconstructed using complete immutable Git trees',()=>{
  const old=[blob('README.md'),blob('index.html')];
  const newEntries=[
    blob('README.md'),blob('index.html',BLOB_NEW),
    ...Array.from({length:301},(_,i)=>blob('docs/full-tree-'+i+'.md')),
    blob('scripts/new-control-plane.js')
  ];
  const f=treeFixtures(old,newEntries);
  assert.equal(classify(f.comparison,BASE,HEAD,paths).state,'blocked');
  const result=verifyTrees(f);
  assert.equal(result.state,'blocked');
  assert.equal(result.reason,'unrecognized changed files require source review');
  assert.equal(result.comparison_source,'verified_full_git_trees');
  assert.equal(result.compared_files,303);
  assert.equal(result.production.length,1);
  assert.deepEqual(result.production,['index.html']);
  assert.equal(result.benign.length,301);
  assert.deepEqual(result.unknown,['scripts/new-control-plane.js']);
  assert.match(renderDriftSummary(HEAD,BASE,result),/comparison source: verified_full_git_trees/);
  assert.match(renderDriftSummary(HEAD,BASE,result),/production-affecting files: 1/);
  assert.match(renderDriftSummary(HEAD,BASE,result),/decision: \*\*blocked\*\*/);
});
test('P0: complete tree classification of docs-only >300-file change remains no automatic deployment',()=>{
  const previous=[blob('README.md')];
  const newer=[blob('README.md'),...Array.from({length:305},(_,i)=>blob('docs/snapshot-'+i+'.md'))];
  const result=verifyTrees(treeFixtures(previous,newer));
  assert.equal(result.state,'nonproduction_only');
  assert.equal(result.compared_files,305);
  assert.equal(result.unknown.length,0);
  assert.equal(result.production.length,0);
});
test('P0: tree rename classifies both old and new paths; executable mode changes require review',()=>{
  const ren=verifyTrees(treeFixtures(
    [blob('index.html'),blob('api/module.js')],
    [blob('docs/new.html'),blob('api/module.js',BLOB_OLD,'100755')]));
  assert.equal(ren.state,'manual_release_required');
  assert.deepEqual(ren.production,['api/module.js','index.html']);
  assert.deepEqual(ren.benign,['docs/new.html']);
});
test('P0: incomplete, spoofed or malformed full Git trees are always blocked',()=>{
  const factory=()=>treeFixtures([blob('README.md')],[blob('README.md'),blob('index.html')]);
  const mutants=[
    f=>{f.previous.truncated=true},
    f=>{f.current.truncated=undefined},
    f=>{f.previous.sha='e'.repeat(40)},
    f=>{f.current.sha='f'.repeat(40)},
    f=>{f.comparison.base_commit.commit.tree.sha='0'.repeat(40)},
    f=>{f.comparison.commits[0].commit.tree.sha='0'.repeat(40)},
    f=>{f.comparison.status='diverged'},
    f=>{f.comparison.commits=[]},
    f=>{f.comparison.total_commits=250},
    f=>{f.comparison.merge_base_commit.sha='0'.repeat(40)},
    f=>{f.previous.tree=[]},
    f=>{f.current.tree.push(blob('index.html'))},
    f=>{f.current.tree.push({...blob('other.js'),mode:'999999'})},
    f=>{f.current.tree.push({...blob('other.js'),type:'tree'})},
    f=>{f.current.tree.push({...blob('other.js'),sha:'123'})},
    f=>{f.current.tree.push({...blob('other.js'),path:'../escape.js'})},
  ];
  for (const mutate of mutants) {
    const fixture=factory();mutate(fixture);
    assert.equal(verifyTrees(fixture).state,'blocked',String(mutate));
  }
});
test('P0: no source changes cannot be mistaken for a verified deployed release',()=>{
  const f=treeFixtures([blob('README.md')],[blob('README.md')]);
  const r=verifyTrees(f);
  assert.equal(r.state,'nonproduction_only');
  assert.equal(r.compared_files,0);
  assert.equal(r.comparison_source,'verified_full_git_trees');
});
