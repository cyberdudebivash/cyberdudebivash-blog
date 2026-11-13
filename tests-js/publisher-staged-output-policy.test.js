'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {isApprovedPath,assessStagedPaths,MAX_FILES} =
  require('../scripts/assert-publisher-staged-paths.cjs');
const regular=()=>({isFile:()=>true,isSymbolicLink:()=>false});
const symlink=()=>({isFile:()=>false,isSymbolicLink:()=>true});

test('published intelligence output paths are explicitly allowlisted',()=>{
  const approved=[
    'live-intel.json','intel-state.json','intel-memory.json',
    'rss.xml','sitemap.xml','search-index.json','index.html',
    'data/ioc-feed.json','data/ioc-store.json',
    'api/intel/live.json','api/intel/iocs.json',
    'api/intel/cve/CVE-2026-0257.json',
    'api/intel/products/cve-2026-128027-frankenphp.json',
    'posts/cve-2026-128027-frankenphp.html'
  ];
  for(const file of approved)assert.equal(isApprovedPath(file),true,file);
  assert.equal(assessStagedPaths(approved,regular).status,'PASS');
});

test('new code, workflows, keys, generated executable and customer data never enter scheduled publication commits',()=>{
  const forbidden=[
    '.github/workflows/cloudflare-production-deploy.yml','workers/entry.js',
    'scripts/unknown.js','api/v1/billing.js','api/_lib/security.js',
    'package.json','package-lock.json','wrangler.jsonc','migrations/0001.sql',
    '.env','.npmrc','credentials.json','logs/run-20261113-001.json',
    'data/customer-data.json','api/intel/private.json',
    'api/intel/cve/not-a-cve.json','posts/unsafe.js','posts/nested/post.html',
    '../secrets.txt','api/intel/../secret.json','api//intel/live.json',
    '/api/intel/live.json','posts\\post.html','posts/.hidden.html'
  ];
  for(const file of forbidden){
    assert.equal(isApprovedPath(file),false,file);
    assert.equal(assessStagedPaths([file],regular).status,'HOLD',file);
  }
});

test('deletions, symlinks and excessive staging fail closed',()=>{
  assert.equal(assessStagedPaths(['posts/valid.html'],symlink).status,'HOLD');
  assert.equal(assessStagedPaths(['posts/valid.html'],()=>{throw Error('ENOENT')}).status,'HOLD');
  assert.equal(assessStagedPaths(Array(MAX_FILES+1).fill('live-intel.json'),regular).status,'HOLD');
  assert.equal(assessStagedPaths(null,regular).status,'HOLD');
});

test('high-frequency publisher must enforce the staged output gate before commit and each push remains ledger-certified',()=>{
  const wf=fs.readFileSync(path.join(__dirname,'..','.github/workflows/sentinel-apex.yml'),'utf8');
  const stage=wf.indexOf('git add -A');
  const gate=wf.indexOf('node scripts/assert-publisher-staged-paths.cjs');
  const commit=wf.indexOf('git commit -m "$COMMIT_MSG"');
  const push=wf.indexOf('if git push origin main');
  assert(stage>=0&&gate>stage&&commit>gate&&push>commit,
    'staged paths must be checked after staging and before commit/push');
  assert.match(wf,/node scripts\/assert-publication-ledger\.cjs/);
  assert.match(wf,/git reset HEAD pipeline\.lock/);
  assert.doesNotMatch(wf,/node scripts\/assert-publisher-staged-paths\.cjs\s*\|\|\s*true/);
});
