'use strict';

const fs=require('node:fs');
const path=require('node:path');
const ROOT=path.resolve(__dirname,'..');
const workflow=fs.readFileSync(
  path.join(ROOT,'.github','workflows','sentinel-apex.yml'),'utf8'
);
const homepage=fs.readFileSync(path.join(ROOT,'index.html'),'utf8');
const {assertHomepageIntegrity}=require('../scripts/soc-homepage-integrity');

describe('P0 intel publisher exact-tree integrity gates',()=>{
  test('published source currently passes strict homepage structural assertions',()=>{
    expect(assertHomepageIntegrity(homepage)).toBe(homepage);
  });
  test('precommit gate runs after generator and before git add -A',()=>{
    const generate=workflow.indexOf('timeout 290 node fetch-live-intel.js');
    const gate=workflow.indexOf('P0 homepage precommit integrity gate');
    const staging=workflow.indexOf('git add -A');
    expect(generate).toBeGreaterThan(0);
    expect(gate).toBeGreaterThan(generate);
    expect(staging).toBeGreaterThan(gate);
    expect(workflow).toMatch(/assertHomepageIntegrity\(require\('fs'\)\.readFileSync\('index\.html','utf8'\),'publisher precommit'\)/);
  });
  test('post-rebase retry checks final checkout before every git push',()=>{
    const loop=workflow.indexOf('for i in 1 2 3; do');
    const check=workflow.indexOf("'publisher prepush'");
    const push=workflow.indexOf('if git push origin main; then',loop);
    const rebase=workflow.indexOf('git pull --rebase origin main',push);
    expect(loop).toBeGreaterThan(0);
    expect(check).toBeGreaterThan(loop);
    expect(push).toBeGreaterThan(check);
    expect(rebase).toBeGreaterThan(push);
    expect(workflow).not.toContain('|| true # disable homepage validation');
  });
});
