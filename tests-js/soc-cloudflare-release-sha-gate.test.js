'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {verify,approvedOrigin} = require('../scripts/soc-cloudflare-release-sha-gate.cjs');
const A = 'a'.repeat(40), B = 'b'.repeat(40);
function sample() {
  return {event:'workflow_dispatch', ref:'refs/heads/main',
    repository:'cyberdudebivash/cyberdudebivash-blog',
    origin:'https://github.com/cyberdudebivash/cyberdudebivash-blog.git',
    githubSha:A,headSha:A,mainSha:A,inputSha:A,approvedSha:A};
}
const result = mutate => { const s=sample(); if(mutate)mutate(s); return verify(s); };
test('separately approved current-main manual dispatch passes pin, never deploy authorization',()=>{
  assert.deepEqual(result(),{status:'PASS_NOT_DEPLOY_AUTHORIZATION',codes:[]});
  assert(approvedOrigin('git@github.com:cyberdudebivash/cyberdudebivash-blog.git'));
});
test('wrong workflow event, ref or repository identity fail closed',()=>{
  for(const tweak of [s=>s.event='push',s=>s.ref='refs/heads/release',
    s=>s.repository='attacker/repository',s=>s.origin='https://github.com/attacker/repository.git'])
    assert.equal(result(tweak).status,'HOLD');
});
test('all five SHA attestations are mandatory and correctly shaped',()=>{
  for(const field of ['githubSha','headSha','mainSha','inputSha','approvedSha']) {
    for(const value of ['',undefined,'1234','z'.repeat(40)])
      assert(result(s=>s[field]=value).codes.includes('RELEASE_SHA_MISSING_OR_INVALID'),field);
  }
});
test('changed approval, advancing main, forged run SHA or incorrect checkout hold',()=>{
  for(const field of ['githubSha','headSha','mainSha','inputSha','approvedSha'])
    assert(result(s=>s[field]=B).codes.includes('RELEASE_SHA_NOT_PINNED_TO_CURRENT_MAIN'),field);
});
test('uppercase hexadecimal input compares case-insensitively',()=>{
  assert.equal(result(s=>s.inputSha=A.toUpperCase()).status,'PASS_NOT_DEPLOY_AUTHORIZATION');
});
test('workflow pins before build and immediately before Worker mutation',()=>{
  const src=fs.readFileSync(path.join(__dirname,'..','.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  assert.match(src,/workflow_dispatch:\s*\n\s*inputs:\s*\n\s*approved_release_sha:/);
  assert.match(src,/github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main'/);
  assert.match(src,/environment: production/);
  const locations=[...src.matchAll(/run: node scripts\/soc-cloudflare-release-sha-gate\.cjs/g)].map(x=>x.index);
  assert.equal(locations.length,2,'pin must run early and again before deploy');
  assert(locations[0]<src.indexOf('Install locked dependencies'));
  assert(locations[1]>src.indexOf('P0 shared Cloudflare account zero-overage gate'));
  assert(locations[1]<src.indexOf('Deploy Worker assets to the existing, approved domain'));
  assert.equal((src.match(/secrets\.CDB_SOC_APPROVED_RELEASE_SHA/g)||[]).length,2);
  assert.equal((src.match(/inputs\.approved_release_sha/g)||[]).length,2);
});
test('pin helper cannot mutate production or claim customer release authorization',()=>{
  const src=fs.readFileSync(path.join(__dirname,'..','scripts/soc-cloudflare-release-sha-gate.cjs'),'utf8');
  assert.doesNotMatch(src,/wrangler|git\s+(?:push|reset|checkout)|cloudflare\.com\/client|writeFileSync|JSON\.stringify\(process\.env\)/);
  assert.match(src,/ls-remote/);
  assert.match(src,/PASS_NOT_DEPLOY_AUTHORIZATION/);
});
