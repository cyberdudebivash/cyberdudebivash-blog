'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs'),path=require('node:path');
const {verdict,isApprovedOrigin}=require('../scripts/soc-operator-release-preflight.cjs');
const {PLAN,REQUIRED_PLATFORMS}=require('../scripts/cloudflare-account-zero-overage-gate.cjs');
const NOW=Date.parse('2026-10-26T16:10:00Z'),SHA='a'.repeat(40),ACCOUNT='b'.repeat(32);
const stamp=m=>new Date(NOW-m*60*1000).toISOString();
function sample(){
  const ids=Array.from({length:12},(_,i)=>({id:'CVE-2026-'+(10000+i)}));
  const t=stamp(20);
  return {
    approvedSha:SHA,accountId:ACCOUNT,nowMs:NOW,
    git:{origin:'https://github.com/cyberdudebivash/cyberdudebivash-blog.git',
      head:SHA,upstream:SHA,clean:true,shallow:false},
    budgetEvidence:{
      schemaVersion:'cdb-cloudflare-shared-budget/v1',
      accountScope:'ALL_PLATFORMS_SINGLE_CLOUDFLARE_ACCOUNT',
      accountCoverageConfirmed:true,allActiveMeteredServicesReviewed:true,
      reviewedPlatforms:[...REQUIRED_PLATFORMS],
      accountFingerprintSha256:crypto.createHash('sha256').update(ACCOUNT).digest('hex'),
      source:'cloudflare-account-billing-and-service-metrics',
      privateEvidenceSha256:'c'.repeat(64),
      operatorApprovalReference:'vault/owner-release-20261026',
      operatorReviewed:true,verifiedWorkersPlan:'paid-standard',
      r2StorageClass:'standard-only',anyInfrequentAccessStorage:false,
      unmodeledBillableServicesPresent:false,optionalPaidProductsOrAddonsPresent:false,
      currentAccountProjectedOverageUsd:0,
      cycle:{start:'2026-10-01T00:00:00.000Z',end:'2026-11-01T00:00:00.000Z'},
      capturedAt:stamp(15),
      metrics:Object.fromEntries(Object.entries(PLAN).map(([k,v])=>[k,{used:v*.10,forecastRemaining:v*.15}]))
    },
    bundle:{
      state:{lastRun:t,lastReportGeneratedAt:t,totalPublished:6563,lastIngestion:{reportsGenerated:15}},
      rootSource:{generatedAt:t,totalPublished:6563,metadata:{lastPipelineRun:t},items:ids},
      apiSource:{generated:t,total_published:6563,items:ids},
      rootAsset:{generatedAt:t,totalPublished:6563,metadata:{lastPipelineRun:t},items:structuredClone(ids)},
      apiAsset:{generated:t,total_published:6563,items:structuredClone(ids)}
    }
  };
}
const evaluate=fn=>{const x=sample();if(fn)fn(x);return verdict(x);};
test('reconciled local source and genuine private budget receipt passes only offline preflight',()=>{
  const out=evaluate();
  assert.equal(out.status,'OFFLINE_PREFLIGHT_PASS_NOT_DEPLOY_APPROVAL',JSON.stringify(out));
  assert.equal(out.customerManagedSocGo,false);
  assert.equal(out.workerDeploymentAuthorized,false);
});
test('unapproved or wrong remote fails even for clean matching HEAD and fresh intel',()=>{
  assert(isApprovedOrigin('git@github.com:cyberdudebivash/cyberdudebivash-blog.git'));
  assert(isApprovedOrigin('https://github.com/cyberdudebivash/cyberdudebivash-blog'));
  for(const remote of ['https://github.com/attacker/cyberdudebivash-blog.git',
    'https://github.com/cyberdudebivash/cyberdudebivash-blog-malicious',
    'https://evil.example/cyberdudebivash/cyberdudebivash-blog'])
    assert(evaluate(x=>x.git.origin=remote).codes.includes('REPOSITORY_ORIGIN_NOT_APPROVED'));
});
test('unpinned/unfetched origin main, dirty local edits, incomplete history fail closed',()=>{
  for(const edit of [
    x=>x.git.head='b'.repeat(40),
    x=>x.git.upstream='b'.repeat(40),
    x=>x.approvedSha='b'.repeat(40)
  ])assert(evaluate(edit).codes.includes('PINNED_SHA_NOT_CURRENT_MAIN'));
  assert(evaluate(x=>x.git.clean=false).codes.includes('GIT_WORKTREE_NOT_CLEAN'));
  assert(evaluate(x=>x.git.shallow=true).codes.includes('COMPLETE_GIT_HISTORY_NOT_VERIFIED'));
});
test('missing or stale private Cloudflare usage never authorizes a release',()=>{
  assert(evaluate(x=>x.budgetEvidence=null).codes.includes('ACCOUNT_WIDE_BUDGET_UNCERTIFIED'));
  assert(evaluate(x=>x.budgetEvidence.capturedAt=stamp(130)).codes.includes('ACCOUNT_WIDE_BUDGET_UNCERTIFIED'));
  assert(evaluate(x=>x.budgetEvidence.reviewedPlatforms.pop()).codes.includes('ACCOUNT_WIDE_BUDGET_UNCERTIFIED'));
});
test('forecast paid overage or unmodeled services must block even when source is fresh',()=>{
  assert(evaluate(x=>x.budgetEvidence.metrics.queuesStandardOperations.used=900000)
    .codes.includes('ACCOUNT_WIDE_BUDGET_UNCERTIFIED'));
  assert(evaluate(x=>x.budgetEvidence.unmodeledBillableServicesPresent=true)
    .codes.includes('ACCOUNT_WIDE_BUDGET_UNCERTIFIED'));
});
test('last real publication stale, source ledger disagreement or built API drift holds',()=>{
  assert(evaluate(x=>x.bundle.state.lastReportGeneratedAt=stamp(300))
    .codes.includes('SOURCE_AND_BUILT_FEEDS_NOT_CERTIFIED'));
  assert(evaluate(x=>x.bundle.apiSource.total_published=6548)
    .codes.includes('SOURCE_AND_BUILT_FEEDS_NOT_CERTIFIED'));
  assert(evaluate(x=>x.bundle.apiAsset.items.reverse())
    .codes.includes('SOURCE_AND_BUILT_FEEDS_NOT_CERTIFIED'));
});
test('helper remains local read only and cannot deploy or claim customer readiness',()=>{
  const src=fs.readFileSync(path.join(__dirname,'..','scripts/soc-operator-release-preflight.cjs'),'utf8');
  assert.doesNotMatch(src,/npx\s+wrangler|wrangler\s+deploy|git\s+push|git\s+checkout|workflow_dispatch/);
  assert.match(src,/workerDeploymentAuthorized:false,customerManagedSocGo:false/);
  assert.match(src,/--porcelain=v1/);
  assert.match(src,/refs\/remotes\/origin\/main/);
});
