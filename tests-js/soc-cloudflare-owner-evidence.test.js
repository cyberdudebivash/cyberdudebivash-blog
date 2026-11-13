'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {classifyDeployment,inventory,WORKER}=require('../scripts/soc-cloudflare-owner-inventory.cjs');
const drift=require('../scripts/production-drift-policy.cjs');
const root=path.resolve(__dirname,'..');
const UUID1='11111111-2222-4333-8444-555555555555';
const UUID2='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const NOW=Date.parse('2026-11-13T00:00:00.000Z');
const item=(extra={})=>({
  id:UUID1,created_on:'2026-11-12T23:00:00.000Z',source:'api',
  versions:[{percentage:100,version_id:UUID2}],...extra
});
const api=items=>({success:true,result:{deployments:items}});
const good=()=>api([item()]);
test('positive: exact active deployment with one 100-percent serving version',()=>{
  const out=classifyDeployment(good(),NOW);
  assert.equal(out.ok,true);
  assert.equal(out.code,'ACTIVE_WORKER_DEPLOYMENT_READ');
  assert.equal(out.versionId,UUID2);
});
test('negative: missing or malformed deployment inventory fails closed',()=>{
  for(const body of [null,{}, {success:false,result:{deployments:[item()]}},
    {success:true,result:{}},api([]),api([item({id:'not-a-uuid'})]),
    api([item({versions:[]})]),api([item({versions:[{percentage:100,version_id:'bad'}]})])]){
    assert.equal(classifyDeployment(body,NOW).ok,false,JSON.stringify(body));
  }
});
test('negative: traffic-split, stale-structure and future-dated inventory cannot be mistaken for a single rollback candidate',()=>{
  const half={percentage:50,version_id:UUID2};
  for(const body of [
    api([item({versions:[half,{percentage:50,version_id:UUID1}]})]),
    api([item({versions:[{percentage:99,version_id:UUID2}]})]),
    api([item({created_on:'not-a-date'})]),
    api([item({created_on:'2026-11-13T00:06:00Z'})]),
    api(Array.from({length:11},()=>item())),
  ])assert.equal(classifyDeployment(body,NOW).ok,false);
});
test('read-only inventory GETs list and exact active version and never claims a deployed release',async()=>{
  const called=[],token='synthetic-not-secret-token';
  const fetchImpl=async (url,opts)=>{
    called.push({url:String(url),method:opts.method,redirect:opts.redirect,auth:opts.headers.Authorization});
    assert.equal(opts.method,'GET');
    assert.equal(opts.redirect,'error');
    assert.equal(opts.headers.Authorization,'Bearer '+token);
    const body=called.length===1?good():{success:true,result:{id:UUID2}};
    return new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});
  };
  const result=await inventory({token,accountId:'a'.repeat(32),nowMs:NOW,fetchImpl});
  assert.equal(result.ok,true);
  assert.equal(result.rollbackVerified,false);
  assert.equal(result.productionReleaseAuthorized,false);
  assert.equal(result.versionFingerprint.length,16);
  assert(!JSON.stringify(result).includes(UUID2),'never expose the full version ID');
  assert.equal(called.length,2);
  assert(called[0].url.endsWith('/workers/scripts/'+WORKER+'/deployments?page=1&per_page=10'));
  assert(called[1].url.endsWith('/workers/scripts/'+WORKER+'/versions/'+UUID2));
  assert(called.every(c=>c.method==='GET'));
});
test('negative: inaccessible or mismatched Worker version blocks evidence',async()=>{
  for(const response of [
    {status:200,body:{success:false,result:{id:UUID2}}},
    {status:200,body:{success:true,result:{id:UUID1}}},
    {status:403,body:{}},
  ]){
    let n=0;
    const fetchImpl=async()=>new Response(JSON.stringify((++n===1)?good():response.body),{
      status:n===1?200:response.status});
    await assert.rejects(inventory({
      token:'synthetic-not-secret-token',accountId:'a'.repeat(32),
      nowMs:NOW,fetchImpl}),/ACTIVE_VERSION_NOT_READABLE|CLOUDFLARE_READ_HTTP_FAILURE/);
  }
});
test('no Cloudflare credentials or unbounded inventory means HOLD',async()=>{
  await assert.rejects(inventory({token:'',accountId:'a'.repeat(32)}),/CLOUDFLARE_READ_CONTEXT_MISSING/);
  await assert.rejects(inventory({token:'synthetic-not-secret-token',accountId:'invalid'}),/CLOUDFLARE_READ_CONTEXT_MISSING/);
  const fetchImpl=async()=>new Response(JSON.stringify(good()),{status:200});
  await assert.rejects(inventory({token:'synthetic-not-secret-token',accountId:'a'.repeat(32),
    fetchImpl,nowMs:NOW-90*60*1000}),/DEPLOYMENT_TIMESTAMP_INVALID/);
});
test('owner audit workflow is opt-in, no deployment operation, private and fail-closed',()=>{
  const workflow=fs.readFileSync(path.join(root,'.github/workflows/soc-owner-release-evidence.yml'),'utf8');
  assert.match(workflow,/^on:\s*\n  workflow_dispatch:/m);
  assert.doesNotMatch(workflow,/^\s*(?:schedule|push|pull_request|workflow_run)\s*:/m);
  assert.match(workflow,/^permissions:\s*\n  contents: read/m);
  assert.match(workflow,/environment: production/);
  assert.match(workflow,/if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(workflow,/timeout-minutes: 6/);
  assert.match(workflow,/persist-credentials: false/);
  assert.match(workflow,/node scripts\/cloudflare-account-zero-overage-gate\.cjs/);
  assert.match(workflow,/node scripts\/verify-existing-cloudflare-domain\.cjs/);
  assert.match(workflow,/node scripts\/soc-cloudflare-owner-inventory\.cjs/);
  assert.match(workflow,/node scripts\/certify-soc-public-feed-parity\.cjs/);
  assert.match(workflow,/node scripts\/certify-soc-s2n-api-release\.cjs --monitor-public/);
  assert.match(workflow,/SOC_READ_ONLY_EVIDENCE_INCOMPLETE/);
  assert.match(workflow,/exit 2/);
  assert.doesNotMatch(workflow,/npx wrangler|wrangler deploy|createWorkflowDispatch|\bcurl\s+-X\s*(?:POST|PUT|PATCH|DELETE)/i);
  assert.doesNotMatch(workflow,/actions:\s*write|contents:\s*write/);
});
test('new evidence utilities stay exact-path OPERATIONAL and unknown siblings still block',()=>{
  const source=fs.readFileSync(path.join(root,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  const patterns=drift.deployPaths(source);
  const names=['.github/workflows/soc-owner-release-evidence.yml','scripts/soc-cloudflare-owner-inventory.cjs'];
  for(const n of names)assert.equal(drift.isReviewedOperationalPath(n),true,n);
  const files=names.map(filename=>({filename,status:'added'}));
  const out=drift.classifyChangedFiles ?
    drift.classifyChangedFiles(files,patterns):
    drift.classify({status:'ahead',base_commit:{sha:'a'.repeat(40)},
      merge_base_commit:{sha:'a'.repeat(40)},ahead_by:1,behind_by:0,
      total_commits:1,commits:[{sha:'b'.repeat(40)}],files},'a'.repeat(40),'b'.repeat(40),patterns);
  assert.equal(out.state,'manual_release_required');
  assert.deepEqual(out.operational,names.slice().sort());
  assert.deepEqual(out.unknown,[]);
  assert.equal(drift.isReviewedOperationalPath('scripts/soc-cloudflare-owner-inventory-v2.cjs'),false);
});
