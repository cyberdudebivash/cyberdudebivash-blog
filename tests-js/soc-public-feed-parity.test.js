'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {inspect,assess,predeployGate,check,boundedJson,TARGETS}=require('../scripts/certify-soc-public-feed-parity.cjs');
const now=Date.parse('2026-10-25T05:10:00.000Z');
function fixture({stamp='2026-10-25T04:40:00.000Z',total=6518,items=150}={}){
  return {generatedAt:stamp,metadata:{lastPipelineRun:stamp},totalPublished:total,items:Array.from({length:items},(_,id)=>({id}))};
}
function fakeResponse(d,{status=200,type='application/json'}={}){
  const response=new Response(JSON.stringify(d),{status,headers:{'content-type':type}});
  return response;
}
test('exact source and public parity passes with real bounded timestamp',()=>{
  const r=assess(fixture(),fixture(),now);assert.equal(r.status,'PASS');
});
test('screenshot regression: 23 Oct production versus 25 Oct source is a hard P0 failure',()=>{
  const r=assess(fixture(),fixture({stamp:'2026-10-23T04:58:29.679Z',total:6466}),now);
  assert.equal(r.status,'FAIL');assert.equal(r.reason,'PUBLIC_PIPELINE_STALE');
  assert.equal(r.live.totalPublished,6466);
});
test('fresh-enough public file still fails if five-plus minutes behind source',()=>{
  const r=assess(fixture(),fixture({stamp:'2026-10-25T04:30:00Z',total:6518}),now);
  assert.equal(r.reason,'PUBLIC_SOURCE_DEPLOYMENT_DRIFT');
});
test('public corpus regression is not hidden by current timestamp',()=>{
  const r=assess(fixture(),fixture({total:6466}),now);
  assert.equal(r.reason,'PUBLIC_CORPUS_BEHIND_SOURCE');
});
test('source itself stale cannot attest production freshness',()=>{
  const r=assess(fixture({stamp:'2026-10-24T01:10:00Z'}),fixture(),now);
  assert.equal(r.reason,'SOURCE_PIPELINE_STALE');
});
test('invalid JSON shape and future-dated generatedAt fail closed',()=>{
  assert.equal(inspect({...fixture(),items:[]},now).reason,'INVALID_FEED_SHAPE');
  assert.equal(inspect(fixture({stamp:'2026-10-26T01:00:00Z'}),now).reason,'FUTURE_PIPELINE_TIMESTAMP');
});
test('reader rejects HTML success and returns inconclusive on public 429',async()=>{
  assert.equal((await boundedJson(fakeResponse(fixture(),{type:'text/html'}))).reason,'PUBLIC_CONTENT_TYPE_INVALID');
  assert.equal((await boundedJson(fakeResponse({}, {status:429}))).status,'INCONCLUSIVE');
});
test('both SOC and legacy public domain must return source-concordant data',async()=>{
  const visited=[];
  const out=await check({expected:fixture(),nowMs:now,fetchImpl:async(url)=>{
    visited.push(url);return fakeResponse(url===TARGETS.soc?fixture():fixture({total:6466}));
  }});
  assert.deepEqual(visited,[TARGETS.soc,TARGETS.blog]);
  assert.equal(out.status,'FAIL');
  assert.equal(out.results[1].reason,'PUBLIC_CORPUS_BEHIND_SOURCE');
});
test('unreachable edge cannot be misrepresented as healthy',async()=>{
  const out=await check({expected:fixture(),nowMs:now,fetchImpl:async()=>{throw Error('offline');}});
  assert.equal(out.status,'INCONCLUSIVE');assert(out.results.every(r=>r.reason==='PUBLIC_READ_UNAVAILABLE'));
});


test('a recent pipeline heartbeat never masks an old lastReportGeneratedAt',()=>{
  const fresh=fixture();
  const r=assess(fresh,fresh,now,{
    sourceState:{lastRun:fresh.generatedAt,lastReportGeneratedAt:'2026-10-24T21:27:18.946Z'}
  });
  assert.equal(r.status,'FAIL');
  assert.equal(r.reason,'SOURCE_INTEL_CONTENT_STALE');
});
test('missing or future-dated report receipts cannot certify a release',()=>{
  const f=fixture();
  assert.equal(assess(f,f,now,{sourceState:{lastRun:f.generatedAt}}).reason,'SOURCE_REPORT_EVIDENCE_MISSING');
  assert.equal(assess(f,f,now,{sourceState:{lastRun:f.generatedAt,lastReportGeneratedAt:'2026-10-25T05:50:00Z'}}).reason,'SOURCE_REPORT_TIMESTAMP_FUTURE');
  assert.equal(assess(f,f,now,{sourceState:{lastRun:'2026-10-24T03:00:00Z',lastReportGeneratedAt:f.generatedAt}}).reason,'SOURCE_STATE_RUNTIME_MISMATCH');
});
test('byte exact release verification passes only for identical build artifact',()=>{
  const f=fixture();
  const bytes=Buffer.from(JSON.stringify(f));
  const state={lastRun:f.generatedAt,lastReportGeneratedAt:f.generatedAt};
  assert.equal(assess(f,f,now,{sourceState:state,expectedBytes:bytes,publicBytes:Buffer.from(bytes)}).status,'PASS');
  const altered=Buffer.from(JSON.stringify({...f,harmlessLookingExtraField:true}));
  assert.equal(assess(f,{...f,harmlessLookingExtraField:true},now,{sourceState:state,expectedBytes:bytes,publicBytes:altered}).reason,'PUBLIC_ASSET_SHA256_MISMATCH');
  assert.equal(assess(f,f,now,{sourceState:state,expectedBytes:bytes}).reason,'PUBLIC_ASSET_BYTES_UNAVAILABLE');
});
test('bounded network reader supplies exact public bytes to release parity gate',async()=>{
  const f=fixture();
  const expectedBytes=Buffer.from(JSON.stringify(f));
  const state={lastRun:f.generatedAt,lastReportGeneratedAt:f.generatedAt};
  const out=await check({expected:f,expectedBytes,sourceState:state,nowMs:now,fetchImpl:async()=>fakeResponse(f)});
  assert.equal(out.status,'PASS');
  const drift=await check({expected:f,expectedBytes,sourceState:state,nowMs:now,
    fetchImpl:async()=>new Response(JSON.stringify({...f,mark:'different'}),{status:200,headers:{'content-type':'application/json'}})});
  assert.equal(drift.status,'FAIL');
  assert(drift.results.every(r=>r.reason==='PUBLIC_ASSET_SHA256_MISMATCH'));
});

test('P0 predeploy gate passes an identical recent source/report/build without any network',()=>{
  const feed=fixture();const state={lastRun:feed.generatedAt,lastReportGeneratedAt:feed.generatedAt};
  assert.deepEqual(predeployGate({source:feed,asset:structuredClone(feed),state,nowMs:now}),
    {status:'PASS',reason:'SOURCE_REPORT_AND_BUILT_ASSET_FRESH'});
});
test('P0 predeploy negative: recent heartbeat with stale real report blocks BEFORE mutation',()=>{
  const feed=fixture();
  const result=predeployGate({source:feed,asset:feed,
    state:{lastRun:feed.generatedAt,lastReportGeneratedAt:'2026-10-24T21:27:18.946Z'},nowMs:now});
  assert.deepEqual(result,{status:'FAIL',reason:'SOURCE_INTEL_CONTENT_STALE'});
});
test('P0 predeploy negative: source pipeline stale or source state missing blocks',()=>{
  const old=fixture({stamp:'2026-10-24T03:54:29Z'});
  assert.equal(predeployGate({source:old,asset:old,
    state:{lastRun:old.generatedAt,lastReportGeneratedAt:old.generatedAt},nowMs:now}).reason,
    'SOURCE_PIPELINE_STALE');
  const feed=fixture();
  assert.equal(predeployGate({source:feed,asset:feed,state:{lastRun:feed.generatedAt},nowMs:now}).reason,
    'SOURCE_REPORT_EVIDENCE_MISSING');
});
test('P0 predeploy negative: altered build timestamp, corpus, or item window blocks',()=>{
  const feed=fixture();
  const state={lastRun:feed.generatedAt,lastReportGeneratedAt:feed.generatedAt};
  const verdict=asset=>predeployGate({source:feed,asset,state,nowMs:now}).reason;
  assert.equal(verdict({...feed,generatedAt:'2026-10-25T04:41:00Z'}),
    'PREDEPLOY_BUILD_TIMESTAMP_DIVERGED');
  assert.equal(verdict({...feed,totalPublished:feed.totalPublished+1}),
    'PREDEPLOY_BUILD_CORPUS_DIVERGED');
  assert.equal(verdict({...feed,items:feed.items.slice(1)}),
    'PREDEPLOY_BUILD_ITEMS_DIVERGED');
});

test('release workflow structurally preserves predeploy-before-mutation and public parity after',()=>{
  const fs=require('node:fs');
  const path=require('node:path');
  const workflow=fs.readFileSync(path.join(__dirname,'..','.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  const build=workflow.indexOf('npm run build:cloudflare');
  const preflight=workflow.indexOf('node scripts/certify-soc-public-feed-parity.cjs --predeploy');
  const mutation=workflow.indexOf('npx wrangler deploy --config wrangler.jsonc');
  const postflight=workflow.indexOf('node scripts/certify-soc-public-feed-parity.cjs --release-asset');
  assert(build>=0&&preflight>build&&mutation>preflight&&postflight>mutation,
    'required order: built source, offline P0 freshness gate, Wrangler mutation, live two-host SHA-256 parity');
  assert.match(workflow,/if:\s*\$\{\{\s*github\.event_name == 'workflow_dispatch'\s*&&\s*github\.ref == 'refs\/heads\/main'/,
    'the Cloudflare deploy must remain explicitly approved and manual-only');
});
