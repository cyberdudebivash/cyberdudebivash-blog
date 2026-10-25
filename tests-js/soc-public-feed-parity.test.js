'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {inspect,assess,check,boundedJson,TARGETS}=require('../scripts/certify-soc-public-feed-parity.cjs');
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
