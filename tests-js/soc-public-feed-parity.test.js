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
