'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {evaluate}=require('../scripts/check-intel-source-yield.cjs');
const now=Date.parse('2026-10-25T06:15:00Z');
function fixture({active=5,total=35,records=75,reports=0,age=10}={}) {
  const checkedAt=new Date(now-age*60000).toISOString();
  return {lastRun:checkedAt,lastIngestion:{checkedAt,activeSources:active,
    totalSources:total,fetchedRecords:records,reportsGenerated:reports}};
}
test('5 of 35 sources returning records passes even when no novel report exists',()=>{
  const result=evaluate(fixture(),now);
  assert.equal(result.status,'COVERAGE_VERIFIED');
  assert.equal(result.exitCode,0);
  assert.equal(result.reportsGenerated,0);
});
test('reproduce production incident: 2 of 35 return items but previous 6518 cumulative is NOT healthy',()=>{
  const state={...fixture({active:2,total:35,reports:0}),totalPublished:6518};
  const result=evaluate(state,now);
  assert.equal(result.status,'SOURCE_COVERAGE_DEGRADED');
  assert.equal(result.exitCode,2);
  assert.equal(result.code,'FEWER_THAN_FIVE_SOURCES_RETURNED_RECORDS');
});
test('source count can never be inferred from old state.sourceHealth ok entries',()=>{
  const state=fixture({active:0,total:35,records:0});
  state.sourceHealth=Object.fromEntries(Array.from({length:35},(_,i)=>['s'+i,{status:'ok'}]));
  assert.equal(evaluate(state,now).status,'SOURCE_COVERAGE_DEGRADED');
});
test('receipt impossible counts fail as monitoring corruption',()=>{
  for(const v of [-1,36,1.5,'35']) {
    assert.equal(evaluate(fixture({active:v}),now).status,'MONITOR_ERROR',String(v));
  }
  assert.equal(evaluate(fixture({total:0}),now).status,'MONITOR_ERROR');
  assert.equal(evaluate(fixture({reports:-1}),now).status,'MONITOR_ERROR');
  assert.equal(evaluate({lastRun:fixture().lastRun},now).status,'MONITOR_ERROR');
});
test('stale, future, or detached receipts do not certify green',()=>{
  assert.equal(evaluate(fixture({age:121}),now).code,'INGESTION_RECEIPT_TIME_INVALID');
  assert.equal(evaluate(fixture({age:-10}),now).code,'INGESTION_RECEIPT_TIME_INVALID');
  const invalid=fixture();invalid.lastRun='2026-10-24T03:00:00Z';
  assert.equal(evaluate(invalid,now).code,'INGESTION_RECEIPT_TIME_INVALID');
});
test('real source-health implementation records empty results separately from transport failures',()=>{
  const engine=require('../fetch-live-intel.js');
  const state={sourceHealth:{}};
  engine.recordSourceSuccess(state,'test',0);
  assert.equal(state.sourceHealth.test.status,'empty');
  assert.equal(state.sourceHealth.test.lastItemCount,0);
  assert.equal(state.sourceHealth.test.lastDataAt,undefined);
  assert.equal(engine.getSourceHealthReport(state).empty.length,1);
  engine.recordSourceSuccess(state,'test',3);
  assert.equal(state.sourceHealth.test.status,'ok');
  assert.equal(state.sourceHealth.test.lastItemCount,3);
  assert.equal(state.sourceHealth.test.consecutiveEmpty,0);
  assert.equal(engine.getSourceHealthReport(state).empty.length,0);
});
test('workflow gate executes after commit to preserve legitimately generated reports',()=>{
  const fs=require('node:fs');
  const path=require('node:path');
  const wf=fs.readFileSync(path.join(__dirname,'..','.github/workflows/sentinel-apex.yml'),'utf8');
  assert(wf.indexOf('Commit and push intel') < wf.indexOf('node scripts/check-intel-source-yield.cjs'));
  assert(wf.indexOf('node scripts/check-intel-source-yield.cjs') < wf.indexOf('name: "Run summary"'));
  assert.match(wf,/cancel-in-progress: false/);
});
