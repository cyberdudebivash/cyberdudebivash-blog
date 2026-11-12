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

test('scheduled publisher heartbeat never manufactures a new report timestamp or missing item evidence date',()=>{
  const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
  const source=fs.readFileSync(path.join(__dirname,'..','.github/workflows/sentinel-apex.yml'),'utf8');
  const start=source.indexOf('- name: "Ensure feed heartbeat (production stability)"');
  const end=source.indexOf('      # A timed-out publisher',start);
  assert.ok(start>=0&&end>start,'publisher heartbeat step must exist');
  const script=source.slice(start,end).match(/node -e "\n([\s\S]*?)\n          " 2>&1/);
  assert.ok(script,'embedded heartbeat program must be present and isolated');
  const prior='2026-10-23T04:58:15.799Z';
  const now='2026-11-03T16:15:00.000Z';
  const fixture={
    metadata:{generatedAt:prior,lastPipelineRun:prior},
    generatedAt:prior,
    items:[
      {id:'existing',_addedAt:'2026-10-20',pubDate:'2026-10-19'},
      {id:'dated',pubDate:'2026-10-21'},
      {id:'undated'},
      {id:'invalid',pubDate:'unknown'},
      {id:'future',pubDate:'2027-01-01'},
    ],
  };
  let output;
  class FixedDate extends Date{
    constructor(...args){super(...(args.length?args:[now]));}
    static now(){return Date.parse(now);}
  }
  const context={
    Date:FixedDate,
    require(name){
      assert.equal(name,'fs');
      return {
        readFileSync(file,encoding){assert.equal(file,'live-intel.json');assert.equal(encoding,'utf8');return JSON.stringify(fixture);},
        writeFileSync(file,content){assert.equal(file,'live-intel.json');output=JSON.parse(content);},
      };
    },
    console:{log(){},error(message){throw new Error(String(message));}},
  };
  vm.runInNewContext(script[1],context,{timeout:1000});
  assert.ok(output,'heartbeat must persist the audit-only update');
  assert.equal(output.generatedAt,prior,'top-level report timestamp preserved');
  assert.equal(output.metadata.generatedAt,prior,'report generatedAt never refreshed by heartbeat');
  assert.equal(output.metadata.lastPipelineRun,now,'pipeline heartbeat remains separately visible');
  assert.equal(output._heartbeat,now,'diagnostic heartbeat remains separately visible');
  assert.equal(output.items[0]._addedAt,'2026-10-20');
  assert.equal(Object.hasOwn(output.items[1],'_addedAt'),false,'a source article date never proves platform ingestion time');
  assert.equal(Object.hasOwn(output.items[2],'_addedAt'),false,'missing item date stays unknown');
  assert.equal(Object.hasOwn(output.items[3],'_addedAt'),false,'invalid item date stays unknown');
  assert.equal(Object.hasOwn(output.items[4],'_addedAt'),false,'future item date is not trusted');
  const missingMeta={items:[{id:'undated'}]};
  let output2;
  context.require=()=>({
    readFileSync(){return JSON.stringify(missingMeta);},
    writeFileSync(_,content){output2=JSON.parse(content);},
  });
  vm.runInNewContext(script[1],{...context},{timeout:1000});
  assert.equal(Object.hasOwn(output2.metadata,'generatedAt'),false,'missing publication timestamp is never forged');
  assert.equal(output2.metadata.lastPipelineRun,now);
});
