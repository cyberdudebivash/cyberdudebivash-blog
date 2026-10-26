'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {assess}=require('../scripts/assess-pipeline-operational-health.cjs');
const NOW=Date.parse('2026-10-26T04:30:00Z');
const stamp=mins=>new Date(NOW-mins*60000).toISOString();
function sample(){
 const feed={generatedAt:stamp(10),totalPublished:100,metadata:{generated:stamp(10)},
   items:Array.from({length:16},(_,i)=>({id:'CVE-2026-'+(10000+i),_addedAt:stamp(15+i)}))};
 const state={lastRun:stamp(10),lastReportGeneratedAt:stamp(15),totalPublished:100,
  lastIngestion:{checkedAt:stamp(10),totalSources:35,activeSources:5,
    fetchedRecords:80,newAfterDedup:2,reportsGenerated:1}};
 return {feed,state,feedBytes:22000,nowMs:NOW};
}
function check(edit){const x=sample();if(edit)edit(x);return assess(x);}
test('valid fresh source and actual last-report evidence is source-pipeline verified, not customer GA',()=>{
 const x=check();assert.equal(x.exitCode,0,JSON.stringify(x));
 assert.equal(x.status,'SOURCE_PIPELINE_VERIFIED');
 assert(!('customerDeliveryCertified' in x));
});
test('historical incident: pipeline checks green but 2 of 35 yielding is NOT source health',()=>{
 const x=check(z=>z.state.lastIngestion.activeSources=2);
 assert.equal(x.status,'SOURCE_PIPELINE_NOT_CERTIFIED');
 assert(x.codes.includes('SOURCE_SOURCE_COVERAGE_DEGRADED'));
});
test('heartbeat refresh cannot mask older content',()=>{
 const x=check(z=>z.state.lastReportGeneratedAt=stamp(500));
 assert(x.codes.includes('INTEL_CONTENT_STALE'));
 assert.equal(x.exitCode,2);
});
test('old runtime or missing evidence never qualifies',()=>{
 assert(check(z=>z.state.lastRun=stamp(220)).codes.includes('INTEL_PIPELINE_DOWN'));
 assert(check(z=>delete z.state.lastReportGeneratedAt).codes.includes('AUTHORITATIVE_TIMESTAMPS_MISSING'));
 assert(check(z=>delete z.state.lastIngestion).codes.includes('SOURCE_MONITOR_ERROR'));
});
test('publisher cumulative total and state timestamp mismatch cannot certify fresh',()=>{
 assert(check(z=>z.feed.totalPublished=101).codes.includes('PUBLISH_SOURCE_STATE_MISMATCH'));
 assert(check(z=>z.feed.generatedAt=stamp(180)).codes.includes('PUBLISH_SOURCE_STATE_MISMATCH'));
});
test('future timestamps and corrupted feed structures fail closed',()=>{
 assert(check(z=>z.state.lastRun=stamp(-20)).codes.includes('INTEL_MONITOR_ERROR'));
 assert.equal(check(z=>z.feed.items=[]).exitCode,2);
 assert.deepEqual(assess({feed:{},state:{},feedBytes:0}).codes,['SOURCE_INPUT_INVALID']);
});
test('operational green metadata from empty sourceHealth entries is insufficient',()=>{
 const x=check(z=>{
   z.state.lastIngestion.activeSources=0;
   z.state.sourceHealth=Object.fromEntries(Array.from({length:35},(_,i)=>['s'+i,{status:'ok'}]));
 });
 assert.equal(x.status,'SOURCE_PIPELINE_NOT_CERTIFIED');
});
test('health certification workflow must require strict source truth and never treat calculated ages as certification',()=>{
 const workflow=fs.readFileSync(path.join(__dirname,'..','.github/workflows/pipeline-health-certification.yml'),'utf8');
 const p=workflow.indexOf('node scripts/assess-pipeline-operational-health.cjs');
 const cert=workflow.indexOf('name: "CERTIFICATION: Verify Acceptance Criteria"');
 assert(p>0&&cert>p,'independent gate must run before certification');
 assert.match(workflow,/steps\.source_content_truth\.outputs\.source_content_verified/);
 assert.doesNotMatch(workflow,/echo "freshness_verified=true"/);
 assert.match(workflow,/status=SOURCE_HEALTH_CERTIFIED/);
});
