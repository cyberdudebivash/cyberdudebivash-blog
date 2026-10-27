'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {check,TARGETS}=require('../scripts/certify-soc-public-feed-parity.cjs');
const workflow=fs.readFileSync(path.join(__dirname,'..','.github/workflows/freshness-check.yml'),'utf8');
const t=Date.parse('2026-10-27T01:10:00.000Z');
const stamp='2026-10-27T00:20:00.000Z';
const feed=(generatedAt,totalPublished)=>({
  generatedAt,metadata:{lastPipelineRun:generatedAt},totalPublished,
  items:Array.from({length:15},(_,i)=>({id:'CVE-2026-'+(10000+i)}))
});
test('normal 30-minute scheduled freshness path now verifies BOTH customer SOC hostnames',()=>{
 assert.match(workflow,/cron: '13,43 \* \* \* \*'/);
 assert.match(workflow,/freshness-check:\s*\n\s*if: github.event_name != 'push'/);
 const idx=workflow.indexOf('id: soc_public_freshness');
 const summary=workflow.indexOf('name: "Monitor result summary"');
 assert(idx>0&&summary>idx);
 const step=workflow.slice(workflow.lastIndexOf('      - name:',idx),summary);
 assert.match(step,/node scripts\/certify-soc-public-feed-parity\.cjs/);
 assert.match(step,/set -euo pipefail/);
 assert.match(step,/if: \$\{\{ !cancelled\(\) \}\}/);
 assert.doesNotMatch(step,/wrangler|createWorkflowDispatch|git reset|force_reset_state|publish/);
 assert.match(workflow,/steps\.soc_public_freshness\.outcome \}\}" = "failure"/);
});
test('23 Oct deployed public snapshots cause failure even with fresh 27 Oct publisher',async()=>{
 const source=feed(stamp,6593);
 const old=feed('2026-10-23T04:58:15.799Z',6466);
 const accessed=[];
 const result=await check({expected:source,
  sourceState:{lastRun:stamp,lastReportGeneratedAt:stamp},
  nowMs:t,fetchImpl:async url=>{
   accessed.push(url);
   return new Response(JSON.stringify(old),{status:200,
    headers:{'content-type':'application/json'}});
  }});
 assert.equal(result.status,'FAIL');
 assert.deepEqual(accessed,[TARGETS.soc,TARGETS.blog]);
 assert(result.results.every(r=>r.reason==='PUBLIC_PIPELINE_STALE'));
});
test('fresh root corpus on just one of the two hostnames cannot certify public health',async()=>{
 const source=feed(stamp,6593),older=feed('2026-10-26T23:04:12.474Z',6563);
 const result=await check({expected:source,nowMs:t,
  sourceState:{lastRun:stamp,lastReportGeneratedAt:stamp},
  fetchImpl:async url=>new Response(JSON.stringify(url===TARGETS.soc?source:older),
    {status:200,headers:{'content-type':'application/json'}})});
 assert.equal(result.status,'FAIL');
 assert.equal(result.results[1].reason,'PUBLIC_SOURCE_DEPLOYMENT_DRIFT');
});
test('public URL throttling or access failure remains INCONCLUSIVE not a customer GO',async()=>{
 const source=feed(stamp,6593);
 const result=await check({expected:source,nowMs:t,
   fetchImpl:async ()=>new Response('{}',{status:429})});
 assert.equal(result.status,'INCONCLUSIVE');
});
test('monitor cannot silently repair a Cloudflare edge deploy by dispatching the content publisher',()=>{
 const idx=workflow.indexOf('id: soc_public_freshness');
 const summary=workflow.indexOf('name: "Monitor result summary"');
 const subset=workflow.slice(idx,summary);
 assert.doesNotMatch(subset,/createWorkflowDispatch|force_reset_state|wrangler deploy/);
 assert.match(workflow,/Release operation: MANUAL_OWNER_APPROVED_ONLY/);
});
