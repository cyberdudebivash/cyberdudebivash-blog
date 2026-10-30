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


test('SOC browser widget classifies genuine source age, not browser fetch time',()=>{
 const vm=require('node:vm');
 const widgetSource=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 const sandbox={
   window:{location:{origin:'https://soc.cyberdudebivash.in'}},
   document:{readyState:'loading',addEventListener(){}},
   encodeURIComponent, Date, Number, URL, console,
 };
 vm.runInNewContext(widgetSource,sandbox,{timeout:1000});
 const classify=sandbox.window.LIVE_FEED_WIDGET.classifyFeedTimestamp;
 assert.equal(typeof classify,'function');
 const now=Date.parse('2026-10-30T12:00:00Z');
 const current=classify('2026-10-30T11:15:00Z',now);
 assert.equal(current.state,'current');
 assert.equal(current.publishedAt,Date.parse('2026-10-30T11:15:00Z'));
 const edgeStale=classify('2026-10-23T04:58:15.799Z',now);
 assert.equal(edgeStale.state,'stale');
 assert.equal(edgeStale.publishedAt,Date.parse('2026-10-23T04:58:15.799Z'));
 assert.equal(classify('2026-10-30T08:59:00Z',now).state,'stale');
 assert.equal(classify('2026-10-30T09:00:00Z',now).state,'current');
 assert.equal(classify('2026-10-30T12:05:01Z',now).state,'unverified');
 assert.equal(classify('2026-10-30T12:05:00Z',now).state,'current');
 for(const bad of [null,undefined,'','NaN','definitely-not-a-date',{},12345]){
   const result=classify(bad,now);
   assert.equal(result.state,'unverified',String(bad));
   assert.equal(result.publishedAt,null);
 }
});

test('SOC widget cannot pretend CISA fallback retrieval created fresh intel',()=>{
 const source=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 assert.doesNotMatch(source,/_feedGenerated\s*=\s*new Date\(\)\.toISOString\(\)/);
 assert.match(source,/item\._feedGenerated=null/);
 assert.match(source,/SOURCE TIMESTAMP UNVERIFIED/);
 assert.match(source,/STALE FEED — LAST VERIFIED INTEL/);
 assert.doesNotMatch(source,/Live Breaking Intel/);
 assert.match(source,/Threat Intelligence Feed/);
 assert.match(source,/lastVerifiedSourceLabel\(\)/);
 assert.match(source,/lfw-bt/);
 assert.match(source,/classList\.toggle\('lfw-dot-load',stale\)/);
});


test('SOC feed renderer denies untrusted report links and CSS attribute injection',()=>{
 const vm=require('node:vm');
 const source=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 const sandbox={
   window:{location:{origin:'https://soc.cyberdudebivash.in'}},
   document:{readyState:'loading',addEventListener(){}},
   encodeURIComponent, Date, Number, URL, console,
 };
 vm.runInNewContext(source,sandbox,{timeout:1000});
 const safe=sandbox.window.LIVE_FEED_WIDGET.safeReportHref;
 const color=sandbox.window.LIVE_FEED_WIDGET.safeThreatColor;
 assert.equal(safe('/posts/verified-cve.html'),
   'https://soc.cyberdudebivash.in/posts/verified-cve.html');
 assert.equal(safe('https://blog.cyberdudebivash.in/posts/verified-cve.html'),
   'https://blog.cyberdudebivash.in/posts/verified-cve.html');
 assert.equal(safe('https://cti.cyberdudebivash.in/2026/10/intel.html'),
   'https://cti.cyberdudebivash.in/2026/10/intel.html');
 assert.equal(safe('https://intel.cyberdudebivash.com/reports/a.html'),
   'https://intel.cyberdudebivash.com/reports/a.html');
 for(const malicious of [
   'javascript:alert(1)','data:text/html,hello','//attacker.example/x',
   'https://soc.cyberdudebivash.in.attacker.example/report',
   'https://someone:password@soc.cyberdudebivash.in/posts/a',
   'https://evil.example/fake-report', 'http://blog.cyberdudebivash.in/posts/a',
   '\nhttps://blog.cyberdudebivash.in/posts/a',
   'https://blog.cyberdudebivash.in/posts/a\u0000'
 ]){
   assert.equal(safe(malicious),null,JSON.stringify(malicious));
 }
 assert.equal(color('#abcdef'),'#abcdef');
 assert.equal(color('#00b4d8'),'#00b4d8');
 for(const injection of ['";onmouseover="alert(1)','red;background:url(javascript:alert(1))',
   'var(--untrusted)','linear-gradient(red,blue)',null,'#abc']){
   assert.equal(color(injection),'#00b4d8',String(injection));
 }
 assert.match(source,/safeThreatColor\(rawThreat\.color\)/);
 assert.match(source,/safeReportHref\(item\.link\)/);
 assert.match(source,/Report link unavailable/);
});
