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


test('SOC public browser feed never relays CISA intelligence through anonymous proxy services',()=>{
 const source=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 assert.match(source,/CISA_DIRECT:\s*'https:\/\/www\.cisa\.gov\//);
 assert.match(source,/xhrFetch\(CFG\.CISA_DIRECT/);
 assert.doesNotMatch(source,/corsproxy\.io|allorigins\.win|CISA_PROXY1|CISA_PROXY2/);
 // A blocked official CISA fetch must return an unavailable state; never
 // simulate a current publication or silently trust another domain.
 assert.match(source,/Official origin unavailable => visible unavailable state/);
 assert.doesNotMatch(source,/_feedGenerated\s*=\s*new Date\(\)\.toISOString\(\)/);
});


test('SOC customer widget prioritizes report age, not high-priority archival file order',()=>{
 const vm=require('node:vm');
 const source=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 const sandbox={
   window:{location:{origin:'https://soc.cyberdudebivash.in'}},
   document:{readyState:'loading',addEventListener(){}},
   encodeURIComponent, Date, Number, URL, console,
 };
 vm.runInNewContext(source,sandbox,{timeout:1000});
 const select=sandbox.window.LIVE_FEED_WIDGET.selectLocalItems;
 assert.equal(typeof select,'function');
 const now=Date.parse('2026-10-30T14:00:00Z');
 const rows=[
   {id:'ARCHIVE-HIGH',priority:100,_addedAt:'2026-07-31T22:07:00Z'},
   {id:'YESTERDAY',priority:5,_addedAt:'2026-10-29T16:00:00Z'},
   {id:'TODAY',priority:1,_addedAt:'2026-10-30T13:23:00Z'},
   {id:'FUTURE',priority:999,_addedAt:'2026-10-31T00:00:00Z'},
   {id:'UNDATED',priority:999},
   {id:'TIE-HIGH',priority:11,_addedAt:'2026-10-29T16:00:00Z'},
 ];
 const selected=select(rows,now);
 assert.deepEqual(Array.from(selected,r=>r.id),['TODAY','TIE-HIGH','YESTERDAY']);
 assert(selected.every(r=>r._contentArchived===false));
 assert.equal(selected[0]._reportAddedAt,'2026-10-30T13:23:00.000Z');
 assert.equal(rows[0]._contentArchived,undefined,'do not mutate authoritative report source');
 assert.equal(rows[0].id,'ARCHIVE-HIGH');
});

test('SOC source selector enforces 15-card bound and labels an archival-only corpus',()=>{
 const vm=require('node:vm');
 const source=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 const sandbox={
   window:{location:{origin:'https://soc.cyberdudebivash.in'}},
   document:{readyState:'loading',addEventListener(){}},
   encodeURIComponent, Date, Number, URL, console,
 };
 vm.runInNewContext(source,sandbox,{timeout:1000});
 const select=sandbox.window.LIVE_FEED_WIDGET.selectLocalItems;
 const now=Date.parse('2026-10-30T14:00:00Z');
 const archives=Array.from({length:150},(_,i)=>({
   id:'OLD-'+i,priority:100-i,_addedAt:new Date(now-(60+i)*86400000).toISOString(),
 }));
 const result=select(archives,now);
 assert.equal(result.length,15,'must never render the full 150-item priority-ranked corpus');
 assert.equal(result[0].id,'OLD-0');
 assert(result.every(r=>r._contentArchived===true));
 assert.equal(select([{id:'NO_DATE'},{id:'FUTURE',_addedAt:'2099-01-01'}],now).length,0);
 assert.match(source,/ARCHIVAL INTEL — NO RECENT REPORTS/);
 assert.match(source,/No reports added in last/);
 assert.match(source,/selectLocalItems\(data\.items\)/);
});

test('SOC genuine 150-row fixture is recency-ranked and DOM bounded',()=>{
 const vm=require('node:vm');
 const source=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 const sandbox={
   window:{location:{origin:'https://soc.cyberdudebivash.in'}},
   document:{readyState:'loading',addEventListener(){}},
   encodeURIComponent, Date, Number, URL, console,
 };
 vm.runInNewContext(source,sandbox,{timeout:1000});
 const choose=sandbox.window.LIVE_FEED_WIDGET.selectLocalItems;
 const feed=JSON.parse(fs.readFileSync(path.join(__dirname,'..','live-intel.json'),'utf8'));
 const generated=Date.parse(feed.generatedAt);
 assert(Number.isFinite(generated));
 const selected=choose(feed.items,generated+1000);
 assert(selected.length<=15);
 assert(selected.length>0);
 assert(selected.every(x=>typeof x._reportAddedAt==='string'));
 const dates=Array.from(selected,x=>Date.parse(x._reportAddedAt));
 assert(dates.every((d,i)=>i===0||dates[i-1]>=d),'the most recently added report must be first');
 if(selected.some(x=>!x._contentArchived)){
   assert(selected.every(x=>!x._contentArchived),'never pad a recent feed with months-old cards');
 }
});


test('SOC command center triage uses latest reports, not oldest high-priority ones',()=>{
 const vm=require('node:vm');
 const js=fs.readFileSync(path.join(__dirname,'..','apex-command-center.js'),'utf8');
 const start=js.indexOf('function selectTriageFeed(');
 const end=js.indexOf('function renderFeed(',start);
 assert(start>=0&&end>start,'extract exact production triage selection function');
 const choose=vm.runInNewContext('(function(){'+js.slice(start,end)+'return selectTriageFeed;})()',{
   Date,Number,Array,
 },{timeout:1000});
 const now=Date.parse('2026-10-30T14:00:00Z');
 const rows=[
  {id:'ARCHIVE-HIGH',priority:100,_addedAt:'2026-07-31T22:07:00Z'},
  {id:'RECENT-LOW',priority:1,_addedAt:'2026-10-30T13:23:00Z'},
  {id:'YESTERDAY',priority:90,_addedAt:'2026-10-29T13:23:00Z'},
  {id:'FUTURE',priority:999,_addedAt:'2026-11-02T13:23:00Z'},
  {id:'NO-DATE',priority:999},
 ];
 const selected=choose(rows,now);
 assert.equal(selected.archived,false);
 assert.deepEqual(Array.from(selected.items,x=>x.id),['RECENT-LOW','YESTERDAY']);
 const allOld=choose(Array.from({length:30},(_,i)=>({
  id:'ARCHIVE-'+i,priority:100-i,
  _addedAt:new Date(now-(70+i)*86400000).toISOString(),
 })),now);
 assert.equal(allOld.archived,true);
 assert.equal(allOld.items.length,7,'triage DOM cap is seven cards');
 assert.equal(allOld.items[0].id,'ARCHIVE-0');
 assert.equal(choose([{id:'FUTURE',_addedAt:'2099-01-01'}],now).items.length,0);
 assert.match(js,/ARCHIVAL · NO RECENT REPORTS/);
 assert.match(js,/selectTriageFeed\(feed\.items\)/);
 assert.doesNotMatch(js,/items\.sort\(function\(a,b\)\{return \(Number\(b\.priority\)/);
});

test('SOC command center and live widget agree on the latest source report',()=>{
 const vm=require('node:vm');
 const widget=fs.readFileSync(path.join(__dirname,'..','live-feed-widget.js'),'utf8');
 const sandbox={
  window:{location:{origin:'https://soc.cyberdudebivash.in'}},
  document:{readyState:'loading',addEventListener(){}},
  encodeURIComponent,Date,Number,URL,console,
 };
 vm.runInNewContext(widget,sandbox,{timeout:1000});
 const src=fs.readFileSync(path.join(__dirname,'..','apex-command-center.js'),'utf8');
 const start=src.indexOf('function selectTriageFeed(');
 const end=src.indexOf('function renderFeed(',start);
 const triage=vm.runInNewContext('(function(){'+src.slice(start,end)+'return selectTriageFeed;})()',{
  Date,Number,Array,
 },{timeout:1000});
 const feed=JSON.parse(fs.readFileSync(path.join(__dirname,'..','live-intel.json'),'utf8'));
 const now=Date.parse(feed.generatedAt)+1000;
 const widgetTop=sandbox.window.LIVE_FEED_WIDGET.selectLocalItems(feed.items,now);
 const triageTop=triage(feed.items,now);
 assert(widgetTop.length>0&&triageTop.items.length>0);
 assert.equal(widgetTop[0].id,triageTop.items[0].id,
  'both customer panels must lead with the same newest verified report');
 assert(triageTop.items.length<=7);
 assert(widgetTop.length<=15);
});


test('SOC command center report links deny foreign and insecure destinations',()=>{
 const vm=require('node:vm');
 const js=fs.readFileSync(path.join(__dirname,'..','apex-command-center.js'),'utf8');
 const start=js.indexOf('var REPORT_HOSTS=');
 const end=js.indexOf('function age(',start);
 assert(start>=0 && end>start,'must test the exact source function and allowlist');
 const safe=vm.runInNewContext(
   '(function(){'+js.slice(start,end)+'return safeHref;})()',
   {URL,Object,window:{location:{origin:'https://soc.cyberdudebivash.in'}}},
   {timeout:1000}
 );
 const fallback='/search.html?q=verified';
 const firstParty=[
  'https://blog.cyberdudebivash.in/posts/verified.html',
  'https://soc.cyberdudebivash.in/posts/verified.html',
  'https://cti.cyberdudebivash.in/2026/10/report.html',
  'https://intel.cyberdudebivash.com/reports/verified.html'
 ];
 for(const url of firstParty) assert.equal(safe(url,fallback),url);
 assert.equal(safe('/posts/verified.html',fallback),
  'https://soc.cyberdudebivash.in/posts/verified.html');
 for(const bad of [
   'javascript:alert(1)','data:text/html,x','http://blog.cyberdudebivash.in/posts/x',
   '//attacker.example/x','https://evil.example/','https://blog.cyberdudebivash.in.attacker.example/x',
   'https://user:secret@blog.cyberdudebivash.in/posts/x',
   'https://blog.cyberdudebivash.in:8443/posts/x',
   '\nhttps://blog.cyberdudebivash.in/posts/x',
   'https://blog.cyberdudebivash.in/posts/x\u0000',
   '',
   'x'.repeat(2049),
 ])assert.equal(safe(bad,fallback),fallback,JSON.stringify(bad));
 assert.match(js,/safeHref\(it\.link,fallback\)/);
 assert.match(js,/Object\.prototype\.hasOwnProperty\.call\(REPORT_HOSTS/);
});
