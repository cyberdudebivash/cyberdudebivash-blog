'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {ORIGIN,SPECS,evaluate,MAX_BYTES}=require('./soc-public-integration-gate.cjs');
const NOW=Date.parse('2026-10-24T06:54:30Z');
const at='2026-10-24T06:50:00Z';
const goodPage='<html><head><link rel="canonical" href="'+ORIGIN+'/soc.html">'+
 '<meta property="og:url" content="'+ORIGIN+'/soc.html"></head>'+
 '<body>SENTINEL APEX SOC</body></html>';
function responses(){
  return {
    soc_page:{status:200,type:'text/html; charset=utf-8',body:goodPage},
    workbench_page:{status:200,type:'text/html',body:'<html><head><meta name="robots" content="noindex, nofollow"></head><body>X-Analyst-Key</body></html>'},
    anonymous_dashboard:{status:401,type:'application/json',cacheControl:'no-store',allowOrigin:'',
      body:JSON.stringify({error:{code:'UNAUTHORIZED'}})},
    public_stats:{status:200,type:'application/json',
      body:JSON.stringify({success:true,stats:{total_published:7,live_intel_count:2,last_run:at}})},
    public_feed:{status:200,type:'application/json',
      body:JSON.stringify({totalPublished:7,generatedAt:at,items:[{id:'sample'}]})},
  };
}
test('P0 bounded read-only probe is exactly five first-party GET routes',()=>{
  assert.equal(ORIGIN,'https://soc.cyberdudebivash.in');
  assert.equal(SPECS.length,5);
  assert.ok(SPECS.every(s=>s.path.startsWith('/') && !s.path.startsWith('//')));
  assert.ok(MAX_BYTES<=300000);
  const source=fs.readFileSync(__dirname+'/soc-public-integration-gate.cjs','utf8');
  assert.match(source,/method:'GET'/);
  assert.match(source,/process\.argv\[2\]!=='--live'/);
  assert.doesNotMatch(source,/method:\s*['"]POST|Authorization:\s*['"]Bearer|setInterval\(/);
});
test('valid same-origin source-read-only contracts classify positive without implying customer release',()=>{
  const result=evaluate(responses(),NOW);
  assert.equal(result.status,'SOURCE_PUBLIC_READONLY_PASS');
  assert.deepEqual(result.codes,[]);
  assert.match(result.warning,/No customer login/);
});
test('public SOC canonical drift, missing workbench noindex or unauth API success are blockers',()=>{
  const scenarios=[
    ['bad canonical',x=>x.soc_page.body=x.soc_page.body.replace(ORIGIN,'https://blog.cyberdudebivash.in'),'soc_page:SOC_CANONICAL_OR_OG_MISMATCH'],
    ['no noindex',x=>x.workbench_page.body=x.workbench_page.body.replace('noindex, nofollow','index, follow'),'workbench_page:WORKBENCH_NOT_NOINDEX'],
    ['missing auth denial',x=>{x.anonymous_dashboard.status=200},'anonymous_dashboard:ANONYMOUS_ACCESS_NOT_DENIED'],
    ['credentialed wildcard CORS',x=>{x.anonymous_dashboard.allowOrigin='*'},'anonymous_dashboard:CORS_WILDCARD'],
    ['missing no-store',x=>{x.anonymous_dashboard.cacheControl='public, max-age=3600'},'anonymous_dashboard:CACHE_CONTROL_MISSING'],
  ];
  for(const [label,mutate,code] of scenarios){
    const x=responses();mutate(x);
    const out=evaluate(x,NOW);
    assert.equal(out.status,'HOLD',label);
    assert.ok(out.codes.includes(code),label+': '+out.codes.join(','));
  }
});
test('stale feed or stats, future timestamps and cross-feed contract drift all block release',()=>{
  const cases=[
    ['stale feed',x=>{const f=JSON.parse(x.public_feed.body);f.generatedAt='2026-10-23T04:58:15Z';x.public_feed.body=JSON.stringify(f)},'public_feed:DATA_STALE'],
    ['stale stats',x=>{const f=JSON.parse(x.public_stats.body);f.stats.last_run='2026-10-23T04:58:15Z';x.public_stats.body=JSON.stringify(f)},'public_stats:DATA_STALE'],
    ['future timestamp',x=>{const f=JSON.parse(x.public_feed.body);f.generatedAt='2026-10-25T04:00:00Z';x.public_feed.body=JSON.stringify(f)},'public_feed:TIMESTAMP_INVALID_OR_FUTURE'],
    ['count mismatch',x=>{const f=JSON.parse(x.public_feed.body);f.totalPublished=8;x.public_feed.body=JSON.stringify(f)},'public_feed:STATS_FEED_COUNT_DRIFT'],
    ['invalid API schema',x=>{x.public_stats.body='{"success":true,"stats":{}}'},'public_stats:CONTRACT_INVALID'],
  ];
  for(const [label,mutate,code] of cases){
    const x=responses();mutate(x);
    const out=evaluate(x,NOW);
    assert.equal(out.status,'HOLD',label);
    assert.ok(out.codes.includes(code),label+': '+out.codes.join(','));
  }
});
test('oversized or missing responses cannot be interpreted as an operational GO',()=>{
  const x=responses();
  delete x.anonymous_dashboard;
  x.public_feed.body='A'.repeat(MAX_BYTES+1);
  const out=evaluate(x,NOW);
  assert.equal(out.status,'HOLD');
  assert.ok(out.codes.includes('anonymous_dashboard:RESPONSE_MISSING_OR_INVALID'));
  assert.ok(out.codes.includes('public_feed:RESPONSE_MISSING_OR_INVALID'));
});
