'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const RS=require('../runtime-state.js');
const ROOT=path.resolve(__dirname,'..');
const src=fs.readFileSync(path.join(ROOT,'auto-intel-engine.js'),'utf8');
const NOW=Date.parse('2026-11-13T00:00:00Z');
const at=m=>new Date(NOW-m*60000).toISOString();
function extracted(begin,end,vars={}){
  const start=src.indexOf(begin),finish=src.indexOf(end,start);
  assert(start>0&&finish>start,'exact live frontend logic must exist');
  const ctx=vm.createContext({Date,Number,Array,Object,...vars});
  vm.runInContext(src.slice(start,finish),ctx,{timeout:1000});
  return ctx;
}
const fixture=(stamp,items)=>({generated_at:stamp,report_generated_at:stamp,items});
const item=(id,ingested,published)=>({id,first_ingested:ingested,published});

test('P0 client rejects a 200 response with a stale Worker timestamp, no live cards',()=>{
  const c=extracted('  function verifiedDashboardPayload(','  function fetchDashboardFeed(',{
    window:{SentinelRuntimeState:RS}
  });
  const recent=item('CURRENT',at(10),at(10));
  assert.equal(c.verifiedDashboardPayload(fixture(at(40),[recent]),NOW),true);
  assert.equal(c.verifiedDashboardPayload({...fixture(at(10),[recent]),report_generated_at:at(240)},NOW),false,
    'a new API response timestamp cannot mask old real report provenance');
  assert.equal(c.verifiedDashboardPayload({...fixture(at(10),[recent]),report_generated_at:null},NOW),false,
    'missing report-generation proof blocks live cards');
  assert.equal(c.verifiedDashboardPayload(fixture(at(181),[recent]),NOW),false);
  assert.equal(c.verifiedDashboardPayload(fixture('2026-10-23T04:58:15.799Z',[recent]),NOW),false);
  assert.equal(c.verifiedDashboardPayload(fixture('bad-time',[recent]),NOW),false);
});

test('P0 client independently verifies immutable ingestion and original source date',()=>{
  const c=extracted('  function verifiedDashboardPayload(','  function fetchDashboardFeed(',{
    window:{SentinelRuntimeState:RS}
  });
  const good=item('REAL-NEW',at(10),'2026-11-12');
  const oldPublished=item('REINGESTED',at(10),'2026-07-05');
  const oldIngest=item('OLD-FIRST',at(24*60+1),at(10));
  assert.equal(c.verifiedDashboardPayload(fixture(at(30),[good]),NOW),true);
  assert.equal(c.verifiedDashboardPayload(fixture(at(30),[good,oldPublished]),NOW),false);
  assert.equal(c.verifiedDashboardPayload(fixture(at(30),[oldIngest]),NOW),false);
  assert.equal(c.verifiedDashboardPayload(fixture(at(30),[{id:'NO_CLOCK',published:at(10)}]),NOW),false);
  assert.equal(c.verifiedDashboardPayload(fixture(at(30),[good,...Array.from({length:25},(_,i)=>item('x'+i,at(10),at(10)))]),NOW),false);
  assert.equal(c.verifiedDashboardPayload(fixture(at(30),[]),NOW),true,'fresh pipeline with no new reports is honest');
  const noModel=extracted('  function verifiedDashboardPayload(','  function fetchDashboardFeed(',{window:{}});
  assert.equal(noModel.verifiedDashboardPayload(fixture(at(10),[good]),NOW),false);
});

test('P0 page status uses canonical 90m/180m policy, never 240m or a report timestamp fallback',()=>{
  const outputs=[];
  const c=extracted('  function updateRuntimeState(items, generatedAt, reportGeneratedAt) {','  function updateLiveCounts(items)',{
    window:{SentinelRuntimeState:RS},
    setRuntimeState:(state,reason)=>outputs.push({state,reason})
  });
  const oldNow=Date.now;
  Date.now=()=>NOW;
  try{
    c.updateRuntimeState([],at(10),at(10));assert.equal(outputs.pop().state,'LIVE');
    c.updateRuntimeState([],at(120),at(120));assert.equal(outputs.pop().state,'DEGRADED');
    c.updateRuntimeState([],at(181),at(181));assert.equal(outputs.pop().state,'STALE');
    c.updateRuntimeState([{}],null,null);assert.equal(outputs.pop().state,'STALE');
  }finally{Date.now=oldNow;}
  assert.doesNotMatch(src,/ageMinutes\s*<=\s*240/);
  assert.match(src,/RS\.classifyFeed\(/);
  assert.match(src,/RS\.pipelineAllowsLive\(/);
});

test('P0 no stale marquee after API failure, and expired open tabs erase stale content',()=>{
  assert.match(src,/if \(!items\.length\) \{\s*ticker\.textContent='Current first-party intelligence unavailable/);
  assert.match(src,/activePublicPayload=null;\s*updateTicker\(\[\]\);\s*setRuntimeState\('UNAVAILABLE'/);
  assert.match(src,/setInterval\(expireDashboardIfNeeded,5000\)/);
  assert.match(src,/if \(!activePublicPayload \|\| verifiedDashboardPayload\(activePublicPayload\)\) return/);
  assert.match(src,/updateLiveCounts\(\[\]\);\s*updateTicker\(\[\]\)/);
  assert.doesNotMatch(src.slice(src.indexOf('  function expireDashboardIfNeeded()'),src.indexOf('  function startExpiryMonitor()')),
    /fetch\(|XMLHttpRequest|sendBeacon|location\.reload/);
});

test('P0 only genuine intelligence workspaces poll the dashboard API',()=>{
  assert.match(src,/if \(!document\.getElementById\(containerId\)\) return/);
  const pages=['intel/index.html','breaking/index.html','malware/index.html','ai-security/index.html'];
  for(const page of pages){
    const html=fs.readFileSync(path.join(ROOT,page),'utf8');
    const runtime=html.indexOf('<script src="/runtime-state.js?v=20261113-public-api-1"></script>');
    const client=html.indexOf('<script src="/auto-intel-engine.js"></script>');
    assert(runtime>0&&client>runtime,page+' must load shared model BEFORE client');
    assert(html.includes('id="intel-feed"'));
  }
});
