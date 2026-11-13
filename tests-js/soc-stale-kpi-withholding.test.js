'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const RS=require('../runtime-state.js');
const src=fs.readFileSync(path.join(__dirname,'..','apex-command-center.js'),'utf8');
const start=src.indexOf('  function renderMetrics(feed){');
const end=src.indexOf('  function renderAssurance(',start);
assert(start>0&&end>start,'must test the actual customer dashboard metrics renderer');
const NOW=Date.now();
class FixedDate extends Date { static now(){return NOW;} }
const feed=(ts,total=6466)=>({
  metadata:ts?{lastPipelineRun:ts}:{},generatedAt:ts,
  totalPublished:total,
  stats:{critical:39,cisaKev:32,exploited:143,ransomware:31,sources:14},
  items:[]
});
function harness(runtime=RS) {
  const kpis={},labels={},elements={},observed=[];
  const ctx=vm.createContext({
    RS:runtime,Date:FixedDate,Number,Object,
    fmt:new Intl.NumberFormat('en-US'),
    state:{feed:null,metricsCurrent:null,lastRuntimeState:null},
    feedStamp: f=>f?.metadata?.lastPipelineRun||f?.generatedAt||null,
    age:stamp=>({label:stamp?'OBSERVED AGE':'UNKNOWN',iso:stamp||null}),
    setKpi:(id,value,note)=>{kpis[id]={value,note};},
    setText:(id,value)=>{labels[id]=value;},
    $:id=>(elements[id]??={textContent:null}),
    applyFeedState:cls=>{observed.push(cls.state);}
  });
  vm.runInContext(src.slice(start,end),ctx,{timeout:1000});
  return {render:ctx.renderMetrics,state:ctx.state,kpis,labels,elements,observed};
}
const stale='2026-10-23T04:58:15.799Z';
const recent=new Date(NOW-10*60000).toISOString();
test('P0 stale public October bundle cannot expose 6,466 as live operational KPI',()=>{
  const x=harness();
  x.render(feed(stale));
  for(const id of ['cdb-total','cdb-critical','cdb-kev','cdb-exploited','cdb-ransomware','cdb-sources']){
    assert.equal(x.kpis[id].value,'—',id);
    assert.match(x.kpis[id].note,/WITHHELD — STALE intelligence source/,id);
  }
  for(const id of ['cdb-hero-total','cdb-hero-kev','cdb-hero-sources'])assert.equal(x.labels[id],'—',id);
  assert.equal(x.state.metricsCurrent,false);
  assert.equal(x.state.lastRuntimeState,'STALE');
  assert.equal(x.elements['cdb-freshness'].textContent,'OBSERVED AGE');
  assert.equal(x.elements['cdb-feed-time'].textContent,stale);
  assert.equal(x.labels['cdb-hero-freshness'],'OBSERVED AGE');
  assert.match(x.labels['cdb-hero-freshness-note'],/STALE — operational metrics withheld/);
  assert.deepEqual(x.observed,['STALE']);
});
test('P0 fresh certified feed still presents actual customer KPI totals',()=>{
  const x=harness();
  x.render(feed(recent,7466));
  assert.equal(x.kpis['cdb-total'].value,'7,466');
  assert.equal(x.kpis['cdb-critical'].value,'39');
  assert.equal(x.kpis['cdb-kev'].value,'32');
  assert.equal(x.labels['cdb-hero-total'],'7,466');
  assert.equal(x.state.metricsCurrent,true);
  assert.equal(x.state.lastRuntimeState,'HEALTHY');
});
test('P0 missing, unverifiable or future source does not reveal historical metrics',()=>{
  for(const stamp of [null,'not-a-date',new Date(NOW+10*60000).toISOString()]){
    const x=harness();
    x.render(feed(stamp,7466));
    assert.equal(x.state.metricsCurrent,false);
    assert.equal(x.kpis['cdb-total'].value,'—');
    assert.equal(x.labels['cdb-hero-total'],'—');
  }
  const x=harness(null);
  x.render(feed(recent,7466));
  assert.equal(x.state.metricsCurrent,false,'missing runtime authority fails closed');
  assert.equal(x.kpis['cdb-kev'].value,'—');
});
test('P0 open-tab ticker removes aged-out cards and KPIs without fetches or state mutation',()=>{
  const start=src.indexOf('  // A dashboard left open overnight must not keep reporting');
  const end=src.indexOf('  var refresh=',start);
  assert(start>0&&end>start,'stale-open-tab revalidation must exist');
  const ticker=src.slice(start,end);
  assert.match(ticker,/setInterval\(function\(\)\{/);
  assert.match(ticker,/state\.metricsCurrent && !allowed/);
  assert.match(ticker,/renderMetrics\(state\.feed\);\s*renderFeed\(state\.feed\)/);
  assert.match(ticker,/state\.feedItems\.some\(function\(item\)\{return !RS\.isLiveRecord\(item,now\)/);
  assert.doesNotMatch(ticker,/fetchJson|XMLHttpRequest|wrangler|sendBeacon|document\.location\.reload/);
  assert.match(ticker,/\},5000\);/);
});
