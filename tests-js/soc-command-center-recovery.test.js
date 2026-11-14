'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const RS=require('../runtime-state.js');
const root=path.resolve(__dirname,'..');
const center=fs.readFileSync(path.join(root,'apex-command-center.js'),'utf8');
const widget=fs.readFileSync(path.join(root,'live-feed-widget.js'),'utf8');

function extract(source,open,close){
  const start=source.indexOf(open),end=source.indexOf(close,start+open.length);
  assert(start>0&&end>start, 'tested production function exists: '+open);
  return source.slice(start,end);
}
test('P0 an initial failed feed request cannot leave operational counters or loading placeholders visible',()=>{
  const numbers={},labels={},statuses=[],fabric=[];
  const old={generatedAt:'2026-11-13T18:48:10Z',items:[{id:'OLD'}]};
  const state={feed:old,feedItems:old.items,metricsCurrent:true,lastRuntimeState:'HEALTHY'};
  const ctx=vm.createContext({
    state,RS,setKpi:(id,value,note)=>{numbers[id]={value,note};},
    setText:(id,value)=>{labels[id]=value;},
    applyFeedState:classification=>{statuses.push(classification.state);},
    drawFabric:records=>{fabric.push(records);}
  });
  vm.runInContext(extract(center,
    '  function withholdDashboardMetrics(reason) {','  function renderMetrics(feed){'),ctx,{timeout:1000});
  ctx.withholdDashboardMetrics('http 503');
  assert.equal(state.feed,null);
  assert.deepEqual([...state.feedItems],[]);
  assert.equal(state.metricsCurrent,false);
  assert.equal(state.lastRuntimeState,'UNAVAILABLE');
  for(const id of ['cdb-total','cdb-critical','cdb-kev','cdb-exploited','cdb-ransomware','cdb-sources']){
    assert.equal(numbers[id].value,'—',id);
    assert.match(numbers[id].note,/WITHHELD/);
  }
  for(const id of ['cdb-hero-total','cdb-hero-kev','cdb-hero-sources'])
    assert.equal(labels[id],'—');
  assert.equal(labels['cdb-hero-freshness'],'UNAVAILABLE');
  assert.equal(labels['cdb-feed-time'],'timestamp unavailable');
  assert.deepEqual(statuses,['UNAVAILABLE']);
  assert.deepEqual([...fabric[0]],[]);
});

test('P0 15-minute widget observations refresh the open SOC command center without extra network requests',()=>{
  const rendered=[],states=[];
  const state={feed:{generatedAt:'2026-11-14T07:00:00.000Z'},feedItems:[]};
  const ctx=vm.createContext({
    RS,state,Number,Date,Object,Array,
    renderMetrics:feed=>rendered.push(feed.generatedAt),
    renderFeed:feed=>states.push(feed.generatedAt),
    renderFeedUnavailable:()=>{throw Error('fresh input should not be hidden');},
    withholdDashboardMetrics:()=>{throw Error('runtime is present');},
  });
  vm.runInContext(extract(center,'  function applyWidgetFeedObservation(event) {',
    "  window.addEventListener('cdb:source-feed-observed',applyWidgetFeedObservation);"),ctx,{timeout:1000});
  ctx.applyWidgetFeedObservation({detail:{generatedAt:'2026-11-14T06:59:00.000Z',items:[]}});
  assert.equal(rendered.length,0,'late or cached older response must not regress current source');
  ctx.applyWidgetFeedObservation({detail:{generatedAt:'2026-11-14T07:30:00.000Z',items:[],metadata:{
    lastReportGeneratedAt:'2026-11-14T07:20:00.000Z'}}});
  assert.deepEqual(rendered,['2026-11-14T07:30:00.000Z']);
  assert.deepEqual(states,['2026-11-14T07:30:00.000Z']);
  assert.equal(state.feed.metadata.lastReportGeneratedAt,'2026-11-14T07:20:00.000Z');
  for(const invalid of [null,{generatedAt:'garbage',items:[]},{generatedAt:'2026-11-14T08:00:00Z',items:null}])
    ctx.applyWidgetFeedObservation({detail:invalid});
  assert.equal(rendered.length,1,'malformed source observations are ignored');
});

test('P0 initial fetch failure clears display; valid first party source is reclassified',()=>{
  assert.match(center,/if\(first\.status==='fulfilled'&&first\.value&&typeof first\.value==='object'&&/);
  assert.match(center,/applyWidgetFeedObservation\(\{detail:first\.value\}\)/);
  assert.match(center,/renderFeedUnavailable\(why\);\s*withholdDashboardMetrics\(why\);/);
  assert.match(center,/renderMetrics\(incoming\);\s*renderFeed\(incoming\);/);
  assert.match(center,/window\.addEventListener\('cdb:source-feed-observed',applyWidgetFeedObservation\)/);
  assert.match(center,/next<previous\)return/);
  assert.match(center,/RS\.classifyFeed\(\{ok:true,feed:feed\}\)/);
});

test('P0 widget shares its existing fetched JSON without increasing Cloudflare polling',()=>{
  assert.match(widget,/REFRESH_MS:\s*15 \* 60 \* 1000/);
  const flow=extract(widget,'  function pipeline() {','  /* ── RENDER CARD ─');
  assert.match(flow,/return xhrFetch\(CFG\.LOCAL_JSON/);
  assert.match(flow,/announceObservedFeed\(data\)/);
  assert.match(widget,/window\.dispatchEvent\(new window\.CustomEvent\('cdb:source-feed-observed',\{detail:data\}\)\)/);
  assert.doesNotMatch(center,/setInterval\(function\(\)\{[\s\S]{0,1000}fetchJson/);
  // The producer also remains independently fail-closed when no current
  // report/source timestamp can be verified by the shared runtime model.
  assert.match(flow,/shared\.pipelineAllowsLive\(/);
});
