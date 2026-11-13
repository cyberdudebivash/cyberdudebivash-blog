'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {assessPublicIntel}=require('../api/_lib/public-intel-freshness');
const RS=require('../runtime-state.js');

const NOW=Date.parse('2026-11-13T00:00:00Z');
const at=h=>new Date(NOW-h*3600000).toISOString();
const record=(id,ingested,published)=>({id,_addedAt:ingested,pubDate:published});
const feed=(timestamp,items)=>({
  metadata:{lastPipelineRun:timestamp,lastReportGeneratedAt:timestamp},
  generatedAt:timestamp,
  items
});

test('P0 fresh source: two clocks, de-duplication and chronological live-only ordering',()=>{
  const source=feed(at(.5),[
    record('OLD-REINGESTED',at(.25),'2026-07-05'),
    record('UNKNOWN-FIRST-INGEST',undefined,at(.2)),
    record('INVALID-ZONELESS','2026-11-12T22:00:00',at(1)),
    record('NEW',at(2),at(1)),
    record('NEW',at(3),at(1)),
    record('LATEST',at(1),at(1)),
    record('FUTURE',new Date(NOW+6*60000).toISOString(),at(1)),
  ]);
  const r=assessPublicIntel(source,NOW);
  assert.equal(r.ok,true);
  assert.equal(r.state,'HEALTHY');
  assert.deepEqual(r.items.map(x=>x.id),['LATEST','NEW']);
  assert.equal(r.timestamp,at(.5));
  assert.equal(r.considered,7);
  assert.equal(r.excluded.NO_INGEST_TIME,1);
});
test('P0 20-day-old Worker JSON cannot pass an API request as live',()=>{
  const r=assessPublicIntel(feed('2026-10-23T04:58:15.799Z',[
    record('OLD',at(1),at(1))
  ]),NOW);
  assert.equal(r.ok,false);
  assert.equal(r.state,'STALE');
  assert.equal(r.reason,'PUBLIC_SOURCE_NOT_CURRENT');
  assert.deepEqual(r.items,[]);
});
test('P0 missing, malformed or future pipeline evidence fail closed',()=>{
  for(const value of [null,'not-a-time',new Date(NOW+15*60000).toISOString()]){
    const r=assessPublicIntel(feed(value,[record('x',at(1),at(1))]),NOW);
    assert.equal(r.ok,false);
    assert.equal(r.items.length,0);
  }
  for(const value of [null,{items:null},{items:'[]'},[]]){
    const r=assessPublicIntel(value,NOW);
    assert.equal(r.ok,false);
    assert.equal(r.state,'UNAVAILABLE');
    assert.deepEqual(r.items,[]);
  }
});
test('P0 a healthy source with no genuinely new reports returns honest empty list',()=>{
  const r=assessPublicIntel(feed(at(.5),[record('OLD',at(20),'2026-01-01')]),NOW);
  assert.equal(r.ok,true);
  assert.equal(r.state,'HEALTHY');
  assert.deepEqual(r.items,[]);
});
test('P0 source authority is the single shared runtime policy',()=>{
  const data=feed(at(.5),[record('fresh',at(2),at(2))]);
  const classification=RS.classifyFeed({ok:true,feed:data,nowMs:NOW});
  const r=assessPublicIntel(data,NOW);
  assert.equal(r.ok,RS.pipelineAllowsLive(classification,NOW));
  assert.equal(r.items[0].id,RS.selectLiveRecords(data.items,NOW).items[0].id);
});
