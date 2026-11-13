'use strict';
const {verifyOperationalSource} = require('../operational-intel-freshness');
const {getIntel} = require('../intel');
const NOW=Date.parse('2026-11-13T19:00:00Z');
const at=h=>new Date(NOW-h*3600000).toISOString();
function root(reportHours=1,generatedHours=.5) {
  return {generatedAt:at(generatedHours),metadata:{
    lastPipelineRun:at(.05),lastReportGeneratedAt:at(reportHours)
  },items:[
    {id:'FRESH-RECORD',_addedAt:at(1),pubDate:at(1)},
    {id:'HISTORIC-RECORD',_addedAt:at(24*30),pubDate:at(24*30)},
    {id:'REINGESTED-OLD',_addedAt:at(.3),pubDate:at(24*30)}
  ]};
}

test('paid operational authority keeps only immutable real report IDs, never historical priorities',()=>{
  const source=root();
  const r=verifyOperationalSource(source,source.generatedAt,NOW);
  expect(r.ok).toBe(true);
  expect([...r.ids]).toEqual(['FRESH-RECORD']);
  expect(r.report_generated_at).toBe(at(1));
});

test('recent pipeline heartbeat cannot promote reports older than 180 minutes to LIVE',()=>{
  const old=root(4,.5),r=verifyOperationalSource(old,old.generatedAt,NOW);
  expect(r.ok).toBe(false);
  expect(r.code).toBe('OPERATIONAL_INTELLIGENCE_STALE');
  expect(r.items).toEqual([]);
  expect(r.ids.size).toBe(0);
});

test('a route JSON from a different Worker build cannot inherit new source freshness',()=>{
  const source=root();
  for(const ts of [at(3),at(-.4),'garbage',null,'2026-11-13T18:30:00']) {
    const r=verifyOperationalSource(source,ts,NOW);
    expect(r.ok).toBe(false);
    expect(r.code).toBe('OPERATIONAL_ASSET_GENERATION_DIVERGED');
    expect(r.items).toEqual([]);
  }
  expect(verifyOperationalSource(source,at(.51),NOW).ok).toBe(true);
});

test('source lacking genuine report receipt is always unavailable to paid LIVE routes',()=>{
  const source=root();delete source.metadata.lastReportGeneratedAt;
  expect(verifyOperationalSource(source,source.generatedAt,NOW)).toMatchObject({
    ok:false,code:'OPERATIONAL_INTELLIGENCE_STALE'
  });
});

test('paid loader allowlist applies before pagination, entitlement and client filters',()=>{
  // Use current committed source only to exercise the loader's allowlist and
  // pagination semantics: never assert that its wall-clock is customer-live.
  const unscoped=getIntel('live','free',{limit:'3'});
  const all=getIntel('live','free',{limit:'100'});
  expect(Array.isArray(all.items)).toBe(true);
  expect(unscoped.items.length).toBeGreaterThan(0);
  const eligible=all.items.slice(-1)[0]?.id;
  if(!eligible)return;
  const result=getIntel('live','free',{limit:'1'},{allowedIds:new Set([eligible])});
  expect(result.items.map(x=>x.id)).toEqual([eligible]);
  expect(result.pagination.total).toBe(1);
  expect(result.pagination.has_next).toBe(false);
  const excluded=getIntel('live','enterprise',{limit:'10'},{allowedIds:new Set()});
  expect(excluded.items).toEqual([]);
  expect(excluded.pagination.total).toBe(0);
});
