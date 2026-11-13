'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {verifyOperationalSource}=require('../api/_lib/operational-intel-freshness');
const NOW=Date.parse('2026-11-13T19:20:00.000Z');
const at=m=>new Date(NOW-m*60000).toISOString();
function verifiedRoot(){
  const stamp=at(20);
  return {generatedAt:stamp,metadata:{
    generated:stamp,lastPipelineRun:at(1),lastReportGeneratedAt:at(35)
  },items:[{id:'CVE-2026-22222',_addedAt:at(30),pubDate:at(30)}]};
}

test('P0 matching source and S2N genuine report receipts permit verified operational scope',()=>{
  const root=verifiedRoot();
  const output=verifyOperationalSource(root,at(20),NOW,at(35));
  assert.equal(output.ok,true);
  assert.equal(output.report_generated_at,at(35));
  assert(output.ids.has('CVE-2026-22222'));
});

test('P0 matching generation clocks do not authorize a mismatched genuine report receipt',()=>{
  const root=verifiedRoot();
  for(const forged of [at(1),at(80),null,'invalid',undefined]){
    const output=verifyOperationalSource(root,at(20),NOW,forged);
    assert.equal(output.ok,false,String(forged));
    assert.equal(output.code,'OPERATIONAL_REPORT_RECEIPT_DIVERGED');
    assert.deepEqual([...output.ids],[]);
    assert.deepEqual(output.items,[]);
  }
});

test('P0 old root report cannot be revived by matching new route receipt or heartbeat',()=>{
  const root=verifiedRoot();
  root.metadata.lastPipelineRun=at(1);
  root.metadata.lastReportGeneratedAt=at(240);
  const output=verifyOperationalSource(root,at(20),NOW,at(240));
  assert.equal(output.ok,false);
  assert.equal(output.code,'OPERATIONAL_INTELLIGENCE_STALE');
});

test('P0 route build divergence remains a separate fail-closed gate',()=>{
  const output=verifyOperationalSource(verifiedRoot(),at(50),NOW,at(35));
  assert.equal(output.ok,false);
  assert.equal(output.code,'OPERATIONAL_ASSET_GENERATION_DIVERGED');
});
