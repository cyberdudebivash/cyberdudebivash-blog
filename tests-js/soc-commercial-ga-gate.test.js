'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {validate,CONTROLS,DYNAMIC}=require('../scripts/soc-commercial-ga-gate.cjs');
const TIME=Date.parse('2026-10-26T06:00:00.000Z');
const iso=mins=>new Date(TIME-mins*60000).toISOString();
const commit='b'.repeat(40);
function sample(){
  const controls=Object.fromEntries(CONTROLS.map((key,i)=>[key,{
    status:'PASS',
    privateEvidenceRef:'vault/operational-proof-record-'+String(i).padStart(2,'0'),
    evidenceSha256:(i+1).toString(16).padStart(64,'0'),
    collectedAt:iso(35),
    releaseCommit:commit
  }]));
  return {
    manifest:{
      schemaVersion:'sentinel-soc-managed-ga/v1',service:'MANAGED_SOC',environment:'production',
      hosts:['soc.cyberdudebivash.in','blog.cyberdudebivash.in'],
      releaseCommit:commit,deployedCommit:commit,
      workerVersion:'12345678-1234-1234-1234-123456789abc',
      deployedAt:iso(36),controls,
      customerPilot:{status:'ACCEPTED',privateAcceptanceRef:'vault/pilot-acceptance-record',
        customerApproverRole:'authorized-customer-security-officer',acceptedAt:iso(40)},
      operatorApproval:{status:'APPROVED',privateApprovalRef:'vault/approved-release-record',
        approvedByRole:'accountable-business-proprietor',approvedAt:iso(30)}
    },
    state:{lastRun:iso(20),lastReportGeneratedAt:iso(25),totalPublished:50,
      lastIngestion:{checkedAt:iso(20),totalSources:35,activeSources:5,
        fetchedRecords:61,reportsGenerated:1}},
    feed:{generatedAt:iso(20),metadata:{generated:iso(20)},
      totalPublished:50,items:Array.from({length:15},(_,i)=>({id:'CVE-2026-'+(10000+i),_addedAt:iso(25+i)}))},
    feedBytes:20000,nowMs:TIME,expectedCommit:commit
  };
}
function result(modifier){
  const x=sample();if(modifier)modifier(x);
  return validate(x);
}
test('synthetic complete evidence METADATA schema passes but does not certify actual live customer readiness',()=>{
  let x=result();assert.equal(x.ok,true,JSON.stringify(x));
  assert.equal(x.status,'METADATA_COMPLETE_NOT_INDEPENDENTLY_CERTIFIED');
  assert.equal(x.controlsChecked,CONTROLS.length);
});
test('missing private managed GA attestation fails closed; assessment is not managed SOC',()=>{
  assert.deepEqual(validate({}).codes,['MANIFEST_INVALID']);
  assert(result(x=>x.manifest.service='SCOPED_ASSESSMENT').codes.includes('MANAGED_SOC_SCHEMA_INVALID'));
});
test('source coverage from actual last run is mandatory despite all PASS manifest claims',()=>{
  assert(result(x=>x.state.lastIngestion.activeSources=2).codes.includes('CURRENT_SOURCE_COVERAGE_NOT_CERTIFIED'));
});
test('stale real report behind green pipeline heartbeat blocks commercial launch',()=>{
  assert(result(x=>x.state.lastReportGeneratedAt=iso(400)).codes.includes('INTEL_CONTENT_OR_RUNTIME_NOT_FRESH'));
});
test('stale source pipeline blocks commercial launch without a synthetic refresh',()=>{
  assert(result(x=>x.state.lastRun=iso(250)).codes.includes('INTEL_CONTENT_OR_RUNTIME_NOT_FRESH'));
});
test('owner approval must follow all proof and be less than two hours old',()=>{
  assert(result(x=>x.manifest.operatorApproval.approvedAt=iso(300)).codes.includes('OWNER_RELEASE_APPROVAL_INVALID'));
  assert(result(x=>x.manifest.operatorApproval.approvedAt=iso(40)).codes.includes('OWNER_RELEASE_APPROVAL_INVALID'));
});
test('release SHA and Worker version require exact reviewed deployed provenance',()=>{
  assert(result(x=>x.manifest.deployedCommit='c'.repeat(40)).codes.includes('RELEASE_SHA_OR_DEPLOYMENT_PROVENANCE_INVALID'));
  assert(result(x=>x.manifest.workerVersion='not-a-worker-version').codes.includes('RELEASE_SHA_OR_DEPLOYMENT_PROVENANCE_INVALID'));
  assert(result(x=>x.expectedCommit='c'.repeat(40)).codes.includes('RELEASE_SHA_OR_DEPLOYMENT_PROVENANCE_INVALID'));
});
test('full exact control inventory mandatory: missing or extra control rejects',()=>{
  const id=CONTROLS[0];
  assert(result(x=>delete x.manifest.controls[id]).codes.includes('CONTROL_SET_INCOMPLETE_OR_UNREVIEWED'));
  assert(result(x=>x.manifest.controls.unknown={}).codes.includes('CONTROL_SET_INCOMPLETE_OR_UNREVIEWED'));
});
test('every control must be PASS with hash, private reference and matching commit',()=>{
  for(const mutate of [
    c=>c.status='PENDING',c=>c.evidenceSha256='placeholder',
    c=>c.privateEvidenceRef='https://example.com/customer',
    c=>c.privateEvidenceRef='vault/demo-tenant-synthetic-fixture',
    c=>c.releaseCommit='c'.repeat(40),c=>c.rawCustomerData='secret data'
  ]){
    const id='multi_tenant_idor_negative_canary';
    assert(result(x=>mutate(x.manifest.controls[id])).codes.includes('CONTROL_PROOF_INVALID_'+id));
  }
});
test('dynamic live billing/host/alerts receipts expire within two hours',()=>{
  for(const id of DYNAMIC)
    assert(result(x=>x.manifest.controls[id].collectedAt=iso(121)).codes.includes('CONTROL_PROOF_INVALID_'+id),id);
});
test('customer pilot signoff cannot be absent, synthetic, future-dated or later than release approval',()=>{
  assert(result(x=>x.manifest.customerPilot.status='PENDING').codes.includes('REAL_CUSTOMER_PILOT_ACCEPTANCE_MISSING'));
  assert(result(x=>x.manifest.customerPilot.privateAcceptanceRef='fixture/test-pilot').codes.includes('REAL_CUSTOMER_PILOT_ACCEPTANCE_MISSING'));
  assert(result(x=>x.manifest.customerPilot.acceptedAt=iso(-10)).codes.includes('REAL_CUSTOMER_PILOT_ACCEPTANCE_MISSING'));
  assert(result(x=>x.manifest.customerPilot.acceptedAt=iso(10)).codes.includes('REAL_CUSTOMER_PILOT_ACCEPTANCE_MISSING'));
});
test('state and source feed must be same publish revision and cumulative counter',()=>{
  assert(result(x=>x.feed.totalPublished=1000).codes.includes('SOURCE_FEED_STATE_MISMATCH'));
  assert(result(x=>x.feed.generatedAt=iso(180)).codes.includes('SOURCE_FEED_STATE_MISMATCH'));
});
test('customer-facing machine-readable status is NOT_CERTIFIED, not a test fixture GA promise',()=>{
  const m=JSON.parse(fs.readFileSync(path.join(__dirname,'..','api/intel/customer-assurance.json'),'utf8'));
  assert.equal(m.managed_soc_release.release_status,'NOT_CERTIFIED');
  assert.equal(m.managed_soc_release.customer_onboarding_enabled,false);
  assert.equal(m.managed_soc_release.continuous_monitoring_sla_verified,false);
  assert.equal(m.soc2_certified,false);
});
test('managed GA gate never runs as part of routine content Worker deploy',()=>{
  const workflow=fs.readFileSync(path.join(__dirname,'..','.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  assert.doesNotMatch(workflow,/soc-commercial-ga-gate\.cjs/);
  assert.match(workflow,/github\.event_name == 'workflow_dispatch'/);
  assert.match(workflow,/node scripts\/cloudflare-account-zero-overage-gate\.cjs/);
});
\ntest('one generic document or repeated evidence locator cannot greenwash separate controls',()=>{
  const a=CONTROLS[0],b=CONTROLS[1];
  assert(result(x=>x.manifest.controls[b].evidenceSha256=x.manifest.controls[a].evidenceSha256)
    .codes.includes('CONTROL_PROOF_REUSED'));
  assert(result(x=>x.manifest.controls[b].privateEvidenceRef=x.manifest.controls[a].privateEvidenceRef)
    .codes.includes('CONTROL_PROOF_REUSED'));
});
test('owner approval must be after exact production deployment',()=>{
  assert(result(x=>x.manifest.deployedAt=iso(20)).codes.includes('OWNER_RELEASE_APPROVAL_INVALID'));
});
