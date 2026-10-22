'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {validate}=require('../scripts/soc-readiness-delivery-gate.cjs');
const TODAY='2026-10-22T00:00:00.000Z';
const sample=()=>({
  schemaVersion:'soc-readiness-delivery/v1',engagementId:'ENG-SYNTH-0001',
  customerReference:'SYNTHETIC-TENANT-REF',
  scope:{tenantReference:'synthetic-tenant-a',inScopeAssets:['synthetic-lab-host-a'],
    allowedMethods:['read-only questionnaire'],exclusions:['No active exploitation']},
  authorization:{status:'APPROVED',reference:'private-approval-receipt',
    authorizedByRole:'test-customer-security-owner',signedAt:'2026-10-20T00:00:00Z',
    expiresAt:'2026-11-20T00:00:00Z'},
  evidence:[{id:'E-synthetic-01',sourceType:'synthetic questionnaire',
    privateReference:'private-internal-evidence-001',sha256:'a'.repeat(64),
    collectedAt:'2026-10-21T00:00:00Z',tenantReference:'synthetic-tenant-a'}],
  findings:[{id:'F-synthetic-01',status:'CONFIRMED',title:'Synthetic telemetry coverage gap',
    impact:'Demonstration only; not a real customer finding',recommendation:'Review visibility',
    validationPlan:'Run authorized review against test logs',limitations:'Synthetic evidence only',
    severity:'LOW',confidence:'LOW',evidenceIds:['E-synthetic-01'],detectionStatus:'DRAFT'}],
  deliverables:{scopeDocumentRef:'private-signed-scope',coverageMatrixRef:'private-coverage',
    executiveReportRef:'private-executive-report',remediationBacklogRef:'private-backlog',
    handoffReceiptRef:'private-handoff-record'},
  qa:{status:'APPROVED',reviewerRole:'synthetic-test-reviewer',
    approvalReference:'private-qa-record',approvedAt:'2026-10-21T18:00:00Z'},
  customerAcceptance:{status:'PENDING',customerApproverRole:'__REQUIRED__',
    acceptanceReference:'__REQUIRED__',acceptedAt:'__REQUIRED__'}
});
function result(mutator,stage='delivery'){
  const m=sample();mutator(m);
  return validate(m,stage,TODAY);
}
function blocks(code,mutator,stage='delivery'){
  const got=result(mutator,stage);
  assert.equal(got.ok,false,'expected HOLD not PASS');
  assert.ok(got.codes.includes(code),'missing '+code+' in '+got.codes.join(','));
}
test('positive: complete synthetic preflight and QA delivery receipts pass schema gates',()=>{
  assert.equal(validate(sample(),'preflight',TODAY).ok,true);
  const got=validate(sample(),'delivery',TODAY);
  assert.equal(got.ok,true,got.codes.join(','));
  assert.equal(got.evidenceCount,1);assert.equal(got.findingCount,1);
});
test('positive: explicit customer acceptance after QA passes accepted gate',()=>{
  const m=sample();m.customerAcceptance={
    status:'ACCEPTED',customerApproverRole:'synthetic-customer-security-owner',
    acceptanceReference:'private-signoff-receipt',acceptedAt:'2026-10-21T21:00:00Z'};
  assert.equal(validate(m,'accepted',TODAY).ok,true);
  assert.equal(validate(m,'delivery',TODAY).ok,false,'accepted must not appear pending');
});
test('negative: template is intentionally not an authorized customer manifest',()=>{
  const template=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/commercial/templates/SOC-READINESS-DELIVERY.template.json'),'utf8'));
  const res=validate(template,'preflight',TODAY);
  assert.equal(res.ok,false);
  assert.ok(res.codes.includes('AUTHORIZATION_NOT_APPROVED'));
  assert.ok(res.codes.includes('ENGAGEMENT_ID_INVALID'));
});
test('negative: signed approval required before preflight',()=>blocks('AUTHORIZATION_NOT_APPROVED',m=>m.authorization.status='PENDING','preflight'));
test('negative: expired approval blocks all stages',()=>blocks('AUTHORIZATION_NOT_APPROVED',m=>m.authorization.expiresAt='2026-10-21T23:00:00Z','preflight'));
test('negative: scope must be explicit and authorized',()=>blocks('SCOPE_INVALID',m=>m.scope.inScopeAssets=[],'preflight'));
test('negative: cross-tenant evidence must not contribute to any report',()=>blocks('EVIDENCE_METADATA_INVALID',m=>m.evidence[0].tenantReference='synthetic-tenant-b'));
test('negative: every evidence artifact must carry source hash',()=>blocks('EVIDENCE_METADATA_INVALID',m=>m.evidence[0].sha256='missing'));
test('negative: raw customer evidence cannot be embedded in manifest',()=>blocks('EVIDENCE_METADATA_INVALID',m=>m.evidence[0].rawContent='untrusted raw provider event'));
test('negative: duplicate evidence IDs rejected',()=>blocks('EVIDENCE_ID_INVALID_OR_DUPLICATE',m=>m.evidence.push({...m.evidence[0]})));
test('negative: confirmed finding requires at least one approved evidence locator',()=>blocks('FINDING_EVIDENCE_INVALID',m=>m.findings[0].evidenceIds=[]));
test('negative: unknown evidence IDs are not silently accepted',()=>blocks('FINDING_EVIDENCE_INVALID',m=>m.findings[0].evidenceIds=['E-other-unknown']));
test('negative: duplicate finding IDs rejected',()=>blocks('FINDING_ID_INVALID_OR_DUPLICATE',m=>m.findings.push({...m.findings[0]})));
test('negative: unknown severity/confidence cannot be certified',()=>blocks('FINDING_FIELDS_MISSING',m=>m.findings[0].confidence='CERTIFIED'));
test('negative: detection cannot be described as validated without validation proof and analyst approval',()=>blocks('DETECTION_PROOF_INVALID',m=>m.findings[0].detectionStatus='VALIDATED'));
test('negative: delivery requires meaningful evidence',()=>blocks('DELIVERY_HAS_NO_EVIDENCE',m=>{m.evidence=[];m.findings=[];}));
test('negative: no final report means no completed delivery',()=>blocks('DELIVERABLES_INCOMPLETE',m=>m.deliverables.executiveReportRef='__REQUIRED__'));
test('negative: QA missing blocks delivery',()=>blocks('QA_NOT_APPROVED',m=>m.qa.status='PENDING'));
test('negative: customer sign-off cannot be fabricated from a pending status',()=>blocks('CUSTOMER_ACCEPTANCE_MISSING',()=>{},'accepted'));
test('negative: acceptance before human QA is invalid',()=>blocks('CUSTOMER_ACCEPTANCE_MISSING',m=>{
  m.customerAcceptance={status:'ACCEPTED',customerApproverRole:'synthetic-customer-owner',
    acceptanceReference:'private-receipt',acceptedAt:'2026-10-21T10:00:00Z'};
},'accepted'));
test('negative: unknown or malformed schema/stage must fail closed',()=>{
  assert.equal(validate(sample(),'sell_now',TODAY).ok,false);
  assert.equal(validate(null,'preflight',TODAY).ok,false);
  blocks('SCHEMA_INVALID',m=>m.schemaVersion='unknown','preflight');
});
