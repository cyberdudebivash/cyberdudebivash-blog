#!/usr/bin/env node
'use strict';

/**
 * Read-only, offline SOC readiness delivery acceptance gate.
 * Never accepts raw customer evidence; manifests hold opaque evidence references.
 * No network, database, GitHub or Cloudflare calls. Do not commit filled-in manifests.
 */
const fs=require('node:fs');
const VALID_STAGES=new Set(['preflight','delivery','accepted']);
const PLACEHOLDER=/^(?:__REQUIRED__|TBD|PLACEHOLDER|UNKNOWN|NOT_VERIFIED)$/i;
const SHA256=/^[a-f0-9]{64}$/i;
const privateRef=v=>typeof v==='string' && v.length>0 && v.length<=512 && !PLACEHOLDER.test(v.trim()) && !/^(?:https?:|mailto:|javascript:|data:)/i.test(v.trim()) && !/@|\?|[&](?:token|key|sig|secret|password)=/i.test(v);
const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
function validate(input,stage='delivery',now=new Date().toISOString()){
  const errors=[];
  const mark=(code,condition)=>{if(!condition)errors.push(code);};
  const object=v=>v!==null && typeof v==='object' && !Array.isArray(v);
  const str=v=>typeof v==='string' && v.trim().length>0 && v.length<=512 && !PLACEHOLDER.test(v.trim());
  const arr=v=>Array.isArray(v);
  const time=v=>typeof v==='string' && ISO.test(v) && Number.isFinite(Date.parse(v));
  if(!VALID_STAGES.has(stage))return {ok:false,codes:['STAGE_INVALID']};
  if(!object(input))return {ok:false,codes:['MANIFEST_INVALID']};
  mark('SCHEMA_INVALID',input.schemaVersion==='soc-readiness-delivery/v1');
  mark('ENGAGEMENT_ID_INVALID',typeof input.engagementId==='string' && /^[A-Za-z0-9][A-Za-z0-9_-]{4,79}$/.test(input.engagementId) && !PLACEHOLDER.test(input.engagementId));
  mark('CUSTOMER_REF_INVALID',str(input.customerReference) && !/@/.test(input.customerReference));
  const scope=input.scope||{};
  mark('SCOPE_INVALID',object(scope)&&str(scope.tenantReference)&&arr(scope.inScopeAssets)&&scope.inScopeAssets.length>0 && scope.inScopeAssets.length<=200 && scope.inScopeAssets.every(str) && arr(scope.allowedMethods)&&scope.allowedMethods.length>0&&scope.allowedMethods.length<=30&&scope.allowedMethods.every(str)&&arr(scope.exclusions)&&scope.exclusions.length>0&&scope.exclusions.every(str));
  const auth=input.authorization||{};
  mark('AUTHORIZATION_NOT_APPROVED',object(auth)&&auth.status==='APPROVED' && str(auth.reference) && str(auth.authorizedByRole) && time(auth.signedAt) && time(auth.expiresAt) && Date.parse(auth.expiresAt)>Date.parse(now) && Date.parse(auth.signedAt)<=Date.parse(now) && Date.parse(auth.signedAt)<Date.parse(auth.expiresAt));
  const refs=new Set();
  const evidence=input.evidence||[];
  mark('EVIDENCE_LIST_INVALID',arr(evidence)&&evidence.length<=500);
  if(arr(evidence)){
    for(const entry of evidence){
      if(!object(entry)||!/^E-[A-Za-z0-9_-]{2,64}$/.test(entry.id||'')||refs.has(entry.id)) {errors.push('EVIDENCE_ID_INVALID_OR_DUPLICATE');continue;}
      refs.add(entry.id);
      mark('EVIDENCE_METADATA_INVALID',str(entry.sourceType)&&privateRef(entry.privateReference)&&SHA256.test(entry.sha256||'') && time(entry.collectedAt) && Date.parse(entry.collectedAt)<=Date.parse(now) && entry.tenantReference===scope.tenantReference && entry.rawContent===undefined);
    }
  }
  const findings=input.findings||[];
  mark('FINDINGS_LIST_INVALID',arr(findings)&&findings.length<=200);
  if(arr(findings)){
    const keys=new Set();
    for(const item of findings){
      if(!object(item)||!/^F-[A-Za-z0-9_-]{2,64}$/.test(item.id||'')||keys.has(item.id)){errors.push('FINDING_ID_INVALID_OR_DUPLICATE');continue;}
      keys.add(item.id);
      mark('FINDING_FIELDS_MISSING',str(item.title) && str(item.impact) && str(item.recommendation) && str(item.validationPlan) && str(item.limitations) && ['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].includes(item.severity) && ['HIGH','MEDIUM','LOW'].includes(item.confidence));
      mark('FINDING_STATUS_INVALID',['CONFIRMED','NOT_VERIFIED'].includes(item.status));
      mark('FINDING_EVIDENCE_INVALID',arr(item.evidenceIds) && item.evidenceIds.every(id=>refs.has(id)) && (item.status!=='CONFIRMED'||item.evidenceIds.length>0));
      mark('DETECTION_PROOF_INVALID',['NOT_APPLICABLE','DRAFT','VALIDATED'].includes(item.detectionStatus) &&
        (item.detectionStatus!=='VALIDATED'||(arr(item.validationEvidenceIds)&&item.validationEvidenceIds.length>0 && item.validationEvidenceIds.every(id=>refs.has(id)) && str(item.analystApprovalReference))));
    }
  }
  if(stage==='delivery'||stage==='accepted'){
    mark('DELIVERY_HAS_NO_EVIDENCE',arr(evidence)&&evidence.length>0);
    const out=input.deliverables||{};
    mark('DELIVERABLES_INCOMPLETE',object(out)&&str(out.scopeDocumentRef)&&str(out.coverageMatrixRef)&&str(out.executiveReportRef)&&str(out.remediationBacklogRef)&&str(out.handoffReceiptRef));
    const qa=input.qa||{};
    mark('QA_NOT_APPROVED',object(qa)&&qa.status==='APPROVED'&&str(qa.reviewerRole)&&str(qa.approvalReference)&&time(qa.approvedAt) && Date.parse(qa.approvedAt)<=Date.parse(now));
  }
  const acceptance=input.customerAcceptance||{};
  if(stage==='accepted'){
    mark('CUSTOMER_ACCEPTANCE_MISSING',object(acceptance)&&acceptance.status==='ACCEPTED'&&str(acceptance.customerApproverRole)&&str(acceptance.acceptanceReference)&&time(acceptance.acceptedAt) && Date.parse(acceptance.acceptedAt)<=Date.parse(now) && (!time(input.qa?.approvedAt)||Date.parse(acceptance.acceptedAt)>=Date.parse(input.qa.approvedAt)));
  }else{
    mark('CUSTOMER_ACCEPTANCE_MUST_REMAIN_PENDING',object(acceptance)&&['PENDING','REJECTED'].includes(acceptance.status));
  }
  return {ok:errors.length===0,codes:[...new Set(errors)].sort(),evidenceCount:arr(evidence)?evidence.length:0,findingCount:arr(findings)?findings.length:0};
}
if(require.main===module){
  const args=process.argv.slice(2);
  const stage=args[0]?.replace(/^--stage=/,'');
  const file=args[1];
  if(!VALID_STAGES.has(stage)||!file){
    process.stderr.write('HOLD: USAGE_INVALID (node scripts/soc-readiness-delivery-gate.cjs --stage=preflight|delivery|accepted <private-manifest-path>)\n');
    process.exitCode=2;
  }else{
    try{
      const info=fs.statSync(file);
      if(!info.isFile()||info.size>131072)throw Error('MANIFEST_FILE_INVALID');
      const report=validate(JSON.parse(fs.readFileSync(file,'utf8')),stage,new Date().toISOString());
      if(!report.ok) {
        process.stderr.write('HOLD: '+report.codes.join(', ')+'\n');
        process.exitCode=1;
      }else{
        process.stdout.write('PASS: '+stage+' gate | evidence='+report.evidenceCount+' findings='+report.findingCount+'\n');
      }
    }catch(err){
      process.stderr.write('HOLD: MANIFEST_UNREADABLE_OR_INVALID\n');process.exitCode=1;
    }
  }
}
module.exports={validate};
