#!/usr/bin/env node
'use strict';
/**
 * SENTINEL APEX SOC — managed customer GA evidence-completeness gate.
 *
 * This validates local immutable source receipts and private operator evidence
 * metadata. It DOES NOT verify remote evidence bytes, Cloudflare usage,
 * customer consent, payment, staffing or recipient receipt independently.
 * A schema PASS is NEVER permission to deploy or sell. No network/write calls.
 *
 * Scoped readiness consulting is a separate, narrower service governed by
 * scripts/soc-readiness-delivery-gate.cjs, not this managed SOC gate.
 */
const fs=require('node:fs');
const path=require('node:path');
const {evaluateFreshness}=require('./check-intel-freshness.js');
const {evaluate:checkSourceYield}=require('./check-intel-source-yield.cjs');

const CONTROLS=Object.freeze([
  'immutable_deployment_provenance',
  'dual_hostname_live_asset_parity',
  'independent_public_intel_freshness',
  'upstream_source_coverage',
  'branch_and_environment_approvals',
  'customer_identity_mfa_revocation',
  'multi_tenant_idor_negative_canary',
  'customer_consent_and_telemetry_scope',
  'evidence_chain_and_privacy_retention',
  'detection_to_case_validated_telemetry',
  'incident_state_audit_and_approvals',
  'outbox_native_d1_crash_and_replay',
  'real_customer_delivery_receipt_canary',
  'backups_restore_and_disaster_recovery',
  'staffed_rota_and_contractual_escalation',
  'signed_terms_privacy_processing_agreement',
  'payment_invoice_fulfillment_reconciliation',
  'shared_cloudflare_account_zero_overage',
  'version_pinned_rollback_and_negative_canary',
  'pilot_scope_and_customer_signed_acceptance',
  'external_security_governance_review'
]);
const DYNAMIC=new Set([
  'immutable_deployment_provenance',
  'dual_hostname_live_asset_parity',
  'independent_public_intel_freshness',
  'upstream_source_coverage',
  'real_customer_delivery_receipt_canary',
  'shared_cloudflare_account_zero_overage',
  'version_pinned_rollback_and_negative_canary'
]);
const HOURS=3600*1000,DAY=24*HOURS;
const HASH=/^[a-f0-9]{64}$/i,COMMIT=/^[a-f0-9]{40}$/i,UUID=/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i;
const REF=/^[A-Za-z][A-Za-z0-9._/-]{11,159}$/;
const FORBIDDEN=/(?:demo|synthetic|fixture|placeholder|unknown|not_verified|test[-_/]|token|password|secret|bearer)/i;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const reference=x=>typeof x==='string'&&REF.test(x)&&!FORBIDDEN.test(x);
const stamp=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(x)&&Number.isFinite(Date.parse(x));
function validate({manifest,feed,state,feedBytes,nowMs=Date.now(),expectedCommit}={}) {
  const errors=new Set();
  const fail=(name,passed)=>{if(!passed)errors.add(name);};
  if(!Number.isFinite(nowMs)||!object(manifest))return {ok:false,status:'HOLD',codes:['MANIFEST_INVALID']};
  const m=manifest;
  fail('MANAGED_SOC_SCHEMA_INVALID',m.schemaVersion==='sentinel-soc-managed-ga/v1'&&m.service==='MANAGED_SOC'&&m.environment==='production');
  fail('CUSTOMER_HOST_IDENTITY_INVALID',Array.isArray(m.hosts)&&m.hosts.length===2&&
    m.hosts[0]==='soc.cyberdudebivash.in'&&m.hosts[1]==='blog.cyberdudebivash.in');
  fail('RELEASE_SHA_OR_DEPLOYMENT_PROVENANCE_INVALID',COMMIT.test(m.releaseCommit||'')&&
    m.releaseCommit===m.deployedCommit&&UUID.test(m.workerVersion||'')&&
    (!expectedCommit||m.releaseCommit===expectedCommit));
  const deployTime=stamp(m.deployedAt)?Date.parse(m.deployedAt):NaN;
  fail('DEPLOYMENT_FRESHNESS_UNVERIFIED',Number.isFinite(deployTime)&&deployTime<=nowMs&&nowMs-deployTime<=2*HOURS);
  const checks=m.controls;
  fail('CONTROL_SET_INCOMPLETE_OR_UNREVIEWED',object(checks)&&
    Object.keys(checks).length===CONTROLS.length&&CONTROLS.every(key=>Object.hasOwn(checks,key)));
  let newest=0;
  const proofRefs=new Set(),proofHashes=new Set();
  if(object(checks)){
    for(const id of CONTROLS){
      const c=checks[id];
      if(!object(c)){errors.add('CONTROL_PROOF_MISSING_'+id);continue;}
      const when=stamp(c.collectedAt)?Date.parse(c.collectedAt):NaN;
      if(Number.isFinite(when)&&when>newest)newest=when;
      const maxAge=DYNAMIC.has(id)?2*HOURS:7*DAY;
      if(reference(c.privateEvidenceRef)){
        if(proofRefs.has(c.privateEvidenceRef))errors.add('CONTROL_PROOF_REUSED');
        proofRefs.add(c.privateEvidenceRef);
      }
      if(HASH.test(c.evidenceSha256||'')){
        if(proofHashes.has(c.evidenceSha256.toLowerCase()))errors.add('CONTROL_PROOF_REUSED');
        proofHashes.add(c.evidenceSha256.toLowerCase());
      }
      fail('CONTROL_PROOF_INVALID_'+id,c.status==='PASS'&&reference(c.privateEvidenceRef)&&
        HASH.test(c.evidenceSha256||'')&&c.releaseCommit===m.releaseCommit&&
        Number.isFinite(when)&&when<=nowMs&&nowMs-when<=maxAge&&
        c.rawCustomerData===undefined&&c.customerToken===undefined);
    }
  }
  const approval=m.operatorApproval||{};
  const approvalTime=stamp(approval.approvedAt)?Date.parse(approval.approvedAt):NaN;
  fail('OWNER_RELEASE_APPROVAL_INVALID',object(approval)&&approval.status==='APPROVED'&&
    reference(approval.privateApprovalRef)&&reference(approval.approvedByRole)&&
    Number.isFinite(approvalTime)&&approvalTime<=nowMs&&
    nowMs-approvalTime<=2*HOURS&&approvalTime>=newest&&approvalTime>=deployTime);
  const pilot=m.customerPilot||{};
  const acceptanceTime=stamp(pilot.acceptedAt)?Date.parse(pilot.acceptedAt):NaN;
  fail('REAL_CUSTOMER_PILOT_ACCEPTANCE_MISSING',object(pilot)&&pilot.status==='ACCEPTED'&&
    reference(pilot.privateAcceptanceRef)&&reference(pilot.customerApproverRole)&&
    Number.isFinite(acceptanceTime)&&acceptanceTime<=nowMs&&
    nowMs-acceptanceTime<=7*DAY&&acceptanceTime<=approvalTime);

  // Machine-derive what can be established from checked-in source evidence.
  // Never accept manifest claims as a replacement for these two classifiers.
  const freshness=evaluateFreshness({feed,state,nowMs,feedBytes:feedBytes??null});
  fail('INTEL_CONTENT_OR_RUNTIME_NOT_FRESH',freshness.status==='HEALTHY'&&
    freshness.runtimeSource==='intel-state.json lastRun'&&
    freshness.contentSource==='intel-state.json lastReportGeneratedAt');
  const yieldResult=checkSourceYield(state,nowMs);
  fail('CURRENT_SOURCE_COVERAGE_NOT_CERTIFIED',yieldResult.status==='COVERAGE_VERIFIED');
  fail('SOURCE_FEED_STATE_MISMATCH',object(feed)&&object(state)&&
    typeof feed.generatedAt==='string'&&stamp(feed.generatedAt)&&
    Math.abs(Date.parse(feed.generatedAt)-Date.parse(state.lastRun||''))<=15*60*1000&&
    Number.isSafeInteger(feed.totalPublished)&&feed.totalPublished===state.totalPublished);
  return {ok:errors.size===0,status:errors.size?'HOLD':'METADATA_COMPLETE_NOT_INDEPENDENTLY_CERTIFIED',
    codes:[...errors].sort(),controlsChecked:CONTROLS.length};
}
if(require.main===module){
  const args=process.argv.slice(2);
  if(args.length!==1){console.error('HOLD: PRIVATE_GA_MANIFEST_PATH_REQUIRED');process.exitCode=2;}
  else{
    try{
      const name=args[0],info=fs.statSync(name);
      if(!info.isFile()||info.size<1||info.size>32768)throw Error('PRIVATE_MANIFEST_INVALID');
      const root=path.join(__dirname,'..');
      const raw=fs.readFileSync(path.join(root,'live-intel.json'));
      const report=validate({
        manifest:JSON.parse(fs.readFileSync(name,'utf8')),
        feed:JSON.parse(raw.toString('utf8')),
        feedBytes:raw.length,
        state:JSON.parse(fs.readFileSync(path.join(root,'intel-state.json'),'utf8')),
        expectedCommit:process.env.GITHUB_SHA||undefined
      });
      console.log(JSON.stringify(report));
      process.exitCode=report.ok?0:2;
    }catch(_){console.error('HOLD: PRIVATE_GA_EVIDENCE_UNAVAILABLE');process.exitCode=2;}
  }
}
module.exports={validate,CONTROLS,DYNAMIC};
