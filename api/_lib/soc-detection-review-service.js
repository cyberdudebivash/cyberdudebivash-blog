'use strict';

/**
 * SENTINEL APEX SOC — INTERNAL ONLY source-backed detection review and
 * incident-linking service. No Worker route, no generated threat claims.
 *
 * Entry requires a cryptographically verified, revocation-aware OIDC identity,
 * fresh active tenant-analyst membership, primary D1, and for a VERIFIED
 * decision a SEPARATE trusted verifySourceEvidence implementation that
 * actually retrieves/checks authorized source content. Mere HMAC receipt
 * metadata and a caller-supplied digest are NOT independent verification.
 *
 * There is deliberately no candidate-create method: a governed rule runner
 * and customer-authorized source access have not yet been implemented.
 */
const TENANT=/^[a-z0-9_-]{3,64}$/;
const DETECTION=/^[A-Za-z0-9_.:-]{8,128}$/;
const INCIDENT=/^inc_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REQUEST=/^[A-Za-z0-9_.:-]{16,128}$/;
const HASH=/^[a-f0-9]{64}$/;

class SocDetectionError extends Error {
  constructor(code,status=400) {super(code);this.name='SocDetectionError';this.code=code;this.status=status;}
}
function deny(code,status) {throw new SocDetectionError(code,status);}
function requireId(value,re,code) {if(typeof value!=='string'||!re.test(value))deny(code);}
function requireNote(value) {
  if(typeof value!=='string'||value.trim().length<24||
      value.trim().length>2000||/[\u0000-\u001f\u007f]/.test(value))
    deny('INVALID_REVIEW_RATIONALE');
  return value.trim();
}
function sessionOf(nativeD1) {
  let session;
  try{session=nativeD1.withSession('first-primary');}
  catch(_){deny('SOC_PRIMARY_UNAVAILABLE',503);}
  if(!session||typeof session.prepare!=='function')deny('SOC_PRIMARY_UNAVAILABLE',503);
  return session;
}
async function first(session,sql,params){
  try{return await session.prepare(sql).bind(...params).first();}
  catch(_){deny('SOC_PRIMARY_UNAVAILABLE',503);}
}
async function write(session,sql,params,code){
  try{
    const output=await session.prepare(sql).bind(...params).all();
    if(!output||output.success===false||!Array.isArray(output.results)||
       output.results.length!==1)deny(code,409);
    return output.results[0];
  }catch(_){deny(code,409);}
}

function createSocDetectionReviewService({
  nativeD1,verifyIdentity,verifySourceEvidence,now=()=>new Date().toISOString(),
}={}){
  if(!nativeD1||typeof nativeD1.withSession!=='function'||
     typeof verifyIdentity!=='function'||typeof verifySourceEvidence!=='function'||
     typeof now!=='function')deny('SOC_DETECTION_AUTHORITY_REQUIRED',503);

  async function authorize(accessToken,tenantId){
    requireId(tenantId,TENANT,'INVALID_TENANT');
    let identity;
    try{identity=await verifyIdentity(accessToken);}
    catch(_){deny('UNAUTHENTICATED',401);}
    if(!identity||identity.verified!==true||
       typeof identity.issuer!=='string'||!identity.issuer.startsWith('https://')||
       identity.issuer.length>512||typeof identity.subject!=='string'||
       !identity.subject||identity.subject.length>512)deny('UNAUTHENTICATED',401);
    const session=sessionOf(nativeD1);
    const row=await first(session,[
      'SELECT p.principal_id FROM soc_principals p',
      'JOIN soc_tenants t ON t.tenant_id=p.tenant_id',
      'WHERE p.tenant_id=? AND p.oidc_issuer=? AND p.oidc_subject=?',
      "AND p.status='ACTIVE' AND t.status='ACTIVE'",
      "AND p.role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN') LIMIT 1",
    ].join(' '),[tenantId,identity.issuer,identity.subject]);
    if(!row||typeof row.principal_id!=='string'||!row.principal_id)
      deny('FORBIDDEN',403);
    return {session,actorId:row.principal_id};
  }

  async function review({accessToken,tenantId,detectionId,decision,requestId,reviewNote}={}){
    requireId(detectionId,DETECTION,'INVALID_DETECTION');
    requireId(requestId,REQUEST,'INVALID_REQUEST');
    if(decision!=='ANALYST_VERIFIED'&&decision!=='REJECTED')
      deny('INVALID_REVIEW_DECISION');
    const note=requireNote(reviewNote);
    const {session,actorId}=await authorize(accessToken,tenantId);
    const source=await first(session,[
      'SELECT d.detection_id,d.event_id,d.evidence_state,d.review_version,',
      'e.digest_sha256,e.attestation_sha256,e.connector_id,e.signing_key_id,e.source_event_at',
      'FROM soc_detections d',
      'JOIN soc_event_receipts e ON e.tenant_id=d.tenant_id AND e.event_id=d.event_id',
      'WHERE d.tenant_id=? AND d.detection_id=? LIMIT 1',
    ].join(' '),[tenantId,detectionId]);
    if(!source)deny('DETECTION_NOT_FOUND',404);
    if(source.evidence_state!=='SOURCE_REPORTED'||source.review_version!==0)
      deny('DETECTION_ALREADY_REVIEWED',409);
    if(!HASH.test(source.digest_sha256||'')||
       !HASH.test(source.attestation_sha256||'')||
       !source.signing_key_id)deny('SOURCE_PROVENANCE_INCOMPLETE',409);

    let digest=null;
    if(decision==='ANALYST_VERIFIED'){
      // Must independently check authorized source bytes/provenance outside D1.
      // No production implementation is provided in this phase.
      let verified;
      try{
        verified=await verifySourceEvidence(Object.freeze({
          tenantId,eventId:source.event_id,connectorId:source.connector_id,
          signingKeyId:source.signing_key_id,
          digestSha256:source.digest_sha256,
          attestationSha256:source.attestation_sha256,
          sourceEventAt:source.source_event_at,
        }));
      }catch(_){deny('INDEPENDENT_EVIDENCE_UNAVAILABLE',503);}
      if(!verified||verified.verified!==true||
         !HASH.test(verified.recomputedDigestSha256||'')||
         verified.recomputedDigestSha256!==source.digest_sha256)
        deny('INDEPENDENT_EVIDENCE_UNVERIFIED',409);
      digest=verified.recomputedDigestSha256;
    }

    const at=now();
    const result=await write(session,[
      'UPDATE soc_detections SET evidence_state=?,review_actor_id=?,',
      'review_request_id=?,review_note=?,reviewed_at=?,review_basis_sha256=?,',
      'review_version=review_version+1',
      "WHERE tenant_id=? AND detection_id=? AND evidence_state='SOURCE_REPORTED'",
      'AND review_version=0 RETURNING detection_id,evidence_state,review_version',
    ].join(' '),[
      decision,actorId,requestId,note,at,digest,tenantId,detectionId,
    ],'DETECTION_REVIEW_WRITE_REJECTED');
    return Object.freeze({
      tenantId,detectionId:result.detection_id,
      evidenceState:result.evidence_state,reviewVersion:Number(result.review_version),
    });
  }

  async function linkToIncident({accessToken,tenantId,incidentId,detectionId,requestId}={}){
    requireId(incidentId,INCIDENT,'INVALID_INCIDENT');
    requireId(detectionId,DETECTION,'INVALID_DETECTION');
    requireId(requestId,REQUEST,'INVALID_REQUEST');
    const {session,actorId}=await authorize(accessToken,tenantId);
    const result=await write(session,[
      'INSERT INTO soc_incident_detections',
      '(tenant_id,incident_id,detection_id,linked_at,linked_by,link_request_id)',
      'VALUES(?,?,?,?,?,?)',
      'RETURNING incident_id,detection_id',
    ].join(' '),[tenantId,incidentId,detectionId,now(),actorId,requestId],
    'DETECTION_LINK_REJECTED');
    return Object.freeze({tenantId,incidentId:result.incident_id,
      detectionId:result.detection_id,linked:true});
  }

  return Object.freeze({review,linkToIncident});
}

module.exports={createSocDetectionReviewService,SocDetectionError};
