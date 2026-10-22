'use strict';

/**
 * Internal source-byte evidence verification boundary (NO customer HTTP route).
 *
 * Only an operator-authenticated, tenant-scoped EDR/SIEM adapter may implement
 * readAuthorizedEvent(). It must fetch the ACTUAL source record from the
 * approved provider using provider-managed credentials, not arbitrary caller
 * URLs or in-memory test fixtures. No provider adapter is bundled/enabled.
 *
 * This verifier computes SHA256 over bounded source bytes itself. A provider
 * supplied 'verified:true' flag or a copied claimed digest is never trusted.
 * No raw payload, credentials, URLs, user identifiers or provider record bytes
 * are stored or returned. An attested digest matching alone does not prove that
 * the alert is malicious; analyst judgment is still required.
 */
const crypto=require('node:crypto');
const {receiptId}=require('./soc-event-receipt-service');

const TENANT=/^[a-z0-9_-]{3,64}$/;
const CONNECTOR=/^[A-Za-z0-9_.:-]{1,128}$/;
const SOURCE=/^[A-Za-z0-9_.:-]{1,128}$/;
const EVENT=/^evt_[a-f0-9]{64}$/;
const SHA=/^[a-f0-9]{64}$/;

class SocSourceEvidenceError extends Error {
  constructor(code) { super(code);this.name='SocSourceEvidenceError';this.code=code; }
}
function deny(code){throw new SocSourceEvidenceError(code);}
const own=(obj,k)=>Object.prototype.hasOwnProperty.call(obj,k);
function safeShape(object, keys) {
  return object && typeof object==='object' && !Array.isArray(object) &&
    Object.keys(object).length===keys.length &&
    keys.every(key=>own(object,key));
}
function checkReference(ref) {
  const keys=['tenantId','eventId','connectorId','sourceEventId','signingKeyId',
    'digestSha256','attestationSha256','sourceEventAt'];
  if(!safeShape(ref,keys)||
    typeof ref.tenantId!=='string'||!TENANT.test(ref.tenantId)||
    typeof ref.connectorId!=='string'||!CONNECTOR.test(ref.connectorId)||
    typeof ref.sourceEventId!=='string'||!SOURCE.test(ref.sourceEventId)||
    typeof ref.eventId!=='string'||!EVENT.test(ref.eventId)||
    typeof ref.signingKeyId!=='string'||!/^[a-z0-9_-]{8,64}$/.test(ref.signingKeyId)||
    typeof ref.digestSha256!=='string'||!SHA.test(ref.digestSha256)||
    typeof ref.attestationSha256!=='string'||!SHA.test(ref.attestationSha256)||
    typeof ref.sourceEventAt!=='string'||!Number.isFinite(Date.parse(ref.sourceEventAt)))
      deny('EVIDENCE_REFERENCE_INVALID');
  if(receiptId(ref)!==ref.eventId)deny('SOURCE_EVENT_ID_MISMATCH');
}

/** Create a verifier tied to a trusted, already-authorized source adapter.
 * No provider URL, token or network is accepted via caller's evidence ref.
 */
function createSocSourceByteVerifier({
  readAuthorizedEvent,maxBytes=262144,timeoutMs=6000,
}={}){
  if(typeof readAuthorizedEvent!=='function'||
     !Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>1048576||
     !Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>30000)
    deny('SOURCE_ADAPTER_NOT_CONFIGURED');

  return async function verifySourceEvidence(ref) {
    checkReference(ref);
    const controller=new AbortController();
    let timer;
    const deadline=new Promise((_,reject)=>{
      timer=setTimeout(()=>{
        controller.abort();
        reject(new SocSourceEvidenceError('SOURCE_READ_TIMEOUT'));
      },timeoutMs);
    });
    let record;
    try{
      // The adapter is an INTERNAL trust dependency, never a request handler.
      // Its provider-side credential and allowed tenant/connector mapping are
      // configured independently of this reference.
      record=await Promise.race([
        Promise.resolve().then(()=>readAuthorizedEvent(Object.freeze({
          tenantId:ref.tenantId,connectorId:ref.connectorId,
          sourceEventId:ref.sourceEventId,signal:controller.signal,
        }))),
        deadline,
      ]);
    }catch(error){
      if(error instanceof SocSourceEvidenceError)throw error;
      deny('SOURCE_READ_UNAVAILABLE');
    }finally{clearTimeout(timer);}

    if(!record || typeof record!=='object' || Array.isArray(record) ||
       Object.keys(record).sort().join(',')!=='connectorId,payloadBytes,sourceEventId,tenantId')
      deny('SOURCE_RESPONSE_INVALID');
    if(record.tenantId!==ref.tenantId || record.connectorId!==ref.connectorId ||
       record.sourceEventId!==ref.sourceEventId)
      deny('SOURCE_RESPONSE_SCOPE_MISMATCH');
    const b=record.payloadBytes;
    if(!(Buffer.isBuffer(b)||b instanceof Uint8Array) ||
       b.byteLength<1||b.byteLength>maxBytes)deny('SOURCE_BYTES_INVALID');

    // The provider's bytes are recomputed locally; never trust
    // claimedDigest, verified or plaintext source URLs from a caller.
    const computed=crypto.createHash('sha256').update(b).digest('hex');
    if(computed!==ref.digestSha256)return Object.freeze({
      verified:false,recomputedDigestSha256:computed,
    });
    return Object.freeze({
      verified:true,recomputedDigestSha256:computed,
    });
  };
}

module.exports={createSocSourceByteVerifier,SocSourceEvidenceError};
