'use strict';

/**
 * SENTINEL APEX SOC — source-attested event receipt intake, no HTTP route.
 *
 * Pilot-only trust boundary:
 *   cryptographically HMAC-signed event metadata -> current approved connector
 *   -> active tenant -> D1 immutable metadata receipt + atomic audit trigger.
 *
 * No raw customer event payload is accepted, no auto-generated detection or
 * incident is created, no commercial/24x7 monitoring claim follows from this.
 * Source-attested digest is NOT an independent proof of a real source event.
 * Provider webhook signature verification and secret onboarding are NOT live.
 *
 * Never ship a test/mock resolveSecret to production. Retrieve secrets from an
 * operator-controlled secure backend and restrict resolver to approved source.
 */
const crypto = require('node:crypto');

const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const TENANT = /^[a-z0-9_-]{3,64}$/;
const HASH = /^[a-f0-9]{64}$/;
const SIG = /^[A-Za-z0-9_-]{43}$/;
const MAX_SKEW_MS = 5 * 60 * 1000;
const MAX_EVENT_AGE_MS = 30 * 24 * 60 * 60 * 1000;

class SocIntakeError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = 'SocIntakeError';
    this.code = code;
    this.status = status;
  }
}
const deny = (code, status=400) => { throw new SocIntakeError(code,status); };

function canonicalFields(event) {
  // Fixed ordered tuple prevents JSON key order and delimiter ambiguities.
  // Signing NEVER includes client-chosen SQL, timestamp/headers or raw bytes.
  return JSON.stringify([
    2,event.tenantId,event.connectorId,event.keyId,event.sourceEventId,
    event.eventTime,event.signedAt,event.payloadSha256,
  ]);
}
function parseExactIso(value) {
  if (typeof value !== 'string' || value.length !== 24 ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)) return NaN;
  const time=Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString()===value ? time : NaN;
}
function receiptId({tenantId,connectorId,sourceEventId}) {
  return 'evt_'+crypto.createHash('sha256').update(
    JSON.stringify([tenantId,connectorId,sourceEventId]),'utf8').digest('hex');
}
function validate(envelope, current) {
  if (!envelope || typeof envelope!=='object' || Array.isArray(envelope) ||
      Object.keys(envelope).sort().join(',') !==
      ['connectorId','eventTime','keyId','payloadSha256','signature','signedAt','sourceEventId','tenantId','version'].sort().join(',')) {
    deny('INVALID_ENVELOPE');
  }
  if (envelope.version!==2 || typeof envelope.tenantId!=='string' ||
      !TENANT.test(envelope.tenantId) ||
      typeof envelope.connectorId!=='string' || !ID.test(envelope.connectorId) ||
      typeof envelope.keyId!=='string' || !/^[a-z0-9_-]{8,64}$/.test(envelope.keyId) ||
      typeof envelope.sourceEventId!=='string' || !ID.test(envelope.sourceEventId) ||
      typeof envelope.payloadSha256!=='string' || !HASH.test(envelope.payloadSha256) ||
      typeof envelope.signature!=='string' || !SIG.test(envelope.signature)) {
    deny('INVALID_ENVELOPE');
  }
  const issued=parseExactIso(envelope.signedAt);
  const observed=parseExactIso(envelope.eventTime);
  if (!Number.isFinite(issued) || !Number.isFinite(observed) ||
      Math.abs(current-issued)>MAX_SKEW_MS ||
      observed>current+MAX_SKEW_MS ||
      observed<current-MAX_EVENT_AGE_MS) deny('EVENT_TIME_REJECTED');
}
function hmac(secret, data) {
  return crypto.createHmac('sha256',secret).update(data,'utf8').digest();
}

function createSocEventReceiptService({nativeD1,resolveSecret,now=()=>Date.now()}={}) {
  if (!nativeD1 || typeof nativeD1.withSession!=='function' ||
      typeof resolveSecret!=='function' || typeof now!=='function') {
    deny('INTAKE_AUTHORITY_NOT_CONFIGURED',503);
  }

  async function ingest(envelope) {
    const current=now();
    if (!Number.isSafeInteger(current)) deny('TIME_SOURCE_INVALID',503);
    validate(envelope,current);

    // Never trust the signature supplied by the client as an authentication
    // decision. Resolve a tenant/connector-bound secret from trusted storage.
    // The resolver must not fetch network URLs supplied inside the envelope.
    let secret;
    try {
      // This injected vault resolver MUST enforce exact tenant/connector/key ID
      // scoping and must never interpret keyId as an arbitrary URL or file path.
      secret=await resolveSecret(envelope.tenantId,envelope.connectorId,envelope.keyId);
    } catch (_) {deny('CONNECTOR_AUTH_UNAVAILABLE',503);}
    if (!((typeof secret==='string' && Buffer.byteLength(secret,'utf8')>=32) ||
          ((Buffer.isBuffer(secret) || secret instanceof Uint8Array) && secret.length>=32))) {
      deny('CONNECTOR_NOT_AUTHORIZED',403);
    }
    let received;
    try {received=Buffer.from(envelope.signature,'base64url');}
    catch (_) {deny('INVALID_SIGNATURE',401);}
    const expected=hmac(secret,canonicalFields(envelope));
    if (received.length!==32 || !crypto.timingSafeEqual(received,expected)) {
      deny('INVALID_SIGNATURE',401);
    }

    const session=nativeD1.withSession('first-primary');
    if (!session || typeof session.prepare!=='function') deny('INTAKE_PRIMARY_UNAVAILABLE',503);
    let connector;
    try {
      connector=await session.prepare(
        "SELECT c.connector_id FROM soc_connectors c "+
        "INNER JOIN soc_tenants t ON t.tenant_id=c.tenant_id "+
        "INNER JOIN soc_connector_signing_keys k "+
        "ON k.tenant_id=c.tenant_id AND k.connector_id=c.connector_id "+
        "WHERE c.tenant_id=? AND c.connector_id=? AND k.key_id=? "+
        "AND c.state='APPROVED' AND t.status='ACTIVE' AND k.state='ACTIVE' "+
        "AND k.valid_from_epoch<=? AND k.expires_epoch>? "+
        "AND k.valid_from_epoch<=? AND k.expires_epoch>? LIMIT 1"
      ).bind(envelope.tenantId,envelope.connectorId,envelope.keyId,
        Math.floor(current/1000),Math.floor(current/1000),
        Math.floor(parseExactIso(envelope.signedAt)/1000),
        Math.floor(parseExactIso(envelope.signedAt)/1000)).first();
    } catch (_) {deny('INTAKE_PRIMARY_UNAVAILABLE',503);}
    if (!connector) deny('CONNECTOR_NOT_AUTHORIZED',403);

    const id=receiptId(envelope);
    const attestationSha256=crypto.createHash('sha256')
      .update(canonicalFields(envelope)+'.'+envelope.signature,'utf8').digest('hex');
    const receivedAt=new Date(current).toISOString();
    try {
      const result=await session.prepare(
        'INSERT INTO soc_event_receipts '+
        '(tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,created_at,source_signed_at,attestation_sha256,signing_key_id,source_event_id) '+
        'VALUES(?,?,?,?,?,?,?,?,?,?,?)'
      ).bind(
        envelope.tenantId,id,envelope.connectorId,envelope.eventTime,
        receivedAt,envelope.payloadSha256,receivedAt,envelope.signedAt,attestationSha256,envelope.keyId,envelope.sourceEventId
      ).run();
      if (!result || result.success!==true) deny('RECEIPT_REJECTED',409);
    } catch (_) {
      // Final D1 trigger independently enforces active signing key and
      // the original signed opaque source ID at INSERT.
      // Reject replayed source IDs and trigger failures. Never silently
      // treat duplicate/rejected events as newly ingested security evidence.
      deny('RECEIPT_REJECTED',409);
    }

    return Object.freeze({
      tenantId:envelope.tenantId,eventId:id,source:'SOURCE_ATTESTED',
      keyId:envelope.keyId,
      sourceEventAt:envelope.eventTime,receivedAt,
      state:'RECEIVED_NOT_ANALYST_VERIFIED',
    });
  }
  return Object.freeze({ingest});
}

module.exports={createSocEventReceiptService,SocIntakeError,canonicalFields,receiptId};
