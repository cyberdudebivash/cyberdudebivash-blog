'use strict';

/**
 * SENTINEL APEX SOC — INTERNAL ONLY connector key administration.
 *
 * No HTTP route, customer onboarding or runtime secret binding. The caller's
 * identity MUST come from the cryptographically verified SOC OIDC/session
 * boundary, not a decoded JWT payload or a request body's actor ID.
 *
 * DB PENDING ledger insertion happens BEFORE encrypted KV storage. On KV
 * failure a PENDING key remains inactive; never activate or report success.
 * D1 ledger uniqueness serializes enrollment of each (tenant,connector,key).
 * Since KV writes are eventually consistent, final activation verifies a
 * decryptable vault record and production operations still require a
 * cross-region propagation canary. Revocation is D1-primary authoritative.
 */
const {createSocEncryptedConnectorVault}=require('./soc-encrypted-connector-vault');

const TENANT=/^[a-z0-9_-]{3,64}$/;
const CONNECTOR=/^[A-Za-z0-9_.:-]{1,128}$/;
const KEY=/^[a-z0-9_-]{8,64}$/;
const MAX_KEY_AGE=90*24*60*60;

class SocKeyAdminError extends Error {
  constructor(code,status=400){super(code);this.name='SocKeyAdminError';this.code=code;this.status=status;}
}
function deny(code,status){throw new SocKeyAdminError(code,status);}
function ids(tenantId,connectorId,keyId) {
  if(typeof tenantId!=='string'||!TENANT.test(tenantId) ||
     typeof connectorId!=='string'||!CONNECTOR.test(connectorId) ||
     typeof keyId!=='string'||!KEY.test(keyId)) deny('INVALID_CONNECTOR_KEY');
}
function sqlSession(db) {
  let session;
  try{session=db.withSession('first-primary');}catch(_){deny('SOC_PRIMARY_UNAVAILABLE',503);}
  if(!session||typeof session.prepare!=='function')deny('SOC_PRIMARY_UNAVAILABLE',503);
  return session;
}
async function first(session,query,params) {
  try{return await session.prepare(query).bind(...params).first();}
  catch(_){deny('SOC_PRIMARY_UNAVAILABLE',503);}
}
async function mutate(session,query,params) {
  try{
    const result=await session.prepare(query).bind(...params).run();
    if(!result || result.success!==true)deny('SOC_KEY_MUTATION_REJECTED',409);
    if(result.meta && Number(result.meta.changes)!==1)deny('SOC_KEY_MUTATION_REJECTED',409);
    return result;
  }catch(error) {
    if(error instanceof SocKeyAdminError)throw error;
    deny('SOC_KEY_MUTATION_REJECTED',409);
  }
}
function createSocConnectorKeyAdminService({nativeD1,verifyIdentity,vault,now=()=>Date.now()}={}) {
  if(!nativeD1||typeof nativeD1.withSession!=='function' ||
     typeof verifyIdentity!=='function' ||
     !vault||typeof vault.sealKey!=='function'||typeof vault.resolveSecret!=='function' ||
     typeof now!=='function')deny('SOC_OPERATOR_AUTHORITY_REQUIRED',503);

  async function authorize(accessToken,tenantId,connectorId,keyId) {
    ids(tenantId,connectorId,keyId);
    let identity;
    try{identity=await verifyIdentity(accessToken);}catch(_){deny('UNAUTHENTICATED',401);}
    if(!identity||identity.verified!==true ||
       typeof identity.issuer!=='string'||!identity.issuer.startsWith('https://') ||
       typeof identity.subject!=='string'||!identity.subject ||
       identity.issuer.length>512||identity.subject.length>512)deny('UNAUTHENTICATED',401);
    const session=sqlSession(nativeD1);
    const actor=await first(session,[
      'SELECT p.principal_id FROM soc_principals p',
      'JOIN soc_tenants t ON t.tenant_id=p.tenant_id',
      'JOIN soc_connectors c ON c.tenant_id=t.tenant_id',
      'WHERE t.tenant_id=? AND c.connector_id=?',
      'AND p.oidc_issuer=? AND p.oidc_subject=?',
      "AND p.status='ACTIVE' AND p.role='TENANT_ADMIN'",
      "AND t.status='ACTIVE' AND c.state='APPROVED' LIMIT 1",
    ].join(' '),[tenantId,connectorId,identity.issuer,identity.subject]);
    if(!actor||typeof actor.principal_id!=='string'||!actor.principal_id)deny('FORBIDDEN',403);
    return {session,actor:actor.principal_id};
  }

  async function enroll({accessToken,tenantId,connectorId,keyId,secret,validFromEpoch,expiresEpoch}={}) {
    const {session,actor}=await authorize(accessToken,tenantId,connectorId,keyId);
    if(!(Buffer.isBuffer(secret)||secret instanceof Uint8Array)||secret.byteLength!==32)
      deny('SIGNING_SECRET_REQUIRED');
    const current=Math.floor(now()/1000);
    if(!Number.isSafeInteger(current)||
       !Number.isSafeInteger(validFromEpoch)||!Number.isSafeInteger(expiresEpoch)||
       validFromEpoch<current-300||validFromEpoch>current+300||
       expiresEpoch<=current||expiresEpoch-validFromEpoch>MAX_KEY_AGE)
      deny('INVALID_KEY_LIFETIME');
    const at=new Date(current*1000).toISOString();
    await mutate(session,[
      'INSERT INTO soc_connector_signing_keys',
      '(tenant_id,connector_id,key_id,state,valid_from_epoch,expires_epoch,',
      'created_by,changed_by,created_at,updated_at)',
      "VALUES(?,?,?,'PENDING',?,?,?,?,?,?)",
    ].join(' '),[tenantId,connectorId,keyId,validFromEpoch,expiresEpoch,actor,actor,at,at]);
    // If encryption or KV fails, leave the D1 ledger PENDING: no usable key.
    try{await vault.sealKey({tenantId,connectorId,keyId,secret});}
    catch(_){deny('KEY_ENROLLED_BUT_VAULT_UNAVAILABLE',503);}
    return Object.freeze({tenantId,connectorId,keyId,state:'PENDING',sealed:true});
  }

  async function activate({accessToken,tenantId,connectorId,keyId}={}) {
    const {session,actor}=await authorize(accessToken,tenantId,connectorId,keyId);
    let decrypted;
    try{
      decrypted=await vault.resolveSecret(tenantId,connectorId,keyId);
      if(!Buffer.isBuffer(decrypted)&&!(decrypted instanceof Uint8Array))
        deny('SEALED_KEY_UNAVAILABLE',503);
      if(decrypted.length!==32)deny('SEALED_KEY_UNAVAILABLE',503);
    }catch(_){deny('SEALED_KEY_UNAVAILABLE',503);}
    finally {if(decrypted && typeof decrypted.fill==='function')decrypted.fill(0);}
    const at=new Date(now()).toISOString();
    await mutate(session,[
      'UPDATE soc_connector_signing_keys SET state=\'ACTIVE\',changed_by=?,updated_at=?',
      'WHERE tenant_id=? AND connector_id=? AND key_id=? AND state=\'PENDING\'',
    ].join(' '),[actor,at,tenantId,connectorId,keyId]);
    return Object.freeze({tenantId,connectorId,keyId,state:'ACTIVE'});
  }

  async function revoke({accessToken,tenantId,connectorId,keyId}={}) {
    const {session,actor}=await authorize(accessToken,tenantId,connectorId,keyId);
    const at=new Date(now()).toISOString();
    await mutate(session,[
      "UPDATE soc_connector_signing_keys SET state='REVOKED',",
      'changed_by=?,updated_at=?,revoked_at=?',
      "WHERE tenant_id=? AND connector_id=? AND key_id=?",
      "AND state IN ('PENDING','ACTIVE')",
    ].join(' '),[actor,at,at,tenantId,connectorId,keyId]);
    return Object.freeze({tenantId,connectorId,keyId,state:'REVOKED'});
  }

  return Object.freeze({enroll,activate,revoke});
}

/** Integration root: NEVER register this in public Worker routes. It requires
 * the real SOC OIDC verifier and the primary-consistent session authority.
 * Vault and JWT keys remain opaque to the caller of the returned admin object.
 */
function createSocConnectorOperatorBoundary({nativeD1,kv,masterKey,oidc,fetcher,nowMillis}={}) {
  const {createSocOidcVerifier}=require('./soc-oidc-verifier');
  const {createSocSessionAuthority}=require('./soc-session-authority');
  if(!oidc || typeof oidc!=='object'||Array.isArray(oidc)||
     !nativeD1||typeof nativeD1.withSession!=='function')
    deny('SOC_OPERATOR_AUTHORITY_REQUIRED',503);
  const clock=typeof nowMillis==='function'?nowMillis:()=>Date.now();
  const authority=createSocSessionAuthority({db:nativeD1,now:()=>Math.floor(clock()/1000)});
  const verifyIdentity=createSocOidcVerifier({
    issuer:oidc.issuer,audience:oidc.audience,jwksUrl:oidc.jwksUrl,
    checkRevocation:authority.checkRevocation,now:clock,
    ...(fetcher?{fetcher}:{}),
  });
  const vault=createSocEncryptedConnectorVault({kv,masterKey});
  return createSocConnectorKeyAdminService({
    nativeD1,verifyIdentity,vault,now:clock,
  });
}

module.exports={createSocConnectorKeyAdminService,createSocConnectorOperatorBoundary,SocKeyAdminError};
