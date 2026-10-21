'use strict';

/**
 * SENTINEL APEX SOC — encrypted connector HMAC key material (source-only).
 *
 * No Worker route or customer key is provisioned by this module.
 *
 * Designed for a trusted server-only coordinator:
 *   1. Generate a random 32-byte signing key in an approved provisioning flow;
 *   2. sealKey() into an existing authorized KV namespace using AES-256-GCM;
 *   3. Create PENDING metadata in D1, check the sealed key and explicitly
 *      activate after an operator-approved, independently authenticated action;
 *   4. For signed receipts call resolveSecret(tenantId,connectorId,keyId).
 *
 * IMPORTANT: Cloudflare KV is eventually consistent. It is NOT the source of
 * authority for activation, revocation or tenant access. Primary D1 metadata
 * and an atomic receipt INSERT trigger remain the authoritative controls.
 *
 * An operator must provide masterKey as 32 bytes from a dedicated Workers
 * secret binding. No default secrets, URLs, env lookups or logging of keys.
 * This module does not distribute secrets to customers or create admin routes.
 */
const {
  randomBytes, hkdfSync, createCipheriv, createDecipheriv,
} = require('node:crypto');

const TENANT=/^[a-z0-9_-]{3,64}$/;
const CONNECTOR=/^[A-Za-z0-9_.:-]{1,128}$/;
const KEY_ID=/^[a-z0-9_-]{8,64}$/;
const PREFIX='soc:hmac:v1:';
const VERSION=1;
const HKDF_SALT=Buffer.from('sentinel-apex-soc-connector-vault-v1','utf8');

class SocVaultError extends Error {
  constructor(code) {
    super(code);this.name='SocVaultError';this.code=code;
  }
}
function deny(code) {throw new SocVaultError(code);}
function identity(tenantId,connectorId,keyId) {
  if (typeof tenantId!=='string' || !TENANT.test(tenantId) ||
      typeof connectorId!=='string' || !CONNECTOR.test(connectorId) ||
      typeof keyId!=='string' || !KEY_ID.test(keyId)) deny('INVALID_KEY_IDENTITY');
  return [tenantId,connectorId,keyId];
}
function locator(tenantId,connectorId,keyId) {
  identity(tenantId,connectorId,keyId);
  // No user-influenced path interpretation or remote secret URLs.
  return PREFIX+tenantId+':'+connectorId+':'+keyId;
}
function encoded(bytes) {return Buffer.from(bytes).toString('base64url');}
function unencoded(value,expected) {
  if(typeof value!=='string' || !/^[A-Za-z0-9_-]+$/.test(value)) deny('CIPHERTEXT_INVALID');
  const bytes=Buffer.from(value,'base64url');
  if(bytes.length!==expected || encoded(bytes)!==value) deny('CIPHERTEXT_INVALID');
  return bytes;
}

function createSocEncryptedConnectorVault({kv,masterKey}={}) {
  if(!kv || typeof kv.get!=='function' || typeof kv.put!=='function')
    deny('VAULT_BINDING_REQUIRED');
  if(!(Buffer.isBuffer(masterKey) || masterKey instanceof Uint8Array) ||
      masterKey.byteLength!==32) deny('VAULT_MASTER_KEY_REQUIRED');
  // Clone: callers cannot alter a caller-owned key buffer after construction.
  const master=Buffer.from(masterKey);
  function derive(tenantId,connectorId,keyId) {
    return Buffer.from(hkdfSync(
      'sha256',master,HKDF_SALT,
      Buffer.from(JSON.stringify(['connector-hmac',tenantId,connectorId,keyId]),'utf8'),32
    ));
  }
  function aad(tenantId,connectorId,keyId) {
    return Buffer.from(JSON.stringify([VERSION,tenantId,connectorId,keyId]),'utf8');
  }

  /** Encrypted storage only; must be called by a separately authenticated,
   * serialized operator provisioning workflow, NEVER from a public handler.
   * Exactly one versioned signing key per keyId. No plaintext return. */
  async function sealKey({tenantId,connectorId,keyId,secret}) {
    const loc=locator(tenantId,connectorId,keyId);
    if(!(Buffer.isBuffer(secret) || secret instanceof Uint8Array) ||
        secret.byteLength!==32) deny('SIGNING_SECRET_REQUIRED');

    // KV get+put is NOT atomic. The future provisioning authority must
    // serialize writes per key ID and use D1 ledger for uniqueness/replay.
    let existing;
    try {existing=await kv.get(loc);}catch(_){deny('VAULT_UNAVAILABLE');}
    if(existing!==null && existing!==undefined) deny('KEY_ALREADY_SEALED');

    const iv=randomBytes(12);
    const key=derive(tenantId,connectorId,keyId);
    let record;
    try {
      const cipher=createCipheriv('aes-256-gcm',key,iv);
      cipher.setAAD(aad(tenantId,connectorId,keyId));
      const ciphertext=Buffer.concat([cipher.update(Buffer.from(secret)),cipher.final()]);
      record=JSON.stringify({
        v:VERSION,iv:encoded(iv),ct:encoded(ciphertext),tag:encoded(cipher.getAuthTag()),
      });
    } finally {key.fill(0);}
    try {await kv.put(loc,record);}catch(_){deny('VAULT_UNAVAILABLE');}
    return Object.freeze({tenantId,connectorId,keyId,sealed:true});
  }

  /** For signed-intake validation, called with strictly scoped key identifiers.
   * Plain key material is returned only to the trusted in-memory HMAC verifier;
   * never log, cache in telemetry, export to client or store in D1. */
  async function resolveSecret(tenantId,connectorId,keyId) {
    const loc=locator(tenantId,connectorId,keyId);
    let raw;
    try {raw=await kv.get(loc);}catch(_){deny('VAULT_UNAVAILABLE');}
    if(raw===null || raw===undefined) deny('KEY_NOT_FOUND');
    if(typeof raw!=='string' || Buffer.byteLength(raw,'utf8')>512)
      deny('CIPHERTEXT_INVALID');
    let item;
    try {item=JSON.parse(raw);}catch(_){deny('CIPHERTEXT_INVALID');}
    if(!item || typeof item!=='object' || Array.isArray(item) ||
        Object.keys(item).sort().join(',')!=='ct,iv,tag,v' ||
        item.v!==VERSION) deny('CIPHERTEXT_INVALID');
    const iv=unencoded(item.iv,12);
    const ciphertext=unencoded(item.ct,32);
    const tag=unencoded(item.tag,16);
    const key=derive(tenantId,connectorId,keyId);
    try {
      const decipher=createDecipheriv('aes-256-gcm',key,iv);
      decipher.setAAD(aad(tenantId,connectorId,keyId));
      decipher.setAuthTag(tag);
      const secret=Buffer.concat([decipher.update(ciphertext),decipher.final()]);
      if(secret.length!==32) deny('CIPHERTEXT_INVALID');
      return secret;
    } catch(_) {deny('KEY_AUTHENTICATION_FAILED');}
    finally {key.fill(0);}
  }

  return Object.freeze({sealKey,resolveSecret});
}

module.exports={createSocEncryptedConnectorVault,SocVaultError};
