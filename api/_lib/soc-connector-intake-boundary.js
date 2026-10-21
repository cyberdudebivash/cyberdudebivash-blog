'use strict';

/**
 * Secure source-only composition: encrypted KV key material -> authenticated
 * HMAC v2 envelope -> primary D1 approved-key/tenant state -> atomic D1 receipt.
 *
 * This intentionally exports ONLY ingest(), never sealKey(), key registration,
 * the master secret, internal KV handle or a public HTTP handler.
 *
 * Cloudflare KV is eventually consistent; D1 remains the authoritative source
 * for revocation and receipt acceptance, checked at INSERT as well as SELECT.
 * Do not register this module in the Worker router without a full SOC release.
 */
const {createSocEncryptedConnectorVault}=require('./soc-encrypted-connector-vault');
const {createSocEventReceiptService}=require('./soc-event-receipt-service');

function createSocConnectorIntakeBoundary({nativeD1,kv,masterKey,now}={}) {
  if(!nativeD1 || typeof nativeD1.withSession!=='function')
    throw new Error('SOC_PRIMARY_D1_REQUIRED');
  const vault=createSocEncryptedConnectorVault({kv,masterKey});
  const service=createSocEventReceiptService({
    nativeD1,
    resolveSecret:vault.resolveSecret,
    ...(now?{now}:{}),
  });
  return Object.freeze({ingest:service.ingest});
}

module.exports={createSocConnectorIntakeBoundary};
