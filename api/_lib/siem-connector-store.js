'use strict';
/**
 * SENTINEL APEX — Customer SIEM Connector Persistence (Controlled SIEM
 * Deployment Gateway v1)
 *
 * Mirrors defense-profile-store.js's established pattern exactly:
 * ownership always re-derived from the caller's authenticate()-issued
 * userId, never trusted from the request body; identical NOT_FOUND for
 * "doesn't exist" and "exists but belongs to someone else"; a best-effort,
 * capped audit log that never records a credential value.
 *
 * Schema: migrations/0004_siem_deployment_gateway.sql, same
 * `sentinel-apex-core` D1 database every other customer-owned store uses.
 *
 * Credential lifecycle (Sections 18-22, 26): a credential is decrypted
 * ONLY inside getConnectorWithCredential() -- the one function
 * deployment-engine.js's execute/test-connection paths call -- and is
 * never returned by any read path a customer-facing API handler exposes
 * (listConnectors()/getConnectorSafe() only ever expose a
 * `credential_configured` boolean, matching Section 26's "GET connector
 * must return credential_configured: true, not credential value").
 */

const crypto = require('crypto');
const d1 = require('./d1');
const connectorCrypto = require('./connector-crypto');
const taxonomy = require('./siem-connector-taxonomy');
const { tierAtLeast } = require('./tier-entitlements');

const MAX_NAME_LENGTH = 100;
const AUDIT_LOG_MAX_ENTRIES = 10000; // matches defense_profile_audit_log's own bound

function generateConnectorId() {
  return 'conn_' + crypto.randomBytes(12).toString('hex');
}

async function auditConnectorAction(action, data = {}) {
  try {
    await d1.run(
      'INSERT INTO siem_connector_audit_log (action, data, ts) VALUES (?, ?, ?)',
      [action, JSON.stringify(data), new Date().toISOString()]
    );
    await d1.run(
      `DELETE FROM siem_connector_audit_log WHERE id NOT IN
       (SELECT id FROM siem_connector_audit_log ORDER BY id DESC LIMIT ?)`,
      [AUDIT_LOG_MAX_ENTRIES]
    ).catch(() => {});
  } catch (_) {
    // Audit failure must never break the main flow.
  }
}

/* ───────────────────────── entitlements ───────────────────────── */
// New policy this tranche introduces, using the EXISTING tier hierarchy
// (no new price invented): the safe, no-real-infrastructure Sandbox
// connector is open to every tier (exploration should never require
// payment); a real, deploy-capable connector (Microsoft Sentinel today)
// requires Pro/Enterprise, mirroring the exact precedent
// api/v1/intel.js's `action=detection-pack` already established for
// gating an advanced capability behind those two tiers.
function getSiemConnectorEntitlements(tier) {
  const paidTier = tierAtLeast(tier, 'pro');
  return {
    enabled: true,
    sandbox_connectors: { enabled: true, max: 3 },
    live_connectors: { enabled: paidTier, max: paidTier ? (tier === 'enterprise' ? 25 : 5) : 0 },
  };
}

function platformRequiresPaidTier(platformId) {
  const platform = taxonomy.KNOWN_PLATFORMS[platformId];
  return !(platform && platform.is_sandbox);
}

/* ───────────────────────── validation ───────────────────────── */

function validateName(name) {
  const clean = String(name || '').trim().slice(0, MAX_NAME_LENGTH);
  if (!clean) return { error: true, message: `name must be 1-${MAX_NAME_LENGTH} characters.` };
  return { value: clean };
}

function validateTargetConfig(platformId, targetConfig) {
  const platform = taxonomy.KNOWN_PLATFORMS[platformId];
  const cfg = (targetConfig && typeof targetConfig === 'object' && !Array.isArray(targetConfig)) ? targetConfig : {};
  const clean = {};
  for (const field of platform.required_target_fields) {
    const value = cfg[field];
    if (typeof value !== 'string' || !value.trim()) {
      return { error: true, message: `target_config.${field} is required for platform "${platformId}".` };
    }
    clean[field] = value.trim().slice(0, 500);
  }
  // Optional fields (Controlled Read-Only SIEM Hunting Connectors v1):
  // present-if-supplied, never required -- e.g. microsoft-sentinel's
  // workspace_id is needed only for hunt query execution, never for
  // deploy, so it must never become a required_target_fields entry (that
  // would break every existing deploy-only connector's validation).
  for (const field of (platform.optional_target_fields || [])) {
    const value = cfg[field];
    if (typeof value === 'string' && value.trim()) {
      clean[field] = value.trim().slice(0, 500);
    }
  }
  // Sandbox-only escape hatch for contract/QA testing (Section 91) --
  // never present on a real platform's required_target_fields, so it can
  // never be mistaken for a real target identifier.
  if (platform.is_sandbox && typeof cfg.simulate === 'string') {
    clean.simulate = cfg.simulate.slice(0, 64);
  }
  return { value: clean };
}

function validateCredential(platformId, credential) {
  const platform = taxonomy.KNOWN_PLATFORMS[platformId];
  if (!platform.required_credential_fields.length) return { value: null }; // e.g. the sandbox connector needs none
  if (!credential || typeof credential !== 'object' || Array.isArray(credential)) {
    return { error: true, message: 'credential must be an object.' };
  }
  const clean = {};
  for (const field of platform.required_credential_fields) {
    const value = credential[field];
    if (typeof value !== 'string' || !value.trim()) {
      return { error: true, message: `credential.${field} is required for platform "${platformId}".` };
    }
    clean[field] = value;
  }
  return { value: clean };
}

/* ───────────────────────── serialization ───────────────────────── */

function toSafeConnector(row) {
  return {
    id: row.id,
    platform: row.platform,
    platform_label: (taxonomy.KNOWN_PLATFORMS[row.platform] || {}).label || row.platform,
    name: row.name,
    target_config: JSON.parse(row.target_config || '{}'),
    credential_configured: !!row.credential_configured,
    health_status: row.health_status,
    last_connection_check_at: row.last_connection_check_at,
    last_connection_result: row.last_connection_result ? JSON.parse(row.last_connection_result) : null,
    disabled: !!row.disabled_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

/* ───────────────────────── CRUD ───────────────────────── */

async function listConnectors(ownerId) {
  const rows = await d1.query('SELECT * FROM siem_connectors WHERE owner_id = ? ORDER BY created_at DESC', [ownerId]);
  return rows.map(toSafeConnector);
}

async function getConnectorRaw(ownerId, connectorId) {
  const rows = await d1.query('SELECT * FROM siem_connectors WHERE id = ? AND owner_id = ?', [connectorId, ownerId]);
  return rows[0] || null;
}

/** Customer/API-facing read -- never includes credential_ciphertext in its return value (it's on the raw row, but toSafeConnector() never touches that field). */
async function getConnectorSafe(ownerId, connectorId) {
  const row = await getConnectorRaw(ownerId, connectorId);
  if (!row) return { error: 'NOT_FOUND', message: 'No connector found.' };
  return { connector: toSafeConnector(row) };
}

/**
 * INTERNAL ONLY -- decrypts the credential for the minimum duration of one
 * authorized connector operation (testConnection/deploy/readBack/disable/
 * deleteRemote). Never call this from a request handler and return its
 * result directly to a client (Section 21/26).
 */
async function getConnectorWithCredential(ownerId, connectorId) {
  const row = await getConnectorRaw(ownerId, connectorId);
  if (!row) return { error: 'NOT_FOUND', message: 'No connector found.' };
  if (row.disabled_at) return { error: 'CONNECTOR_DISABLED', message: 'This connector has been disconnected.' };
  const platform = taxonomy.KNOWN_PLATFORMS[row.platform];
  let credential = null;
  if (platform.required_credential_fields.length) {
    if (!row.credential_ciphertext) return { error: 'CREDENTIAL_NOT_CONFIGURED', message: 'No credential configured for this connector yet.' };
    try {
      credential = JSON.parse(connectorCrypto.decryptCredential(row.credential_ciphertext));
    } catch (e) {
      return { error: 'CREDENTIAL_DECRYPT_FAILED', message: 'Stored credential could not be decrypted.' };
    }
  }
  return {
    connector: {
      id: row.id,
      owner_id: row.owner_id,
      platform: row.platform,
      name: row.name,
      target_config: JSON.parse(row.target_config || '{}'),
      credential,
    },
  };
}

async function createConnector(ownerId, tier, { platform, name, target_config, credential }) {
  const platformId = String(platform || '').trim();
  if (!taxonomy.isKnownPlatform(platformId)) {
    return { error: 'UNKNOWN_PLATFORM', message: `Unknown platform "${platformId}". Known: ${Object.keys(taxonomy.KNOWN_PLATFORMS).join(', ')}.` };
  }
  const platformDef = taxonomy.KNOWN_PLATFORMS[platformId];
  if (!platformDef.capabilities.deploy_supported) {
    return { error: 'PLATFORM_NOT_IMPLEMENTED', message: platformDef.not_implemented_reason || `Platform "${platformId}" is not yet implemented.` };
  }
  if (platformRequiresPaidTier(platformId) && !tierAtLeast(tier, 'pro')) {
    return { error: 'TIER_RESTRICTED', message: 'Connecting a live SIEM requires the Pro, Team or Enterprise plan. The Sandbox / Test Connector is available on every plan.' };
  }

  const nameResult = validateName(name);
  if (nameResult.error) return { error: 'INVALID_NAME', message: nameResult.message };
  const targetResult = validateTargetConfig(platformId, target_config);
  if (targetResult.error) return { error: 'INVALID_TARGET_CONFIG', message: targetResult.message };
  const credentialResult = validateCredential(platformId, credential);
  if (credentialResult.error) return { error: 'INVALID_CREDENTIAL', message: credentialResult.message };

  if (credentialResult.value && !connectorCrypto.isConfigured()) {
    return { error: 'ENCRYPTION_NOT_CONFIGURED', message: 'Connector credential storage is not available in this environment (master key not configured).' };
  }

  const entitlements = getSiemConnectorEntitlements(tier);
  const existing = await listConnectors(ownerId);
  const isSandbox = !!platformDef.is_sandbox;
  const sameKind = existing.filter(c => !!(taxonomy.KNOWN_PLATFORMS[c.platform] || {}).is_sandbox === isSandbox && !c.disabled);
  const limit = isSandbox ? entitlements.sandbox_connectors.max : entitlements.live_connectors.max;
  if (sameKind.length >= limit) {
    return { error: 'CONNECTOR_LIMIT_REACHED', message: `Maximum of ${limit} ${isSandbox ? 'sandbox' : 'live'} connector(s) for your plan.` };
  }

  const connectorId = generateConnectorId();
  const nowIso = new Date().toISOString();
  const ciphertext = credentialResult.value ? connectorCrypto.encryptCredential(JSON.stringify(credentialResult.value)) : null;

  await d1.run(
    `INSERT INTO siem_connectors
      (id, owner_id, platform, name, target_config, credential_ciphertext, credential_configured, health_status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'NEVER_TESTED', ?, ?)`,
    [connectorId, ownerId, platformId, nameResult.value, JSON.stringify(targetResult.value), ciphertext, ciphertext ? 1 : 0, nowIso, nowIso]
  );

  auditConnectorAction('CONNECTOR_CREATED', { owner: ownerId, connectorId, platform: platformId }).catch(() => {});
  const row = await getConnectorRaw(ownerId, connectorId);
  return { connector: toSafeConnector(row) };
}

async function rotateCredential(ownerId, connectorId, credential) {
  const row = await getConnectorRaw(ownerId, connectorId);
  if (!row) return { error: 'NOT_FOUND', message: 'No connector found.' };
  if (row.disabled_at) return { error: 'CONNECTOR_DISABLED', message: 'This connector has been disconnected.' };
  const credentialResult = validateCredential(row.platform, credential);
  if (credentialResult.error) return { error: 'INVALID_CREDENTIAL', message: credentialResult.message };
  if (!connectorCrypto.isConfigured()) {
    return { error: 'ENCRYPTION_NOT_CONFIGURED', message: 'Connector credential storage is not available in this environment (master key not configured).' };
  }
  const ciphertext = credentialResult.value ? connectorCrypto.encryptCredential(JSON.stringify(credentialResult.value)) : null;
  const nowIso = new Date().toISOString();
  await d1.run(
    'UPDATE siem_connectors SET credential_ciphertext = ?, credential_configured = ?, health_status = ?, updated_at = ? WHERE id = ? AND owner_id = ?',
    [ciphertext, ciphertext ? 1 : 0, 'NEVER_TESTED', nowIso, connectorId, ownerId]
  );
  auditConnectorAction('CREDENTIAL_ROTATED', { owner: ownerId, connectorId }).catch(() => {});
  const updated = await getConnectorRaw(ownerId, connectorId);
  return { connector: toSafeConnector(updated) };
}

async function recordConnectionTest(ownerId, connectorId, { result, detail }) {
  const healthMap = {
    CONNECTED: 'CONNECTED', AUTH_FAILED: 'AUTH_EXPIRED',
    INSUFFICIENT_PERMISSION: 'PERMISSION_CHANGED', TARGET_NOT_FOUND: 'UNAVAILABLE', UNAVAILABLE: 'UNAVAILABLE',
  };
  const nowIso = new Date().toISOString();
  await d1.run(
    'UPDATE siem_connectors SET health_status = ?, last_connection_check_at = ?, last_connection_result = ?, updated_at = ? WHERE id = ? AND owner_id = ?',
    [healthMap[result] || 'UNAVAILABLE', nowIso, JSON.stringify({ result, detail, checked_at: nowIso }), nowIso, connectorId, ownerId]
  );
  auditConnectorAction('CONNECTION_TESTED', { owner: ownerId, connectorId, result }).catch(() => {});
}

/** Disconnect (Section 79): stops future deployments (disabled_at set),
 *  revokes/deletes the local credential, preserves audit/history. Never
 *  deletes remote SIEM rules automatically. */
async function disableConnector(ownerId, connectorId) {
  const row = await getConnectorRaw(ownerId, connectorId);
  if (!row) return { error: 'NOT_FOUND', message: 'No connector found.' };
  const nowIso = new Date().toISOString();
  await d1.run(
    `UPDATE siem_connectors SET disabled_at = ?, credential_ciphertext = NULL, credential_configured = 0,
       health_status = 'DISABLED', updated_at = ? WHERE id = ? AND owner_id = ?`,
    [nowIso, nowIso, connectorId, ownerId]
  );
  auditConnectorAction('CONNECTOR_DISABLED', { owner: ownerId, connectorId }).catch(() => {});
  return { disabled: true };
}

module.exports = {
  getSiemConnectorEntitlements,
  platformRequiresPaidTier,
  listConnectors,
  getConnectorSafe,
  getConnectorRaw,
  getConnectorWithCredential,
  createConnector,
  rotateCredential,
  recordConnectionTest,
  disableConnector,
};
