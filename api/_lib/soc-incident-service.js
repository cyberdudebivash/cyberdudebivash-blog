'use strict';

/**
 * SENTINEL APEX SOC — tenant-bound incident control plane (NO HTTP ROUTE).
 * Requires an injected cryptographic OIDC verifier; refuses initialization
 * without it. The verifier MUST check signature, issuer, audience, expiry,
 * revocation and any session/nonce bindings before returning verified claims.
 * NEVER derive verified claims directly from request headers, body or query.
 *
 * Roles and tenant membership come from D1 on EVERY operation, not JWT roles.
 * Incident writes are audited atomically by migration 0010's SQLite triggers.
 * There is no telemetry ingestion, response action or public access here.
 */
const crypto = require('node:crypto');
const defaultD1 = require('./d1');

const WRITE_ROLES = new Set(['ANALYST','LEAD_ANALYST','TENANT_ADMIN']);
const SEVERITIES = new Set(['LOW','MEDIUM','HIGH','CRITICAL']);
const STATES = new Set(['OPEN','TRIAGE','INVESTIGATING','AWAITING_APPROVAL','CONTAINED','RESOLVED','CLOSED']);
const TENANT = /^[a-z0-9_-]{3,64}$/;
const INCIDENT = /^inc_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REQUEST = /^[A-Za-z0-9_.:-]{16,128}$/;

class SocServiceError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = 'SocServiceError';
    this.code = code;
    this.status = status;
  }
}
function fail(code, status = 400) { throw new SocServiceError(code, status); }
function assertText(value, max, label) {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > max ||
      /[\u0000-\u001f\u007f]/.test(value)) fail('INVALID_' + label);
  return value.trim();
}
function assertIncident(id) {
  if (typeof id !== 'string' || !INCIDENT.test(id)) fail('INVALID_INCIDENT_ID');
  return id;
}
function assertRequest(id) {
  if (typeof id !== 'string' || !REQUEST.test(id)) fail('INVALID_REQUEST_ID');
  return id;
}
function assertShape(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !keys.includes(key))) fail('UNEXPECTED_INPUT');
}
function view(row) {
  return {
    tenantId: row.tenant_id, incidentId: row.incident_id, title: row.title,
    severity: row.severity, state: row.state, ownerId: row.owner_id || null,
    version: Number(row.version), createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

function createSocIncidentService({
  db = defaultD1,
  verifyIdentity,
  now = () => new Date().toISOString(),
  randomUUID = () => crypto.randomUUID(),
} = {}) {
  if (typeof verifyIdentity !== 'function') fail('OIDC_VERIFIER_REQUIRED', 503);
  if (!db || typeof db.query !== 'function' || typeof db.run !== 'function' ||
      typeof db.runMutationWithChanges !== 'function') fail('SOC_DATABASE_ADAPTER_REQUIRED', 503);

  async function authorize(accessToken, tenantId, writable) {
    if (typeof tenantId !== 'string' || !TENANT.test(tenantId)) fail('INVALID_TENANT');
    let identity;
    try { identity = await verifyIdentity(accessToken); }
    catch (_) { fail('UNAUTHENTICATED', 401); }
    if (!identity || identity.verified !== true ||
        typeof identity.issuer !== 'string' || !identity.issuer.startsWith('https://') ||
        identity.issuer.length > 512 || typeof identity.subject !== 'string' ||
        !identity.subject || identity.subject.length > 512) fail('UNAUTHENTICATED', 401);

    const rows = await db.query([
      'SELECT p.tenant_id,p.principal_id,p.role FROM soc_principals p',
      'INNER JOIN soc_tenants t ON t.tenant_id=p.tenant_id',
      "WHERE p.tenant_id=? AND p.oidc_issuer=? AND p.oidc_subject=?",
      "AND p.status='ACTIVE' AND t.status='ACTIVE' LIMIT 1",
    ].join(' '), [tenantId, identity.issuer, identity.subject]);
    if (!rows.length) fail('FORBIDDEN', 403);
    const user = rows[0];
    if (writable && !WRITE_ROLES.has(user.role)) fail('FORBIDDEN', 403);
    return { tenantId: user.tenant_id, principalId: user.principal_id };
  }

  // An incident assignee is a live SOC operator, not an arbitrary customer-
  // supplied principal ID. The composite foreign key alone only proves the
  // principal existed once; it does not reject REVOKED/INVITED/read-only
  // principals. Keep the lookup scoped to the authenticated tenant and use
  // one indistinguishable 403 for foreign, unknown or inactive principals.
  async function requireActiveOwner(tenantId, ownerId) {
    if (ownerId === null) return;
    const owners = await db.query([
      'SELECT principal_id FROM soc_principals',
      'WHERE tenant_id=? AND principal_id=? AND status=\'ACTIVE\'',
      "AND role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN') LIMIT 1",
    ].join(' '), [tenantId,ownerId]);
    if (!Array.isArray(owners) || owners.length !== 1 ||
        owners[0].principal_id !== ownerId) fail('INVALID_INCIDENT_OWNER',403);
  }

  async function load(tenantId, id) {
    const rows = await db.query([
      'SELECT tenant_id,incident_id,title,severity,state,owner_id,version,created_at,updated_at',
      'FROM soc_incidents WHERE tenant_id=? AND incident_id=? LIMIT 1',
    ].join(' '), [tenantId, assertIncident(id)]);
    if (!rows.length) fail('NOT_FOUND', 404);
    return rows[0];
  }

  async function get({accessToken, tenantId, id}) {
    const user = await authorize(accessToken, tenantId, false);
    return view(await load(user.tenantId, id));
  }

  async function list({accessToken, tenantId, state, limit = 30}) {
    const user = await authorize(accessToken, tenantId, false);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50) fail('INVALID_PAGE_LIMIT');
    if (state !== undefined && !STATES.has(state)) fail('INVALID_STATE');
    const columns = 'tenant_id,incident_id,title,severity,state,owner_id,version,created_at,updated_at';
    const sql = state === undefined
      ? 'SELECT '+columns+' FROM soc_incidents WHERE tenant_id=? ORDER BY updated_at DESC,incident_id LIMIT ?'
      : 'SELECT '+columns+' FROM soc_incidents WHERE tenant_id=? AND state=? ORDER BY updated_at DESC,incident_id LIMIT ?';
    const params = state === undefined ? [user.tenantId,limit] : [user.tenantId,state,limit];
    return (await db.query(sql, params)).map(view);
  }

  async function create({accessToken, tenantId, requestId, input}) {
    const user = await authorize(accessToken, tenantId, true);
    assertShape(input, ['title','severity','ownerId']);
    const title = assertText(input.title, 256, 'TITLE');
    if (!SEVERITIES.has(input.severity)) fail('INVALID_SEVERITY');
    const owner = input.ownerId == null ? null : assertText(input.ownerId,128,'OWNER');
    const rid = assertRequest(requestId);
    await requireActiveOwner(user.tenantId,owner);
    const id = assertIncident('inc_' + randomUUID());
    const time = now();
    // The preflight D1 lookup is good UX, but it is not authorization at
    // commit time: an owner can be revoked after that read. SQLite must
    // observe an ACTIVE, write-capable principal in the SAME atomic INSERT.
    // SELECT ... WHERE instead of VALUES ensures revoked/foreign owners
    // cannot create an incident or trigger its append-only audit record.
    const sql = [
      'INSERT INTO soc_incidents(tenant_id,incident_id,title,severity,state,owner_id,version,',
      'audit_actor_id,audit_request_id,created_at,updated_at)',
      "SELECT ?,?,?,?,'OPEN',?,1,?,?,?,? WHERE ? IS NULL OR EXISTS (",
      'SELECT 1 FROM soc_principals WHERE tenant_id=? AND principal_id=?',
      "AND status='ACTIVE' AND role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN'))",
    ].join(' ');
    try {
      const affected = await db.runMutationWithChanges(sql, [
        user.tenantId,id,title,input.severity,owner,user.principalId,rid,time,time,
        owner,user.tenantId,owner,
      ]);
      if (affected !== 1) fail('INCIDENT_WRITE_REJECTED',409);
    } catch (_) { fail('INCIDENT_WRITE_REJECTED',409); }
    return view(await load(user.tenantId,id));
  }

  async function update({accessToken, tenantId, id, expectedVersion, requestId, changes}) {
    const user = await authorize(accessToken, tenantId, true);
    assertIncident(id);
    assertRequest(requestId);
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) fail('INVALID_EXPECTED_VERSION');
    assertShape(changes, ['title','severity','state','ownerId']);
    if (!Object.keys(changes).length) fail('EMPTY_CHANGE');
    const old = await load(user.tenantId,id);
    if (Number(old.version) !== expectedVersion) fail('VERSION_CONFLICT',409);
    const title = changes.title === undefined ? old.title : assertText(changes.title,256,'TITLE');
    const severity = changes.severity === undefined ? old.severity : changes.severity;
    const state = changes.state === undefined ? old.state : changes.state;
    if (!SEVERITIES.has(severity)) fail('INVALID_SEVERITY');
    if (!STATES.has(state)) fail('INVALID_STATE');
    const owner = changes.ownerId === undefined ? old.owner_id
      : changes.ownerId === null ? null : assertText(changes.ownerId,128,'OWNER');
    // Reconfirm only when changing the assignee: unrelated edits to legacy
    // incidents must not accidentally grant access or silently reassign.
    if (changes.ownerId !== undefined && owner !== old.owner_id) {
      await requireActiveOwner(user.tenantId,owner);
    }
    // A changed, non-null assignee must STILL be active at the moment of
    // the write, even if their account is revoked between preflight and
    // this statement. Single-statement EXISTS shares SQLite's write
    // serialization and optimistic incident version check. An unchanged
    // legacy owner or explicit unassignment does not need re-authorization.
    const assignmentChanged = changes.ownerId !== undefined &&
      owner !== old.owner_id && owner !== null;
    const sql = [
      'UPDATE soc_incidents SET title=?,severity=?,state=?,owner_id=?,',
      'version=version+1,updated_at=?,audit_actor_id=?,audit_request_id=?',
      'WHERE tenant_id=? AND incident_id=? AND version=?',
      ...(assignmentChanged ? [
        'AND EXISTS (SELECT 1 FROM soc_principals',
        'WHERE tenant_id=? AND principal_id=?',
        "AND status='ACTIVE' AND role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN'))",
      ] : []),
    ].join(' ');
    const params = [
      title,severity,state,owner,now(),user.principalId,requestId,
      user.tenantId,id,expectedVersion,
      ...(assignmentChanged ? [user.tenantId,owner] : []),
    ];
    let affected;
    try {
      affected = await db.runMutationWithChanges(sql, params);
    } catch (_) { fail('INCIDENT_WRITE_REJECTED',409); }
    if (affected !== 1) fail('VERSION_CONFLICT',409);
    return view(await load(user.tenantId,id));
  }

  return Object.freeze({get,list,create,update});
}

module.exports = {createSocIncidentService,SocServiceError};
