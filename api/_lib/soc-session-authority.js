'use strict';

/**
 * SENTINEL APEX SOC — primary-consistent, D1-backed JWT session check.
 *
 * No HTTP route, no public session enrollment and no customer provisioning.
 * Active token issuance requires a separate, trusted, audited provisioning
 * workflow, not supplied here. An empty registry denies all access.
 *
 * This checker runs AFTER the actual RS256 signature/claim checks and BEFORE
 * any tenant incident service authorization. All JWT IDs are SHA-256 hashed.
 *
 * A D1 session deliberately starts with 'first-primary'. A stale read
 * replica could otherwise accept a recently revoked credential. If primary
 * routing or a database read is unavailable, reject instead of degrading.
 */
const crypto = require('node:crypto');

class SocSessionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SocSessionError';
    this.code = code;
  }
}
function deny(code) { throw new SocSessionError(code); }

function createSocSessionAuthority({ db, now = () => Math.floor(Date.now() / 1000) } = {}) {
  if (!db || typeof db.withSession !== 'function') deny('PRIMARY_D1_SESSION_REQUIRED');
  if (typeof now !== 'function') deny('TIME_SOURCE_REQUIRED');

  async function checkRevocation({ issuer, subject, jti, expiresAt, tokenIssuedAt } = {}) {
    // A caller-supplied identity is NOT authoritative: this callback is only
    // intended for the pinned, signature-validating SOC OIDC verifier.
    if (typeof issuer !== 'string' || !issuer.startsWith('https://') || issuer.length > 512 ||
        typeof subject !== 'string' || !subject || subject.length > 512 ||
        typeof jti !== 'string' || jti.length < 16 || jti.length > 256 ||
        !Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(tokenIssuedAt) ||
        tokenIssuedAt <= 0 || expiresAt <= tokenIssuedAt ||
        expiresAt - tokenIssuedAt > 3600) return false;

    const current = now();
    if (!Number.isSafeInteger(current) || expiresAt <= current) return false;

    const fingerprint = crypto.createHash('sha256').update(jti, 'utf8').digest('hex');
    // Restrict all credential decisions to latest-committed primary state:
    // never use first-unconstrained, a caller bookmark or a replica.
    const session = db.withSession('first-primary');
    if (!session || typeof session.prepare !== 'function') deny('PRIMARY_D1_SESSION_REQUIRED');
    const sql = [
      'SELECT 1 AS allowed FROM soc_auth_sessions s',
      'INNER JOIN soc_auth_subjects u ON u.issuer=s.issuer AND u.subject=s.subject',
      'WHERE s.issuer=? AND s.subject=? AND s.jti_sha256=?',
      'AND s.state=\'ACTIVE\' AND s.revoked_at IS NULL',
      'AND u.status=\'ACTIVE\' AND s.token_iat_epoch>u.valid_after_epoch',
      'AND s.token_iat_epoch=? AND s.token_exp_epoch=? AND s.token_exp_epoch>?',
      'LIMIT 1',
    ].join(' ');
    const row = await session.prepare(sql).bind(
      issuer, subject, fingerprint, tokenIssuedAt, expiresAt, current
    ).first();
    return Boolean(row && row.allowed === 1);
  }

  return Object.freeze({ checkRevocation });
}

module.exports = { createSocSessionAuthority, SocSessionError };
