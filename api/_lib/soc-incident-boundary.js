'use strict';

/**
 * Internal-only composition root for a cryptographically validated SOC
 * incident service. Not registered in the Worker router; no HTTP endpoint.
 *
 * Trust chain:
 *   approved IdP JWT signature + fixed issuer/audience/short expiry/MFA
 *     -> D1 primary-only registered active hashed-JTI session
 *     -> active D1 subject and tenant membership
 *     -> tenant-scoped SOC incident queries and atomic audit triggers.
 *
 * Never expose this directly before:
 * - operator-verified IdP and revocation/session provisioning;
 * - local D1 migration rehearsal and backups;
 * - rate-limited, tested HTTPS API, cookie/CSRF or bearer-token handling;
 * - independently certified tenant isolation and deployment authorization.
 */
const { createSocOidcVerifier } = require('./soc-oidc-verifier');
const { createSocSessionAuthority } = require('./soc-session-authority');
const { createSocIncidentService } = require('./soc-incident-service');

function createSocIncidentBoundary({
  nativeD1,
  incidentDb,
  oidc,
  fetcher,
  nowMillis,
  randomUUID,
} = {}) {
  if (!nativeD1 || typeof nativeD1.withSession !== 'function') {
    throw new Error('SOC_PRIMARY_D1_REQUIRED');
  }
  if (!incidentDb || typeof incidentDb.query !== 'function' ||
      typeof incidentDb.run !== 'function' ||
      typeof incidentDb.runMutationWithChanges !== 'function') {
    throw new Error('SOC_INCIDENT_D1_REQUIRED');
  }
  if (!oidc || typeof oidc !== 'object' || Array.isArray(oidc)) {
    throw new Error('SOC_OIDC_CONFIG_REQUIRED');
  }

  const clock = typeof nowMillis === 'function' ? nowMillis : () => Date.now();
  const sessionAuthority = createSocSessionAuthority({
    db: nativeD1,
    now: () => Math.floor(clock() / 1000),
  });
  const verifiedIdentity = createSocOidcVerifier({
    issuer:oidc.issuer,
    audience:oidc.audience,
    jwksUrl:oidc.jwksUrl,
    ...(fetcher ? {fetcher} : {}),
    checkRevocation: sessionAuthority.checkRevocation,
    now:clock,
  });
  return createSocIncidentService({
    db: incidentDb,
    verifyIdentity: verifiedIdentity,
    now: () => new Date(clock()).toISOString(),
    ...(randomUUID ? {randomUUID} : {}),
  });
}

module.exports = { createSocIncidentBoundary };
