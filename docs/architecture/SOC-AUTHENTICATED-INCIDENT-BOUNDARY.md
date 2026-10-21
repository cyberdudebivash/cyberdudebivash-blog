# SENTINEL APEX SOC — Authenticated Incident Boundary

**Change classification:** Source-only Phase 4; NO customer login, NO active HTTP API route, NO database migration applied to production.

## Implemented trust chain

1. An operator-approved identity provider signs a typed JWT access token. The existing RS256 verifier validates signature, pinned issuer and audience, lifetime, required MFA claim and token type. It rejects untrusted key discovery.
2. The verifier consults the new **authoritative session registry** through a D1 session explicitly started with `first-primary`. Revocation must be checked against the latest committed database state, never an unconstrained read replica. The registry stores SHA-256 of `jti`, not tokens or raw JTIs.
3. Only an explicit, active `soc_auth_subjects` plus a separately registered, active, unexpired `soc_auth_sessions` entry can pass. Disabled subjects, revoked token IDs, expired sessions, and tokens older than a subject-wide cutoff fail closed. There is NO self-service enrollment route in this change, so an empty registry allows nobody.
4. The tenant incident service independently resolves the signed issuer/subject to an active tenant/principal/role. It enforces tenant-scoped SELECT/UPDATE and relies on migration 0010 for atomic audit and lifecycle controls. No JWT role or tenant claim is treated as permission.

Source files: `migrations/0011_soc_auth_session_authority.sql`, `api/_lib/soc-session-authority.js`, `api/_lib/soc-incident-boundary.js`.

## Release blockers (all mandatory)

- Define a real IdP and resource-server audience compatible with the strict JWT access-token profile; validate actual MFA claims and certificate/JWKS rotation.
- Implement and certify an **audited trusted session provisioning authority** after OAuth authorization-code + PKCE and secure session establishment. Do not hand-create fictional tenant/customer sessions or expose enrollment to arbitrary JWT holders.
- Implement user/session revocation, provider event integration, administrative lifecycle, unauthorized-access monitoring, session expiration cleanup and emergency disable controls.
- Verify D1 production primary-first session behavior, latency and ongoing Cloudflare Workers/D1 usage under the approved plan; no new paid resource is authorized.
- Establish a dedicated rate-limited Worker API, identity-linked authorization on every method, non-cacheability, CSRF/session policy, error redaction, strict request validation and end-to-end Workerd/D1 negative cases.
- Test token theft/replay exposure (bearer token security), key rollover, stale identity revocation, cross-tenant reads and exports, invalid principal/tenant status, failover, backup/recovery and legal retention.
- Approve production application of migrations 0009–0011 only after inventory, local D1 rehearsal, backup/restore certification, operator change control and cost measurement.

## Design constraints and limitations

- RFC 9068 requires a typed signed JWT access token, but the `amr` claim is optional in the standard. The existing SOC verifier **additionally requires** `amr: ['mfa', ...]` as a conservative local policy. Provider integration must prove it actually issues the required claims; never silently drop that gate.
- D1 read replication can lag; Cloudflare documents `withSession('first-primary')` for first-query primary consistency. The session authority intentionally refuses a database adapter lacking `withSession`; no replica downgrade.
- Each `jti` requires trusted registration. The service has no issuer or registration key to register a token by itself. The registry's default subject status is DISABLED and session status defaults to REVOKED.
- SQLite validation cannot establish the cryptographic trust or production response time of a real IdP, or make a SOC staffed/available.
- The new library is NOT referenced by `workers/lib/router.js` or `workers/lib/route-table.js`; nothing in this PR enables new public functionality.

## Verification

- Full Jest source/cryptographic integration suite using generated, real RSA-signed tokens, with denial for invalid audience, unregistered JTI, missing membership and unavailable D1.
- SQLite in-memory execution for constraints, subject-level logout, token revocation, non-reactivation and immutability, no seed records.
- Existing GitHub workflow security checks; no Cloudflare production deployment.
- Compare router state and verify no new routes or customer sign-up links.

**GO:** source-only engineering and security review. **NO-GO:** customer SOC registration, managed service, production domain migration, payment and 24/7/SOC 2 claims.
