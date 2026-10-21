# SENTINEL APEX SOC — connector key administrative trust boundary

**Classification:** source-only, internal operator library. No HTTP endpoints, production D1 writes, KV operations, customer credentials, Cloudflare deploy or DNS cutover.

## Trusted identity and audit chain

`api/_lib/soc-connector-key-admin.js` composes:
1. A pinned RS256 OIDC access-token verifier (issuer, audience, expiry, signed MFA claim).
2. Primary-consistent D1 session-token allowlisting/revocation.
3. A separate **current** D1 lookup for ACTIVE tenant, APPROVED connector and matching issuer/subject ACTIVE `TENANT_ADMIN`; caller-supplied actor IDs or JWT roles are never accepted.
4. Metadata-only D1 signing-key ledger (migration 0013, previously merged), whose database triggers require an active tenant administrator and create atomic audit entries.
5. AES-256-GCM per-tenant/key encryption into an injected existing KV namespace, backed by a 32-byte server-side master secret, already implemented by Phase 9.

This boundary is **not** registered in the public Worker router. The deployed system has no credential-issuance endpoint or IdP configured.

## State machine

**enroll:** trusted operator supplies a separately generated 32-byte key using an approved secure, out-of-band source enrollment ceremony. The service authorizes the signed OIDC principal and first writes a new `PENDING` ledger entry to primary D1. Only after the ledger accepts this unique tenant/connector/keyId does it encrypt and write the key to KV. It returns only metadata, never signing material. If KV fails, the ledger stays PENDING and the key is unusable. The same keyId is not retried; create a new version after reconciliation.

**activate:** the signed administrator is authorized again; encrypted KV material must be fetchable and authenticate with AES-GCM. Only then does D1 transition PENDING → ACTIVE through the existing audit trigger. The activation outcome is not a guarantee of global KV propagation: a cross-region read/revocation canary must pass before any customer traffic.

**revoke:** a fresh signed administrator authorization precedes a primary D1 transition from PENDING/ACTIVE → terminal REVOKED. No access to KV is needed for emergency revocation. Source-event intake separately verifies active D1 key state and the final D1 receipt trigger rejects revoked keys; encrypted KV ciphertext may remain until the legal retention/erasure policy is approved.

**Denial:** absent valid access token/session, revoked OIDC subject, missing active tenant-admin membership, suspended tenant, paused connector, invalid key version, malformed clock window, failed DB audit trigger, duplicate enrollment, inaccessible encrypted key or cryptographic error. No failure path reports successful activation.

## Critical limitations and release blockers

- **Operator enrollment remains internal, not usable by customers.** The currently available source requires an **operator-provided** 32-byte signing key. Implement secure key generation, a single-delivery authorized customer/source secret handoff, proof of source ownership, SOC legal permission and revocable support accounts before activation.
- **No atomic KV create-if-absent.** D1's unique PENDING ledger serializes the initial enrollment, but KV propagation remains eventual, and an interrupted transaction can leave an inactive pending record. Reconciliation/abandonment are mandatory, and operators must not reuse the keyId blindly.
- **No end-to-end native Workerd/D1/KV attestation.** Jest uses real cryptography and simulated provider/database behavior; it does not prove latency, cross-region visibility or database rollback under live traffic.
- **No master-key rollover/disaster recovery** until a dual-version cipher envelope, backup validation, reliable rotation and revocation drill are independently implemented.
- **D1 audit status is source-only.** Migrations 0009–0013 have not been authorized/applied to the production database. Production D1 storage, Workers billing, data residency, retention and quotas require approval before any pilot.
- **No customer SOC.** No telemetry provider wired, no supported incoming webhook, no staffed response SLA or verified customer payment. The domain `soc.cyberdudebivash.in` remains behind separate release gates.

## Acceptance

- Exact-head Node Jest and CI security checks pass, including real RSA-signed MFA token tests, D1 allowlisting, cross-tenant/role denial, key-ID uniqueness, PENDING-on-KV-failure, activation check, terminal revocation and no secret output.
- Confirm Worker `route-table.js` and `router.js` remain unchanged. Confirm no new billing, DNS, cloud bindings, production D1 migration or customer data was modified.
- Perform actual Workerd/D1/KV dry runs, operator identity lifecycle, race and replay negative tests, master-key rotation/restore test and multi-region propagation/failover proof.
- Require explicit release authorization and an actual customer-signed pilot scope.

**Decision:** eligible for internal code review only. Customer SOC operations and customer charges remain NO-GO.
