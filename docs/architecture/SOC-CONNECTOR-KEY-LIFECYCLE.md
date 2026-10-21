# SENTINEL APEX SOC — Source connector HMAC key lifecycle (Phase 7)

**Status:** Source-only, no customer credentials created, no production D1 migration, no live webhook. **No payment, domain or deployment change.**

## Attack-surface finding and patch

Phase 6 tied the HMAC signing secret only to tenant + connector, with no signed key version. That prevented independently revoking an old secret after rotation without disrupting the entire connector. Phase 7 changes the **unpublished** event signature contract to version 2 and binds an explicit **keyId** in the HMAC.

Signed canonical tuple: `JSON.stringify([2,tenantId,connectorId,keyId,sourceEventId,eventTime,signedAt,payloadSha256])` encoded UTF-8; `signature` is 32-byte HMAC-SHA256 base64url. Extra envelope fields or old v1 messages fail closed. Signing key resolution receives the exact validated `(tenantId, connectorId, keyId)` triplet. The resolver must use an operator-controlled secret store, not an arbitrary path/URL from the caller. Never store raw HMAC secrets, resolved secret values, or customer event payloads in D1, Git, logs or browser storage.

Migration `0013_soc_connector_key_lifecycle.sql` introduces a D1 metadata-only signing-key registry with immutable tenant, connector, key ID and validity window. Keys start **PENDING**. Only an active tenant-admin actor is eligible for enrollment/activation/revocation (application OIDC binding remains a separate control). Valid activation requires an APPROVED connector, ACTIVE tenant and current validity window of no more than 90 days. Up to **two** ACTIVE keys may overlap for rotation. REVOKED keys cannot be reactivated, hard-deleted or assigned to a different connector.

Signed event receipt intake retains a primary-consistent key-status/window lookup. The database performs an additional **BEFORE INSERT active-key check**, preventing the revocation race between request verification and receipt commit. The existing 0012 receipt audit trigger remains atomic and append-only. Every key enrollment/activation/revocation also appends an audit event in the same SQLite statement. Registry and receipts remain empty by default.

## Key rotation operating procedure (future approved operator action only)

1. Verify the customer's signed scope, tenant/connector ownership, trusted source provider and secure key lifecycle operator.
2. Generate a new 32+ byte secret using a CSPRNG **outside the D1 registry**. Put it in an approved secret storage system with tenant+connector+keyId binding. Never log/commit/export raw secret values.
3. Enroll the new key as PENDING using a trusted, MFA-protected admin API with actor attribution and immutable audit.
4. Validate source-integrity HMAC signing and authorized source delivery in an isolated pilot. Activate key only after protected connector/tenant authorization and local D1 integration tests pass.
5. During dual-key rotation, allow at most two approved ACTIVE versions. Stop signing with the old key, revoke it, verify fresh D1 primary reads reject it immediately, and preserve old signed receipt/audit evidence under the applicable retention policy.
6. On compromise, revoke key immediately and suspend the connector as appropriate. Rotating a key must not erase forensic evidence or silently replay previously accepted events.
7. Monitor rejected signatures, key expiry, source liveness, queue lag, D1 usage and cost. No contract SLA can be inferred from a healthy source receipt.

## Security and implementation limitations

- **No production key administration workflow exists.** The D1 triggers check that an actor record has an active tenant-admin role, but only a future trusted service can bind that `changed_by` ID to an authenticated principal; clients must never write D1 directly.
- The protocol's `payloadSha256` remains **source-attested, not independently verified**. A valid signature does not establish that the source payload is genuine or malicious.
- The active-key counter and audit triggers are database integrity controls, not substitute for edge throttling, queueing, authorization, retention, secret escrow/rotation and legal processing agreements.
- No Worker API route points to the internal receipt service; customers cannot send live telemetry by merging the code. Migration 0013 is **not** applied to production here.
- Historical v1 sample envelopes are not a compatibility guarantee. There is no live version 1 customer API to preserve.
- No raw event log or analytics lake is designed yet. D1 is metadata/control-plane only.

## Go/no-go evidence

**Source acceptance:** exact-head Jest HMAC tests, SQLite migration tests, security lint, cloud runtime build and API route inventory; cross-tenant and revoked-key negative tests.

**Runtime acceptance:** operator-approved local Workerd+D1 rehearsal including key rotation at receipt commit, native D1 session consistency, failure injection, secret store outage, event rate limiting and actual source signature verification.

**Commercial acceptance:** one written-authorized scope/pilot, verified telemetry consent, monitored support schedule, customer payment/fulfillment checks and retained incident audit evidence.

**NO-GO:** DNS migration to `soc.cyberdudebivash.in`, public SOC connector activation, production D1 migration, paid SOC service, 24/7 monitoring claims or customer billing based only on this PR.
