# SENTINEL APEX SOC — Connector Key Encryption Boundary

**Status:** Source-only Phase 9 component, no live connector, no Cloudflare KV binding configured, no customer credential provisioned, no remote D1 migration, no public API route.

## Background

The merged Phase 7 connector registry tracks PENDING/ACTIVE/REVOKED signing-key IDs in D1, with an active-key receipt guard. The source event-intake contract is HMAC v2 and requires a trusted resolver for 32-byte per-connector signing material. Previously the code only specified an injected resolver; no encrypted storage implementation existed.

This source-only change adds `api/_lib/soc-encrypted-connector-vault.js`, with a composition root `api/_lib/soc-connector-intake-boundary.js`, backed by an **existing authorized KV namespace** (no new resources configured) and a **32-byte dedicated operator-provisioned Workers secret**.

## Cryptographic scheme

- 32-byte CSPRNG-produced per-version HMAC key, provided to `sealKey` only by a future reviewed and MFA-authenticated operator enrollment process. Never derive a signing key from a passphrase, device identifier, tenant name or fixed test sample.
- A 32-byte master-key binding injected by the trusted runtime; neither the master nor the signing key is committed to Git, stored in D1, logged or emitted to the public frontend.
- HKDF-SHA256 derives a distinct AES-256 key per tenant + connector + keyId with a fixed, application-specific domain separation salt and an identity-bound info tuple.
- A new 96-bit random AES-GCM nonce for each record; associated authenticated data binds protocol version, tenant ID, connector ID and keyId. KV stores only a bounded `{v,iv,ct,tag}` encoded JSON ciphertext envelope.
- Fetch/decrypt authenticates the expected tenant and key scope. Missing, corrupted, moved or unauthenticated envelopes **fail closed**, without falling back to plaintext or unsigned keys.
- `createSocConnectorIntakeBoundary` exports **only ingest()**. After HMAC verification the existing event-intake service checks the authoritative active tenant/connector/signing-key state via primary-first D1; the receipt insertion trigger checks again at commit time and creates the audit record atomically.

## Authorization and operational requirements

**This is NOT a customer secret-provisioning service.** A future trusted operator flow must bind the authenticated TENANT_ADMIN (including active tenant, issuer/subject, MFA, and revocation) to any D1 key lifecycle mutation and cryptographic enrollment. The phase 7 D1 trigger checking a `created_by` principal is not sufficient to establish who submitted an HTTP request. Do not expose `sealKey` or `resolveSecret` directly to customers or general Worker routes.

Key ceremony must use a secure, private channel to deliver a connector HMAC secret to its customer-managed source once. This code does not implement that ceremony, generate production secrets, or return secrets to browsers.

**KV consistency:** Cloudflare KV is eventually consistent. A successful `put` may not be immediately readable in other regions. The read-before-write check in `sealKey` is a defensive convenience, **not an atomic create**; a trusted, serialized issuer must prevent concurrent overwrite. The D1 key registry is the uniqueness, activation and revocation authority, and production rollout must prove correct behavior across KV propagation lag and D1 primary consistency.

**Master-key lifecycle:** A master secret rotation requires a separately tested, versioned envelope re-encryption and zero-downtime key migration scheme. This v1 module intentionally does not support simultaneous master keys or unversioned fallbacks; losing the master makes existing ciphertext unrecoverable. Key backup, disaster recovery, access permissions and a rotation runbook are release blockers.

**Revocation:** Revoked key material may remain encrypted in KV for forensic retention, but active-key status and receipt acceptance must deny its use. A future approved retention/erasure policy must govern ciphertext disposal. The KV resolver must never be treated as sufficient authorization; use the D1 checks.

**Operational cost:** No new Cloudflare resources, queues, paid services or production traffic are enabled here. Per-event KV reads could become costly/slow at scale; validate low-volume pilot quotas, caching risks and latency before any commercial SLA. Never cache a decrypted secret past its revocation policy without a proven freshness control.

## Verification

- Jest tests use actual AES-GCM encryption, HKDF key derivation, random IV and HMAC-SHA256. Negative cases cover key-name injection, cross-tenant/cross-connector copy, ciphertext/IV/tag tampering, wrong master, absent key, unavailability, size/schema corruption and version isolation.
- Integration tests inject in-memory KV and a stubbed primary D1 session, then exercise signed event acceptance and rejection for tampering, revocation, vault outage, replay and audit failure.
- These tests demonstrate cryptographic behavior but **do not** substitute for native Workerd+KV+D1 end-to-end validation, external penetration testing, authorized secret enrollment or approved signed customer scope.
- Confirm no `workers/lib/router.js` or `route-table.js` change, no D1 migrations applied, no live SOC endpoint, no credential disclosure and no customer charges.

**Release decision:** internal security-library code may be reviewed; customer telemetry ingestion, paid SOC and `soc.cyberdudebivash.in` GA remain NO-GO.
