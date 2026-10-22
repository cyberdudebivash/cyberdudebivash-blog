# SENTINEL APEX SOC — Phase 12 original source identity and independent evidence check

**Release classification: SOURCE ONLY / pilot engineering — NOT operational customer SOC.**

## Root-cause evidence

Previously `soc_event_receipts` stored only a derived receipt ID, digest, connector and signed timestamp, but **not the exact `sourceEventId` signed by the HMAC v2 source connector**. This prevented a trusted provider integration from reliably retrieving the original SIEM/EDR event for independent review. Phase 11 mandated a `verifySourceEvidence` callback but had no actual byte-level verifier.

## Changes

- **Migration 0015 (not applied remotely)** adds `source_event_id` to the immutable receipt. The original provider ID must be a bounded, opaque ASCII technical ID (one to 128 characters; letters, numbers, underscore, dash, colon, period). Existing historical rows are left NULL and cannot pass the new verifier without separately authorized provenance reconciliation.
- The signed intake service writes the **original `sourceEventId` from its validated and authenticated HMAC envelope**, not a client-provided loose parameter. It remains metadata-only. Its existing D1 audit trigger and key-revocation commit guard still apply.
- `soc-detection-review-service.js` retrieves `source_event_id` from the same tenant-scoped original receipt and refuses review if absent. The trusted verifier receives this ID, the deterministic tenant/connector/event receipt ID, signing key ID, attestation fingerprint and source digest.
- `soc-source-byte-verifier.js` is a concrete verifier, injected with one **operator-authorized `readAuthorizedEvent` provider adapter**. It rejects invented event IDs, mismatched tenant/connector/source IDs, URLs and extraneous fields; applies an abort deadline and maximum source byte size; recomputes SHA-256 of the **actual returned Uint8Array/Buffer**. It never trusts an adapter's pre-supplied hash or `verified:true` boolean, stores no payload, and returns only boolean verification plus the computed digest. Digest mismatch fails review.
- `soc-detection-source-boundary.js` composes the existing RS256 signed, MFA-and-revocation-checked OIDC session verifier, fresh primary D1 tenant-analyst authorization, original source-ID lookup, byte-level independent verification and Phase 11 audit-atomic review.

## External source security requirements

No actual SIEM/EDR provider integration is implemented. A customer-authorized `readAuthorizedEvent` adapter must be deployed separately with a **fixed, operator-approved provider endpoint and tenant/connector mapping**. Never construct network URLs or select credentials from input `sourceEventId`, `tenantId` or a browser field. The adapter must enforce credentials, customer consent, IDOR/tenant rules, stream-size limits before buffering, HTTP timeout, TLS verification and revocation/circuit breaking. The verifier's bounded post-read checks alone cannot prevent an adapter from allocating unbounded memory; the adapter MUST independently stream-limit its upstream response.

The original provider source ID is an opaque technical locator, **not a free-form URL or personal identifier**. Source providers that expose usernames, emails, device identifiers or regulated data as their event ID require an approved pseudonymization/lookup design instead of storing those IDs in D1. Do not claim this regex guarantees non-PII.

The verifier confirms that the authorized adapter returned bytes with the expected SHA-256. It **does not prove** source-system honesty, adversary attribution, maliciousness, customer legal authorization, containment, analyst staffing, or compliance certification. Human analysts retain control; the reviewer writes a signed, audited rationale.

## Regression and acceptance

- Offline SQLite test checks immutable original provider locator, no raw payload reference, request replay, cross-tenant identity, revoked connector and zero seeded data.
- Real-byte Jest tests check independent hash generation, scope mismatch, unexpected `verified:true` flags, token-free artifact leakage, unsupported/oversize payloads, provider outage, timeout and ID tampering.
- Integration test checks signed RS256 + MFA token, active session and tenant analyst from primary D1, authorized provider bytes and one-way review. All fixtures are **offline synthetic test data only**.
- Existing Cloudflare build, security, Blogger evidence, accessibility and full test suite must pass at the **exact PR HEAD**; no production workers/D1 migration was performed.
- Before customer release: actual Workerd + D1 + KV rehearsals including the full 0009–0015 migration chain, authorized source adapter/key management, encrypted source handling/retention, signed pilot scope, business acceptance, endpoint rate limits, observability and on-call coverage. Confirm the public SOC hostname, deployment SHA and raw homepage integrity after an independently approved release.

**No production deployments, D1 changes, customers, raw telemetry, billing or DNS. NO-GO for Fortune 500 or any paid operated SOC until live and legal gates close.**
