# SENTINEL APEX SOC — Source-Attested Event Intake (Phase 6)

> **Phase 7 protocol update (2026-10-21):** The internal, unpublished envelope contract is now **version 2** and MUST carry `keyId` (8–64 lowercase alphanumeric/underscore/hyphen characters) identifying a currently ACTIVE tenant/connector signing key. The signing tuple is now `JSON.stringify([2,tenantId,connectorId,keyId,sourceEventId,eventTime,signedAt,payloadSha256])`. Phase 7 migration 0013 adds signing-key status, rotation/revocation controls and a commit-time receipt guard. The legacy v1 examples below are historical only and must not be used for integrations. Neither version has a public route or an approved live connector.

**Status:** Source-only engineering. NOT deployed, NOT a customer-managed SOC, no active telemetry connector.

## Threat model

Real customer security signals must be ingested from a customer-authorized, authenticated connector. No event payload, simulated incidents, or source assertion may be represented as analyst-verified merely because a provider transmitted it.

Phase 6 accepts **metadata only** from an approved connector. It does not store raw event payloads, derive detection severity, automatically correlate events, initiate containment, or open incident cases. No new Worker route or public navigation is added.

## Source-to-receipt contract

`api/_lib/soc-event-receipt-service.js` expects a strictly versioned envelope:

```json
{
  "version": 1,
  "tenantId": "tenant-id",
  "connectorId": "approved-connector-id",
  "sourceEventId": "provider-event-id",
  "eventTime": "2026-10-21T15:55:00.000Z",
  "signedAt": "2026-10-21T16:00:00.000Z",
  "payloadSha256": "64-lowercase-hex-digest-of-actual-source-event",
  "signature": "base64url-encoded-HMAC-SHA256-of-canonical-fields"
}
```

The signature is computed using HMAC-SHA256 over UTF-8 `JSON.stringify([1,tenantId,connectorId,sourceEventId,eventTime,signedAt,payloadSha256])`, with **secret length >=32 bytes**. All fields are fixed-order, signed and validated; unknown keys are rejected. The signature is checked using a constant-time comparison. The provider's secret resolver is injected by the trusted operator, scoped by tenant and connector; no production secret provider is implemented in this phase.

The source event ID is bound to tenant/connector to derive a deterministic `evt_` + SHA-256 receipt ID. Reusing the same source event ID under a tenant and connector conflicts with the database primary key and is rejected. New signatures on a replayed source ID do not create a second receipt.

Timestamp policy: the source signature must be within 5 minutes of current time; event timestamp no further than 5 minutes in the future or 30 days in the past. Historical backfills require a separately approved policy and independent replay controls, not a global bypass.

## D1 audit guarantees

Migration `0012_soc_event_receipt_integrity.sql`, dependent on `0009`, adds signed-at and attestation-fingerprint columns plus triggers.

- The **active tenant** and **approved connector** are required by a database trigger, independent of the service's own primary-consistent connector lookup.
- The source receipt is metadata-only: event ID, connector, source/receipt timestamps, source-attested SHA-256 digest, signed-at time and SHA-256 fingerprint of canonical envelope plus signature. No raw payload or external payload-storage references are accepted.
- An AFTER INSERT trigger inserts a SYSTEM `EVENT_RECEIVED` audit record in the **same SQLite statement**. Audit insert failure rejects the receipt write.
- Receipt UPDATE and DELETE are blocked until a lawful, audited retention/legal-hold process exists.
- The service labels accepted receipts `SOURCE_ATTESTED` and `RECEIVED_NOT_ANALYST_VERIFIED`. This is explicitly not independent proof of the original payload, source system reliability or validated malicious activity.

## Remaining production P0 gates

- Authenticate and authorize provisioning/rotation/revocation of per-connector HMAC secrets. A secret selected solely from client-controlled metadata without operator authorization is a risk; the resolver must use a trusted store and must never log the secret.
- Implement an isolated, rate-limited connector webhook/API with replay guards and independently documented data-handling authorization. No HTTP route exists in this change.
- Run a live-like Workerd/D1/secret-binding drill, prove replay protection under concurrency and measure D1 cost/latency. Source test fakes are not production certification.
- Ensure customer-provided payload SHA-256 is computed by a trusted signed provider; a valid HMAC attests the sender, not the truth of an arbitrary payload digest.
- Implement a source-provenance assessment and analyst-reviewed, versioned detection pipeline before transforming receipts into verified detections or cases.
- Approve migrations 0009–0012 with real schema inventory, rollback/backup, cost and residency proof. No remote migration is authorized by this PR.
- Complete customer identity/provider deployment, consent/scope, SLA, service hours, checkout and actual incident handover gates.

## Verification

- Jest uses genuine HMAC signatures to test tampering, missing secrets, revoked connectors, suspended tenants, timestamps, strict schema, over-30-day receipts and authenticated primary D1 calls.
- SQLite offline tests verify real D1-compatible triggers: approved source, receipt immutability, SHA-256 evidence, single-event audit, replay and audit rollback.
- Existing Cloudflare production Worker router and domain remain unchanged.

**Release decision:** GO for internal code review and CI; NO-GO for production customer telemetry or enterprise SOC GA.
