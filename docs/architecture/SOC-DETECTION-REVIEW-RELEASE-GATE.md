# SENTINEL APEX SOC — Phase 11 detection evidence and analyst decision integrity

**Status:** Source-only, no public route, no customer authorization, no rule-engine feed, no production migration or SOC GA.

## Confirmed P0 defect

The original additive control-plane migration `0009_soc_tenant_control_plane.sql` permitted inserting `soc_detections.evidence_state='ANALYST_VERIFIED'` directly, without requiring an active analyst's review decision, an audit event, independently verified source bytes or a durable rationale. The original `soc_incident_detections` table allowed linking such unverified metadata to incidents without human actor attribution or a link audit. These database-level bypasses are unacceptable for enterprise customer incident integrity.

## Implemented controls

**Migration `0014_soc_detection_review_provenance.sql`:**
- Candidate creation is strictly **SOURCE_REPORTED**, review_version 0, with no reviewer fields. Requires a genuine stored event receipt with signed-source attestation, key metadata and active authorized tenant/connector; rejects duplicate source-event + rule + version records.
- Candidate creation appends a same-statement SYSTEM `DETECTION_CANDIDATE_RECORDED` audit. A failed audit insertion aborts the source candidate.
- Decisions are one-way from SOURCE_REPORTED to ANALYST_VERIFIED or REJECTED. Reviewer must be an ACTIVE ANALYST/LEAD_ANALYST/TENANT_ADMIN in the same ACTIVE tenant; review request ID, UTC time, rationale and monotonically increasing version are required. The verification digest must equal the immutable signed source-receipt digest. Rejections cannot claim verified evidence.
- Decisions atomically append reviewer/audit action, and replayed request IDs fail without changing evidence status. After review, immutable source/detection fields and reviewer outcome cannot be rewritten.
- Incident/detection links require a previously ANALYST_VERIFIED same-tenant detection, a non-CLOSED existing incident, fresh analyst identity and a uniquely attributable request ID. Link and audit are committed atomically. Hard deletion or mutation of review/link records fails.
- All of these are D1-compatible SQLite constraints and audit triggers; there is no seeded customer, sample alert, or fabricated verified event.

**Internal `api/_lib/soc-detection-review-service.js`:**
- A cryptographically verified, revocation-aware identity verifier must be supplied by an approved integration layer. The service cannot initialize with an absent verifier and uses `nativeD1.withSession('first-primary')` for current membership, reads and writes.
- A completely **separate, trusted `verifySourceEvidence` implementation is mandatory**. The actual source content must be independently retrieved through an authorized customer-controlled mechanism and its SHA-256 recomputed; only `{verified:true,recomputedDigestSha256:matching-receipt-digest}` permits an analyst-verified write. The callback is **not implemented for real customer feeds**, so no production verified status may be set through this library today.
- Rejection requires documented rationale and active human identity; it does not claim proof.
- Incident links carry verified actor and request IDs; database triggers independently reject links to unverified findings. No auto-escalation, incident mutation, containment action or customer-facing HTTP route is added.

## Critical caveats

The database can ensure a provided verification digest matches an earlier source-attested hash, but **cannot independently prove the analyst fetched real source bytes, customer consent or truth of the detection**. Thus the runtime verifier, authenticated key/source access, analyst runbook, evidence retention and independent customer acceptance remain mandatory. Never use the Jest stub or a function returning true based only on the stored digest as a production verification implementation.

A customer SIEM/EDR may provide raw event data containing sensitive identifiers. No such payload is stored in D1 here; its custody, encryption, access controls, retention, residency, key rotation and lawful processing agreement require a separate approved evidence backend.

**Migration preflight:** `0014` depends on `0009`, `0010`, `0012` and `0013`. Any earlier detections or incident links must be inventoried and reconciled before the migration, because legacy verified rows have no reviewer and links have no actor. Never run schema migrations remotely as a result of merging code.

**Containment remains deliberately disabled**, and a linked candidate alone is not proof of successful remediation or a staffed global SOC.

## Certification requirements

- Exact PR-head Jest and offline SQLite tests for direct fake verification, audited review/reject, actor revocation, wrong tenant, evidence digest mismatch, replay, atomic rollback, immutability and incident linkage; Cloudflare source/build and security CI.
- Isolated native Workerd+D1 rehearsal with real OAuth and provider evidence export, trusted verifier implementation and both active/revoked tenants. Prove no customer telemetry leaks through API response paths, cross-tenant IDOR, failure/retry races or audit rollback.
- Customer-signed scope, named escalation owner, documented service hours and incident handover, support costs, approved production migration and Cloudflare deployment.
- Exact deployed SHA plus raw public homepage canary, independent from this source-only detection patch.

**Decision:** safe for source review and test; NO-GO for customer live SOC and incident certification.
