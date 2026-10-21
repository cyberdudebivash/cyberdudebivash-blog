# SENTINEL APEX SOC — Phase 3 Incident Integrity Acceptance

**Status:** Source implementation candidate. **Not customer-production ready.**

## Delivered components

- Migration 0010_soc_incident_audit_invariants.sql (dependent on 0009) enforces active-tenant and active-analyst writes, state transitions, version increments, replay protection and incident hard-delete prohibition. Database triggers atomically append audit records; failure of audit insertion rejects the incident write.
- api/_lib/soc-incident-service.js implements create, get, list and optimistic update with tenant predicates. Each entrypoint requires an injected identity verifier and resolves current membership against D1 before any action. No role or audit actor from user input is accepted.
- Jest tests target verifier failure, revoked or absent tenant membership, read-only callers, cross-tenant reads, replay and version error behavior, SQL scoping and projection hygiene.
- Offline Python SQLite tests execute both migrations and test trigger integrity, replay, customer isolation, evidence-linked closure and append-only audit.

## Strict deployment blockers

1. **Missing live identity integration.** No production OIDC adapter, JWKS/certificate trust, issuer/audience policy, MFA, session revocation, cookie security or anti-CSRF scheme exists for this new service. A mock verified-identity callback must NEVER be used in customer-facing routes.
2. **No public API route or UI.** No new handler was added to workers/lib/route-table.js, workers/lib/router.js, or public asset navigation.
3. **D1 migration not applied.** Migration 0010 depends on 0009 and cannot be executed on production without verifying current schema state, prior incident data, an authenticated operator, quota impacts and recoverable backup.
4. **No telemetry or customer incident input.** This is a control-plane library. Do not describe tests as real detections, customers, incidents or service delivery.
5. **Containment blocked.** The database rejects entering CONTAINED until a separately authorized, evidence-backed approval system exists.
6. **Customer acceptance and response operations unavailable.** No committed SLA, 24/7 staffed SOC, SOC 2 attestation, approved pricing or verified customer payments.
7. **Evidence closure remains a minimum check.** An associated detection/manifest alone does not prove mitigation quality or integrity of an external evidence artifact. Separate verification, signed evidence custody and SOC runbook acceptance are required.

## Review and certification

- Confirm all exact-head CI checks pass, including offline SQLite migration execution and full Jest suite.
- Complete an isolated local Cloudflare D1 migration rehearsal, negative authorization exercises and real Workerd runtime probe with an appropriately verified OIDC provider before any customer route is introduced.
- Validate encrypted evidence storage, retention, legal holds, deletion and data residency.
- Verify protection under concurrent updates, revoked identities, failed D1 writes, failed signing keys and replayed requests.
- Document customer support operating hours and incident escalation before offering a subscription.

## Explicit non-effects

This pull request does not change DNS, Cloudflare Worker routes or deployed versions, schedules, payments, customer records, canonical links, branding, public telemetry, or production D1 state. Rollback of this source-only change is via git revert. Schema rollback after any future authorized deployment requires a separately certified backup and restore procedure.

**GO:** internal code review and tests.

**NO-GO:** paid customer operations, tenant sign-in, SOC production release and hostname cutover.
