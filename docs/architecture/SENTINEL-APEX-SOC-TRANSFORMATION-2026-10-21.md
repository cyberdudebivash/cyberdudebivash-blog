# ADR: SENTINEL APEX SOC — Enterprise transformation

**Date:** 2026-10-21  
**Status:** Proposed / Phase 0 implementation in review; NOT customer-production certified  
**Current production:** \`blog.cyberdudebivash.in\` (Cloudflare Worker); canonical intelligence corpus and Blogger publisher preserved  
**Target public hostname:** \`soc.cyberdudebivash.in\` (NOT ACTIVE by this change)  
**Operating constraint:** No paid infrastructure additions, no new billing authority, no unsanctioned DNS/deployments, no synthetic customer/incident evidence.

## 1. Decision and nomenclature

Build SENTINEL APEX™ SOC as an **evidence-driven security operations platform** with an initial service-led offer, and incrementally reuse the existing CTI platform. "SOC" means **Security Operations Center**. "SOC 2" means the AICPA attestation framework, is distinct from an SOC product, and cannot be claimed as achieved. Existing truthful "SOC 2-aligned, not certified" statements stay in place until an independent audit.

The current research/intelligence website is not yet a validated, customer-isolated managed SOC. Do not rebrand its intelligence counters as incidents, monitored endpoints, active tenants, MTTR or 24/7 staffing. Do not promise revenue, Fortune 500 procurement eligibility, SOC certification or 24/7 response.

## 2. Verified starting architecture

- The Worker \`workers/entry.js\` delegates to \`workers/lib/router.js\`; \`workers/lib/route-table.js\` resolves dynamic API handlers and explicit asset rewrites. \`wrangler.jsonc\` binds existing D1, R2 and the SENTINEL_GATEWAY service and currently owns the \`blog.\` custom domain.
- \`scripts/build-cloudflare-assets.js\` uses an allowlisted \`dist-public\` static bundle. Never publish repository-private state or credentials.
- CTI intelligence generation and Blogger syndication are independent pipelines. Feed/report freshness requires public read-after-write evidence; successful scheduled jobs are not delivery acceptance.
- An internal SOC workbench (\`workbench.html\`, \`api/v1/workbench/*\`) exists, with \`ANALYST_KEYS\` authentication and Redis-backed investigations/cases. Its prior release note explicitly retained live-runtime and route-verification limitations.
- Current workbench paths are NOT customer-multi-tenant safe: data selectors, indices, and dashboard allow cross-analyst access inside an internal trust boundary. Adding a tenant selector in HTML or a JWT alone does not solve this.

## 3. Production architecture (target state)

\`\`\`text
Public DNS / Cloudflare WAF / TLS / rate limiting
  ├─ soc.cyberdudebivash.in  → current Worker static public offering + source-linked CTI
  └─ protected customer operations routes → Worker authn/authz enforcement
      ├─ Customer identity: OIDC / scoped API credentials, short-lived sessions, MFA for privileged users
      ├─ Account/tenant authorization: subject-tenant-role-resource-action, fail closed
      ├─ Intake: allowlisted telemetry connectors, signatures, provenance, budgets, replay defense
      ├─ Normalizer: canonical event schema, source/ingest time, tenant ID, deduplication
      ├─ Detection: versioned Sigma/rule queries, severity/confidence, evidence references
      ├─ Cases: tenant-isolated incidents, notes, approvals, workflow state, analyst assignments
      ├─ Evidence: hash-linked immutable manifests, provenance, retention/deletion controls
      ├─ CTI: existing source-attributed intel and CISA KEV enrichment, never auto-enforce drafts
      ├─ Audit: append-only actor/tenant/action/resource/time/result records and export
      └─ Operations: verified health, outage/degraded-state presentation, operator-owned recovery
\`\`\`

Existing Cloudflare D1 can host the **bounded control plane**, subject to capacity and residency review. R2 can store encrypted evidence artifacts under tenant-specific key prefixes and authorization enforced server-side, subject to binding and budget review. Large-scale raw telemetry / long retention is **not** approved for D1 or R2 by this ADR. A scalable ingestion/analytics store must be selected and costed only after real volumes and requirements are measured. The Cloudflare edge itself does not constitute a staffed monitoring center.

## 4. Required data and authorization invariants

Every customer-scoped table/query must contain a server-derived \`tenant_id\`. All reads, writes, search, aggregate metrics, bulk export and async jobs must bind tenant from authenticated identity, **never from a client-provided query/body field**. No global lists or direct-object fetches without tenant predicates.

Baseline logical entities:

| Entity | Minimum attributes |
| --- | --- |
| tenant | id, legal_name, status, retention_policy, region_policy |
| principal | id, tenant_id, identity_provider_subject, role, status |
| connector | id, tenant_id, type, config_reference, approved_scope, status |
| event | id, tenant_id, source_id, event_time, received_time, digest, normalized_payload_ref |
| detection | id, tenant_id, event_ref, rule_id, rule_version, evidence_ref, confidence |
| incident | id, tenant_id, severity, workflow_state, owner, created_at, updated_at |
| evidence_manifest | id, tenant_id, incident_id, object_digest, chain_of_custody, retention_until |
| audit_event | id, tenant_id, principal_id, action, resource, timestamp, outcome, request_id |

Enforce on EVERY entrypoint:
- Tenant-bound RBAC / ABAC, per-action scopes, privileged actions with step-up and two-person approval where relevant.
- Cryptographically secure credential issuance, rotation, revocation, explicit expiration, no storage of clear credentials in browser storage or Git.
- Rate limits that remain protective if Redis is unavailable; \`ANALYST_KEYS\` is only suitable for the existing internal phase, not public enterprise identity.
- Row/object isolation and negative tests for IDOR, tenant tampering, cross-tenant aggregation, search/filter, export, async delivery and billing entitlements.
- Encryption in transit and at rest, tenant-aware object IDs, signed evidence manifests, immutable audit trails, retention/deletion and legal hold.
- Evidence integrity: normalized IOCs and alerts MUST preserve authoritative sources and labels for \`observed\`, \`reported\`, \`confirmed\`, \`hypothesized\` and \`unknown\`. "Exploited in the wild" requires a real qualifying source; do not infer from a CVE mention or news excerpt.
- No automated containment, scanning, external response action, or SIEM rule deployment without explicitly scoped customer authorization and rollback.

## 5. Lifecycle and delivery model

\`collect → validate → normalize → correlate → triage → investigate → decide → customer approval (when applicable) → contain/remediate (authorized) → verify → close → preserve evidence → improve detection\`.

An incident must have real telemetry, a tenant and recorded timestamps. Never display synthetic alert queues, live incident counts, customer logos, MTTA/MTTR or signed SLAs.

Time objectives are **SLO design targets only**, not binding SLAs: monitored collection lag, triage queue age, alert false-positive rate, detection content acceptance and response drill pass rate. Formal targets must follow telemetry baselines, staffing evidence and executed customer contracts. Align incident-response playbooks to NIST SP 800-61 Rev.3 and cybersecurity risk decisions to NIST CSF 2.0.

## 6. Commercial launch sequence

**Phase 0 — Present change:** create a non-indexed, unlinked SOC capability preview and preserve production unchanged; publish this ADR and an executable DNS runbook. No customer or payment state changes.

**Phase 1 — Foundation (blocking):** close CTI freshness and evidence-quality failures; verify workbench route security, production \`ANALYST_KEYS\`, dependency health, CSP/CORS, secret handling and authenticated live tests. Establish audit logging and a clear truth-bound status model.

**Phase 2 — Customer control plane (blocking):** tenant/principal model, OIDC MFA, tenant isolation migration and negative tests, D1/R2 authorization, retention, backups/recovery, audit export, accessibility and security assessment.

**Phase 3 — Real SOC pilot:** onboard one written-authorized pilot tenant; ingest limited opt-in telemetry; demonstrate real detection-to-incident lifecycle, analyst response, escalation and recoverability using documented runbooks. Validate connectors and ingestion costs before scaling.

**Phase 4 — Commercial GA:** signed scope/SOW/DPA, support schedule, SLA where agreed, lawful processing, pricing authority, verified checkout or invoicing, entitlement/delivery acceptance, incident reporting, documented offboarding, SOC staffing plan, referenceable consent-based results. Only then claim commercial SOC production.

**Phase 5 — Hostname transition:** provision the new \`soc.\` hostname and run dual-domain smoke and security checks, then switch canonical URLs/feeds/links, preserve old-path redirects and monitor Search Console. See \`docs/runbooks/SOC-DOMAIN-CUTOVER.md\`. No DNS mutation before gates pass.

## 7. Revenue-first offer design (not a promise or activated checkout)

Sell a **scoped SOC Readiness + Detection Engineering pilot** before selling unstaffed "24/7 Managed SOC":
1. Evidence-backed 2–4 week fixed-scope readiness assessment, telemetry and alert-coverage mapping.
2. Detection engineering / CTI integration pilot: rule drafts, tenant-approved testing, evidence-linked gap report, handover.
3. Optional retainer only with clearly contracted hours, incident escalation procedures and documented operator capacity.

No public price or checkout is enabled by this change. Pricing should be quoted after cost, delivery-capacity and legal-scope verification. Enterprise logos, customer adoption and savings claims require evidence and permission.

## 8. Go/no-go and rollback

- **GO preview branch:** required files compile/parse, no live side effects, contracts and asset allowlist tests pass.
- **NO-GO hostname:** any unfinished tenant isolation, missing audit logs, failed freshness integrity, stale telemetry masquerading as live, unapproved spend, unverified domain ownership, failed domain SSL, untested redirect/canonical plan, absent customer acceptance or missing rollback.
- **GO paid pilot:** signed authorization, 1 pilot only, clear scope and retention, live telemetry verified, delivery capacity and cost proven, no fabricated evidence.
- Roll back all preview changes by reverting the reviewed PR; existing \`blog.\` route remains unchanged. For future DNS changes, preserve old route and immutable rollback version until new domain is certified.

## 9. Open risks and owners

| Priority | Evidence / risk | Closure evidence |
| --- | --- | --- |
| P0 | HTTP 429 Blogger public probe can fail while generator recovery is green | Public read-after-write success and separately classified transient rate limiting |
| P0 | Global Redis indices and analyst query allow internal cross-analyst visibility | Tenant-negative test suite and customer-bound authorization |
| P0 | Existing intelligence cards can conflate article mention with verified exploitation, and carry escaped HTML snippets | Source-specific adjudication and data-quality checks across corpus |
| P0 | Current \`blog.\` custom domain is hardcoded in Wrangler and multiple public metadata/CSP | Two-host staging and reviewed complete URL/metadata inventory |
| P1 | Internal auth rate limiter degrades open on Redis outage | Edge-enforced backup limiter and tested failure modes |
| P1 | Legacy public branding includes unsupported legal form / retired social links in rendered material | Accurate legal entity, approved social identities, production build verification |
| P1 | No proof of 24/7 SOC staffing, external audit, global data residency, contract acceptance | Executed contracts, audited controls where required, staffing and data processing review |

## 10. Explicit non-changes

No DNS changes, Worker route switch, payment activation, new infrastructure, D1 migration, SOC data creation, telemetry import, customer-account opening, auto-containment, autonomous response or production deployment are part of this PR. All changes are source-controlled and reviewable.