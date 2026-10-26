# SENTINEL APEX SOC — Worldwide managed customer GA operational certification

**Date:** 26 October 2026  
**Current release decision:** **NO-GO**. This is a release-control runbook, **not** evidence of a deployed or independently audited global SOC. `SOC 2-aligned` is not SOC 2 Type I/II certification.

## 1. Product and legal separation

- **Scoped SOC Readiness & Detection Engineering Assessment** is an enquiry, quote and manually delivered, explicitly authorized assessment, governed by `scripts/soc-readiness-delivery-gate.cjs`. Signed rules of engagement, evidence-handling agreement, named human reviewer, tax/payment reconciliation and customer acceptance are required for every engagement. No 24/7 monitoring, credential collection or active testing without authorization.
- **Managed SOC subscription/continuous monitoring** is *not approved for sale/onboarding*. No product launch, live customer ingest, new customer Cron, D1 migration, permanent deployment or automated alert delivery may be enabled solely because a checklist or CI passes. `api/intel/customer-assurance.json` explicitly reports `managed_soc_release.release_status=NOT_CERTIFIED`.

## 2. Live production evidence required

A named technical/release owner must privately witness and retain immutable hashed evidence for all **21** controls in `scripts/soc-commercial-ga-gate.cjs`. The complete exact control IDs are exported from its `CONTROLS` constant; the list is deliberately exhaustive and not satisfied by green CI. The evidence must cover:

**Delivery and product truth:** reviewed immutable release SHA and Worker version; HTTPS and exact byte/hash parity at both `soc.` and `blog.` hostnames; source and published-report recency verified independently; at least five real data-bearing source tasks in the current ingestion run; zero unsupported CVSS, exploitation, IOC, uptime, SOC 2, revenue or staffing claims.

**Identity and tenant security:** authorized customer/principal/role with IdP JWT/MFA/session revocation; D1 tenant-level isolation including negative IDOR/search/export/aggregation checks; source-owner consent, named telemetry provenance, rate limiting, CORS/CSP, audit logs, evidence tamper/fault injection and service-specific retention/deletion.

**SOC operations:** real permitted event → detection → case → approved escalation → closure and reviewer receipts; immutable incident/evidence history; bounded native D1 index/CPU costs; durable outbox per-channel state, crash/ambiguous-send handling, dead-letter and idempotency strategy; non-synthetic recipient-delivery canary; authenticated source replay and opt-out controls. A zero-queue successful job is never a customer delivery canary.

**Business and global operations:** staffed shift/support rota and customer-specific SLA, on-call escalation coverage, response drills, backup/restore tests, documented RTO/RPO if contracted, legal seller identity, jurisdiction/data-processing terms, privacy/cross-border transfer rules, commercial authorization, first signed customer pilot acceptance, traceable invoice/settlement/fulfillment, and documented external security review.

**Account-wide financial safety:** authenticated shared Cloudflare account evidence for Worker/CPU/D1/KV/R2/Queues/observability/other enabled metered products, >=20% forecast reserve, owner-approved attestation within 2 hours, and a future overage risk policy. Run the existing `scripts/cloudflare-account-zero-overage-gate.cjs` using the private approved attestation. A snapshot check is not a guaranteed billing hard cap.

**Release and rollback:** repo branch/environment rules and named approvers; authenticated owner confirmation; exact Git/Worker version match and both-host live parity; tested reversible rollback and negative customer canary. No stale-source bypass, synthetic heartbeat, hidden manual link or unapproved DNS mutation.

## 3. Private operator-only commercial GO/HOLD workflow

1. Review `main` branch rules and protected `production` environment owner approvals without disabling authorized CTI publication.
2. Rehearse all 21 checks in a safe staging/authorized pilot environment; collect nonpublic immutable receipts with hashes and timestamps, **never secrets or raw customer telemetry in GitHub**.
3. Author a private manifest matching `sentinel-soc-managed-ga/v1`. It must identify `MANAGED_SOC`, `production`, both hostnames, actual deployed Git SHA and Worker version, each required control with `PASS/privateEvidenceRef/evidenceSha256/collectedAt/releaseCommit`, a real signed accepted pilot, and final accountable proprietor approval.
4. Run from the trusted operator machine:

```powershell
Set-Location "C:\CDB\repos\cyberdudebivash-blog"
node scripts/soc-commercial-ga-gate.cjs "C:\Private\SOC\managed-ga-evidence.json"
if ($LASTEXITCODE -ne 0) { throw "MANAGED SOC GA HOLD — no onboarding" }
```

5. **A passing offline manifest means evidence metadata are complete, not that remote Cloudflare/customer/provider evidence was independently inspected.** Obtain separate human witnessed inspection of cited original evidence, production SHA, tenant-fault canary, real recipient receipts and billing metrics. Use the normal operator-approved manual-only Worker release process, finance gate and dual-host postdeployment parity. Do not publish the private manifest.
6. Have the authorized customer sign actual pilot/delivery acceptance; separate customer legal order, SLA and payment/settlement reconciliation must be completed before any paid service. Only then can a human business owner authorize a distinct managed-GA transition with its own reviewed feature/offer change.

## 4. Failure response

- **Source/freshness blocked:** advertise *last verified publication* with its timestamp; suppress fresh/live claims, preserve content and dedup data, investigate source rights, NVD/CISA schema and Worker release parity. No fabricated new threat.
- **Identity/IDOR/evidence leak:** disable affected customer route/connector via preapproved kill switch, preserve minimum incident forensics, revoke sessions/secrets by authorized procedure, notify under actual contract/law, and investigate before reconnect.
- **Outbox or webhook ambiguous:** quarantine, avoid automatic resend without provider acknowledgment, preserve durable intent and operator review.
- **Cloudflare budget headroom unverified:** block new workload/production feature releases; do not silence invoices or assume included plan is a hard stop.
- **Data corruption/failed migration:** stop writes, confirm exact Worker/D1 backup point, execute practiced rollback with operator signoff, collect read-only failure evidence.
- **Payment or fulfillment discrepancy:** halt activation of affected paid entitlement, reconcile receipt in merchant dashboard, do not claim a paid customer based on a UI success page.

## 5. Audited blockers as of 26 October 2026

Source last report Oct 25 19:54 UTC, latest checked run Oct 26 00:36 UTC had **2/35** nonempty sources, **0** reports, 33 empty. Multiple freshness/drift workflows failing. Last live edge Worker release SHA, real source/public parity, account-wide Cloudflare allowance, deployed D1 schemas, staffing, customer consent/acceptance, alert deliveries and seller payment/fulfillment remain **unverified** here. Native routes are not sufficient to certify worldwide managed SOC service. Preserve a **NO-GO** decision until receipts are independently witnessed.

Related open blockers: #360 (tenant/pilot), #418 (durable channel receipts), #432 (alert config), #404 (shared-account FinOps), #433/#434 (drift/freshness), #400 (governance), #480 (commercial truth).
