# CYBERDUDEBIVASH ECOSYSTEM — Cloudflare shared-account ZERO-OVERAGE mandate

**Effective:** 2026-10-22  
**Classification:** Release-control evidence, NOT a claim that the account has spare headroom  
**Applies:** All Workers and Pages Functions, D1, KV, R2, telemetry/logging, and other chargeable resources in the **same Cloudflare billing account**. The SOC is just one workload.

## Production financial rule

**No new variable-usage charge is authorized.** Keep existing subscribed base-plan charges distinct from variable overages. The same included allowances are shared by all eligible workloads in the billing account, not replenished for each platform. Never assume "under limit" based on one Worker's dashboard, its requests, or old billing screenshots.

The routine SOC release job runs `scripts/cloudflare-account-zero-overage-gate.cjs` **before** the Worker domain read, DNS read and Wrangler deployment. If account evidence is absent, stale, incomplete, contradictory, near the included limit, or has unmodeled billable services, the result is **HOLD**. A failed budget gate never permits a release override through documentation-only changes. The operator must record an independently approved source and may not fake a JSON object to make CI pass.

### Reference included usage — verify actual account plan and current prices each cycle

These are conservative October 2026 Workers Paid Standard / D1 / KV / R2 Standard limits, not estimates of the user's actual usage. Data is manually checked against the authenticated Cloudflare dashboard. Pricing and entitlements can vary by product, plan, or contract.

| Account-wide metric | Included monthly amount | Release reserve at 80% | Billable risk |
|---|---:|---:|---|
| Workers dynamic requests and eligible Pages Functions | 10,000,000 | 8,000,000 | More requests charged |
| Workers CPU time | 30,000,000 CPU ms | 24,000,000 CPU ms | Additional compute charged |
| D1 rows scanned/read | 25,000,000,000 | 20,000,000,000 | Unindexed scans can be expensive |
| D1 rows written | 50,000,000 | 40,000,000 | Inserts/updates/deletes charged |
| D1 stored GB | 5 GB | 4 GB | Storage paid beyond allocation |
| KV reads | 10,000,000 | 8,000,000 | Read operations charged |
| KV writes / deletes / list requests | 1,000,000 **each** | 800,000 each | Each action separately billed |
| KV stored GB | 1 GB | 0.8 GB | Stored data charged |
| R2 Standard storage | 10 GB-month | 8 GB-month | Storage charged |
| R2 Class A | 1,000,000 | 800,000 | Higher-cost mutating requests |
| R2 Class B | 10,000,000 | 8,000,000 | Reads charged |
| Queues standard operations (all queues, writes/reads/deletes/retries) | 1,000,000 | 800,000 | All jobs across AI Security Hub and other Workers, charged after allowance |
| Workers Logs written | 20,000,000 events | 16,000,000 | Logs are billed beyond allocation before Dec 2026 |

**Important:** R2 Infrequent Access has no corresponding free Standard-storage allowance. No R2 Infrequent Access, paid Workers AI, paid Vectorize, Queues, paid Workflows, Logpush, Browser Run, Containers, Images/Stream, extra observability or other metered add-ons may be assumed safe solely because they are absent from the table. Any such services require a **separate verified cost model** before deployment. On **December 1, 2026**, Workers Logs/Traces move to new Cloudflare Observability pricing; the current release gate deliberately blocks billing cycles crossing that date until it is reviewed and updated.

Official sources: https://developers.cloudflare.com/workers/platform/pricing/ ; https://developers.cloudflare.com/d1/platform/pricing/ ; https://developers.cloudflare.com/kv/platform/pricing/ ; https://developers.cloudflare.com/r2/pricing/ ; https://developers.cloudflare.com/queues/platform/pricing/ ; https://developers.cloudflare.com/workers/observability/logs/workers-logs/ .

## Predeployment account-wide evidence

1. Confirm the billing account/plan, monthly **billing-cycle start and end (UTC)**, payment method, current billed **overage** and all enabled services. No account IDs or API keys in public repo/issues.
2. In Billing → Usage/Analytics and per-resource dashboard, collect usage for **the entire account**, all Workers and Pages, D1 databases, all KV namespaces, R2 buckets (including storage class), Worker Logs and all paid add-ons. Count D1 **rows scanned**, not merely query count.
3. Calculate **used in current cycle**, **conservative forecast remaining**, and **headroom** for every modeled metric. The release guard independently tests the greater of the operator's forecast and **1.25× current elapsed-cycle usage pace** for counters; storage GB-month **adds accrued-to-date usage and the estimated additional billing quantity for the remaining cycle** (not just the larger quantity). Require full-cycle total **≤80%** of each included allowance.
4. Record an operator approval reference and the SHA-256 of a **private** evidence package (dashboard-export/signed receipt). Screenshot hashes are not authenticated automatically; a human reviewer must verify the evidence.
5. Populate the private JSON from `docs/runbooks/templates/CLOUDFLARE-ACCOUNT-WIDE-BUDGET.template.json` in **private operator storage**. This repo's template is deliberately invalid. `reviewedPlatforms` must cover the entire Cloudflare account; a platform-specific estimate is prohibited.
6. Put the completed JSON in the protected **GitHub environment secret** `CDB_CF_ACCOUNT_BUDGET_ATTESTATION` (or approved local operator environment); avoid adding it to public repo, logs, comments, Pages assets, or customer intel reports. Its account SHA-256 binding must correspond to the same private `CLOUDFLARE_ACCOUNT_ID` already used by Wrangler.
7. Capture no older than **2 hours** before the operator release. Data may be outdated before the deploy if real traffic spikes; the operator must recheck if necessary. The gate outputs **only HOLD reason codes**.
8. For any missing metric, unexpected paid product, unapproved add-on, impending overage, unknown billing cycle, or absent budget approval: **HOLD** and reduce workload before considering another release.

**This is not a billing hard cap or a guarantee of future zero charges.** Cloudflare Paid can accumulate usage charges after a passing preflight if traffic surges, if other platforms change, or if a metered service is missed. Use Cloudflare Billing alerts and ongoing account-level monitoring; reduce high-cost operations, use static caching where feasible, and avoid increasing cron/polling frequencies. Run account-wide usage checks through the month and before every authorized deployment.

## Cross-platform source inventory (NOT a live Cloudflare account usage report)

Read-only GitHub configuration inspection dated 2026-10-22 identified the following workloads whose runtime usage **must be included in the one account-wide evidence package**:

| Platform | Confirmed source-level Cloudflare resource configuration | FinOps implication |
|---|---|---|
| SENTINEL APEX SOC `cyberdudebivash-blog` | Worker, every-30-minute Cron, D1 `sentinel-apex-core`, R2 `sentinel-apex-premium-reports`, service binding | Account-wide Worker CPU, D1 read scans, R2 operations, and sampled logs |
| SENTINEL APEX AI Security Hub `cyberdudebivash-security-hub` | Worker, D1, KV, R2, **Queues** `scan-jobs` producer/consumer and a service binding | Count Queues at **operations**, not messages; each successful message commonly uses write/read/delete operations; retries add reads |
| SENTINEL APEX Threat Intel (example `sentinel-revenue-engine`) | Multiple Worker configs, KV, D1, multiple Cron triggers, additional Workers elsewhere in repo | Shared requests/CPU/KV/D1 plus all Cron events across the account |
| NILACHALA `nilachala-edge` | Worker with observability enabled; optional **SQLite Durable Object visitor ledger** in distinct visitor configuration | All page/visitor Workers Logs count toward shared allowance; if visitor DO is actually provisioned, explicitly cost-model DO requests, duration and storage before signing attestation |

**These are source bindings, not confirmation they are deployed or associated with the identical billing account.** The authorized owner must reconcile all active Cloudflare resources (including hidden/preproduction Workers, alternate zones, retired deployments, and add-ons) against actual billing dashboards. **The AI Security Hub's Queues are an identified billable service and therefore included in the budget model.** A live Durable Object, Workers AI inference fallback, paid AI Gateway Unified Billing, Vectorize or other unmodeled product blocks release until a separate explicitly reviewed allowance/pricing model exists. Do not mark `unmodeledBillableServicesPresent=false` without verifying them.

## SOC Worker additional guardrails

- `wrangler.jsonc`: retain **the existing every-30-minute cron only**, no increase in frequency or new chargeable bindings without account budget acceptance.
- Set `observability.enabled=true`, `head_sampling_rate=0.1` to **sample 10%** of ordinary Worker logs instead of the default 100%, reducing log-event costs. This is a **tradeoff**: platform sampling can omit some events. **Never use sampled infrastructure logs as the authoritative audit trail for customer SOC activity; use independently authenticated event/evidence receipts.**
- Do not enable new Worker AI/vector database/Containers/Browser Run/Workflows/Logpush/paid R2 Infrequent Access without separate documented cost review. Do not perform live load or stress tests against the Cloudflare production account while pre-revenue.
- No customer-managed SOC traffic or unbounded evidence uploads until tenant isolation, per-tenant quotas and commercial authorization are certified.

## Operator commands (local, no Cloudflare usage)

```powershell
# $env:CLOUDFLARE_ACCOUNT_ID and $env:CDB_CF_ACCOUNT_BUDGET_ATTESTATION
# must be set locally from approved private controls, not printed or committed.
node --test tests-js/cloudflare-account-zero-overage-gate.test.js
node scripts/cloudflare-account-zero-overage-gate.cjs
if ($LASTEXITCODE -ne 0) { throw 'HOLD: Account-wide Cloudflare budget unverified or too close to included limit' }
```

The routine release must then independently pass Worker Domain, DNS conflict, explicit manual-main deployment permissions and eight-route source/build/served HTML parity. A passing cost check **does not** authorize Cloudflare deployment, DNS migration, customer payments, or SOC managed-service availability.

## Operator evidence still missing

**Not verified in this environment:** authenticated account usage/plan, aggregate 2026-10-22 Worker requests/CPU, D1 scan writes/storage, all KV and R2 operations/storage, any paid addons, logging events, current projected bill, charge alerts and environment reviewer enforcement. Until a trusted fresh owner-reviewed account budget report is provided through a private mechanism, **release budget GO remains BLOCKED**.
