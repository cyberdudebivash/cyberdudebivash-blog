# Intel Factory — Customer Release Certification

## Tranche 3 (2026-10-01): #314 live certification + revenue activation readiness

### #314 in production: **PASS**

#314 merged as `726ebb9f` and was deployed by the drift reconciler.

| Check (live, read-only) | Expected | Actual | Result |
|---|---|---|---|
| `POST billing?action=create-intent` | 410 `MANUAL_PAYMENT_RETIRED`, no UPI/bank data | 410, message only | PASS |
| `POST billing?action=create-razorpay-order` | 503 with email fallback, no config details | 503 "Online checkout is temporarily unavailable. Email bivash@cyberdudebivash.com to purchase." | PASS |
| UPI ID / QR / `create-intent` on pricing, buy, faq, payment-flow, api pages | 0 | 0 | PASS |
| Premium catalog | 200 | 200, `count: 0` | PASS |
| IOC rebalance after a post-merge pipeline run (#4175, dispatched 09:00Z) | `type_shares` mix | `generated 09:01:27Z`, healthy, 600: url 224, ipv4 136, domain 120, sha256 120; HIGH 535 / MEDIUM 65; `items: []` | PASS |
| Razorpay webhook | rejects unsigned / forged | 400 / 400 | PASS |

Before #4175 the live feed was the pre-merge 07:00 build: url 459, ipv4 139, domain 1, sha256 1.

### This tranche (repository; pending merge and deploy)

- **Razorpay:**
  - server-side payment confirmation before any grant (captured, order, plan amount, currency);
  - 202 for authorized-but-uncaptured payments;
  - fail-closed 503 on lookup outage;
  - webhook amount checks;
  - expired-order recovery from server-set order notes;
  - API-plan refunds recorded once;
  - post-payment screens reflect the real result and point to the API dashboard.
  - 11/11 mutations detected.
- **Premium store:**
  - `config/premium-catalog.json` lists 4 human-approved products (reviewer BIVASH NAYAK, APPROVE, review hash bound to artifact) at INR 1,999 each (operator decision);
  - `scripts/publish-premium-reports.js` publishes through the production endpoint.
  - The download entitlement check was previously untested and is now tested (P1 mutation now detected).
- **Seats:** "Seats: 5 included" (`api.html`) and "Multi-seat SOC access" (`pricing.html`) removed; tests guard.
- **Cost:**
  - IOC feed hard limit 600;
  - live widget polling 60 s → 15 min, paused when hidden;
  - `cost-guardrails.test.js` added (5/5 mutations detected);
  - `CLOUDFLARE-COST-GUARDRAILS.md` and `CLOUDFLARE-COST-IMPACT-REVIEW.md`: **ZERO MATERIAL INCREMENT**, no new resources;
  - Cloudflare plan and usage NOT VERIFIED (token scope).
- **Pending manual payments:** the Redis review queue is not readable from this environment (no Upstash credentials). Keep `submit-payment` and admin review until the operator confirms the queue is empty.

## Tranche 2 (2026-10-01): #310 production certification + evidence-only IOC engine

### Phase A — PR cyberdudebivash/cyberdudebivash-blog#310 in production: **PASS**

| Field | Value |
|---|---|
| Merge commit on `main` | `af83f6d2` (squash of #310) |
| Deploy run | `cloudflare-production-deploy.yml` run #97, success |
| Production Worker version | `8ad19eef-ad90-4bbe-8bc2-eea11fa5b0cf` (#87), deployed 2026-09-30T18:16:24Z |
| Rollback identity | `ef41a58d-d900-420b-bd45-d3aa053db42e` (#86, the pre-#310 version) |
| Follow-up deploy fix | PR cyberdudebivash/cyberdudebivash-blog#311 (build synthesises CVE pages missing at build time). Runs #98/#99 had failed the link gate; runs #107–#111 green through `main` @ `1f2e06b6` |

| Live check (read-only, blog.cyberdudebivash.in) | Expected | Actual | Result |
|---|---|---|---|
| `api/intel/live.json` CVE-2026-32202 | CVSS 4.3, NVD source, KEV true | 4.3 / NVD / true | PASS |
| Records still served at the anomalous 9.5 | 0 | 0 | PASS |
| `posts/cve-2026-86218.html` correction notice | 1 | 1 | PASS |
| Homepage `VERIFYING` | 0 | 0 | PASS |
| `/runtime-state.js` | 200 | 200 | PASS |
| `pricing.html` legacy seat/latency/Elastic claims | 0 | 0 | PASS |
| Legacy audience/pre-disclosure claims on the sampled post | 0 | 0 | PASS |
| `intelligence.html` unsupported claims | 0 | 0 | PASS |
| Live assets vs locally validated build | byte-identical | sha256 equal | PASS |
| Team-tier canary `action=iocs&format=stix` | bundle | not executed | **BLOCKED** (no customer API key in this environment) |
| Razorpay test-mode purchase | entitlement granted | not executed | **BLOCKED** (no test credentials) |

The headless-browser run against live production failed TLS through the environment proxy (`ERR_CERT_AUTHORITY_INVALID`). TLS verification was **not** bypassed. Instead, byte identity with the locally browser-tested build was proven.

### Phase B — evidence-only IOC engine: **PASS (production)**

**Release record**

| Field | Value |
|---|---|
| Merge | PR cyberdudebivash/cyberdudebivash-blog#312 → `main` @ `b26ac593` |
| Deploy | `cloudflare-production-deploy.yml` run #114 (success) |
| Worker version | `9af2c891-ecfe-492d-beb4-032aba9f5483`, deployed 2026-10-01T05:51:56Z |
| Rollback identity | `51952766-b253-4b7c-bf9e-a6f44422960d` (pre-#312 version) |

**Live checks (read-only, 2026-10-01 ~05:55Z)**

| Check | Expected | Actual | Result |
|---|---|---|---|
| `/api/intel/iocs.json` feed status | `healthy` or `degraded`, count > 0, `items: []` | `healthy`, 600, `[]` | PASS |
| Public summary carries indicator values | 0 | 0 of 600 | PASS |
| `/api/intel/threat-graph.json` IOC nodes | 0 | 0 (`stats.iocs` 0) | PASS |
| `/data/ioc-feed.json`, `/data/ioc-store.json`, `/config/ioc-sources.json` | 404 | 404 / 404 / 404 | PASS |
| `action=iocs` / `action=ioc` without a key | 401 | 401 / 401 | PASS |
| `api.html` retired claims | 0 | 0 | PASS |
| Regressions: homepage; CVE-2026-32202 CVSS / KEV | 200; 4.3 / true | 200; 4.3 / true | PASS |
| Team-key `action=iocs&format=stix` | bundle | not executed | **BLOCKED** (no customer key in this environment) |

The live feed was regenerated at merge time and is all HIGH confidence. By type: url 457, ipv4 83, domain 53, sha256 7. The feed is capped at 600 and ordered by confidence, then recency, so freshly confirmed online URLs crowd out older hashes. A per-type share of the cap is the proposed follow-up.

**Repository results (pre-merge)**

- Design and dependency graph: `docs/architecture/IOC-INTELLIGENCE-PIPELINE.md`.
- Source policy: `docs/intelligence/IOC-SOURCE-POLICY.md`.
- Audits: `docs/audits/IOC-INTELLIGENCE-QUALITY-AUDIT.md`, `docs/audits/IOC-COMMERCIAL-READINESS.md`.
- **Live refresh (2026-10-01):** 4/4 sources healthy; 600 indicators published (url 237, domain 148, sha256 150, ipv4 65; HIGH 496, MEDIUM 104), each with a source record URL. Production currently serves 0.
- **Graph cleanup:** 911 legacy unproven IOC nodes are removed from every served graph, search and detail path, and from the public `threat-graph.json`.
- **STIX:** 601 objects parse with OASIS `stix2` (strict); 0 `stix2-patterns` errors.
- **Tests:** 56 engine + 11 real-handler + 2 build tests. All 7 mandated negative controls are refused at every layer, and 17/17 safeguard mutations are detected.
- **Cost:** no new Cloudflare resources, bindings or secrets.

**Post-deploy checks (read-only):**
1. `curl -s https://blog.cyberdudebivash.in/api/intel/iocs.json | jq '.feed_status.status, .feed_status.indicator_count, (.items|length)'` → `"healthy"` or `"degraded"`, > 0, `0`.
2. `curl -s https://blog.cyberdudebivash.in/api/intel/threat-graph.json | jq '[.nodes[]|select(.type=="IOC")]|length'` → `0`.
3. `curl -s https://blog.cyberdudebivash.in/data/ioc-feed.json -o /dev/null -w '%{http_code}'` → `404`.
4. With a Team key: `GET /api/v1/intel?action=iocs&format=stix&limit=5` → `stix.type == "bundle"`, every `pattern` without `file:value`.

### D1 migrations applied (2026-10-01): **DONE**

Applied on operator instruction to D1 `sentinel-apex-core` (`dfdbdd96-9054-46d6-a434-3de0c56fccfb`) through the authenticated Cloudflare API.

**Pre-flight**
- The database held only `_cf_KV` and had no `d1_migrations` table.
- All 8 migration files were reviewed: they are additive only (`CREATE … IF NOT EXISTS`, plus two `ADD COLUMN` statements in 0007), with no `DROP`, `DELETE` or `UPDATE`.
- All 8 were dry-run in order against an empty SQLite database first.

**Restore point:** Time Travel bookmark `00000102-00000000-000050f7-b2f049371a8c4a367199b147c780928a`, taken at 2026-10-01T06:17:05Z.

**Execution**
- Each migration was sent with a SHA-256 of its comment-stripped SQL and verified inside the executor before running.
- Each was recorded in `d1_migrations` (wrangler's own schema), so `wrangler d1 migrations list` reports them as applied.
- Applied between 06:20:28Z and 07:13:22Z.

**Post-state:** 37 application tables, 41 indexes and 8 recorded migrations, matching the dry run.

**Live check**
- `GET /api/v1/premium-intelligence?action=catalog` → **200** `{"reports":[],"count":0}`. It was 500 before.
- The catalog is empty because no certified report is listed yet. R2 `sentinel-apex-premium-reports` is still empty.

**Next operator step:** list certified reports in `premium_report_catalog` and upload their artefacts to the existing R2 bucket.

**Rollback:** `npx wrangler d1 time-travel restore sentinel-apex-core --bookmark 00000102-00000000-000050f7-b2f049371a8c4a367199b147c780928a`.

### Manual UPI / bank transfer retired (2026-10-01, operator decision): **DONE in repository, pending deploy**

The operator chose to retire the flow immediately, knowing Razorpay is **not** configured in production. Live `create-razorpay-order` returns 503 `RAZORPAY_UNAVAILABLE`, so until the Razorpay secrets are set the only purchase path is email to bivash@cyberdudebivash.com.

| Surface | Change |
|---|---|
| `POST /api/v1/billing?action=create-intent` | **410 `MANUAL_PAYMENT_RETIRED`**. No intent, UPI ID or bank details are issued and nothing is written to Redis. The action stays routed, so clients get an explicit answer rather than `INVALID_ACTION`. |
| `submit-payment`, `status`, admin review | Unchanged and marked deprecated. Intents issued before retirement (24 h TTL) can still be submitted and reviewed, so nobody who already paid is stranded. Remove them once the admin pending queue is empty. |
| `create-razorpay-order` unavailable message | No longer redirects to the manual flow; points to email. |
| `pricing.html` and `payment-flow.js` (used by `buy.html` and `api-dashboard.html`) | Step 1 goes straight to online checkout. The UPI QR, UPI ID, bank details and "I've Paid — Submit UTR" are replaced by a retirement notice. |
| `faq.html` (including FAQPage JSON-LD), `buy.html`, pricing FAQ | The copy no longer offers manual UPI/bank transfer. It explains the retirement and how earlier payments are handled. |

**Evidence**
- `api/v1/__tests__/manual-payment-retirement.test.js`: 13 tests through the real router. Negative controls: restoring any of the 5 changed files fails the suite.
- Headless Chromium on the built `pricing.html` and `buy.html` with the production-equivalent 503: no `create-intent` request, the retirement notice is shown, the "Online checkout unavailable — email to purchase" toast appears, and there are 0 page errors.
- Full Jest CI: 2,883 passed.

**Operator follow-ups**
1. Set Worker secrets `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` and `RAZORPAY_WEBHOOK_SECRET` to restore self-serve purchases.
2. Clear any pending manual submissions in the admin queue, then remove the deprecated `submit-payment` path.

### Operator decisions required (not executed; no production mutation from this environment)

| Item | Evidence | Exact operator action | Validation |
|---|---|---|---|
| **Premium store / D1 (ICF-P1-008)** — migrations DONE 2026-10-01 (see above); catalog content and R2 artefacts still pending | Production D1 `sentinel-apex-core` (bound as `DB` in `wrangler.jsonc`, `migrations_dir: ./migrations`) contains no application tables, only `_cf_KV` (verified via the authenticated Cloudflare API, Phase A). Migrations `0001`–`0008` were never applied. This also disables watchlists, notifications, SIEM connectors, hunting and detection performance. R2 `sentinel-apex-premium-reports` exists and is empty. | 1. Review `migrations/0001…0008_*.sql`. 2. `npx wrangler d1 migrations list sentinel-apex-core --remote`. 3. `npx wrangler d1 migrations apply sentinel-apex-core --remote`. 4. Upload certified artefacts to the existing R2 bucket. No new database or bucket is needed. | `GET /api/v1/premium-intelligence?action=catalog` → 200; `wrangler d1 execute sentinel-apex-core --remote --command "SELECT name FROM sqlite_master WHERE type='table'"` lists the migration tables |
| **Manual UPI (ICF-P1-001)** — RETIRED 2026-10-01 (see above) | `OPERATIONS.md` L73 says: "Do not enable manual payment fallback". Yet the `pricing.html` UPI QR/UTR flow and `api/v1/billing-legacy.js` `create-intent`/`submit-payment` are live. | Decide one: **(a)** retire the manual UPI path (remove the UI and disable the two actions; deploy), or **(b)** amend `OPERATIONS.md` to authorise it with a manual-review SLA. The financial behaviour was not changed here. | Pricing UI and API behaviour match the written policy |
| **Legal entity name** | The repository uses "CYBERDUDEBIVASH PRIVATE LIMITED" (16,502 occurrences) and "CyberDudeBivash Pvt. Ltd." (199 occurrences, mostly `vendor/`, `posts/` and root pages). No CIN or registration document is present to decide which is correct. | Confirm the exact registered name (as on the MCA/ROC certificate). Legal representations were left unchanged. | A single canonical name across footer, terms and invoices |

---

## Tranche 1 (2026-09-30): PR #310

**Release candidate:** branch `claude/amazing-thompson-h8ukxi` (PR cyberdudebivash/cyberdudebivash-blog#310), 7 code commits on top of `main` @ `5c8ba3dd`
**Certified:** 2026-09-30 UTC, repository gates only.
**Production state:** **CONDITIONAL.** The repository release gate passes. Nothing here is deployed until the PR merges
and `cloudflare-production-deploy.yml` succeeds. The CTI surface needs Blogger operator actions, and live
verification is pending.

Rule applied: PASS requires executed evidence. Code that merely looks correct is not PASS.

## SECURITY — PASS (repository) / BLOCKED (CTI PGP)
- Live headers verified (HSTS preload, CSP, `frame-ancestors 'none'`, nosniff, XFO, Referrer-/Permissions-Policy); API `default-src 'none'`, `no-store`.
- Auth enforced on every probed protected route (401); internal files 404.
- Authorization defect fixed with a fail-closed canonical tier module; recurrence guard test.
- No secrets added (diff reviewed).
- Open: third-party CORS proxies on 3 pages (ICF-P1-004); dev-dependency advisories (ICF-P2-001); CTI placeholder PGP (ICF-P0-001, BLOCKED).
- Evidence: `docs/audits/INTEL-FACTORY-SECURITY-AUDIT.md`.

## INTELLIGENCE QUALITY — PASS for corrected classes / FAIL remaining
- PASS: CVSS for 123 CVEs verified against the NVD CVE API 2.0 (0 unresolved) and applied on every serving/publishing path; build gate fails on 343 records without it.
- PASS: KEV flag reconciled from provenance; joined refs split.
- PASS: advisory pseudo-IOC extraction stopped at source; legacy record IOCs withheld (build gate: 458 records fail without it).
- FAIL (open at Tranche 1; addressed in Tranche 2 above): paid IOC feed empty (ICF-P0-010); graph/search pseudo-IOC nodes (ICF-P0-009 remainder); Tier D claim semantics; fixed-value confidence (ICF-P1-002).
- Evidence: `docs/audits/INTELLIGENCE-QUALITY-AUDIT.md`.

## PIPELINE — PASS (unchanged behaviour, verified)
- Blog feed fresh at audit (pipeline completion 2026-09-30T16:47Z). The only generator change is that advisory sources contribute no IOCs.
- `fetch-live-intel.js` loads; the tests covering the generator pass (`tests/evidence-integrity-regression.test.js` within `test:ci`).

## API — PASS
- `test:ci`: 2,797 passed (60 skipped, pre-existing).
- Team entitlements verified through real handlers (13 tests). CVSS/IOC correction through real `getIntel`/`getCVEDetail` (16 tests).
- Response shapes preserved. The only additive fields are `cvss_status`, `cvss_source`, `cvss_vector`, `ioc_status`, `ioc_withheld_count` and `kev_status_basis`, and they appear only on corrected records.

## UX — PASS
- Runtime states: CHECKING → HEALTHY / DEGRADED / STALE / UNAVAILABLE within 8 s. Real `apex-command-center.js` tested in a VM against a hanging network and a stale feed.
- Headless Chromium on the built bundle with the production CSP: homepage and status page reached HEALTHY; no "VERIFYING"; **0 first-party console errors** (previously 2 per homepage view).

## MOBILE — PASS (sampled)
- Chromium at 390 / 768 / 1440 px: no page-level horizontal overflow on `/` and `/service-status.html` (scrollWidth ≤ innerWidth).
- Not certified here: every route at 320/360/412 px (not executed this tranche).

## SEO — PASS (blog) / BLOCKED (CTI)
- Blog: sitemap 9,502 URLs, all resolve to built assets; robots correct; canonical/metadata unchanged by this release. Only the 85 posts with a correction notice changed, and their titles/canonicals are unchanged.
- CTI: indexability sound; the cliff is consistent with templated near-duplicates (median 69% 6-gram containment); recovery needs Blogger access. See `docs/audits/CTI-SEO-RECOVERY.md`.

## COMMERCIAL — PASS for corrected claims / FAIL remaining
- PASS: Team tier delivers ≥ Pro plus STIX. Offer copy no longer sells seats, Elastic export, per-tier latency, "no rate limit" or priority freshness. Unsupported audience/pre-disclosure/FP-validation claims were removed from 4,131+ pages (build gate).
- FAIL (open): IOC feed content; Premium store catalog 500 (BLOCKED, operator); digest/Slack claims (BLOCKED, operator confirm).
- Capability matrix: `docs/audits/COMMERCIAL-READINESS-AUDIT.md`.

## PAYMENTS — PASS (repository)
- Grant-before-mark ordering in both Razorpay paths. Real-handler tests: a retry after a failed grant delivers the tier, and replay protection holds.
- Not executed: a live Razorpay test-mode transaction (no credentials in this environment). Manual UPI policy decision: BLOCKED (ICF-P1-001).

## OBSERVABILITY — FAIL (gap recorded)
- No request IDs on API responses/logs (ICF-P2-007). Existing: Worker observability enabled (`wrangler.jsonc`), payment audit log in Redis, GA4 events.

## DEPLOYMENT — PASS (dry run) / NOT EXECUTED (production)
- `npm ci` ✓ · `check:cloudflare` 15/15 ✓ · `test:ci` ✓ · `build:cloudflare` 16,125 files ✓ · `wrangler deploy --dry-run` ✓ (20,532 KiB / gzip 3,300 KiB; bindings DB, PREMIUM_REPORTS, ASSETS) · deploy node:test gate 126/126 ✓ · `test_commercial_intel_surfaces.py` PASS · pytest 811 ✓ · tests-js 245 ✓ · Sentinel-APEX node suites 170 ✓.
- No production mutation was performed from this environment.
- Rollback: record the current Worker version ID before merge; on failure, restore it via Cloudflare deployment controls and `git revert` the merge (see `ROLLBACK-RUNBOOK.md`). There are no data migrations, D1 schema changes or new bindings in this release.

## LIVE VERIFICATION — BLOCKED (pending merge + deploy)
Post-deploy checks (all read-only):
1. `curl -s https://blog.cyberdudebivash.in/api/intel/live.json | jq '.items[] | select(.id=="CVE-2026-32202") | {cvss, cvss_source, cisa_kev}'` → `4.3`, NVD source, `true`.
2. `curl -s https://blog.cyberdudebivash.in/posts/cve-2026-86218.html | grep -c data-cvss-correction` → `1`.
3. `curl -s https://blog.cyberdudebivash.in/ | grep -c VERIFYING` → `0`; `curl -s https://blog.cyberdudebivash.in/runtime-state.js -o /dev/null -w '%{http_code}'` → `200`.
4. `curl -s https://blog.cyberdudebivash.in/pricing.html | grep -cE '5 team seats|Response latency|Splunk / Sentinel / Elastic'` → `0`.
5. `curl -s https://blog.cyberdudebivash.in/posts/0din-clean-github-repos-can-trick-ai-agents-into-reverse-sh.html | grep -cE '10,000\+|48hr pre-disclosure|FP-validated'` → `0`.
6. Team-tier canary key: `GET /api/v1/intel?action=iocs&format=stix` → 200 with `stix.type == "bundle"`.
7. `python3 scripts/audit_live_cti_home.py` → exit 0 only after the Blogger theme restore (ICF-P0-001).

---

## Change log

| Commit | Files | Change | Tests |
|---|---|---|---|
| f00ba7e7 | `api/_lib/tier-entitlements.js` (new), `intel.js`, `threat-graph.js`, `enrichment-pipeline.js`, `intelligence-dossier.js`, `siem-connector-store.js`, `middleware.js`, `api/v1/intel.js`, `api/v1/ioc/[id].js`, `api/v1/ioc/search.js`, `api/v1/watchlists.js` | Team ≥ Pro on all gates; STIX for Team | `tier-entitlements.test.js` (13) |
| 1be01fb9 | `api/v1/billing/razorpay-webhook.js`, `api/v1/billing-legacy.js` | Grant before replay/paid markers | `razorpay-entitlement-ordering.test.js` (4) |
| dd41a15f | `scripts/build-cloudflare-assets.js` (+test), `intelligence.html`, `owasp-llm-top10.html`, `contact.html`, `pricing.html`, 10 posts | Remove unsupported audience / pre-disclosure / FP-validation claims | build corpus gate + unit |
| 107d7369 | `runtime-state.js` (new), `apex-command-center.js`, `index.html`, `service-status.html`, build allowlist | Deterministic runtime states with deadlines | `tests-js/runtime-state.test.js` |
| 5c46154a | `index.html`, test | Retire dead KEV proxy loop | runtime-state suite (+1) |
| 29cbe3b7 | `pricing.html`, `faq.html`, `api-dashboard.html`, `api.html`, `revenue-conversion-v19.js`, `api/_lib/payment-utils.js`, test | Offer copy matches enforced capability | `capability-claims-consistency.test.js` (+7) |
| d933ac37 | `scripts/verify-cvss-provenance.js` (new), `data/cvss-corrections.json` (new), `api/_lib/cvss-corrections.js` (new), `intel.js`, `search-index.js`, `generate-cve-pages.js`, `fetch-live-intel.js`, build script (+test) | NVD-verified CVSS; KEV/ref reconciliation; pseudo-IOC withholding | `cvss-corrections.test.js` (16) + 3 build gates |
| (docs) | `docs/audits/*` (6), `docs/release/*`, `scripts/measure_cti_template_similarity.py`, `tests/test_measure_cti_template_similarity.py` | Audit deliverables; CTI similarity KPI tool | pytest (2) |

Negative controls were executed for every new test group and are recorded in the commit messages.

## Remaining blockers (external only)

| Blocked operation | Reason | Prerequisite work completed | Operator action | Post-action validation |
|---|---|---|---|---|
| CTI homepage trust fixes + Blogspot identity (ICF-P0-001) | Blogger theme has no API | Candidate generator, certifier, live audit, tests | Dashboard backup → `prepare_blogger_production_theme.py` → review → restore | `python3 scripts/audit_live_cti_home.py` exit 0 |
| CTI legacy quarantine (ICF-P0-008) | Blogger OAuth secrets in GitHub Actions only | Auditor, similarity KPI tool, recovery plan | Run `blogger-legacy-quality.yml` | Auditor report; similarity median of indexed posts < 0.40 |
| Premium store (ICF-P1-008) | D1 migration + R2 need authenticated Cloudflare operator | Commerce code + fail-closed checkout | Apply migration 0008; create/bind R2; upload certified artefacts | catalog → 200 |
| Manual UPI policy (ICF-P1-001) | Business decision | Evidence documented | Retire flow or amend policy | Pricing/API consistent with decision |
| Production deploy of this PR | Merge authority | Full release gate green | Merge PR #310; confirm deploy workflow success; record Worker version ID | Live verification steps 1–6 above |

## Executive status

- **Production state:** CONDITIONAL (repository ready; deploy + CTI operator actions pending)
- **P0 discovered:** 10 · **P0 fixed on branch:** 7 (ICF-P0-009 at record level) · **P0 remaining:** 3 (P0-001 and P0-008 BLOCKED on external access; P0-010 open) plus the graph/search part of P0-009
- **Tests:** Jest 2,797 passed / 0 failed; node:test 126 + 245 + 170 + 15 passed / 0 failed; pytest 811 passed / 0 failed
- **Security:** authorization and payment-state defects fixed; remaining risks are CORS proxies, dev dependencies and the CTI PGP placeholder
- **Intelligence:** feed fresh; CVSS provenance established for the anomalous cohort; pseudo-IOCs stopped; IOC feed empty
- **Customer experience:** deterministic runtime state; 0 console errors on homepage
- **Commercial:** Team tier now sellable as described; offer copy truthful; IOC feed and premium store are the next revenue blockers
- **SEO:** blog sound; CTI cliff evidence and measurable recovery plan documented; execution blocked on Blogger
- **Deployment:** branch `claude/amazing-thompson-h8ukxi`, PR #310 (draft); not deployed
- **Next highest-value action:** persistent structured-feed IOC store (ICF-P0-010), which unlocks Pro, Team and STIX value
