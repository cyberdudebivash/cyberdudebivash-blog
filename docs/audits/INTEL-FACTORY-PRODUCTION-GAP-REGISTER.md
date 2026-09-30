# SENTINEL APEX Intel Factory — Production Gap Register

**Audit date:** 2026-09-30 (UTC) · **Branch:** `claude/amazing-thompson-h8ukxi` · **PR:** cyberdudebivash/cyberdudebivash-blog#310
**Method:** repository inspection, live production probes (blog.cyberdudebivash.in, cti.cyberdudebivash.in,
intel.cyberdudebivash.com), NVD CVE API 2.0 verification, headless Chromium against the built asset bundle.
**Baseline before changes:** `check:cloudflare` 15/15, `test:ci` 2,764/2,764, build output byte-identical to live
`blog.cyberdudebivash.in/` (index.html), so blog production reflected `main` at audit time.

Status legend: **FIXED** = implemented on this branch with tests (production takes effect after merge and the
Cloudflare deploy workflow runs; see the release certification). **BLOCKED** = requires an external operator action
named in the item. **OPEN** = verified, not remediated in this tranche.

## Summary

| ID | Sev | Domain | Title | Status |
|---|---|---|---|---|
| ICF-P0-001 | P0 | Trust / CTI | 13 fabricated metrics, certifications and placeholder PGP on live CTI homepage | BLOCKED |
| ICF-P0-002 | P0 | Revenue / API | Sentinel Team customers served free-tier data; sold STIX/SIEM features not delivered | FIXED |
| ICF-P0-003 | P0 | Trust / Content | 4,131 served posts claim 10,000+ readers, 48hr pre-disclosure, FP-validated rules | FIXED |
| ICF-P0-004 | P0 | Payments | Razorpay marks payment processed before granting tier: stranded payments | FIXED |
| ICF-P0-005 | P0 | Commercial | Plan pages sell seats, Elastic export, per-tier latency that no code delivers | FIXED |
| ICF-P0-006 | P0 | Intelligence | Unsupported CVSS 9.5 served by API, feeds and pages: 119 of 123 CVEs disagree with NVD/CNA | FIXED |
| ICF-P0-007 | P0 | Runtime / UX | Runtime state unbounded "VERIFYING"; "LIVE" for up to 6h-old batch data | FIXED |
| ICF-P0-008 | P0 | SEO | CTI search visibility cliff (issue #219): templated near-duplicate corpus + Blogspot identity | BLOCKED |
| ICF-P0-009 | P0 | Intelligence safety | Advisory text regex hits (vendor domains, commit SHAs, 169.254.169.254, CVE ids) served as IOCs | FIXED (records) / OPEN (graph, search) |
| ICF-P0-010 | P0 | Commercial / Intelligence | Paid IOC feed (`api/intel/iocs.json`, `action=iocs`) is empty in every available version | OPEN |
| ICF-P1-001 | P1 | Payments / Policy | Manual UPI/UTR payment path live despite OPERATIONS.md "no manual fallback" | BLOCKED |
| ICF-P1-002 | P1 | Intelligence | `attestItem()` stamps fixed 0.82/0.95/0.98 confidence and `verified_at = now` | OPEN |
| ICF-P1-003 | P1 | Intelligence | Legacy records self-contradict (source `cisa_kev`, `cisa_kev:false`) and carry joined refs | FIXED |
| ICF-P1-004 | P1 | Security | Third-party CORS proxies in CSP and in browser intel fetches | OPEN (homepage path removed) |
| ICF-P1-005 | P1 | Performance | Homepage downloaded 1.3 MB KEV catalog via proxy every view to write nowhere | FIXED |
| ICF-P1-006 | P1 | Intelligence | 68% of API items name `sentinel_apex` itself as source (circular provenance) | OPEN |
| ICF-P1-007 | P1 | Trust | "real-time" wording for a 30-minute batch pipeline on api.html / index.html | OPEN (intelligence.html fixed) |
| ICF-P1-008 | P1 | Commercial | Premium Intelligence store API returns HTTP 500 live (`action=catalog`) | BLOCKED |
| ICF-P2-001 | P2 | Security | npm audit: 6 high (dev tooling), js-yaml direct | OPEN |
| ICF-P2-002 | P2 | Intelligence | Rolling window lets legacy records persist indefinitely while ranked | OPEN |
| ICF-P2-003 | P2 | Architecture | 19 versioned automation layers patch `premium_main` in sequence | OPEN |
| ICF-P2-004 | P2 | Legal / Brand | Entity name inconsistent: "PRIVATE LIMITED" / "Pvt. Ltd." / none | BLOCKED |
| ICF-P2-005 | P2 | Commercial | Team plan "priority Slack/Discord" support not verifiable from code | BLOCKED |
| ICF-P2-006 | P2 | Deployment | Deploy path filter omits posts/**, cve/**, api/_lib/** (drift reconciler covers ≤30 min) | OPEN |
| ICF-P2-007 | P2 | Observability | API responses and logs carry no request ID | OPEN |
| ICF-P2-008 | P2 | Commercial | "Weekly intel digest" sold on Starter+ has no scheduled sender and is not tier-bound | BLOCKED |
| ICF-P2-009 | P2 | Privacy | `newsletter.html` form posts subscriber email to `formsubmit.co` while a first-party endpoint exists | OPEN |
| ICF-P3-001 | P3 | Payments | UTR length: UI says 12–64, API accepts 8–64 | OPEN |
| ICF-P3-002 | P3 | Payments | Webhook uses pre-parsed `req.body` object instead of the verified raw body | OPEN |
| ICF-P3-003 | P3 | Build | Allowlist names `payment-engine.js`, which does not exist (silently skipped) | OPEN |
| ICF-P3-004 | P3 | Hygiene | Six `.patch` files and a git bundle committed at repo root (not served) | OPEN |

P0 discovered: 10 · fixed on branch: 7 (ICF-P0-009 at record level) · blocked on external action: 2 · open: 1 (ICF-P0-010) + graph/search part of ICF-P0-009.

---

## P0

### ICF-P0-001 — Fabricated trust claims on the live CTI homepage (issue #222)

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Trust, CTI, Security |
| Component | Blogger theme serving `https://cti.cyberdudebivash.in/` |
| Evidence | `python3 scripts/audit_live_cti_home.py --json` on 2026-09-30 → `FAIL`, 13 blockers: `placeholder_pgp`, `placeholder_pgp_id`, `managed_tenant_claim`, `financial_risk_claim`, `insured_coverage_claim`, `platform_uptime_claim`, `tenant_health_claim`, `soc2_type2_claim`, `indicator_count_claim`, `board_sla_claim`, `global_threat_level_claim`, `cyber_insurance_score_claim`, `blogspot_public_identity`. Raw counts in fetched HTML: "142,890" ×1, "99.99" ×2, "SOC 2 Type II" ×1, "ISO 42001" ×3, "mQGNBF" ×1. |
| Current behavior | Public homepage shows tenant counts, 99.99% uptime, $2.4M risk exposure, 100% insured coverage, ISO 42001/27001 and SOC 2 Type II claims, a placeholder PGP block, and a WebSite JSON-LD node identifying `cyberbivash.blogspot.com`. |
| Expected behavior | Zero unsupported metrics; every metric carries value + source + timestamp + provenance, or is absent. Audit exits 0. |
| Customer impact | Enterprise buyers performing due diligence see claims contradicted by `customer-assurance.html` ("not SOC 2 certified"). |
| Commercial impact | Disqualifying in procurement/security review; misrepresentation exposure. |
| Security impact | Placeholder PGP key invites misdirected sensitive disclosures. |
| Root cause | Proven: theme-level markup in Blogger; `blogger-theme/README-production-theme.md` documents drift from every stored XML export. Blogger API v3 exposes no theme resource. |
| Remediation | Repository side is complete and verified: `scripts/prepare_blogger_production_theme.py` (refuses historical exports, strips the known fixtures, fixes WebSite identity), `scripts/certify_blogger_theme_baseline.py`, `scripts/audit_live_cti_home.py`. |
| Test | `tests/test_prepare_blogger_production_theme.py`, `tests/test_live_cti_home_audit.py`, `tests/test_blogger_theme_baseline.py` (pass, part of 809 Python tests). Live acceptance: `python3 scripts/audit_live_cti_home.py` exit 0. |
| Status / Blocker | **BLOCKED** — Blogger dashboard access. |
| Operator action | Blogger → Theme → Backup → download to `blogger-theme/production-current.xml`; `python scripts/prepare_blogger_production_theme.py`; review diff; `python scripts/certify_blogger_theme_baseline.py --theme blogger-theme/production-candidate.xml --checksum blogger-theme/production-candidate.sha256`; Theme → Restore candidate; re-export; `python3 scripts/audit_live_cti_home.py` must exit 0. |
| Deployment required | YES (Blogger theme restore; not a Cloudflare deploy) |

### ICF-P0-002 — Sentinel Team entitlement defect

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Revenue, API, Customer trust |
| Component | `api/_lib/intel.js`, `threat-graph.js`, `enrichment-pipeline.js`, `intelligence-dossier.js`, `siem-connector-store.js`, `api/v1/intel.js`, `api/v1/ioc/*`, `api/v1/watchlists.js` |
| Evidence | Every paid gate was the literal `tier === 'pro' \|\| tier === 'enterprise'`; code comments state intent "free/starter excluded". Live `GET /api/v1/billing?action=plans`: team ₹20,699 > pro ₹1,499. `middleware.nextPaidTier('pro') === 'team'`. |
| Current behavior | Team customers: truncated free-tier descriptions, `ioc_access:false`, 403 on `action=iocs`, `action=ioc`, `action=detection-pack`, `/api/v1/ioc/search`; 0 live SIEM connectors; STIX bundle returned only to enterprise although advertised on Team; graph node budget 60 (free). |
| Expected behavior | Team ≥ Pro on every capability; advertised STIX 2.1 delivered to Team. |
| Customer impact | A customer paying 13.8× Pro received less than Pro; the automated upgrade path downgraded data access. |
| Commercial impact | Refund/chargeback and churn risk on the highest self-serve tier. |
| Security impact | None (under-grant). Fix grants no enterprise-only fields. |
| Root cause | Proven: duplicated hand-written tier literals with no canonical ordering. |
| Remediation | `api/_lib/tier-entitlements.js` (canonical `TIERS`, `tierAtLeast()` failing closed, `dataProfile()` team→pro); all under-granting gates routed through it; STIX uses `tierAtLeast(team)`. No existing entitlement reduced. |
| Test | `api/_lib/__tests__/tier-entitlements.test.js` (13, real handlers + recurrence guard). Negative control: 10/13 fail on pre-fix code. |
| Status | **FIXED** (commit f00ba7e7) |
| Deployment required | YES (Cloudflare Worker) |

### ICF-P0-003 — Unsupported audience, pre-disclosure and validation claims on served pages

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Trust, Content, Commercial |
| Component | `posts/*.html` (legacy v4.0 template), `intelligence.html`, `owasp-llm-top10.html`, `contact.html`, `pricing.html`, 10 editorial posts |
| Evidence | Corpus scan: "Read by 10,000+ security professionals" 3,603 pages; "Join 10,000+ SOC analysts" 4,075; "48hr pre-disclosure" 4,131; "Pre-disclosure intel … deploy-ready SIEM packs" 4,131; "FP-validated YARA rule packs" 2,041; `intelligence.html:1360` "trusted by 500+ SOC teams". The current generator (`fetch-live-intel.js`) no longer emits any of them; no subscriber telemetry, pre-disclosure mechanism or FP-validation process exists in code. |
| Current behavior | Every legacy post advertised a readership count, a pre-disclosure offer and validated detections. |
| Expected behavior | No unsupported audience, adoption, pre-disclosure or validation claims on any public page. |
| Customer impact | Buyers purchase on an offer (pre-disclosure) that cannot be delivered. |
| Commercial impact | Misrepresentation; conflicts with `customer-assurance.html`, which disclaims pre-disclosure access. |
| Security impact | None. |
| Root cause | Proven: retired template output persisted; generator fix did not reach historical pages. |
| Remediation | Build-time exact-literal map from each legacy sentence to the verbatim current-generator wording (`LEGACY_COMMERCIAL_COPY`); hand-authored pages fixed at source; intelligence text never rewritten. |
| Test | `scripts/build-cloudflare-assets.test.js` (deploy gate): corpus-wide zero-claim assertion + unit tests incl. legitimate "pre-disclosure exploitation". Negative control: 4,131 pages fail without the neutralizer; the gate also caught 2 variants a manual grep missed. |
| Status | **FIXED** (commit dd41a15f) |
| Deployment required | YES |

### ICF-P0-004 — Razorpay payments stranded after a transient grant failure

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Payments, Entitlement |
| Component | `api/v1/billing/razorpay-webhook.js`, `api/v1/billing-legacy.js#handleVerifyRazorpayPayment` |
| Evidence | Both paths wrote `payment:rzp:txn:seen:<id>` and order `status:'paid'` before `upgradeUserTier()`; retries short-circuit on those markers. |
| Current behavior | One transient failure between marker writes and the grant permanently left a captured payment "already processed" with no tier. |
| Expected behavior | A payment is marked processed only after the entitlement is written; retries recover. |
| Customer impact | Paid customer without access and no automatic recovery. |
| Commercial impact | Support load, refunds, trust loss. |
| Security impact | Replay protection preserved (grant is an idempotent overwrite). |
| Root cause | Proven: write ordering. |
| Remediation | Grant first, then write markers, in both paths. |
| Test | `api/v1/__tests__/razorpay-entitlement-ordering.test.js` (4, real handlers, in-memory Redis, grant failing once). Negative control: both stranding cases fail pre-fix; replay cases pass before and after. |
| Status | **FIXED** (commit 1be01fb9) |
| Deployment required | YES |

### ICF-P0-005 — Plan capabilities sold without implementation

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Commercial offer integrity |
| Component | `pricing.html`, `faq.html`, `api-dashboard.html`, `api.html`, `revenue-conversion-v19.js`, `api/_lib/payment-utils.js` (PLANS) |
| Evidence | "5 team seats"/"Unlimited team seats": one API key per account, no seat model. "SIEM export (Splunk/Sentinel/Elastic)": `siem-connector-taxonomy.js` marks Elastic not implemented; downloads support `sigma\|kql\|splunk\|osquery\|suricata`. Per-tier "Response latency <200ms…<80ms": one Worker serves all tiers. "Unlimited threat items"/"no rate limit": `parsePagination` caps 100, quotas enforced. "Priority data freshness": single pipeline. "Bulk CSV": no CSV exporter. |
| Current behavior | Checkout plan metadata and pricing page advertised the above. |
| Expected behavior | Every paid feature corresponds to enforced code, or is marked not yet available. |
| Customer impact | Purchases made on undeliverable promises. |
| Commercial impact | Refund exposure; procurement disqualification when tested. |
| Security impact | None. |
| Root cause | Proven: marketing copy authored ahead of implementation. |
| Remediation | Claims replaced with the enforced capability (SPL/KQL rule export + live Microsoft Sentinel connector, page limits, one API key) or "not yet available". Prices, tiers, quotas unchanged. |
| Test | `tests-js/capability-claims-consistency.test.js` (+7). Negative control: pre-fix surfaces match 6/1/3/1/2/2 forbidden claims. |
| Status | **FIXED** (commit 29cbe3b7) |
| Deployment required | YES |

### ICF-P0-006 — Unsupported CVSS scores served to customers

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Intelligence integrity, API |
| Component | `api/intel/live.json` rolling window, `api/intel/cve/*.json` (served by `action=cve`), `cve/*.html`, `posts/*.html` |
| Evidence | NVD CVE API 2.0, 2026-09-30: CVE-2023-27351 served 9.5 vs NVD Primary 7.5; CVE-2024-27199 served 9.5 vs NVD 7.3; CVE-2026-32202 served 9.5 (threat_level LOW) vs Microsoft 4.3. 9.5 appears on 121/2,676 CVE records and 30/100 API items; upstream `intel.cyberdudebivash.com/api/v1/intel/latest.json` currently has no 9.5 (unknowns are null), so the values are legacy persisted records. 86 posts display one of the scores. |
| Current behavior | Paid and public feeds present unsupported CVSS as fact; prioritisation (`+10 CVSS≥9`) inflates these records. |
| Expected behavior | Served CVSS = authoritative score with source, or null ("not assessed"). |
| Customer impact | Wrong remediation priority in SOC/VM workflows. |
| Commercial impact | Direct trust damage for an intelligence product. |
| Security impact | Mis-prioritised patching for customers. |
| Root cause | Proven for the cohort: legacy records persisted by the rolling window (`fetch-live-intel.js` merges prior `live.json` items) and never re-scored. Origin of the 9.5 default predates available history (shallow clone). |
| Remediation | `scripts/verify-cvss-provenance.js` (NVD Primary > CNA > null, deterministic) → `data/cvss-corrections.json` ledger; `api/_lib/cvss-corrections.js` applied on the API serving path (`getIntel`, `searchIntel`, `getCVEDetail`, search index), in the public build (all `api/intel` JSON, `live-intel.json`, re-render of ledger `cve/*.html`), in `generate-cve-pages.js`, and a dated correction notice on legacy posts. Data files are not edited in the PR (pipeline rewrites them every 30 min). |
| Test | `api/_lib/__tests__/cvss-corrections.test.js`, build corpus assertions. |
| Result | NVD CVE API 2.0, 2026-09-30: 123/123 resolved (0 unresolved). 4 genuinely 9.5; 119 differ; 10 below 7.0. Evidence sources: nvd@nist.gov 40, GitHub 30, other CNAs 53. 85 legacy posts receive the notice (the 1 post whose CVE is genuinely 9.5 does not). |
| Status | **FIXED** (commit d933ac37) |
| Deployment required | YES |

### ICF-P0-007 — Ambiguous runtime state on customer pages

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Runtime, UX, Trust |
| Component | `index.html`, `apex-command-center.js`, `service-status.html` |
| Evidence | No fetch deadline anywhere; three implementations; homepage labelled "PRODUCTION DATA LIVE" up to 360 min while `scripts/check-intel-freshness.js` treats >180 min as down; status page "AVAILABLE" derived from `soc2_certified===false`. |
| Current behavior | Pages can remain "VERIFYING" forever; stale data reads live. |
| Expected behavior | CHECKING → HEALTHY / DEGRADED / STALE / UNAVAILABLE from observed evidence within a deadline. |
| Customer impact | Analysts cannot tell whether intelligence is current. |
| Commercial impact | Trust signal on the primary conversion page. |
| Security impact | None. |
| Root cause | Proven: duplicated ad-hoc logic. |
| Remediation | `runtime-state.js` (UMD) with thresholds pinned to the CI monitor and an 8 s AbortController deadline; consumers rewired; duplicate inline homepage block retired. |
| Test | `tests-js/runtime-state.test.js` (16) incl. real `apex-command-center.js` in a VM against a hanging network and a 5h-old feed. Negative control: 6/6 wiring tests fail pre-fix. Headless Chromium: HEALTHY at 390/768/1440, 0 console errors. |
| Status | **FIXED** (commit 107d7369) |
| Deployment required | YES |

### ICF-P0-008 — CTI search visibility cliff (issue #219)

| Field | Entry |
|---|---|
| Severity / Domain | P0 · SEO |
| Component | cti.cyberdudebivash.in (Blogger) corpus and theme |
| Evidence | See `CTI-SEO-RECOVERY.md`. Technical indexability sound on 6 sampled posts (200, self-canonical, `index, follow`, `x-robots-tag: all`). Sitemap index 17 pages × 800 URLs. 8 sampled Aug–Sep posts: pairwise shared 6-gram containment median 0.69, max 0.96; boilerplate share up to 0.69 on CVE-template pages. WebSite JSON-LD Blogspot identity still live (ICF-P0-001). |
| Current behavior | Large templated CVE corpus; publication already capped to 16/day by PR #221. |
| Expected behavior | Indexed pages carry differentiated information; identity consolidated on custom domain. |
| Customer impact | Organic discovery loss. |
| Commercial impact | Top-of-funnel collapse (−96.7% impressions per #219). |
| Security impact | None. |
| Root cause | Pending: consistent with scaled/near-duplicate content signals; not proven (Search Console access required for page-level comparison). |
| Remediation | Repository controls exist (`automation/legacy_quality_auditor.py`, publication cap). Legacy quarantine requires Blogger credentials. |
| Test | Sampling script in `CTI-SEO-RECOVERY.md`; acceptance = Search Console recovery, measured. |
| Status / Blocker | **BLOCKED** — Blogger credentials (GitHub Actions secrets) + Search Console. |
| Deployment required | YES (Blogger) |

### ICF-P0-009 — Pseudo-IOCs from vulnerability advisories

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Intelligence safety |
| Component | `fetch-live-intel.js` NVD (l.491) and GitHub advisory (l.612) ingestion; `api/intel/cve/*.json` `iocs`; threat-graph IOC nodes |
| Evidence | 1,069 "IOCs" in 458 CVE records, all from advisory/news sources (github_advisories 307 records, sentinel_apex 126, reddit 16, fulldisclosure 5, THN 4), no IOC-level source, flat 0.75 confidence. Samples: `indicator` = `CVE-2026-48487`; url = `https://github.com/go-gitea/gitea/blob/…`, `https://reactrouter.com/…`; domain = `typo3.org`; ipv4 = `169.254.169.254`, `12.2.1.4`; sha1 = fix-commit hashes. Graph: 911 IOC nodes, none with provenance, e.g. `ioc:indicator:CVE-2026-14741` confidence 23.5. |
| Current behavior | Pro+ `action=cve` returned up to 50 such values as `iocs`; graph/search/IOC endpoints expose the nodes. |
| Expected behavior | Only indicators from structured threat feeds (urlhaus, threatfox, malwarebazaar, otx) with source and context. |
| Customer impact | Blocking github.com / vendor domains / cloud metadata IP; SIEM false positives. |
| Commercial impact | Trust loss on a core paid capability. |
| Security impact | Customer-side availability risk if ingested into blocklists. |
| Root cause | Proven: `extractIOCs(desc)` applied to vulnerability descriptions. |
| Remediation | Done: advisory sources contribute no IOCs; record-level withholding (`iocs: []`, `ioc_status: WITHHELD_UNVETTED`) at serve and publish time. Open: withhold unprovenanced graph IOC nodes in `threat-graph.js#getGraphForTier` and `search-index.js`; update `intel-unified-search.test.js`, which currently asserts `ioc:domain:example.com` exists. |
| Test | `cvss-corrections.test.js` (3), build corpus gate (458 records fail with corrections disabled). |
| Status | **FIXED** for records (commit d933ac37); **OPEN** for graph/search |
| Deployment required | YES |

### ICF-P0-010 — Paid IOC feed is empty

| Field | Entry |
|---|---|
| Severity / Domain | P0 · Commercial, Intelligence |
| Component | `fetch-live-intel.js:2889-2913` (`api/intel/iocs.json`), `api/v1/intel.js` `action=iocs` |
| Evidence | `count: 0` in the committed file and live `https://blog.cyberdudebivash.in/api/intel/iocs.json` on 2026-09-30; 16/16 versions in available git history have `count=0`. Feed is rebuilt each run from the current run's top 40 passed items only, with no persistence; structured IOC sources did not appear among the top 100 API items. |
| Current behavior | Pro/Team/Enterprise "Complete IOC feed" returns zero indicators. |
| Expected behavior | Persisted, deduplicated, aged indicators from structured feeds, with source and first/last seen, or an offer that states actual coverage. |
| Customer impact | Paid capability delivers nothing. |
| Commercial impact | High; core Pro differentiator. |
| Security impact | None directly. |
| Root cause | Proven: no persistence and ranking-coupled selection. |
| Remediation | Rolling IOC store keyed `type:value`, fed only from urlhaus/threatfox/malwarebazaar/otx items regardless of S2N rank, 30-day age-out, cap 200 per page. Requires a live pipeline run to validate source volume. |
| Status | **OPEN** |
| Deployment required | YES |

## P1

### ICF-P1-001 — Manual UPI/UTR payment path vs documented policy
Evidence: `pricing.html` UPI QR + UTR submission; `api/v1/billing-legacy.js` `create-intent`/`submit-payment` live (`GET …?action=submit-payment` → 405 POST required). `OPERATIONS.md`: "Razorpay and Gumroad are the only authorized payment sources … Do not enable manual payment fallback." Customer impact: manual review latency; commercial: revenue path the policy says is unauthorized. **BLOCKED** — operator decision (retire, or amend policy). Not changed: removing a live payment path is a business decision. Deployment required: YES if retired.

### ICF-P1-002 — Non-explainable confidence in API attestation
Evidence: `api/_lib/intel.js#attestItem` sets `confidence_score` 0.95 (≥2 sources) / 0.98 (KEV) / 0.82 (else), `verified_at: new Date()` and a fixed methodology string on every item. Violates the explainable-confidence rule (§17): the timestamp is request time, not verification. Remediation: additive `confidence_basis` + `verified_at` = source/ingest time; keep fields for compatibility. **OPEN** (API contract change; needs consumer review).

### ICF-P1-003 — Self-contradicting legacy records
Evidence: `CVE-2026-32202` in `api/intel/live.json`: `source:"cisa_kev"`, `cisa_kev:false`, title "CISA KEV Active Exploitation", ref `"https://msrc… ; https://nvd…"` (two URLs joined). Current ingestion (`extractHttpUrls`) prevents new occurrences; persisted records keep them. Remediation: reconcile at serve and publish time from the record's own provenance (`api/_lib/cvss-corrections.js#reconcileLegacyRecord`): KEV-catalog-sourced records are served `cisa_kev: true` with `kev_status_basis`; joined refs are split into valid URLs. Tests: `cvss-corrections.test.js` + build corpus gate. **FIXED** (commit d933ac37).

### ICF-P1-004 — Third-party CORS proxies
Evidence: CSP `connect-src` allows `api.allorigins.win`, `corsproxy.io`, `thingproxy.freeboard.io`, `api.rss2json.com`; used by `intelligence.html` (RSS strategies 1–4), `live-feed-widget.js`, `auto-intel-engine.js`. A proxy can alter intelligence shown to customers without provenance. Homepage usage removed (ICF-P1-005). Remediation: serve first-party pipeline JSON; drop proxies from CSP once no consumer remains. **OPEN**.

### ICF-P1-005 — Dead KEV catalog fetch loop on homepage
Evidence: `updateKEVCounts()` fetched ~1.3 MB per view and every 15 min (direct cisa.gov always CSP-refused → console error; then allorigins) into `#kevCount/#cisaToday/#kevTotal`, none present. **FIXED** (commit 5c46154a); 0 console errors verified in Chromium.

### ICF-P1-006 — Circular source attribution
Evidence: 68/100 `api/intel/live.json` items carry `source:"sentinel_apex"` (the sibling platform) rather than the original publisher; refs sometimes point to `intel.cyberdudebivash.com` reports. Provenance chain stops at our own platform. Remediation: carry the upstream record's original publisher/URL through `normalizeSentinelApexRecord`. **OPEN**.

### ICF-P1-007 — "real-time" wording for batch intelligence
Evidence: `api.html` og:description "real-time threat intelligence", "Webhook-based real-time alerts"; `index.html` "Get real-time threat alerts", "RESTful API delivering real-time CVE data". Pipeline cadence `3,33 * * * *`; webhook delivery via `*/30` cron. `intelligence.html` fixed in this tranche. **OPEN** for remaining pages.

### ICF-P1-008 — Premium Intelligence store unavailable
Evidence: live `GET /api/v1/premium-intelligence?action=catalog` and bare `GET /api/v1/premium-intelligence` → HTTP 500 `PREMIUM_COMMERCE_ERROR` on 2026-09-30. `wrangler.jsonc` documents that applying `migrations/0008_premium_intelligence_commerce.sql` and creating the R2 bucket `sentinel-apex-premium-reports` are explicit operator steps; checkout fails closed without HEAD-verified artefacts. **BLOCKED**: authenticated Cloudflare operator (D1 migration + R2). Validation: catalog → 200 with certified artefacts. Also recommended: return 503 + `Retry-After` for a known-unprovisioned state instead of 500.

## P2 / P3

| ID | Evidence | Remediation | Status |
|---|---|---|---|
| ICF-P2-001 | `npm audit`: 6 high — wrangler/miniflare/undici/sharp (dev), brace-expansion (transitive), js-yaml (direct). Prod-only: 1 moderate. js-yaml parses only first-party Sigma (`detection-intelligence.js#validateSigmaStructural` ← canonical store), not request input. | Dedicated dependency-upgrade change (wrangler 4.145.0, js-yaml 5.4.2) per CLAUDE.md "no opportunistic upgrades". | OPEN |
| ICF-P2-002 | `fetch-live-intel.js:2851-2859` merges prior `live.json` items; 44/100 items first seen before 2026-08-12. | Add record `generator_version` and re-validate or age out legacy records. | OPEN |
| ICF-P2-003 | `automation/` has 19 versioned modules (v7–v19.3) layered around `premium_main`; all imported (none dead). | Consolidation plan with tests before any removal (deprecation policy). | OPEN |
| ICF-P2-004 | Legacy posts "CYBERDUDEBIVASH PRIVATE LIMITED"; `terms.html`/`privacy.html` "CyberDudeBivash Pvt. Ltd."; current generator "CYBERDUDEBIVASH". | Operator/legal to confirm registered entity name; then align. Not changed. | BLOCKED |
| ICF-P2-005 | Team plan "priority Slack/Discord": human service, no code artefact. | Operator to confirm channel exists or remove. | BLOCKED |
| ICF-P2-006 | `cloudflare-production-deploy.yml` `paths:` omits `posts/**`, `cve/**`, `api/_lib/**`, most `api/v1/**`; `production-drift-reconcile.yml` redeploys `main` drift every 30 min. | Accept (mitigated) or add paths. | OPEN (low) |
| ICF-P2-007 | Live `GET /api/v1/intel/live` (401) headers: HSTS, CSP, no-store present; no `X-Request-ID`. Customer-reported errors cannot be correlated to Worker logs. | Generate a UUID per request in `workers/lib/router.js`, echo as `X-Request-ID` and in error bodies/logs. | OPEN |
| ICF-P2-008 | `payment-utils.js` PLANS.starter "weekly intel digest"; `pricing.html` row "Weekly intel digest email" (Starter+). No workflow/script/handler sends a digest; newsletter contacts go to Resend (`api/v1/newsletter.js`), so a manual broadcast is possible but unverifiable, and free subscribers receive the same. | Operator confirms a digest is sent to paid tiers, or the claim is removed; a tier-bound scheduled sender would make it a real differentiator. | BLOCKED |
| ICF-P2-009 | `newsletter.html:94` `action="https://formsubmit.co/bivash@cyberdudebivash.com"`; `/api/v1/newsletter` exists first-party with Resend + Redis lead store. | Post to the first-party endpoint (consent record, no third-party PII transfer). | OPEN |
| ICF-P3-001 | `pricing.html` "UTR must be 12–64"; `security.js#validateUTR` accepts 8–64. | Align copy with validator. | OPEN |
| ICF-P3-002 | `razorpay-webhook.js:41` uses `req.body` when already an object instead of `JSON.parse(rawBody)`. | Always parse the verified raw body. | OPEN |
| ICF-P3-003 | `PUBLIC_ROOT_FILES` includes `payment-engine.js`; file absent; `existsSync` skips silently. | Remove entry or fail loudly. | OPEN |
| ICF-P3-004 | Root: `0001…0006*.patch`, `rc1commitsfinal.bundle` (not in build allowlist, not served). | Move to `docs/archive/` or delete via reviewed change. | OPEN |

## Verified healthy (no gap recorded)

- blog.cyberdudebivash.in: HSTS preload, CSP, `frame-ancestors 'none'`, XFO DENY, nosniff, Referrer-Policy, Permissions-Policy present on HTML.
- Internal files not exposed: `/CLAUDE.md`, `/OPERATIONS.md`, `/package.json`, `/wrangler.jsonc`, `/.env.example`, `/intel-state.json`, `/data/published_posts.json`, `/logs/` → 404.
- API auth enforced: `/api/v1/intel/*`, `/api/v1/customer/dashboard`, `/api/v1/ioc/search` → 401; admin → 401 without `X-Admin-Key`; workbench → 401.
- Razorpay signatures: HMAC-SHA256 + `timingSafeEqual` (`api/_lib/razorpay.js`).
- Blog sitemap: 9,502 URLs, all resolve to built assets; 46 posts not listed.
- Blog feed freshness at audit: `live-intel.json` pipeline run 2026-09-30T16:47Z (≈15 min old).
- CTI homepage freshness rule of `audit_live_cti_home.py` passed (no freshness finding on 2026-09-30).
