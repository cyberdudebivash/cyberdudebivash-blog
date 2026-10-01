# Premium Report Reissue Certification (v2, 2026-10-01)

**Status: v2 REVIEWED — 0/4 APPROVED. Nothing published; v1 unchanged.**

## Release certification (human editorial review, 2026-10-01)

| SKU | Old title (v1, live) | New title (v2) | Version | Review | Evidence | Editorial | Commercial | Artifact SHA-256 | Size | R2 object key | Publication state |
|---|---|---|---:|---|---|---|---|---|---:|---|---|
| PIR-VULN-CVE-2025-62593-RAY | CVE-2025-62593 (Ray) Unauthenticated RCE: Vulnerability Intelligence | Sentinel APEX Vulnerability Intelligence Assessment — CVE-2025-62593 (Ray) | 2.0 | **FAIL** (request changes) | **FAIL**: EPSS now 0.62459 / p99.17, report says 0.369% / p29.94; KEV forensic triage omitted | **FAIL**: internal terms; dangling "Claim Ledger appendix" | PASS vs free page, once refreshed | `28f6f430c2e7a1c1d0d72d2753700455c0633032db454cc8dd569594eaa385df` | 20,441 B | `premium-reports/sentinel-apex-vuln-cve-2025-62593-ray/28f6f430….md` (not uploaded) | **NOT PUBLISHED**; v1 on sale |
| PIR-RANSOMWARE-DRAGONFORCE-VERMONT-XCENTER | DragonForce — 'Vermont XCenter' Leak-Site Claim: Incident & Actor Intelligence | Sentinel APEX Ransomware Intelligence Report — DragonForce Claim Against 'Vermont XCenter' | 2.0 | **FAIL** | PASS (as of cut-off) | **FAIL**: internal terms; Sigma `TargetFilename` under `process_creation` | **FAIL**: condensed public sources | `ddd603a0b9f1767fab3e6375cea1acbfef57bb4aa431f7afb03c3f78072d5c7b` | 25,671 B | `premium-reports/sentinel-apex-ransomware-dragonforce-vermont-xcenter/ddd603a0….md` (not uploaded) | **NOT_FOR_SALE**; v1 on sale |
| PIR-RANSOMWARE-QILIN-SPOONFUL-OF-COMFORT | Qilin — 'Spoonful of Comfort' Leak-Site Claim: Incident & Actor Intelligence | Sentinel APEX Ransomware Intelligence Report — Qilin Claim Against 'Spoonful of Comfort' | 2.0 | **FAIL** | PASS (as of cut-off); one unsourced descriptor | **FAIL**: internal terms | **FAIL**: MITRE + Wikipedia restated | `577d01ee728b1c50de537ff0b2ac18e2647ef436d5f512135e00d475cbcdf8b3` | 22,919 B | `premium-reports/sentinel-apex-ransomware-qilin-spoonful-of-comfort/577d01ee….md` (not uploaded) | **NOT_FOR_SALE**; v1 on sale |
| PIR-RANSOMWARE-MEDUSALOCKER-BIJA-INDUSTRIE | MedusaLocker — 'Bija Industrie' Leak-Site Claim: Incident & Actor Intelligence | Sentinel APEX Ransomware Intelligence Report — MedusaLocker Claim Against 'Bija Industrie' | 2.0 | **FAIL** | PASS (as of cut-off) | **FAIL**: internal terms; gap count wrong (says 7, lists 8) | **FAIL**: 2022 CISA advisory restated, its indicators withheld | `2f888eec7008f0bc7f816c320ee1708477754979fcce964dab0b58b088c4357c` | 21,568 B | `premium-reports/sentinel-apex-ransomware-medusalocker-bija-industrie/2f888eec….md` (not uploaded) | **NOT_FOR_SALE**; v1 on sale |

Hashes verified: local candidate = manifest pin for all four. R2/D1/customer hashes do not apply, since nothing was uploaded and nothing was activated.

**Result: 4/4 reviewed, 0/4 approved, 0/4 published.** No R2 write, no catalog change; v1 stays active (fail-closed per the reissue rule).

Detailed findings are in `docs/quality/PREMIUM-REPORT-HUMAN-REVIEW.md` → "Review record 2026-10-01". The commercial test is in `docs/audits/PREMIUM-REPORT-COMMERCIAL-CERTIFICATION.md`.

### v1 (currently on sale) fails the same review

| v1 product | Live `report_id` | Live SHA-256 (prefix) | Shared defect |
|---|---|---|---|
| Ray | `cve-2025-62593-ray-canary` | `dde2c5ce…` | Same outdated EPSS judgement and loopback-filtered rule; "Premium Intelligence Canary" heading |
| DragonForce | `dragonforce-vermont-xcenter-premium-canary` | `4bac2b5c…` | Same non-matching Sigma selection; canary heading |
| Qilin, MedusaLocker | `…-premium-canary` | `213eec33…`, `4b986cde…` | Canary heading and internal terms |

The editorial gate rejects all four v1 artifacts (`CUSTOMER_COPY_INTERNAL_TERMS`, `EVIDENCE_CUTOFF_MISSING`; DragonForce also `DETECTION_FIELD_LOGSOURCE_MISMATCH`). The "canary" `report_id` is visible to customers in the catalog API. Pausing v1 is an owner decision (it empties the store); the reversible command is in `docs/audits/PREMIUM-REPORT-COMMERCIAL-CERTIFICATION.md`.

### Gate added in this tranche

`scripts/premium-editorial-gate.js` runs in `scripts/publish-premium-reports.js` after certification and the hash pins. A human approval no longer suffices on its own:

| Code | Catches | Mutation control |
|---|---|---|
| `CUSTOMER_COPY_INTERNAL_TERMS` | canary/engineering vocabulary, including the evidence-graph terms found in this review | disabling it: 9 tests fail |
| `DETECTION_FIELD_LOGSOURCE_MISMATCH` | a Sigma selection on a field its logsource category lacks | disabling it: 1 test fails |
| `EVIDENCE_CUTOFF_MISSING` / `EVIDENCE_STALE` | no cut-off, or one older than `max_evidence_age_days` (default 30) | disabling it: 5 tests fail |
| (publisher wiring) | an approved, pinned artifact sent regardless | bypassing it: 9 tests fail |

## Automated certification (all four v2)

| Check | Result |
|---|---|
| Rebuilt from the original modules (same evidence, claims, sources, rules) | PASS; 26–28 changed lines per report |
| Deterministic (two runs, byte-identical) | PASS |
| ReportX 23-control commercial-readiness gate | **23/23 PASS** ×4 |
| Customer copy gate (internal or canary terminology) | **Superseded.** The original gate reported 0 remaining, but the 2026-10-01 human review found 4–7 leaked internal terms per artifact. The gate was extended and now fails all four v2 artifacts. |
| Report id / Sigma id / title / slug / filename free of internal terms | PASS |
| Export hash pinned in the manifest; mismatch refused (`ARTIFACT_HASH_NOT_PINNED`) | PASS |
| Publish service accepts each v2 once approved, and stores exactly the reviewed bytes | PASS (test approval in a temp file only) |
| R2 write → R2 verify → catalog row (ordering asserted) | PASS |
| Publisher: confirm live hash, then retire v1; never retire before; skip unchanged | PASS |
| Price | 199900 paise INR, unchanged |
| Size | 20–26 KB markdown each; no images or fonts |

## Versioning

| Product | v1 (live) | v2 (pending) |
|---|---|---|
| report_id | `…-premium-canary` / `cve-2025-62593-ray-canary` | `sentinel-apex-ransomware-…` / `sentinel-apex-vuln-cve-2025-62593-ray` |
| slug | `…-incident-intelligence` / `…-vulnerability-intelligence` | `…-ransomware-intelligence-report` / `…-vulnerability-intelligence-assessment` |
| R2 key | `premium-reports/<v1 id>/<v1 sha>.md` (kept) | `premium-reports/<v2 id>/<v2 sha>.md` (new object) |
| After v2 is live | `RETIRED` (hidden from the catalog; existing entitlements keep working) | `SELLABLE` |

`config/premium-catalog.json` (schema 2) records both versions:
- the `supersedes` block on each product;
- the `history` array with v1 hashes.

D1 has no version column, and none was added (no schema change). The version is carried by the manifest, the artifact header ("Version 2.0") and `premium-previews.json`.

## Preview

`premium-previews.json` is a static asset with no Worker or D1 cost. The store shows it as "What's inside" on each card:
- version and evidence cut-off;
- word, source and ATT&CK-technique counts;
- the detection rule format and honest maturity;
- intelligence-gap count;
- intended audience;
- the full section list.

It carries no rule bodies, indicators, source URLs or hashes; this is enforced by test.

Browser check at 390, 768 and 1440 px: 4 cards with previews, no horizontal scroll, buy button visible, 0 page errors.

## Delivery security (live, 2026-10-01)

| Check | Result |
|---|---|
| Direct R2 path `/premium-reports/<id>/<sha>.md` | 404 (bucket is private, no public URL) |
| Download without a key, or with an invalid key | 401 |
| Private objects in the sitemap | 0 |
| Catalog API `Cache-Control` | `no-store`; downloads `private, no-store` |
