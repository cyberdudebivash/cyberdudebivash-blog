# Premium Report Reissue Certification (v2, 2026-10-01)

## Release certification

| SKU | Title | Version | Artifact Hash | Size | Human Review | Live Catalog | Download |
|---|---|---:|---|---:|---|---|---|
| PIR-RANSOMWARE-QILIN-SPOONFUL-OF-COMFORT | Sentinel APEX Ransomware Intelligence Report — Qilin Claim Against 'Spoonful of Comfort' | 2.0 | `577d01ee728b…` | 22,919 B | **PENDING** | v1 live (`213eec33…`) | v1: entitlement-gated |
| PIR-RANSOMWARE-DRAGONFORCE-VERMONT-XCENTER | Sentinel APEX Ransomware Intelligence Report — DragonForce Claim Against 'Vermont XCenter' | 2.0 | `ddd603a0b9f1…` | 25,671 B | **PENDING** | v1 live (`4bac2b5c…`) | v1: entitlement-gated |
| PIR-RANSOMWARE-MEDUSALOCKER-BIJA-INDUSTRIE | Sentinel APEX Ransomware Intelligence Report — MedusaLocker Claim Against 'Bija Industrie' | 2.0 | `2f888eec7008…` | 21,568 B | **PENDING** | v1 live (`4b986cde…`) | v1: entitlement-gated |
| PIR-VULN-CVE-2025-62593-RAY | Sentinel APEX Vulnerability Intelligence Assessment — CVE-2025-62593 (Ray) | 2.0 | `28f6f430c2e7…` | 20,441 B | **PENDING** | v1 live (`dde2c5ce…`) | v1: entitlement-gated |

Full hashes are in `config/premium-catalog.json` (`artifact_sha256`, pinned) and `reportx-canary/exports/v2/REISSUE-MANIFEST.json`.

**Status: v2 READY FOR HUMAN REVIEW. Not published.**

The publisher refuses every v2 product (`REVIEW_UNREADABLE`) until a named human writes its review record (`docs/quality/PREMIUM-REPORT-HUMAN-REVIEW.md`). Until then, the human-approved v1 products stay on sale unchanged; that is the owner's decision of 2026-10-01.

## Automated certification (all four v2)

| Check | Result |
|---|---|
| Rebuilt from the original modules (same evidence, claims, sources, rules) | PASS; 26–28 changed lines per report |
| Deterministic (two runs, byte-identical) | PASS |
| ReportX 23-control commercial-readiness gate | **23/23 PASS** ×4 |
| Customer copy gate (internal or canary terminology) | **0 remaining** ×4; the gate fails on every v1 artifact (proves effectiveness) |
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
