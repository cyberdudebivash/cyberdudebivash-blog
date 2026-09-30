# Intel Factory — Architecture Assessment

**Date:** 2026-09-30 UTC · Documentation claims were checked against code and workflow entrypoints, not taken as given.

## 1. Executive summary

The production system is three independently deployed surfaces fed by two batch pipelines. The **runtime-canonical
code** is a hybrid: the root `fetch-live-intel.js` monolith (3,410 lines) and the Python `automation/` package are
the production entrypoints, and both *import* the `Sentinel-APEX/` engines. `Sentinel-APEX/eios/` is a written
standard, not executable code. Several `Sentinel-APEX/` subdirectories are empty or unreferenced. The main
architectural risks are persistence of legacy data through the rolling feed window, deep version layering in
`automation/`, and duplicated per-page client logic. This tranche fixed the last one for runtime state.

## 2. As-built topology (verified)

| Surface | Runtime | Built/published by | Cadence | Evidence |
|---|---|---|---|---|
| blog.cyberdudebivash.in | Cloudflare Worker `workers/entry.js` → `workers/lib/router.js`; static assets from allowlisted `dist-public/` | `.github/workflows/cloudflare-production-deploy.yml` (`npm run build:cloudflare`, `wrangler deploy`) on `main` push (path-filtered) + `production-drift-reconcile.yml` (`*/30`) | on change / ≤30 min drift | Build output byte-identical to live `index.html` on 2026-09-30 |
| Blog intelligence data | `fetch-live-intel.js` → `posts/`, `api/intel/*.json`, `live-intel.json`, `sitemap.xml` | `sentinel-apex.yml` | `3,33 * * * *` | `git log`: "SENTINEL APEX v5.0: +N reports" commits every ~30 min |
| cti.cyberdudebivash.in | Blogger (theme controlled in Blogger dashboard) | `blogger-syndication.yml` → `python -m automation.premium_main` | `17 */3 * * *`, capped 16 posts/day (#221) | issue #219 comment |
| intel.cyberdudebivash.com | Separate repository / Cloudflare gateway | — (out of this repo) | — | `OPERATIONS.md`; feed consumed at `fetch-live-intel.js:108-112` |
| Alerts | `scripts/evaluate-watchlist-changes.js`, `deliver-watchlist-notifications.js` | `alert-delivery.yml` + Worker cron `*/30` (`wrangler.jsonc`) | 30 min | workflow + `workers/entry.js#scheduled` |
| Data plane | D1 `sentinel-apex-core` (binding `DB`), R2 `sentinel-apex-premium-reports`, Upstash Redis (API keys, quotas, legacy billing) | wrangler bindings; `api/_lib/redis.js` | — | `wrangler deploy --dry-run` bindings |

Vercel is retired; no workflow or runtime path references it except the historical DNS retirement step in the deploy
workflow.

## 3. Canonical vs. legacy vs. dead

| Area | Status | Evidence |
|---|---|---|
| `Sentinel-APEX/engine-node/` (detection, reasoning, products, analyst memory) | **Canonical, live** | required by `fetch-live-intel.js:26-44`, `api/_lib/detection-intelligence.js`, `defense-*.js` |
| `Sentinel-APEX/engine/` (Python) | **Canonical, live** | `automation/authority_transformer.py`, `report_renderer.py` add it to `sys.path` |
| `Sentinel-APEX/renderer/` | **Live** | `api/og.js`, `generate-intelligence-hub.js`, `scripts/generate-reports-index.js` |
| `Sentinel-APEX/eios/` (16 docs) | **Standard, not code** | no executable consumer; 1 textual reference |
| `Sentinel-APEX/{analytics,archive,kql,sigma,yara,suricata,osquery,images,scripts}` | **Empty directories** | `ls` = 0 files; references are to *output* paths, not code |
| `Sentinel-APEX/{quality,seo,templates,intelligence,giaap}` | **Unreferenced** | 0 external references |
| `automation/*_v7 … _v19_3` (19 modules) | **Live layered patches** | every module is imported by another; `premium_main` installs them in sequence |
| Root `*.patch` ×6, `rc1commitsfinal.bundle` | **Inert artefacts** | not in build allowlist; not referenced |
| Root client engines (`auto-intel-engine.js`, `live-feed-widget.js`, …) | **Live**, partly duplicating pipeline data via CORS proxies | ICF-P1-004 |

Recommendation: mark the empty/unreferenced `Sentinel-APEX/` directories as reserved or remove them in a reviewed
change (deprecation policy). Do not extend `eios/` as if it were enforced; its rules are enforced only where a test
or gate implements them.

## 4. Pipeline model vs. mission §12

| Stage | Implementation | Assessment |
|---|---|---|
| Source → ingest | 14 sources in `fetch-live-intel.js` (CISA KEV, NVD, GitHub advisories, vendor RSS, abuse.ch, Reddit…) | Present. Reddit (Tier D) records are ingested as intel items (see intelligence audit) |
| Normalize / dedupe | `normalizeSentinelApexRecord`, `correlateAndMerge`, S2N semantic merge (`api/_lib/s2n-engine.js`) | Present |
| Enrich / corroborate | `cve-enrichment-index`, graph, campaign engine | Present; CVSS enrichment not provenance-tagged (ICF-P0-006) |
| Score evidence / confidence | S2N `quality_score`; API `attestItem` fixed values | Partly non-explainable (ICF-P1-002) |
| Generate analysis / artefacts | templates + detection engine (reference drafts) | Present; drafts labelled "reference draft" in current template |
| Quality gate | `qualityGate` (Node); `report_integrity`, `analytical_depth_gate`, `generation_evidence_admission` (Python) | Two parallel gate stacks (Node blog, Python CTI) with different rules |
| Publish / verify | `publication_verifier.py` (Blogger fetch-back); Cloudflare deploy certification | Present |
| Distribute / measure | RSS, API, alerts; GA4 | Present; business KPIs not instrumented end-to-end |

## 5. Architectural risks

1. **Rolling-window persistence** (`fetch-live-intel.js:2851`): prior `live.json` items are merged back every run, so
   records produced by older generator versions persist indefinitely while they rank. This is how fabricated CVSS
   outlived the generator fix (ICF-P0-006, ICF-P2-002). Mitigation in this tranche: ledger applied at serve/publish
   time. Structural fix: stamp `generator_version`, re-validate or age out.
2. **Two quality-gate stacks**: the Node blog pipeline and the Python CTI pipeline enforce different claim rules
   (e.g. `automation/report_integrity.py` has `_QUANTITATIVE_CLAIM_RE`, the Node side does not). Single source of
   truth would share one rule set (e.g. a JSON rules file read by both).
3. **Layered monkey-patch chain** in `automation/premium_main.py` (19 versions): each layer is tested, but
   interaction order is implicit. Needs an explicit, tested pipeline manifest before further layers are added.
4. **Per-page client duplication**: runtime state had 3 implementations (fixed via `runtime-state.js`); proxy-based
   intel fetching still exists in 3 files.
5. **Data files in git rewritten every 30 min**: any PR that edits `api/intel/*.json` conflicts. Corrections must be
   stable ledgers applied at publish time (the pattern used for CVSS here).

## 6. Changes in this tranche (architecture view)

| Change | Type | Consumers |
|---|---|---|
| `api/_lib/tier-entitlements.js` | New canonical module; `middleware.TIERS` re-exported unchanged | 10 gates |
| `runtime-state.js` | New public asset; replaces 3 ad-hoc implementations | `apex-command-center.js`, `service-status.html` |
| `api/_lib/cvss-corrections.js` + `data/cvss-corrections.json` | New ledger pattern for correcting persisted data without editing pipeline-owned files | `intel.js`, `search-index.js`, build, `generate-cve-pages.js` |
| Build: legacy copy map, CVSS JSON/page correction | Extends existing `copyFileForPublicBuild` (same pattern as `repairLegacyCveHtml`) | public build only |

No routing, rendering-model or data-store change was made. No new infrastructure, binding or paid resource.

## 7. Cost discipline

No new Cloudflare resources, cron triggers or third-party services. Homepage bandwidth fell by one ~1.3 MB proxied
fetch per view plus one duplicate ~150 KB `live-intel.json` and one `customer-assurance.json` fetch per view. The NVD
verifier runs offline (operator/CI), not in the Worker.
