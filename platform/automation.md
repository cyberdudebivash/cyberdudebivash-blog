# EIPS — ENTERPRISE AUTOMATION INVENTORY

What's actually automated today, grounded in real workflow files — not a
wishlist. Principle, stated because one real tension below tests it:
**automation supports analyst review, it does not replace it.**

## Automated today

| Function | Mechanism | Cadence |
|---|---|---|
| Multi-source content ingestion, dedup, correlation | `fetch-live-intel.js` | Every 30 minutes (`sentinel-apex.yml` cron `0,30 * * * *`) |
| IOC normalization | `fetch-live-intel.js` (live pipeline) + `ioc_extractor.py` (offline, on-demand) | Live: continuous. Offline: manual invocation |
| Detection generation (Sigma/KQL/Splunk/OSQuery/Suricata) | `engine-node`'s Detection Engine, wired into `fetch-live-intel.js` | Every 30 minutes, same cadence as ingestion |
| Metadata enrichment (CVSS/EPSS/KEV) | Live: `fetch-live-intel.js`. Offline: `enrichment.py` | Live: continuous. Offline: manual/on-demand |
| Publication (posts, RSS, sitemap) | `blogger-syndication.yml` (hourly, target 4 verified Blogger reports/run), `generate-rss.yml` (every 6h), `sentinel-apex.yml` (every 30 min) | Blogger cadence is a P0 customer-facing freshness SLO; evidence/certification/fetch-back gates remain fail closed |
| AI security intelligence collection | `ai-security-intel.yml` → `ai-security-intel-engine.js` | Scheduled |
| Freshness checking | `freshness-check.yml` | Scheduled |
| CVE page generation | `cve-pages.yml` | Scheduled |
| Dependency/secret security audit | `security-audit.yml` | On `api/**` push + weekly |
| Production smoke test + pricing integrity | `smoke-test.yml` | On non-doc push to `main` |
| Engine test suites (path-scoped, fast feedback) | `intelligence-engine-ci.yml`, `detection-engine-node-ci.yml`, `report-renderer-ci.yml` | On push to their respective paths |
| Full assurance pass: all 4 suites + `cli.py gate` + `cli.py certify` (EICF v1) across every published report | `scripts/assure.sh` (ECAP v1), wired into CI by `continuous-assurance.yml` | On push/PR touching `Sentinel-APEX/**`, `tests-js/**`, `fetch-live-intel.js`; on demand locally or via `workflow_dispatch` |

## Not automated (by design or by gap)

| Function | Status |
|---|---|
| `Sentinel-APEX/prompts/` report drafting | Manual/session-driven — no automated pipeline calls `master-prompt.md` for general reports |
| `knowledge_graph.py::ingest()` (offline graph) | Requires manual invocation (`cli.py graph`, added GIKEP v1, is the entry point — not wired to the publish step itself); the *live* graph (`api/_lib/threat-graph.js`) updates automatically but is a separate system — see `open-issues.md` |
| Report version bump / change_log entry (EIOS Layer 8) | Manual convention, no tooling generates it |
| Changelog generation for `prompts/*.md` / `eios/*.md` themselves | Manual — the "Changelog" sections in root `/prompts/` files were hand-maintained, not generated |

## The real tension worth naming

The automated content pipeline (`fetch-live-intel.js`, 5-minute cadence,
hundreds of commits/day per `vercel-ignore-build.sh`'s own comments)
publishes without passing through `Sentinel-APEX/engine/sentinel_engine
/quality.py` — that gate is wired to the manual `Sentinel-APEX/prompts/`
pipeline, not the automated one. This may be entirely intentional (the
automated pipeline's own internal logic — defensive parsing, source-rank
tie-breaking, KEV/CVSS-only exploitation claims — is a different, narrower
quality mechanism suited to its higher volume). It is flagged here because
"automation supports review, never replaces it" is stated as a platform
principle, and the automated pipeline's actual relationship to the
EIOS Layer 4 gate should be a decision someone made on purpose, not an
artifact of the two systems having been built separately and never
cross-checked — which is exactly the pattern found twice already this
session in other subsystems.

## Actual cadence is governed by more than the committed cron (GTIOC v1)

The cron expressions above are what's committed to this repository, but
they are not the whole story. Live GitHub Actions history for both
`sentinel-apex.yml` (2,931 total runs) and `blogger-syndication.yml`
(8,182 total runs) shows every run's `event` field, and the dominant
pattern for both is `workflow_dispatch` firing with clockwork regularity
at (almost exactly) the same interval as the workflow's own declared
cron — 30 minutes for `sentinel-apex.yml`, 2 hours for
`blogger-syndication.yml` — interleaved with the native `schedule` trigger
firing independently and less predictably (GitHub's own scheduler is
documented to delay scheduled runs under load, which this external
dispatch likely exists to compensate for). The result: actual publishing
cadence is the union of two independent triggers, not just the one visible
in the workflow file, and nothing in this repository documents what the
external dispatcher is or where it's configured. Worth knowing before
concluding "it runs every N minutes" from the YAML alone, and worth the
platform owner documenting the external mechanism somewhere so a future
engineer doesn't have to rediscover it from Actions history the way this
audit did.

---
*CyberDudeBivash® Sentinel APEX — Automation Inventory*