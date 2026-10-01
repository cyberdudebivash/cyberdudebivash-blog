# Cloudflare Cost Guardrails

**Principle: no overage by design.** The platform is pre-revenue. A change that adds recurring Cloudflare workload must show it fits the included allowance, or it does not ship.

## 1. What is verified (2026-10-01, authenticated Cloudflare API)

| Item | Value | Source |
|---|---|---|
| Account | Standard account; 24 Worker scripts, 9 D1 databases, 4 R2 buckets, 10 KV namespaces, 2 Queues (all pre-existing) | `GET /accounts/{id}/workers/scripts`, `/d1/database`, `/r2/buckets`, `/storage/kv/namespaces`, `/queues` |
| Workers default usage model | `standard` | `GET /workers/account-settings` |
| This Worker | `cyberdudebivash-blog`: bindings D1 `sentinel-apex-core`, R2 `sentinel-apex-premium-reports`, static `ASSETS`; **cron `*/30 * * * *`** (pre-existing; about 1,440 runs/month; watchlist evaluation and due notification delivery); no KV, no Queue, no Durable Object | `wrangler.jsonc`, `workers/lib/router.js#handleScheduled`, `wrangler deploy --dry-run` |
| D1 `sentinel-apex-core` | 512 KB, migrations 0001–0008 applied | D1 API |
| R2 `sentinel-apex-premium-reports` | empty until premium publication | R2 API (Phase A) |
| Worker bundle | 3,410 KiB gzip on `main` (2026-10-01 ~10:00Z; varies with pipeline data) | `wrangler deploy --dry-run` |
| Plan / billing subscriptions | **NOT VERIFIED.** The API token returns `10000 Authentication error` for `/subscriptions` | — |
| Usage analytics (requests, CPU, D1 rows, R2 ops) | **NOT VERIFIED.** The GraphQL analytics query returned no account data for this token | — |

**Inference (not verification):** the ~3.4 MB gzip bundle exceeds the Workers Free script-size limit, so the account is very likely on Workers Paid. The operator should confirm in Dashboard → Billing.

## 2. Budget table

The operator fills these from Dashboard → Billing / Analytics. Until then, every row is `NOT VERIFIED`, and the rule in §3 applies.

| Resource | Current plan limit | Current usage | Warning (70%) | Hard internal limit |
|---|---:|---:|---:|---:|
| Worker requests / month | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED | No new cron beyond the existing `*/30`; no new polling endpoint (§4) |
| Worker CPU | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED | No feed parsing or rendering in request paths (§4) |
| D1 rows read / written | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED | Every list query capped at 100–500 rows (§4). The `*/30` cron's due-delivery scan is capped at 500 and is indexed. Since the 2026-10-01 migrations it reads real (currently empty) tables. |
| D1 storage | NOT VERIFIED | 512 KB (`sentinel-apex-core`) | NOT VERIFIED | No new databases |
| R2 storage | NOT VERIFIED | ≈ 0 (premium bucket empty) | NOT VERIFIED | ≤ 5 premium products × ~100 KB |
| R2 Class A (writes) | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED | Writes only at publication (4 products × 2 objects) |
| R2 Class B (reads) | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED | 2 operations per paid download (HEAD + GET) |
| KV / Queues / Durable Objects | not used by this Worker | — | — | Must not be added without review |

## 3. Policy

| Level | Trigger | Action |
|---|---|---|
| NORMAL | projected < 70% of a verified quota | proceed |
| WARNING | ≥ 70% | review before merge |
| HIGH | ≥ 85% | only cost-reducing changes |
| CRITICAL | ≥ 95% | freeze workload-increasing changes |
| BLOCK | projected to exceed the included quota, or **any recurring increase while plan/usage is NOT VERIFIED** | do not merge |

## 4. Enforced internal limits (code and tests)

All of these are pinned by `api/_lib/__tests__/cost-guardrails.test.js` plus the suites named below. Raising any of them is a reviewed decision.

| Limit | Value | Where |
|---|---|---|
| IOC published feed (bundled into the Worker) | **600 hard limit** (`FEED_CAP_HARD_LIMIT`). A config above it is clamped and fails the publication gate. | `api/_lib/ioc-engine/store.js` |
| IOC store (repository) | 2,000 records | `store.js` `STORE_CAP` |
| IOC per-source caps | 150–300 per run; 20–30 s timeout; ≤ 25 MB per export | `config/ioc-sources.json` |
| IOC refresh cadence | rides the existing pipeline (~1.5–5 h); conditional GET (ETag / Last-Modified) | `.github/workflows/sentinel-apex.yml` |
| IOC API page size | ≤ 200 | `api/_lib/ioc-engine/feed.js` |
| Unified search | ≤ 100 results | `api/_lib/search-index.js` |
| Notifications / dead letters | ≤ 200 | `api/_lib/notification-store.js`, `api/v1/notifications.js` |
| Watchlist feed | ≤ 100 | `api/_lib/watchlist-store.js`, `api/v1/watchlists.js` |
| Premium catalog / library | ≤ 100 | `api/_lib/premium-commerce-store.js` `clampLimit` |
| Hunt / detection-feedback stores | bounded (`boundedLimit`) | `api/_lib/hunt-store.js` and others |
| Live feed widget polling | ≥ 15 min, paused in hidden tabs; static asset (no Worker invocation) | `live-feed-widget.js` |
| Premium catalog size | 3–5 products | `config/premium-catalog.json` (tested) |

## 5. Request-path rules

Customer request paths do: validate → authorize → read → respond.
- **Never in a request path:** feed parsing, graph construction, NVD enrichment, or report rendering. These run in the GitHub Actions pipeline, which costs no Cloudflare usage.
- **Cacheable publicly:** static assets and `/api/intel/*` public JSON (`_headers`).
- **Never cached:** authenticated API responses, entitlements, payment responses, private report bytes (`private, no-store`).
