# Premium Intelligence Entitlement Cutover (2026-10-02)

**From** standalone ₹1,999 report checkout on the blog **to** Sentinel APEX plan entitlement. Architecture: `docs/architecture/UNIFIED-SENTINEL-COMMERCE.md`.

## Evidence the change was required

| Finding | Evidence |
|---|---|
| Owner decision | Sentinel APEX is the only new-sale payment authority (tranche mandate 2026-10-02) |
| Blog keys never reflect Sentinel APEX subscriptions | Blog `authenticate()` reads Upstash Redis `user:key:<sha256>`. Its `tier` is written only by blog payment paths (`payment-utils.upgradeUserTier`), retired 2026-10-01 |
| Sentinel APEX keys live elsewhere | `sentinel-apex-gateway` and `sentinel-revenue-engine` share KV `API_KEYS_KV` (`ca786702…`). Keys are `cdb_<free|pro|ent|mssp>_…`, record `{tier: FREE|PRO|ENTERPRISE|MSSP, customer_id, subscription_status, expires_at}` (Cloudflare API, Worker bindings and script, read-only) |
| KV alone is not authoritative | The gateway overrides `subscription_status` with its strong-consistency state (`strongAuthStates`) before `evaluateKeyRecordAccess` |
| An authoritative endpoint exists | `GET intel.cyberdudebivash.com/api/auth/validate` returns `{valid, tier, sub}` from the full `resolveAuth`. Live, without a key: `{"valid":false,"tier":"free"}` |
| Live pricing taxonomy | `GET intel…/api/pricing` tiers `PRO`, `ENTERPRISE`, `MSSP` |

## Standalone commerce: kept vs retired

| Kept | Retired for new sales |
|---|---|
| Catalog, CDB review, publisher, R2 storage, artifact hashes, previews | `action=checkout` returns **410** `PREMIUM_CHECKOUT_MOVED` (no Razorpay order, no D1 row, no auth call) |
| Secure download with R2 HEAD + size + SHA checks | Store checkout modal and Razorpay `checkout.js` on `intelligence-store.html` |
| `premium_orders` / `premium_entitlements` / `premium_download_audit` tables | Per-report price and "Unlock report" button |
| `action=verify` and the blog webhook (legacy reconciliation) | Pricing FAQ "sold individually" and products-page "buy certified intelligence" copy |
| `createCheckout` (deprecated, unrouted) | Blog webhook as a launch requirement (**NOT_REQUIRED**) |

## Live transaction state (D1, 2026-10-02)

| Table | Rows |
|---|---|
| `premium_orders` (any state) | 0 |
| `premium_entitlements` | 0 |
| `premium_download_audit` | 0 |

No captured, pending or refundable standalone order exists, so the blog Razorpay webhook is **not required**, and no buyer has to be migrated.

## Security matrix (`api/v1/__tests__/premium-plan-entitlement.test.js`, real SQL)

| Case | Result |
|---|---|
| Free key | 403 `PREMIUM_PLAN_REQUIRED` + intel `upgrade_url`; no R2 read |
| PRO / ENTERPRISE / MSSP key | 200; bytes and `X-Content-SHA256` match; audit `plan:<TIER>`, PII-free owner ref |
| Unknown tier (`PLATINUM`), mis-cased (`pro`) | 403 |
| Revoked or unknown platform key | 401 |
| `?plan=pro`, `tier=`, UTM parameters | Ignored; 403 |
| Gateway down / HTTP 500 / binding missing | 503, fail closed, no R2 read |
| Paused / retired / uncertified report | 403 `REPORT_NOT_AVAILABLE`, even for plan holders |
| Unknown report | 404 |
| Legacy buyer (paused product) | 200; the purchased artifact is kept |
| Cross-account legacy entitlement | 403 |
| Blog key `pro`/`team` | 200; `free`/`Pro` 403 |
| Corrupted artifact | 503, no read |
| Checkout | 410, 0 orders, `createOrder` not called |
| Catalog / library | Never `artifact_key`; paused reports never listed for plan holders |
| Gateway call | Key in header, never in a URL; real client IP forwarded; ≤ 1 call per 60 s per key per isolate |

## Commercial negative controls: **12/12 detected**

| # | Mutation | Failed tests |
|---|---|---|
| 1 | Checkout creates a Razorpay order again | 2 |
| 2 | "Buy for ₹1,999" button returns | 1 (UI) |
| 3 | `?plan=pro` grants access | 1 |
| 4 | FREE is eligible | 4 |
| 5 | Paused report downloadable | 2 |
| 6 | Uncertified report downloadable | 1 |
| 7 | Unknown or mis-cased tier elevates | 6 |
| 8 | Legacy buyer loses access | 1 |
| 9 | Download authorization removed | 6 |
| 10 | Hardcoded Sentinel price on the store | 2 (UI) |
| 11 | R2 location (`artifact_key`) exposed in the public catalog | 1 |
| 12 | Upgrade URL leaves intel.cyberdudebivash.com | 7 |

## Active ₹1,999 purchase CTAs: **0**

- The store, library, pricing FAQ and products page no longer offer a per-report purchase. The UI guard is `tests-js/premium-intelligence-ui.test.js`.
- `api/_lib/sa-eix-commercial-platform.js` contains a "Professional 1999" tier literal. No route imports it, so it is dead code and not a CTA.
- `price_minor`/`currency` remain in the catalog API as historical metadata.
