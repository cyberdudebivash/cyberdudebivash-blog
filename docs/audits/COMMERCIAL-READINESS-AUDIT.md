# Commercial Readiness Assessment

**Date:** 2026-09-30 UTC · Revenue figures: **none asserted**; no transaction records were accessed. Every
capability below was verified in code (file cited) and, where possible, against live production.

## 1. Executive summary

The self-serve ladder (Free → Starter → Pro → Team → Enterprise) is enforced by real daily quotas and response
shaping. Three defects meant the offer did not match delivery:

1. Team, the highest self-serve tier, received less than Pro (fixed).
2. The plan pages sold capabilities with no implementation: seats, Elastic export, per-tier latency, "no rate limit" (fixed).
3. A Razorpay race could take payment without granting access (fixed).

Two sold capabilities remain undelivered and are the top commercial priorities:

- the paid **IOC feed is empty** (ICF-P0-010);
- the **Premium Intelligence store** API returns HTTP 500 live, most likely awaiting the D1 migration 0008 and R2 operator steps.

## 2. Commercial capability matrix (from implementation)

Legend: ✓ enforced in code · — not included · ◐ included but degraded (see note) · ✎ contractual/human service, not code-enforced.

| Capability | Free | Starter | Pro | Team | Enterprise | Verified implementation |
|---|---|---|---|---|---|---|
| Daily API quota | 100 | 5,000 | 25,000 | 100,000 | 999,999 | `api/_lib/middleware.js` `RATE_LIMITS`; `X-RateLimit-*` headers |
| Price (INR/mo) | 0 | 999 | 1,499 | 20,699 | from 82,999 | live `GET /api/v1/billing?action=plans` |
| Items per page | ≤100 | ≤100 | ≤100 | ≤100 | ≤100 | `api/_lib/intel.js#parsePagination` |
| Full threat descriptions | — (150 chars) | — (150 chars) | ✓ | ✓ | ✓ | `filterFree` / `dataProfile` (`tier-entitlements.js`) |
| Full-text search results | 5 | all | all | all | all | `api/v1/intel.js` `action=search` |
| IOC feed (`action=iocs`) | — | — | ◐ | ◐ | ◐ | gate `tierAtLeast(pro)`; **feed empty** (ICF-P0-010) |
| IOC detail / IOC search | — | — | ✓ | ✓ | ✓ | `api/v1/intel.js` `action=ioc`; `api/v1/ioc/*` |
| CVE detail IOCs | — | — | ◐ | ◐ | ◐ | unvetted legacy IOCs withheld (ICF-P0-009) |
| Detection packs (`action=detection-pack`) | — | — | ✓ | ✓ | ✓ | `api/v1/intel.js` |
| Rule downloads (Sigma / KQL / SPL / osquery / Suricata) | ✓ | ✓ | ✓ | ✓ | ✓ | `action=detection-download` (authenticated, not tier-gated) |
| STIX 2.1 bundle (`format=stix`) | — | — | — | ◐ | ◐ | `tierAtLeast(team)`; built from the IOC feed, so empty until ICF-P0-010 |
| Live Microsoft Sentinel connector | — | — | 5 | 5 | 25 | `siem-connector-store.js#getSiemConnectorEntitlements` |
| Sandbox SIEM connector | 3 | 3 | 3 | 3 | 3 | same |
| Threat graph node budget | 60 (filtered) | 60 (filtered) | 300 | 300 | 999 | `threat-graph.js#getGraphForTier` |
| Relationships (CVE/campaign dossiers, watchlist relationship events) | — | — | ✓ | ✓ | ✓ | `intelligence-dossier.js`, `watchlists.js` |
| Campaign shared IOCs | — | — | 20 | all | all | `intel.js#getCampaigns` |
| Raw attribution signals / scoring breakdown | — | — | — | — | ✓ | `filterEnterprise`, `enrichment-pipeline.js` |
| API keys per account | 1 | 1 | 1 | 1 | 1 | no seat model |
| Weekly digest | ✎ | ✎ | ✎ | ✎ | ✎ | newsletter contacts go to Resend (`api/v1/newsletter.js`); no scheduled sender in repo; not tier-bound |
| Dedicated analyst, custom SLA, white-label | — | — | — | — | ✎ | contractual; not code |
| Priority Slack/Discord | — | — | — | ✎ | ✎ | not verifiable (ICF-P2-005) |
| One-time premium reports | — | — | — | — | — | `api/v1/premium-intelligence.js` implemented; **live catalog → HTTP 500** |
| One-time digital products | — | — | — | — | — | intentionally fail-closed 503 (`api/v1/billing.js`) |

## 3. Payment and entitlement integrity

| Check | Result | Evidence |
|---|---|---|
| Offer exists | ✓ | live plans endpoint |
| Amount/currency | ✓ INR amounts consistent between plans API and pricing tests (`tests-js/pricing-consistency.test.js`) | |
| Signature validation | ✓ HMAC-SHA256 + `timingSafeEqual` | `api/_lib/razorpay.js` |
| Replay / idempotency | ✓ `payment:rzp:txn:seen:<id>` + order status | both Razorpay paths |
| Entitlement delivered | ✓ after this tranche; a transient failure previously stranded payments | ICF-P0-004 |
| Entitlement matches offer | ✓ after this tranche for Team; IOC feed still empty | ICF-P0-002, ICF-P0-010 |
| Refunds | Premium reports: full refund revokes entitlement (webhook `refund.processed`). Subscriptions: "existing billing governance" (manual) | `razorpay-webhook.js` |
| Manual UPI/UTR path | Live, with admin approval; conflicts with `OPERATIONS.md` policy | ICF-P1-001 (operator decision) |
| Post-payment path | `order-confirmation.html`; tier visible via `GET /api/v1/auth?action=me` | |

## 4. Conversion architecture observations

- Every major page carries pricing/API/enterprise CTAs; legacy posts carry four CTAs plus a newsletter block. That is adequate density, and this tranche made the claims inside those CTAs accurate.
- The automated quota-exhaustion upsell (`middleware.nextPaidTier`) recommends Pro → Team, and Team now actually exceeds Pro. Before this fix, the upsell moved customers to a worse data tier.
- `newsletter.html` posts to `https://formsubmit.co/bivash@cyberdudebivash.com` (third-party processor for subscriber PII) while `/api/v1/newsletter` exists first-party. Recommend using the first-party endpoint (consent logging, no third-party PII transfer).
- KPIs (§44) are not instrumented end-to-end: GA4 events exist (`trackEvent('post_newsletter_capture'…)`), but visitor → key → paid conversion needs server-side events keyed by API key creation and payment verification (both already audit-logged in Redis: `TIER_UPGRADED`, `RAZORPAY_PAYMENT_VERIFIED`). A baseline must be established before any target is set.

## 5. Value ladder assessment (customer value × trust × margin)

| Tier | Real differentiator today | Gap to close for sellability |
|---|---|---|
| Starter | 50× Free quota, full search | Tier-bound digest or remove the claim |
| Pro | Full descriptions, IOC/detection-pack access, relationships, live SIEM connector | IOC feed content (ICF-P0-010) |
| Team | 4× Pro quota, STIX 2.1, all Pro capabilities | Seats (not implemented), STIX content depends on the IOC feed |
| Enterprise | Unlimited quota, raw signals, 25 connectors, contractual services | Written SLA/terms per contract; no public SLA is claimed (correct) |

Highest-value, lowest-burden next features:
1. Persistent structured-feed IOC store: unlocks Pro, Team and STIX value at once.
2. Multi-key accounts (seats) on D1: the most-requested team capability and a real Team differentiator.
3. Server-side conversion events: the evidence base for pricing decisions.

## 6. Blockers

| Operation | Reason | Operator action | Validation |
|---|---|---|---|
| Premium report store | Live catalog → 500 | Apply `migrations/0008_premium_intelligence_commerce.sql` to D1 `sentinel-apex-core`; create/bind R2 `sentinel-apex-premium-reports`; upload certified artefacts | `GET /api/v1/premium-intelligence?action=catalog` → 200 |
| Manual UPI policy | Policy vs live path | Decide: retire UPI/UTR flow or amend `OPERATIONS.md` | Pricing page and API reflect the decision |
| Digest / Slack claims | Human services | Confirm delivery or remove from offer | Written confirmation in `OPERATIONS.md` |
