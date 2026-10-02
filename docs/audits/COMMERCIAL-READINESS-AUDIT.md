# Commercial Readiness Assessment

**Date:** 2026-09-30 UTC · Revenue figures: **none asserted**; no transaction records were accessed. Every
capability below was verified in code (file cited) and, where possible, against live production.

## 0. Update — 2026-10-02 (commerce consolidation)

Sentinel APEX is the only payment authority. Premium reports are no longer sold individually: `action=checkout` returns 410.

Access requires one of:
- a Sentinel APEX PRO/ENTERPRISE/MSSP key, validated by the gateway through the `SENTINEL_GATEWAY` service binding;
- a blog key on the `pro` tier or above;
- a legacy purchase (0 exist).

Details: `docs/audits/PREMIUM-INTELLIGENCE-ENTITLEMENT-CUTOVER.md`. No revenue is asserted.

## 0a. Update — 2026-10-01 (revenue activation tranche)

No revenue is asserted. No captured transaction exists: Razorpay is not configured in production.

| Capability | Implemented | Live | Sellable | Blocker |
|---|---|---|---|---|
| IOC API (`action=iocs`) | Yes. Evidence-only engine; 600 indicators balanced by type | Yes. 2026-10-01 09:01Z feed: url 224, ipv4 136, domain 120, sha256 120; status healthy | **No self-serve purchase** | Razorpay secrets not set; email-only purchase |
| STIX 2.1 (Team+) | Yes. OASIS `stix2` strict parse | Yes (code path). Team-key canary not executed: no customer key | No self-serve purchase | Same as above |
| Premium reports | Yes. Human-certified ReportX publication, Razorpay checkout, entitlement-gated R2 download, refund revocation | Store API live (catalog 200, **0 listed**); 4 certified products ready in `config/premium-catalog.json` at INR 1,999 each | **No.** 0 listed | (1) Run `scripts/publish-premium-reports.js --publish` with `ANALYST_KEYS` configured; (2) Razorpay secrets |
| Razorpay | Yes. Order at server price; signature check; server-side capture/amount/currency confirmation (added this tranche); grant-before-mark; idempotent webhook; expired-order recovery; refund recording | **No.** Checkout returns `503 RAZORPAY_UNAVAILABLE` | — | `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` (runbook: `docs/runbooks/RAZORPAY-PRODUCTION-ACTIVATION.md`) |
| Watchlists | Yes (D1) | API live (unauthenticated → 401); D1 tables exist since 2026-10-01 | Included in paid tiers | No customer usage observed; no end-to-end paid test |
| SIEM connectors | Yes (D1); deployments to customer SIEMs need customer credentials | API live (unauthenticated → 401) | Included in paid tiers | No live connector tested; no end-to-end paid test |
| Manual UPI | Retired (410) | Retired | No | — (by design) |
| Team seats | **Not implemented**; one account key | Seat claims removed from `api.html` and `pricing.html` (tests guard) | n/a | — |

**Revenue state:** EMAIL-ONLY. Every self-serve path is blocked on the three Razorpay secrets.

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
