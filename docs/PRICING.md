# Pricing — source of truth and incident record

## Canonical source (since 2026-10-01)

**Plans are sold only on the CYBERDUDEBIVASH SENTINEL APEX platform checkout**
(`https://intel.cyberdudebivash.com/upgrade.html`, owner decision 2026-10-01).
That platform owns plan prices: `https://intel.cyberdudebivash.com/api/pricing`
is the single source of truth (INR in paise plus USD display figures).

| Platform plan | Checkout | Blog plan names that map to it |
|---|---|---|
| PRO Defense | `upgrade.html?plan=pro` | starter, pro |
| Enterprise SOC | `upgrade.html?plan=enterprise` | team, enterprise |
| MSSP / White-Label | `upgrade.html?plan=mssp` | — |

Rules for the blog:

- **No plan price is hardcoded on any blog page.** Plan cards carry
  `data-intel-price="PRO|ENTERPRISE|MSSP"` placeholders that
  `intel-plans.js` fills from the platform's pricing endpoint; if that fails,
  the placeholder ("See price") stays and the platform checkout shows the
  amount. Enforced by `tests-js/pricing-consistency.test.js`.
- Every plan CTA links to the platform checkout (`data-intel-plan`), tagged
  `utm_source=blog&utm_campaign=plan-checkout`. The mapping exists once on
  the server (`INTEL_PLAN_FOR` / `intelUpgradeUrl` in
  `api/_lib/payment-utils.js`) and once in the browser (`intel-plans.js`).
- The blog API no longer creates plan orders or subscriptions:
  `billing?action=create-razorpay-order` and `action=create-subscription`
  return `410 PLAN_CHECKOUT_MOVED` with `checkout_url`.
  `action=verify-razorpay-payment` and the Razorpay webhook still complete
  plan orders created before the switch. API rate-limit responses recommend
  the matching platform plan.
- Premium intelligence reports are still sold on the blog (Intelligence
  Store, INR via Razorpay, `config/premium-catalog.json`).

## Legacy blog plans (no longer sold)

`api/_lib/payment-utils.js`'s `PLANS` remains the record of what existing
blog customers bought and drives verification of in-flight orders. Its
prices are not displayed anywhere.

| Tier | Amount | Currency |
|---|---|---|
| Starter | 999 | INR |
| Pro ("SOC Pro") | 1,499 | INR |
| Team ("Sentinel Team") | 20,699 | INR |
| Enterprise ("Enterprise Apex") | 82,999 | INR |

Retired-price literals in already-generated posts are rewritten at build time
(`LEGACY_COMMERCIAL_COPY` in `scripts/build-cloudflare-assets.js`).

## History

The sections below record how blog pricing was managed before 2026-10-01.

## What broke (2026-07-17) and why

SOC Pro was reduced from $49/₹4,099 to $18/₹1,499 at some point before this
incident was found. The rollout updated most of the site but missed four
independent hardcoded copies of the price: the actual billing backend
(`payment-utils.js` — the most consequential miss, since that's what
determined the real Razorpay/UPI charge), the Stripe checkout response in
`billing.js`'s `subscribe` handler, and roughly a dozen scattered
marketing/conversion-engine strings across `ai-monetization-engine.js`,
`ux-controller.js`, `revenue-cta-block.js`, `conversion-engine.js`,
`auto-intel-engine.js`, plus Schema.org structured data in `seo-engine.js`
and `api.html`. Two of those files also carried a "$X, was $Y" discount
anchor built on the stale number.

Direction was confirmed, not assumed: `OPERATIONS.md` and
`AUDIT-REPORT-2026-05-28.md` both already documented ₹1,499/$18 as
canonical; `api/_lib/stripe.js`'s own header comment independently
corroborated $49 as the *old* price; and "4099" appeared nowhere else in
the repository except the one line that was wrong.

## Preventing recurrence

- `tests-js/pricing-consistency.test.js` (run by
  `.github/workflows/pricing-integrity.yml` on every push/PR touching a
  pricing-relevant file) asserts the backend's `PLANS.pro.amount`,
  checks it against both client-side fallback constants, and greps the
  known marketing files for the stale price paired with "SOC Pro".
- `.github/workflows/smoke-test.yml` additionally checks the **live,
  deployed** site after every push to `main`: `live-intel.json` for the
  stale price (hard failure, previously only a non-blocking warning),
  `GET /api/v1/billing?action=plans` for `pro.amount === 1499`, and
  `pricing.html`'s served HTML for any trace of $49/₹4,099.
- Before changing `PLANS.pro.amount` again: update the two client fallback
  constants in the same change, and expect
  `tests-js/pricing-consistency.test.js`'s marketing-surface checks to
  need updating too if any copy quotes the old number by name.

## Pricing change (2026-07-28) — Starter reordered below Pro

The 2026-07-17 incident above fixed every stale *copy* of Pro's price, but
never examined whether the resulting order still made sense: Starter
(₹2,499/$29) ended up priced **above** Pro (₹1,499/$18) despite Pro being a
strict feature superset (50 vs. 10 threat items/request, full CVE
descriptions vs. CVSS-only, a complete IOC feed vs. none, 25,000 vs. 5,000
API calls/day, Sigma+Yara rules vs. none) — a rational buyer got strictly
more for 40% less by choosing the cheaper-looking-but-actually-pricier
"Pro" tier. Recorded as `platform/open-issues.md` Issue 10 and left
unresolved pending an explicit pricing decision, since changing either
tier's amount is a change to real, revenue-bearing production
infrastructure.

**Resolved**: reordered by lowering Starter to ₹999/$12 (below Pro), not by
raising Pro. Every location this file's own discipline requires was updated
together in one change: `api/_lib/payment-utils.js` (`PLANS.starter`,
canonical), `payment-flow.js` and `pricing.html`'s client-side fallback
constants, `pricing.html`'s rendered plan-price card, and
`api-dashboard.html`'s tier-price card. `tests-js/pricing-consistency.test.js`
now also asserts the *relationship* between tiers directly
(`PLANS.starter.amount < PLANS.pro.amount < PLANS.enterprise.amount`), not
just each one's absolute value — this specific failure mode (every copy
internally consistent, but the canonical value itself economically
incoherent) wouldn't have been caught by the 2026-07-17 remediation's
copy-drift tests alone.

**Resolved (2026-07-29)**: `BUSINESS-TRANSFORMATION-ROADMAP-2026.md`
(§2.2, dated 2026-06-22) separately proposed raising Pro to $79/mo as part
of a larger re-tier. Explicit decision: **Pro stays at ₹1,499/$18/mo** —
the roadmap's $79 proposal is not adopted. Reasoning: the affordable,
transparent, self-serve pricing this platform already has is a real,
verified differentiator against competitors with no public pricing
(GreyNoise) or enterprise-quote-only models (Recorded Future), per the
sourced competitive review — raising Pro 4.4x would give that up. The
roadmap document is left as-is (a dated planning snapshot, not rewritten to
match this decision) and should be read accordingly by anyone consulting
it going forward: its pricing proposal is superseded, not current.

## Pricing change (2026-09-10) — added Team, repositioned Enterprise; Pro/Starter deliberately untouched

An external audit (via Gemini) flagged the platform's pricing as severely
underpriced relative to enterprise CTI comparables ($25k-100k+/yr for
CrowdStrike/Recorded Future/Mandiant) and proposed a global ladder with Pro
raised to $199/mo. Before implementing anything, this exact proposal was
checked against the decision immediately above (2026-07-29): Pro was
already reopened once, on a very similar $79/mo proposal, and explicitly
kept at $18/mo for a documented, competitively-sourced reason. The new
proposal is the same category of change (again reopening Pro), only more
aggressive — so it was **not** re-adopted for Pro. $49/mo was also
specifically considered and rejected as a starting point for any renamed
tier: it's the exact stale pre-cut price `tests-js/pricing-consistency
.test.js` permanently guards against ever reappearing next to "SOC Pro"
(see the 2026-07-17 incident above) — reusing it, even for a different
tier name, would be indistinguishable from that regression to anyone
reading the code later.

**Decision**: Starter (₹999/$12) and Pro (₹1,499/$18) are unchanged —
the 2026-07-29 reasoning stands. Two changes were made instead, both pure
upward expansion:

1. **Added `PLANS.team`** ("Sentinel Team", ₹20,699/$249/mo, 100,000
   calls/day, 5 seats, STIX 2.1 + SIEM export) — a genuinely new tier
   above Pro, not a repricing of anything that existed before.
2. **Repositioned `PLANS.enterprise`** ("Enterprise Apex") from a flat
   ₹4,999/$60/mo self-serve API tier to a ₹82,999/$999/mo *starting*
   price for a custom-scoped, contact-sales offering (dedicated analyst,
   custom SLA, white-label reporting) — sitting above Team. This tier's
   `amount` **was** changed, unlike Pro/Starter: no prior decision
   protected this specific number the way Pro's was protected, and
   leaving it at ₹4,999 while introducing a ₹20,699 Team tier directly
   below it would have created a new, self-inflicted contradiction
   (a "premium apex" tier priced below the mid-tier it's supposed to sit
   above) of exactly the kind this whole review was meant to eliminate.

Every location this file's own discipline requires was updated together:
`api/_lib/payment-utils.js` (`PLANS`, canonical), the tier-key enumeration
sites this required touching for the first time (`api/_lib/middleware.js`
`RATE_LIMITS`/`TIERS`/`NEXT_PAID_TIER`, `api/_lib/security.js`
`validatePlan`, `api/v1/billing-legacy.js` and `api/v1/auth.js`'s plan
validation and pending-tier activation lists, `api/_lib/stripe.js`
`PRICE_BY_PLAN`/`planToTier`), `payment-flow.js` and `pricing.html`'s
client-side fallback constants and rendered plan/comparison cards,
`api-dashboard.html` and `api.html`'s tier cards, and `faq.html`/
`contact.html`'s pricing mentions. `tests-js/pricing-consistency.test.js`
now pins Team's and Enterprise Apex's canonical amounts and the full
Starter < Pro < Team < Enterprise monotonic ordering.

If real, currently-active subscribers exist on the old ₹4,999/mo
Enterprise tier, they are **not** automatically grandfathered by this
change — that requires a manual Redis review outside what a code change
here can verify or perform.

## Known open item outside this codebase

Razorpay's Subscriptions API (`api/_lib/subscriptions.js`'s
`createSubscription`) builds a `plan_id` of the form
`plan_<planType>_<period>` (e.g. `plan_pro_monthly`) and expects a
matching Razorpay Plan object to already exist in the Razorpay dashboard,
priced to match `PLANS.<tier>.amount` above. Those Plan objects live in
the Razorpay dashboard, not this repository, and cannot be verified or
created by a code change — confirm one exists for every
`(planType, period)` combination in current use, including the
`team`/`enterprise` tiers added 2026-09-10, before relying on
`action=create-subscription`.

Stripe was fully removed from this platform 2026-09-10 (see
`ENVIRONMENT_VARIABLE_MATRIX.md`) — Razorpay is now the sole automated
payment rail, with manual UPI/bank-transfer as the human-reviewed primary
path and Gumroad available as an optional secondary rail for global
digital-product downloads.
