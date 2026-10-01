'use strict';
// Pricing integrity. Since 2026-10-01 plans are sold only on the
// CYBERDUDEBIVASH SENTINEL APEX platform checkout, which owns plan prices
// (intel.cyberdudebivash.com/api/pricing; see docs/PRICING.md). This suite
// guards: (1) the legacy blog PLANS record that still verifies in-flight
// orders, (2) that no blog surface hardcodes a plan price, (3) that every
// plan CTA goes to the platform checkout with one plan mapping, and (4) that
// intel-plans.js only ever shows a price it read from the platform.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const { PLANS } = require(path.join(ROOT, 'api', '_lib', 'payment-utils.js'));

/* ─── The backend is the canonical source — pin its expected values ──── */

test('canonical PLANS.pro matches the known-correct price (₹1,499/mo)', () => {
  assert.strictEqual(PLANS.pro.amount, 1499);
  assert.strictEqual(PLANS.pro.currency, 'INR');
  assert.ok(PLANS.pro.upiNote.includes('₹1,499'), 'upiNote must quote the same amount it charges');
});

// 2026-07-28: Starter was ₹2,499/$29 -- priced *above* Pro's ₹1,499/$18
// despite Pro being a strict feature superset (platform/open-issues.md
// Issue 10). Reordered to ₹999/$12, below Pro, rather than raising Pro --
// preserves the platform's transparent self-serve pricing as a competitive
// differentiator instead of undoing the 2026-07-17 Pro price cut.
test('canonical PLANS.starter matches the reordered price (₹999/mo, below Pro)', () => {
  assert.strictEqual(PLANS.starter.amount, 999);
  assert.strictEqual(PLANS.starter.currency, 'INR');
  assert.ok(PLANS.starter.upiNote.includes('₹999'), 'upiNote must quote the same amount it charges');
});

// 2026-09-10: repositioned from a flat ₹4,999/$60 self-serve API tier to
// "Enterprise Apex" — a starting price for a custom-quoted, contact-sales
// offering (dedicated analyst, custom SLA, white-label), sitting above the
// new Sentinel Team tier below. Explicit, documented decision (see
// docs/PRICING.md) -- Starter and Pro were deliberately left untouched in
// the same change (see the 2026-07-29 decision above: Pro's affordable,
// transparent self-serve pricing is a verified competitive differentiator
// and was not reopened here).
test('canonical PLANS.enterprise reflects its 2026-09-10 Enterprise Apex reposition (₹82,999/mo)', () => {
  assert.strictEqual(PLANS.enterprise.amount, 82999);
  assert.strictEqual(PLANS.enterprise.currency, 'INR');
  assert.ok(PLANS.enterprise.upiNote.includes('₹82,999'), 'upiNote must quote the same amount it charges');
});

// 2026-09-10: new tier, added above Pro without touching Pro/Starter --
// pure upward expansion for teams needing multi-seat access, STIX 2.1
// export, and SIEM export, not a repricing of any existing tier.
test('canonical PLANS.team matches its introductory price (₹20,699/mo)', () => {
  assert.strictEqual(PLANS.team.amount, 20699);
  assert.strictEqual(PLANS.team.currency, 'INR');
  assert.ok(PLANS.team.upiNote.includes('₹20,699'), 'upiNote must quote the same amount it charges');
});

/* ─── Structural invariant, not just a pinned number ──────────────────── */
/* Issue 10's root cause wasn't a stale copy (every copy agreed) -- it was
   that nobody asserted the *relationship* between tiers. Pin the invariant
   itself so a future isolated price change to any one tier can't silently
   reintroduce a cheaper-but-more-featured tier being priced above a
   pricier-but-less-featured one. */
test('tier prices increase monotonically with tier (Starter < Pro < Team < Enterprise)', () => {
  assert.ok(PLANS.starter.amount < PLANS.pro.amount, 'Starter must be cheaper than Pro');
  assert.ok(PLANS.pro.amount < PLANS.team.amount, 'Pro must be cheaper than Team');
  assert.ok(PLANS.team.amount < PLANS.enterprise.amount, 'Team must be cheaper than Enterprise');
});

function readFile(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf8');
}

/* ─── No stale price should remain in the wider marketing surface ────── */
/* The 2026-07-17 incident: SOC Pro was reduced from $49/₹4,099 to $18/
   ₹1,499, and the rollout missed the backend plus several marketing files.
   These files are known to reference the SOC Pro price by exact string —
   assert the current price is present and the stale one is gone. A file
   legitimately mentioning $49 for something else (one-time products are
   priced independently) would only false-positive here if it also happens
   to pair that "$49" with the literal substring "SOC Pro" — acceptable
   specificity for a regression guard, not a general-purpose price linter. */
const MARKETING_FILES_MUST_NOT_SAY_STALE_PRICE = [
  'ai-monetization-engine.js', 'ux-controller.js', 'revenue-cta-block.js',
  'conversion-engine.js', 'auto-intel-engine.js', 'seo-engine.js', 'api.html',
];

for (const file of MARKETING_FILES_MUST_NOT_SAY_STALE_PRICE) {
  test(`${file} does not pair "SOC Pro" with the stale $49 price`, () => {
    const src = readFile(file);
    // Match "$49" within ~40 chars of "SOC Pro" in either order.
    const stale = /SOC Pro[\s\S]{0,40}\$49|\$49[\s\S]{0,40}SOC Pro/i;
    assert.ok(!stale.test(src), `${file} still pairs "SOC Pro" with $49 somewhere`);
  });
}

/* ─── bare "Enterprise" tier-name collision guard ─────────────────────── */
/* Found and fixed directly (not caught by any existing test before this):
   three separate pages each named a "Custom"-priced, sales-assisted
   Enterprise plan just "Enterprise" — colliding with pricing.html's
   canonical $60/mo self-serve Enterprise API tier. All three use different
   markup (enterprise.html: <div class="tier-name">, api.html:
   <div class="plan-tier">, index.html: <div class="pt-name">), which is why
   no single existing check caught all of them. Renamed to "Enterprise
   Managed" (two different products, not a price conflict — confirmed with
   the business owner). */

const BARE_ENTERPRISE_TIER_NAME_LOCATIONS = [
  { file: 'enterprise.html', divClass: 'tier-name' },
  { file: 'api.html', divClass: 'plan-tier' },
  { file: 'index.html', divClass: 'pt-name' },
];

for (const { file, divClass } of BARE_ENTERPRISE_TIER_NAME_LOCATIONS) {
  test(`${file} has no tier named exactly "Enterprise" (would collide with pricing.html's $60/mo Enterprise tier)`, () => {
    const src = readFile(file);
    const re = new RegExp(`<div class="${divClass}"[^>]*>([^<]+)</div>`, 'g');
    const tierNames = [...src.matchAll(re)].map(m => m[1].trim());
    assert.ok(tierNames.length > 0, `expected at least one <div class="${divClass}"> in ${file}`);
    assert.ok(
      !tierNames.includes('Enterprise'),
      `${file} has a bare "Enterprise" tier name (found: ${JSON.stringify(tierNames)}) — ` +
      'this collides with pricing.html\'s $60/mo Enterprise tier; use a disambiguated name ' +
      '(e.g. "Enterprise Managed") if this is a different product, or match the canonical price if not.'
    );
  });
}

test('api.html does not advertise annual billing (no backend support exists for it anywhere in api/)', () => {
  const src = readFile('api.html');
  assert.ok(!/\$470\/yr|save 20%/i.test(src), 'api.html still advertises an unimplemented annual-billing discount');
});

/* ─── Plans are sold on the Sentinel APEX platform (2026-10-01) ──────── */

const vm = require('vm');
const { INTEL_PLAN_FOR, intelUpgradeUrl } = require(path.join(ROOT, 'api', '_lib', 'payment-utils.js'));
const { neutralizeLegacyCommercialCopy, RETIRED_PLAN_PRICE_COPY } = require(path.join(ROOT, 'scripts', 'build-cloudflare-assets.js'));

// Every customer-facing source that used to quote a blog plan price, plus the
// post generator. Generated posts are covered by the build-time rewrite test.
const PLAN_PRICE_SURFACES = [
  'pricing.html', 'api.html', 'api-dashboard.html', 'faq.html', 'contact.html', 'index.html',
  'enterprise.html', 'intelligence.html', 'buy.html', 'payment-flow.js', 'intel-plans.js',
  'ux-controller.js', 'revenue-cta-block.js', 'conversion-engine.js', 'monetization.js',
  'ai-monetization-engine.js', 'auto-intel-engine.js', 'seo-engine.js', 'fetch-live-intel.js',
];
const HARDCODED_PLAN_PRICE = /₹\s?(?:999|1,499|20,699|82,999|4,100|41,600|83,300)\b|\$(?:12|18|49|249|299|499|999)\s*(?:\/|per\s)\s*(?:mo|month)|<sup>\$<\/sup>\s*(?:18|249)\b|>\$(?:18|299)</;

for (const file of PLAN_PRICE_SURFACES) {
  test(`${file} hardcodes no plan price (prices come from the Sentinel APEX platform)`, () => {
    const m = readFile(file).match(HARDCODED_PLAN_PRICE);
    assert.ok(!m, `${file} hardcodes a plan price: "${m && m[0]}"`);
  });
}

// Fabricated urgency/discount copy removed on 2026-10-01 must never return.
const RETIRED_OFFER_COPY = /\d+\s+spots\s+left|Save\s+63%|\$49\s*(?:→|->|&rarr;)\s*\$18|normally\s+\$49|class="rcb-orig"/i;
for (const file of PLAN_PRICE_SURFACES.concat(['intelligence-store.html', 'products.html'])) {
  test(`${file} carries no retired urgency or discount offer copy`, () => {
    const m = readFile(file).match(RETIRED_OFFER_COPY);
    assert.ok(!m, `${file} reintroduces retired offer copy: "${m && m[0]}"`);
  });
}

test('pricing, API and dashboard pages show live platform prices for all three plans', () => {
  for (const file of ['pricing.html', 'api.html', 'api-dashboard.html']) {
    const src = readFile(file);
    for (const tier of ['PRO', 'ENTERPRISE', 'MSSP']) {
      assert.ok(src.includes(`data-intel-price="${tier}"`), `${file} lacks a live ${tier} price slot`);
    }
    assert.ok(src.includes('/intel-plans.js'), `${file} must load intel-plans.js`);
  }
});

test('every plan CTA on the pricing page goes to the platform checkout; none starts a blog checkout', () => {
  const src = readFile('pricing.html');
  assert.doesNotMatch(src, /create-razorpay-order|checkout\.razorpay\.com|PaymentFlow\.payInstant|id="modalOverlay"/);
  for (const plan of ['pro', 'enterprise', 'mssp']) {
    assert.ok(src.includes(`data-intel-plan="${plan}"`), `missing ${plan} CTA`);
    assert.ok(src.includes(`href="https://intel.cyberdudebivash.com/upgrade.html?plan=${plan}&amp;utm_source=blog`), `${plan} CTA must link to the platform checkout without JavaScript`);
  }
  assert.doesNotMatch(src, /API Starter|Sentinel Team|Enterprise Apex/, 'retired blog plans must not be offered');
});

test('payment-flow.js keeps its public API but only forwards to the platform checkout', () => {
  const src = readFile('payment-flow.js');
  assert.doesNotMatch(src, /create-razorpay-order|verify-razorpay-payment|checkout\.razorpay\.com/);
  assert.match(src, /startUpgrade/);
  assert.match(src, /intel\.cyberdudebivash\.com\/upgrade\.html/);
});

test('browser plan mapping (intel-plans.js) equals the server mapping (payment-utils.js)', () => {
  const m = readFile('intel-plans.js').match(/var PLAN_FOR = (\{[^}]+\});/);
  assert.ok(m, 'PLAN_FOR not found in intel-plans.js');
  assert.deepStrictEqual(JSON.parse(JSON.stringify(vm.runInNewContext(`(${m[1]})`))), INTEL_PLAN_FOR);
  assert.strictEqual(new URL(intelUpgradeUrl('team', 'x')).searchParams.get('plan'), 'enterprise');
  assert.strictEqual(new URL(intelUpgradeUrl('unknown', 'x')).searchParams.has('plan'), false, 'unknown plans must not default to a paid plan');
});

/* Run intel-plans.js against a tiny DOM stub and a stubbed platform pricing
   response: prices appear only from a well-formed INR/paise document. */
function runIntelPlans(pricingDoc) {
  const els = ['PRO', 'ENTERPRISE', 'MSSP'].flatMap(tier => [
    { attrs: { 'data-intel-price': tier }, textContent: 'See price', setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k] ?? null; } },
    { attrs: { 'data-intel-price': tier, 'data-intel-period': 'annual', 'data-intel-currency': 'usd' }, textContent: 'See price', setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k] ?? null; } },
  ]);
  const document = {
    readyState: 'complete',
    querySelector: sel => (sel === '[data-intel-price]' ? els[0] : null),
    querySelectorAll: sel => (sel === '[data-intel-price]' ? els : []),
    addEventListener() {},
  };
  const window = { location: { href: '' } };
  const fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve(pricingDoc) });
  vm.runInNewContext(readFile('intel-plans.js'), { window, document, fetch, URLSearchParams, Promise, Math });
  return { els, window, settle: () => window.IntelCheckout.pricing().then(() => new Promise(r => setImmediate(r))) };
}

test('intel-plans.js fills prices from the platform pricing document', async () => {
  const doc = { currency: 'INR', unit: 'paise', tiers: {
    PRO: { monthly: 410000, annual: 4100000, usd_monthly: 49, usd_annual: 490 },
    ENTERPRISE: { monthly: 4160000, annual: 41600000, usd_monthly: 499, usd_annual: 4990 },
    MSSP: { monthly: 8330000, annual: 83300000, usd_monthly: 999, usd_annual: 9990 },
  } };
  const { els, settle } = runIntelPlans(doc);
  await settle();
  assert.deepStrictEqual(els.map(e => e.textContent), ['₹4,100', '$490', '₹41,600', '$4,990', '₹83,300', '$9,990']);
});

test('intel-plans.js leaves placeholders when the platform document is not INR/paise', async () => {
  const { els, settle } = runIntelPlans({ currency: 'USD', unit: 'cents', tiers: { PRO: { monthly: 1 } } });
  await settle();
  assert.ok(els.every(e => e.textContent === 'See price'));
});

test('intel-plans.js checkout URL maps retired blog plans and never defaults to a paid plan', () => {
  const { window } = runIntelPlans(null);
  const u = new URL(window.IntelCheckout.url('starter', 'pricing-card'));
  assert.strictEqual(u.origin + u.pathname, 'https://intel.cyberdudebivash.com/upgrade.html');
  assert.strictEqual(u.searchParams.get('plan'), 'pro');
  assert.strictEqual(u.searchParams.get('utm_source'), 'blog');
  assert.strictEqual(new URL(window.IntelCheckout.url('bogus')).searchParams.has('plan'), false);
});

test('generated posts lose retired plan prices at build time', () => {
  const html = '<a href="/pricing.html" class="btn-p">⚡ SOC Pro — $18/mo</a> IOC bundles — $18/mo. <span class="plan-tag">$18/mo</span>';
  const out = neutralizeLegacyCommercialCopy(html);
  assert.doesNotMatch(out, /\$18/);
  assert.match(out, /PRO Defense/);
  for (const [legacy] of RETIRED_PLAN_PRICE_COPY) {
    const once = neutralizeLegacyCommercialCopy(`<p>${legacy}</p>`);
    assert.doesNotMatch(once, HARDCODED_PLAN_PRICE, legacy);
    assert.doesNotMatch(once, /\$18/, legacy);
    assert.strictEqual(neutralizeLegacyCommercialCopy(once), once, 'rewrite must be idempotent');
  }
  const intel = '<p>LockBit demanded $18/month from victims in a subscription scheme.</p>';
  assert.strictEqual(neutralizeLegacyCommercialCopy(intel), intel, 'intelligence text is never rewritten');
});
