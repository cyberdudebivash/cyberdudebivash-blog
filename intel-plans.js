/**
 * CYBERDUDEBIVASH SENTINEL APEX — Platform plan checkout links
 *
 * Owner decision 2026-10-01: API plans are sold only on the Sentinel APEX
 * platform checkout (intel.cyberdudebivash.com/upgrade.html). That platform
 * owns plan prices, so this script never hardcodes one: it reads them from
 * the platform's public pricing endpoint and fills elements marked
 * data-intel-price. Until (or unless) that succeeds the element keeps its
 * neutral placeholder text, so the blog can never show a price the
 * platform does not charge.
 *
 * Markup:
 *   <a data-intel-plan="pro" data-intel-medium="pricing-card">…</a>
 *       href is set to the platform checkout for that plan (UTM-tagged)
 *   <span data-intel-price="PRO" data-intel-period="monthly|annual"
 *         data-intel-currency="inr|usd">…</span>
 *
 * API: window.IntelCheckout.url(plan, medium), .go(plan, medium)
 */
(function () {
  'use strict';

  var UPGRADE_URL = 'https://intel.cyberdudebivash.com/upgrade.html';
  var PRICING_URL = 'https://intel.cyberdudebivash.com/api/pricing';
  // Same mapping as api/_lib/payment-utils.js INTEL_PLAN_FOR (retired blog
  // plan names keep working for old links and saved buttons).
  var PLAN_FOR = { starter: 'pro', pro: 'pro', team: 'enterprise', enterprise: 'enterprise', mssp: 'mssp' };
  var TIER_FOR = { pro: 'PRO', enterprise: 'ENTERPRISE', mssp: 'MSSP' };

  function url(plan, medium) {
    var params = new URLSearchParams();
    var mapped = PLAN_FOR[String(plan || '').toLowerCase()];
    if (mapped) params.set('plan', mapped);
    params.set('utm_source', 'blog');
    params.set('utm_medium', String(medium || 'cta').replace(/[^a-z0-9-]/gi, '').slice(0, 30) || 'cta');
    params.set('utm_campaign', 'plan-checkout');
    return UPGRADE_URL + '?' + params.toString();
  }

  function track(plan, medium) {
    try {
      if (typeof window.gtag === 'function') {
        window.gtag('event', 'begin_checkout', { plan: PLAN_FOR[plan] || 'none', placement: medium || 'cta', destination: 'sentinel-apex-platform' });
      }
    } catch (_) { /* analytics must never block checkout */ }
  }

  function go(plan, medium) {
    track(plan, medium);
    window.location.href = url(plan, medium);
  }

  function bindLinks(root) {
    var links = (root || document).querySelectorAll('a[data-intel-plan]');
    for (var i = 0; i < links.length; i++) {
      var a = links[i];
      a.href = url(a.getAttribute('data-intel-plan'), a.getAttribute('data-intel-medium'));
      a.rel = 'noopener';
      if (!a.__intelBound) {
        a.__intelBound = true;
        a.addEventListener('click', function () {
          track(this.getAttribute('data-intel-plan'), this.getAttribute('data-intel-medium'));
        });
      }
    }
  }

  function formatAmount(tier, period, currency) {
    if (!tier) return null;
    if (currency === 'usd') {
      var usd = period === 'annual' ? tier.usd_annual : tier.usd_monthly;
      return typeof usd === 'number' && usd > 0 ? '$' + usd.toLocaleString('en-US') : null;
    }
    var paise = period === 'annual' ? tier.annual : tier.monthly;
    if (typeof paise !== 'number' || paise <= 0) return null;
    return '₹' + Math.round(paise / 100).toLocaleString('en-IN');
  }

  function fillPrices(data) {
    if (!data) return;
    var els = document.querySelectorAll('[data-intel-price]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      var key = String(el.getAttribute('data-intel-price') || '').toUpperCase();
      var text = formatAmount(data.tiers[key], el.getAttribute('data-intel-period') || 'monthly',
        (el.getAttribute('data-intel-currency') || 'inr').toLowerCase());
      if (text) {
        el.textContent = text;
        el.setAttribute('data-intel-loaded', 'true');
      }
    }
  }

  var pricingPromise = null;
  // Resolves to the platform's pricing document, or null if unavailable.
  function pricing() {
    if (pricingPromise) return pricingPromise;
    if (typeof fetch !== 'function') return (pricingPromise = Promise.resolve(null));
    pricingPromise = fetch(PRICING_URL, { mode: 'cors', credentials: 'omit' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) { return data && data.currency === 'INR' && data.unit === 'paise' && data.tiers ? data : null; })
      .catch(function () { return null; /* placeholders stay; checkout shows the price */ });
    return pricingPromise;
  }

  function loadPrices() {
    if (!document.querySelector('[data-intel-price]')) return;
    pricing().then(fillPrices);
  }

  function init() { bindLinks(document); loadPrices(); }

  window.IntelCheckout = { url: url, go: go, bindLinks: bindLinks, pricing: pricing, tierFor: TIER_FOR };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
