/*
 * CYBERDUDEBIVASH SENTINEL APEX — Revenue Conversion Controller v19
 *
 * DEPRECATED 2026-10-01: buy.html no longer loads this controller; plans are
 * sold on the Sentinel APEX platform checkout and buy.html forwards there
 * (intel-plans.js). Kept published for any cached page that still loads it;
 * remove in the next major release.
 *
 * P0 objective: reduce paid-subscription checkout friction without changing
 * canonical prices, entitlements, payment verification, or customer identity.
 *
 * Privacy boundary: browser analytics emitted here contain plan + campaign
 * attribution only. Email, API keys, intent/order/payment IDs and payment
 * details are never copied into analytics payloads.
 */
(function (root, factory) {
  'use strict';
  const api = factory(root || null);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.ApexRevenueConversionV19 = api;
})(typeof window !== 'undefined' ? window : null, function (root) {
  'use strict';

  const VALID_PLANS = Object.freeze(['starter', 'pro', 'team', 'enterprise']);
  const PAYMENT_SESSION_KEY = 'apex_pf_state';
  const MANUAL_STATUS_INTERVAL_MS = 10000;
  const FALLBACK_PLANS = Object.freeze({
    starter: {
      label: 'API Starter', amount: 999, currency: 'INR',
      features: ['5,000 API calls/day', 'Weekly threat intelligence digest', 'Unlimited full-text search', 'Single authenticated API key'],
    },
    pro: {
      label: 'SOC Pro', amount: 1499, currency: 'INR',
      features: ['25,000 API calls/day', 'Complete IOC feed access', 'SIGMA + Yara detection rules', 'Authenticated full-intelligence API depth'],
    },
    team: {
      label: 'Sentinel Team', amount: 20699, currency: 'INR',
      features: ['100,000 API calls/day', 'STIX 2.1 bundle export', 'SIEM rule export (Splunk SPL / Sentinel KQL)', 'Live Microsoft Sentinel connector', 'All Pro capabilities'],
    },
    enterprise: {
      label: 'Enterprise Apex', amount: 82999, currency: 'INR',
      features: ['Unlimited API capacity', 'Dedicated analyst & custom SLA', 'White-label reporting', 'All Sentinel Team capabilities'],
    },
  });

  function sanitizePlan(value) {
    const plan = String(value || '').trim().toLowerCase();
    return VALID_PLANS.includes(plan) ? plan : null;
  }

  function safeToken(value, maxLen) {
    return String(value || '')
      .replace(/[^a-zA-Z0-9_.-]/g, '_')
      .slice(0, maxLen || 80);
  }

  function parseAttribution(search) {
    const params = new URLSearchParams(String(search || '').replace(/^\?/, ''));
    return {
      source: safeToken(params.get('utm_source') || 'direct', 80),
      medium: safeToken(params.get('utm_medium') || 'checkout', 80),
      campaign: safeToken(params.get('utm_campaign') || 'p0_revenue_conversion_v19', 100),
      content: safeToken(params.get('utm_content') || 'direct_checkout', 100),
    };
  }

  function formatPrice(plan) {
    const currency = plan && plan.currency === 'USD' ? '$' : '₹';
    const amount = Number(plan && plan.amount);
    if (!Number.isFinite(amount)) return '—';
    return `${currency}${amount.toLocaleString(plan && plan.currency === 'USD' ? 'en-US' : 'en-IN')}/month`;
  }

  function eventPayload(plan, attribution, extra) {
    const attr = attribution || { source: 'direct', medium: 'checkout', campaign: 'p0_revenue_conversion_v19', content: 'direct_checkout' };
    return Object.assign({
      plan: sanitizePlan(plan) || 'unknown',
      revenue_surface: 'buy_v19',
      utm_source: attr.source,
      utm_medium: attr.medium,
      utm_campaign: attr.campaign,
      utm_content: attr.content,
    }, extra || {});
  }

  function track(name, plan, attribution, extra) {
    if (!root) return;
    const payload = eventPayload(plan, attribution, extra);
    try {
      if (typeof root.trackEvent === 'function') {
        root.trackEvent(name, payload);
        return;
      }
      if (typeof root.gtag === 'function') {
        root.gtag('event', name, Object.assign({ platform: 'sentinel_apex' }, payload));
      }
    } catch (_) {}
  }

  /* The legacy billing status endpoint returns the authoritative manual-payment
   * state under payment_status. Keep this normalizer pure/testable so the v19
   * direct-checkout watcher cannot silently regress to reading a wrong top-level
   * status field. No identity or transaction value is returned from here. */
  function extractPaymentStatus(body) {
    const source = (body && body.payment_status)
      || (body && body.data && body.data.payment_status)
      || {};
    const status = String(source.status || 'pending_review').toLowerCase();
    return {
      status: ['pending_review', 'approved', 'rejected'].includes(status) ? status : 'pending_review',
      rejectionNote: String(source.rejection_note || ''),
    };
  }

  function verifiedPaymentCopy(plan) {
    const key = sanitizePlan(plan) || 'pro';
    const label = (FALLBACK_PLANS[key] || FALLBACK_PLANS.pro).label;
    return {
      title: `Payment Verified — ${label}`,
      subtitle: 'If this email already has a SENTINEL APEX account, paid access is active now. If not, register with the same email and the verified entitlement will activate automatically.',
      capabilityHeading: 'PLAN CAPABILITIES AFTER ACTIVATION',
    };
  }

  function applyVerifiedPaymentCopy(plan) {
    if (!root || !root.document) return;
    const copy = verifiedPaymentCopy(plan);
    const title = root.document.getElementById('pf-ok-title');
    const sub = root.document.getElementById('pf-ok-sub');
    if (title) title.textContent = copy.title;
    if (sub) sub.textContent = copy.subtitle;
    const unlock = root.document.getElementById('pf-unlock');
    const heading = unlock && unlock.querySelector ? unlock.querySelector('h4') : null;
    if (heading) heading.textContent = copy.capabilityHeading;
  }

  let manualStatusTimer = null;

  function stopManualStatusWatch() {
    if (manualStatusTimer && root && typeof root.clearInterval === 'function') {
      root.clearInterval(manualStatusTimer);
    }
    manualStatusTimer = null;
  }

  function readPaymentSession() {
    if (!root || !root.sessionStorage) return null;
    try {
      const parsed = JSON.parse(root.sessionStorage.getItem(PAYMENT_SESSION_KEY) || 'null');
      if (!parsed || typeof parsed !== 'object') return null;
      return parsed;
    } catch (_) {
      return null;
    }
  }

  function startManualStatusWatch(flow, plan, attribution) {
    if (!root || typeof root.fetch !== 'function' || !flow) return false;
    const session = readPaymentSession();
    if (!session || !session.transactionId || !session.email) return false;

    stopManualStatusWatch();
    let stopped = false;
    const finish = () => {
      stopped = true;
      stopManualStatusWatch();
    };

    const check = async () => {
      if (stopped) return;
      try {
        const url = `/api/v1/billing?action=status&transaction_id=${encodeURIComponent(session.transactionId)}&email=${encodeURIComponent(session.email)}`;
        const response = await root.fetch(url, { credentials: 'same-origin' });
        if (!response.ok) return;
        const body = await response.json();
        if (!body || body.success !== true) return;
        const payment = extractPaymentStatus(body);

        if (payment.status === 'approved') {
          finish();
          try { root.sessionStorage.removeItem(PAYMENT_SESSION_KEY); } catch (_) {}
          flow._go(5);
          applyVerifiedPaymentCopy(plan);
          track('manual_payment_verified', plan, attribution, { checkout_version: 'v19' });
          return;
        }

        if (payment.status === 'rejected') {
          finish();
          const doc = root.document;
          const badge = doc && doc.getElementById('pf-status-badge');
          const sub = doc && doc.getElementById('pf-poll-sub');
          if (badge) {
            badge.className = 'pf-badge rejected';
            badge.textContent = '✗ Rejected';
          }
          if (sub) sub.textContent = payment.rejectionNote || 'Payment could not be verified. Contact billing support with your Intent ID.';
          track('manual_payment_rejected', plan, attribution, { checkout_version: 'v19' });
        }
      } catch (_) {
        /* Fail open to the original payment-flow poller; never mutate billing. */
      }
    };

    check();
    if (typeof root.setInterval === 'function') {
      manualStatusTimer = root.setInterval(check, MANUAL_STATUS_INTERVAL_MS);
    }
    return true;
  }

  function instrumentPaymentFlow(flow, plan, attribution) {
    if (!flow || flow.__cdbRevenueV19Instrumented) return flow;
    let completionTracked = false;

    if (typeof flow.startUpgrade === 'function') {
      const innerStart = flow.startUpgrade.bind(flow);
      flow.startUpgrade = async function (requestedPlan) {
        const selected = sanitizePlan(requestedPlan) || plan;
        track('checkout_start', selected, attribution, { checkout_version: 'v19' });
        return innerStart(selected);
      };
    }

    if (typeof flow._go === 'function') {
      const innerGo = flow._go.bind(flow);
      flow._go = function (step) {
        const result = innerGo(step);
        const n = Number(step);
        if (n >= 1 && n <= 5) {
          track('checkout_step', plan, attribution, { step: n });
          if (n === 4) startManualStatusWatch(flow, plan, attribution);
          if (n === 5) {
            stopManualStatusWatch();
            /* The shared payment-flow historically says "Tier Activated" even
             * when a verified pre-registration payment is intentionally held as
             * a pending entitlement. v19 replaces only the customer copy with a
             * statement that is correct for both backend outcomes. */
            applyVerifiedPaymentCopy(plan);
            if (!completionTracked) {
              completionTracked = true;
              track('checkout_complete', plan, attribution, { checkout_version: 'v19' });
            }
          }
        }
        return result;
      };
    }

    if (typeof flow.close === 'function') {
      const innerClose = flow.close.bind(flow);
      flow.close = function () {
        stopManualStatusWatch();
        track('checkout_closed', plan, attribution, { before_completion: !completionTracked });
        return innerClose();
      };
    }

    Object.defineProperty(flow, '__cdbRevenueV19Instrumented', {
      value: true, enumerable: false, configurable: false,
    });
    return flow;
  }

  async function loadCanonicalPlan(plan) {
    if (!root || typeof root.fetch !== 'function') return FALLBACK_PLANS[plan];
    try {
      const response = await root.fetch('/api/v1/billing?action=plans', { credentials: 'same-origin' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = await response.json();
      const plans = body.plans || (body.data && body.data.plans) || {};
      const canonical = plans[plan];
      if (!canonical) throw new Error('PLAN_NOT_FOUND');
      return {
        label: canonical.label || FALLBACK_PLANS[plan].label,
        amount: Number(canonical.amount),
        currency: canonical.currency || 'INR',
        features: FALLBACK_PLANS[plan].features,
      };
    } catch (_) {
      return FALLBACK_PLANS[plan];
    }
  }

  function applyPlanUI(planKey, plan) {
    if (!root || !root.document) return;
    const doc = root.document;
    const set = (id, value) => {
      const node = doc.getElementById(id);
      if (node) node.textContent = value;
    };
    set('buyPlanName', plan.label);
    set('buyPlanPrice', formatPrice(plan));
    set('buyPlanTag', planKey.toUpperCase());
    set('buyCtaLabel', `Continue to ${plan.label} Checkout`);
    const list = doc.getElementById('buyFeatures');
    if (list) {
      list.innerHTML = '';
      for (const feature of plan.features || []) {
        const li = doc.createElement('li');
        li.textContent = feature;
        list.appendChild(li);
      }
    }
  }

  let activePlan = null;
  let activeAttribution = null;

  async function begin() {
    if (!root) return false;
    const flow = root.ApexPaymentFlow;
    if (!flow || !activePlan) return false;
    instrumentPaymentFlow(flow, activePlan, activeAttribution);
    await flow.startUpgrade(activePlan);
    return true;
  }

  async function init() {
    if (!root || !root.document || !root.location) return null;
    const params = new URLSearchParams(root.location.search || '');
    activePlan = sanitizePlan(params.get('plan')) || 'pro';
    activeAttribution = parseAttribution(root.location.search || '');

    const plan = await loadCanonicalPlan(activePlan);
    applyPlanUI(activePlan, plan);
    track('checkout_landing_view', activePlan, activeAttribution, { checkout_version: 'v19' });

    const flow = root.ApexPaymentFlow;
    if (flow) instrumentPaymentFlow(flow, activePlan, activeAttribution);

    const button = root.document.getElementById('buyNowButton');
    if (button) button.addEventListener('click', begin);

    if (params.get('checkout') === '1') {
      root.setTimeout(function () { begin(); }, 120);
    }
    return { plan: activePlan, attribution: activeAttribution };
  }

  if (root && root.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', init, { once: true });
    else init();
  }

  return {
    VALID_PLANS,
    FALLBACK_PLANS,
    sanitizePlan,
    safeToken,
    parseAttribution,
    formatPrice,
    eventPayload,
    extractPaymentStatus,
    verifiedPaymentCopy,
    instrumentPaymentFlow,
    loadCanonicalPlan,
    begin,
    init,
  };
});