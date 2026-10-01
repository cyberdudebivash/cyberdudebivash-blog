/**
 * CYBERDUDEBIVASH SENTINEL APEX — Payment Flow Module (compatibility shim)
 *
 * Owner decision 2026-10-01: API plans are sold only on the Sentinel APEX
 * platform checkout (intel.cyberdudebivash.com/upgrade.html). The blog's
 * own plan checkout (Razorpay order + verification modal) is retired; the
 * server returns 410 PLAN_CHECKOUT_MOVED for new plan orders.
 *
 * DEPRECATED interface kept so existing pages and saved buttons keep
 * working: ApexPaymentFlow.startUpgrade(plan) now opens the platform
 * checkout for the nearest platform plan (mapping lives in intel-plans.js,
 * loaded on demand). ApexPaymentFlow.close() is a no-op.
 * Remove once no page calls ApexPaymentFlow (next major release).
 *
 * Premium intelligence reports are unaffected: they are bought in the
 * Intelligence Store (/intelligence-store.html).
 */
(function (global) {
  'use strict';

  var FALLBACK_URL = 'https://intel.cyberdudebivash.com/upgrade.html?utm_source=blog&utm_medium=payment-flow&utm_campaign=plan-checkout';
  var loading = null;

  function loadIntelPlans() {
    if (global.IntelCheckout) return Promise.resolve(global.IntelCheckout);
    if (loading) return loading;
    loading = new Promise(function (resolve) {
      var script = document.createElement('script');
      script.src = '/intel-plans.js';
      script.onload = function () { resolve(global.IntelCheckout || null); };
      script.onerror = function () { resolve(null); };
      document.head.appendChild(script);
    });
    return loading;
  }

  var ApexPaymentFlow = {
    startUpgrade: function (plan) {
      return loadIntelPlans().then(function (checkout) {
        if (checkout) checkout.go(plan, 'payment-flow');
        else global.location.href = FALLBACK_URL;
      });
    },
    close: function () {},
  };

  global.ApexPaymentFlow = ApexPaymentFlow;
})(typeof window !== 'undefined' ? window : global);
