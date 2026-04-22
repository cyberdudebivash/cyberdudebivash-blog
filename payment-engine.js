/**
 * CYBERDUDEBIVASH — PAYMENT ENGINE v1.0
 * Stripe-ready purchase flow with dynamic pricing integration
 * Replace YOUR_STRIPE_PUBLISHABLE_KEY and price IDs with real Stripe values
 * Setup: https://dashboard.stripe.com/products
 */

(function() {
  'use strict';

  // ─────────────────────────────────────────────
  // § 1. STRIPE CONFIGURATION
  // ─────────────────────────────────────────────
  var STRIPE_CONFIG = {
    publishable_key: 'YOUR_STRIPE_PUBLISHABLE_KEY',   // pk_live_... or pk_test_...
    success_url: window.location.origin + '/order-confirmation.html?session_id={CHECKOUT_SESSION_ID}',
    cancel_url:  window.location.href,

    // Product catalog — map to your Stripe Price IDs
    // Create products at: https://dashboard.stripe.com/products
    products: {
      'ioc-megapack': {
        id: 'ioc-megapack',
        name: 'IOC Megapack 2026',
        description: '50,000+ verified indicators of compromise',
        price: 49,
        stripe_price_id: 'price_IOC_MEGAPACK_ID',     // Replace with real Stripe price ID
        category: 'intelligence',
        badge: 'BEST SELLER'
      },
      'sigma-ruleset': {
        id: 'sigma-ruleset',
        name: 'Sigma Detection Ruleset',
        description: '500+ production-ready Sigma rules',
        price: 79,
        stripe_price_id: 'price_SIGMA_RULESET_ID',
        category: 'detection',
        badge: null
      },
      'yara-bundle': {
        id: 'yara-bundle',
        name: 'YARA Rule Bundle',
        description: '200+ YARA rules for ransomware & APT',
        price: 69,
        stripe_price_id: 'price_YARA_BUNDLE_ID',
        category: 'detection',
        badge: null
      },
      'threat-report-q2': {
        id: 'threat-report-q2',
        name: 'Q2 2026 Threat Landscape Report',
        description: '150-page deep-dive threat intelligence report',
        price: 99,
        stripe_price_id: 'price_THREAT_REPORT_Q2_ID',
        category: 'reports',
        badge: 'NEW'
      },
      'cve-intel-pack': {
        id: 'cve-intel-pack',
        name: 'CVE Intelligence Pack',
        description: 'PoC details, patch analysis, detection logic for 100 CVEs',
        price: 129,
        stripe_price_id: 'price_CVE_INTEL_PACK_ID',
        category: 'intelligence',
        badge: null
      },
      'stix-feed': {
        id: 'stix-feed',
        name: 'STIX 2.1 Threat Feed',
        description: 'Machine-readable structured threat intelligence',
        price: 149,
        stripe_price_id: 'price_STIX_FEED_ID',
        category: 'feeds',
        badge: null
      },
      'soc-starter': {
        id: 'soc-starter',
        name: 'SOC Starter Bundle',
        description: 'IOC Pack + Sigma Rules + YARA + Quick Reference Cards',
        price: 149,
        stripe_price_id: 'price_SOC_STARTER_ID',
        category: 'bundles',
        badge: 'BUNDLE'
      },
      'enterprise-detection': {
        id: 'enterprise-detection',
        name: 'Enterprise Detection Bundle',
        description: 'Sigma + YARA + Threat Report + CVE Intel + STIX Feed',
        price: 249,
        stripe_price_id: 'price_ENTERPRISE_DETECTION_ID',
        category: 'bundles',
        badge: 'BUNDLE'
      },
      'complete-arsenal': {
        id: 'complete-arsenal',
        name: 'Complete Arsenal',
        description: 'Everything — all products + 6 months priority updates',
        price: 499,
        stripe_price_id: 'price_COMPLETE_ARSENAL_ID',
        category: 'bundles',
        badge: 'BEST VALUE'
      },
      'api-starter': {
        id: 'api-starter',
        name: 'Threat Intel API — Starter',
        description: '10,000 calls/month, CVE + IOC endpoints',
        price: 49,
        stripe_price_id: 'price_API_STARTER_ID',
        category: 'api',
        badge: null,
        recurring: true,
        interval: 'month'
      },
      'api-pro': {
        id: 'api-pro',
        name: 'Threat Intel API — Pro',
        description: '100,000 calls/month + STIX feed + Sigma export',
        price: 199,
        stripe_price_id: 'price_API_PRO_ID',
        category: 'api',
        badge: 'POPULAR',
        recurring: true,
        interval: 'month'
      },
      'api-enterprise': {
        id: 'api-enterprise',
        name: 'Threat Intel API — Enterprise',
        description: 'Unlimited calls + SLA + dedicated support',
        price: 499,
        stripe_price_id: 'price_API_ENTERPRISE_ID',
        category: 'api',
        badge: null,
        recurring: true,
        interval: 'month'
      }
    }
  };

  // ─────────────────────────────────────────────
  // § 2. STRIPE LOADER
  // ─────────────────────────────────────────────
  var _stripe = null;

  function loadStripe(cb) {
    if (STRIPE_CONFIG.publishable_key.startsWith('YOUR_')) {
      if (cb) cb(null);
      return;
    }
    if (_stripe) { if (cb) cb(_stripe); return; }
    if (window.Stripe) { _stripe = window.Stripe(STRIPE_CONFIG.publishable_key); if (cb) cb(_stripe); return; }

    var s = document.createElement('script');
    s.src = 'https://js.stripe.com/v3/';
    s.onload = function() {
      _stripe = window.Stripe(STRIPE_CONFIG.publishable_key);
      if (cb) cb(_stripe);
    };
    document.head.appendChild(s);
  }

  // ─────────────────────────────────────────────
  // § 3. CHECKOUT FLOW
  // ─────────────────────────────────────────────
  var CHECKOUT = {

    /**
     * Open Stripe Checkout for a product ID
     * Integrates with ai-monetization-engine dynamic pricing
     */
    open: function(productId) {
      var product = STRIPE_CONFIG.products[productId];
      if (!product) {
        console.warn('[PE] Unknown product:', productId);
        return;
      }

      // Get dynamic price if AIM is loaded
      var finalPrice = product.price;
      var priceLabel = '';
      if (window.AIM && window.AIM.DYNPRICE) {
        var dp = window.AIM.DYNPRICE.compute(product.price);
        finalPrice = dp.final;
        priceLabel = dp.label;
      }

      // Track with analytics engine
      if (window.AE) {
        window.AE.ecommerce.beginCheckout({ id: product.id, name: product.name, price: finalPrice });
      } else if (window.trackEvent) {
        window.trackEvent({ category: 'conversion', action: 'begin_checkout', label: product.name, value: finalPrice });
      }

      // If Stripe key not configured — show setup modal
      if (STRIPE_CONFIG.publishable_key.startsWith('YOUR_')) {
        CHECKOUT._showSetupRequired(product, finalPrice);
        return;
      }

      loadStripe(function(stripe) {
        if (!stripe) return;

        // Show loading state on button
        var btn = document.querySelector('[data-product="' + productId + '"]');
        if (btn) { btn.disabled = true; btn.textContent = 'Loading...'; }

        // Create checkout session via your backend
        // Option A: Stripe Checkout (requires backend /create-checkout-session endpoint)
        // Option B: Payment Links (no backend needed) — set stripe_payment_link in product config
        if (product.stripe_payment_link) {
          window.location.href = product.stripe_payment_link;
          return;
        }

        // Option B fallback: direct payment link placeholder
        // TODO: Replace with your Vercel/Netlify serverless function
        fetch('/api/create-checkout-session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            price_id:    product.stripe_price_id,
            product_id:  product.id,
            success_url: STRIPE_CONFIG.success_url,
            cancel_url:  STRIPE_CONFIG.cancel_url
          })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.sessionId) {
            return stripe.redirectToCheckout({ sessionId: data.sessionId });
          } else if (data.url) {
            window.location.href = data.url;
          }
        })
        .catch(function(err) {
          console.error('[PE] Checkout error:', err);
          if (btn) { btn.disabled = false; btn.textContent = 'Buy Now'; }
          CHECKOUT._showPaymentLinkFallback(product);
        });
      });
    },

    _showSetupRequired: function(product, price) {
      // Show a professional "coming soon / waitlist" modal instead of broken checkout
      var overlay = document.createElement('div');
      overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;';
      overlay.innerHTML = '<div style="background:#0d1117;border:1px solid #00ff88;border-radius:12px;padding:40px;max-width:480px;width:90%;text-align:center;">' +
        '<div style="font-size:2em;margin-bottom:16px;">🔒</div>' +
        '<h2 style="color:#00ff88;margin:0 0 8px;">' + product.name + '</h2>' +
        '<p style="color:#aaa;margin:0 0 16px;">$' + price + ' USD</p>' +
        '<p style="color:#ccc;margin:0 0 24px;">Secure checkout via Stripe. Complete your purchase to get instant access.</p>' +
        '<a href="mailto:bivash@cyberdudebivash.com?subject=Purchase: ' + encodeURIComponent(product.name) + '&body=I want to purchase ' + encodeURIComponent(product.name) + ' for $' + price + '" ' +
        'style="display:inline-block;background:#00ff88;color:#000;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:1.1em;">📧 Complete Purchase via Email</a>' +
        '<p style="color:#666;font-size:0.85em;margin:16px 0 0;">We\'ll send your download link within 24 hours</p>' +
        '<button onclick="this.closest(\'div\').parentElement.remove()" style="background:transparent;border:none;color:#666;cursor:pointer;margin-top:12px;font-size:0.9em;">✕ Close</button>' +
        '</div>';
      document.body.appendChild(overlay);
    },

    _showPaymentLinkFallback: function(product) {
      // If backend not available, show email-based purchase option
      alert('Redirecting to secure purchase. Please contact bivash@cyberdudebivash.com to complete your order for: ' + product.name);
    }
  };

  // ─────────────────────────────────────────────
  // § 4. BUY BUTTON AUTO-WIRING
  // ─────────────────────────────────────────────
  var BUTTON_WIRER = {
    init: function() {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', this.wire.bind(this));
      } else {
        this.wire();
      }
    },

    wire: function() {
      // Wire all [data-product] buy buttons
      var btns = document.querySelectorAll('[data-product]');
      for (var i = 0; i < btns.length; i++) {
        (function(btn) {
          var productId = btn.getAttribute('data-product');
          if (!btn.getAttribute('data-pe-wired')) {
            btn.setAttribute('data-pe-wired', '1');
            btn.addEventListener('click', function(e) {
              e.preventDefault();
              CHECKOUT.open(productId);
            });

            // Inject dynamic price display
            var product = STRIPE_CONFIG.products[productId];
            if (product && window.AIM && window.AIM.DYNPRICE) {
              var dp = window.AIM.DYNPRICE.compute(product.price);
              var priceEl = document.querySelector('[data-price="' + productId + '"]');
              if (priceEl) {
                if (dp.discount > 0) {
                  priceEl.innerHTML = '<span style="text-decoration:line-through;opacity:0.5;font-size:0.85em;">$' + product.price + '</span> ' +
                    '<span style="color:#00ff88;">$' + dp.final + '</span> ' +
                    '<span style="background:#ff4444;color:#fff;font-size:0.75em;padding:2px 6px;border-radius:4px;">' + dp.label + '</span>';
                } else {
                  priceEl.textContent = '$' + product.price;
                }
              }
            }

            // Track product view
            if (product && window.AE) {
              window.AE.ecommerce.viewItem(product);
            }
          }
        })(btns[i]);
      }
    }
  };

  // ─────────────────────────────────────────────
  // § 5. ORDER CONFIRMATION HANDLER
  // ─────────────────────────────────────────────
  var ORDER_CONFIRMATION = {
    init: function() {
      if (window.location.pathname.indexOf('order-confirmation') < 0) return;

      var params = new URLSearchParams(window.location.search);
      var sessionId = params.get('session_id');
      var productId = params.get('product') || localStorage.getItem('cdb_last_product');

      if (sessionId || productId) {
        var product = STRIPE_CONFIG.products[productId] || { name: 'Your Product', price: 0, id: productId };

        // Fire purchase event
        if (window.AE) {
          window.AE.ecommerce.purchase(product, sessionId);
        }

        // Update revenue tracker
        try {
          var revenue = JSON.parse(localStorage.getItem('cdb_revenue')) || { total: 0, orders: [] };
          revenue.total += product.price;
          revenue.orders.push({ id: sessionId, product: product.id, amount: product.price, ts: Date.now() });
          if (revenue.orders.length > 100) revenue.orders = revenue.orders.slice(-100);
          localStorage.setItem('cdb_revenue', JSON.stringify(revenue));
        } catch(e) {}

        // Clear pending product
        localStorage.removeItem('cdb_last_product');
      }
    }
  };

  // ─────────────────────────────────────────────
  // § 6. API KEY REQUEST FORM HANDLER
  // ─────────────────────────────────────────────
  var API_FORM = {
    init: function() {
      var form = document.getElementById('api-key-request-form');
      if (!form) return;

      form.addEventListener('submit', function(e) {
        e.preventDefault();
        var data = {
          name:    (form.querySelector('[name=name]') || {}).value || '',
          email:   (form.querySelector('[name=email]') || {}).value || '',
          company: (form.querySelector('[name=company]') || {}).value || '',
          plan:    (form.querySelector('[name=plan]') || {}).value || 'starter',
          use_case:(form.querySelector('[name=use_case]') || {}).value || ''
        };

        if (window.trackEvent) window.trackEvent({ category: 'conversion', action: 'api_page_visit', label: data.plan });

        // Store lead locally
        try {
          var leads = JSON.parse(localStorage.getItem('cdb_api_leads')) || [];
          leads.push(Object.assign(data, { ts: Date.now() }));
          localStorage.setItem('cdb_api_leads', JSON.stringify(leads));
        } catch(e) {}

        // Submit via formsubmit.co
        var hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = '_subject';
        hidden.value = 'API Key Request: ' + data.plan + ' plan — ' + data.email;
        form.appendChild(hidden);
        form.action = 'https://formsubmit.co/bivash@cyberdudebivash.com';
        form.method = 'POST';
        form.submit();
      });
    }
  };

  // ─────────────────────────────────────────────
  // § 7. INIT
  // ─────────────────────────────────────────────
  window.PE = {
    checkout:  CHECKOUT,
    products:  STRIPE_CONFIG.products,
    openCheckout: function(id) { CHECKOUT.open(id); }
  };

  BUTTON_WIRER.init();
  ORDER_CONFIRMATION.init();
  API_FORM.init();

  // Allow other scripts to wire buttons after DOM updates
  window.PE.rewire = function() { BUTTON_WIRER.wire(); };

})();
