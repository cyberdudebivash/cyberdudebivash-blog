/**
 * CYBERDUDEBIVASH — ANALYTICS ENGINE v1.0
 * Full GA4 + Google Ads unified event tracking system
 * Replace YOUR_GA4_MEASUREMENT_ID and YOUR_GADS_ID with real values
 */

(function() {
  'use strict';

  // ─────────────────────────────────────────────
  // § 1. CONFIGURATION
  // ─────────────────────────────────────────────
  var CONFIG = {
    GA4_ID: 'YOUR_GA4_MEASUREMENT_ID',       // e.g. G-XXXXXXXXXX
    GADS_ID: 'YOUR_GADS_CONVERSION_ID',      // e.g. AW-XXXXXXXXXX
    GADS_CONVERSIONS: {
      enterprise_form:   'YOUR_CONVERSION_LABEL_1',
      email_signup:      'YOUR_CONVERSION_LABEL_2',
      product_click:     'YOUR_CONVERSION_LABEL_3',
      api_page_visit:    'YOUR_CONVERSION_LABEL_4'
    },
    FB_PIXEL_ID: 'YOUR_FACEBOOK_PIXEL_ID',
    DEBUG: false,
    SESSION_KEY: 'cdb_analytics_session',
    EVENTS_KEY:  'cdb_events_log',
    MAX_EVENTS:  500
  };

  // ─────────────────────────────────────────────
  // § 2. GTAG LOADER
  // ─────────────────────────────────────────────
  function loadGtag() {
    if (CONFIG.GA4_ID.startsWith('YOUR_')) return;
    if (window.__cdb_gtag_loaded) return;
    window.__cdb_gtag_loaded = true;

    // Google tag (gtag.js)
    var s = document.createElement('script');
    s.async = true;
    s.src = 'https://www.googletagmanager.com/gtag/js?id=' + CONFIG.GA4_ID;
    document.head.appendChild(s);

    window.dataLayer = window.dataLayer || [];
    window.gtag = function() { window.dataLayer.push(arguments); };
    window.gtag('js', new Date());
    window.gtag('config', CONFIG.GA4_ID, {
      send_page_view: true,
      cookie_flags: 'SameSite=None;Secure',
      custom_map: {
        dimension1: 'user_segment',
        dimension2: 'intent_score',
        dimension3: 'visit_count',
        metric1: 'scroll_depth'
      }
    });

    if (!CONFIG.GADS_ID.startsWith('YOUR_')) {
      window.gtag('config', CONFIG.GADS_ID);
    }
  }

  // ─────────────────────────────────────────────
  // § 3. FACEBOOK PIXEL LOADER
  // ─────────────────────────────────────────────
  function loadFBPixel() {
    if (CONFIG.FB_PIXEL_ID.startsWith('YOUR_')) return;
    !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?
    n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;
    n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
    t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}
    (window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
    window.fbq('init', CONFIG.FB_PIXEL_ID);
    window.fbq('track', 'PageView');
  }

  // ─────────────────────────────────────────────
  // § 4. SESSION MANAGER
  // ─────────────────────────────────────────────
  var SESSION = {
    data: null,

    init: function() {
      try {
        this.data = JSON.parse(localStorage.getItem(CONFIG.SESSION_KEY)) || {};
      } catch(e) { this.data = {}; }

      if (!this.data.session_id) this.data.session_id = 'cdb_' + Date.now() + '_' + Math.random().toString(36).substr(2,9);
      if (!this.data.first_visit) this.data.first_visit = Date.now();
      this.data.last_visit = Date.now();
      this.data.visit_count = (this.data.visit_count || 0) + 1;
      this.data.page_views  = (this.data.page_views  || 0) + 1;

      // UTM capture
      var params = new URLSearchParams(window.location.search);
      ['utm_source','utm_medium','utm_campaign','utm_term','utm_content'].forEach(function(k) {
        if (params.get(k)) this.data[k] = params.get(k);
      }, this);

      // Referrer
      if (document.referrer && !this.data.referrer) {
        this.data.referrer = document.referrer;
      }

      this.save();
      return this;
    },

    get: function(key) { return this.data ? this.data[key] : null; },
    set: function(key, val) { if (this.data) { this.data[key] = val; this.save(); } },

    save: function() {
      try { localStorage.setItem(CONFIG.SESSION_KEY, JSON.stringify(this.data)); } catch(e) {}
    }
  };

  // ─────────────────────────────────────────────
  // § 5. UNIFIED EVENT TRACKER (CORE)
  // ─────────────────────────────────────────────
  var ANALYTICS = {

    /**
     * trackEvent({ category, action, label, value, nonInteraction })
     * Fires to: GA4, Google Ads (if conversion), Facebook Pixel, localStorage log
     */
    trackEvent: function(opts) {
      if (!opts || !opts.action) return;

      var payload = {
        event_category:   opts.category   || 'general',
        event_label:      opts.label      || '',
        value:            opts.value      || 0,
        non_interaction:  opts.nonInteraction || false,
        user_segment:     SESSION.get('segment')   || 'unknown',
        intent_score:     SESSION.get('intentScore') || 0,
        visit_count:      SESSION.get('visit_count')  || 1,
        page_path:        window.location.pathname,
        session_id:       SESSION.get('session_id')
      };

      // GA4
      if (window.gtag && !CONFIG.GA4_ID.startsWith('YOUR_')) {
        window.gtag('event', opts.action, payload);
      }

      // Google Ads conversion ping
      if (window.gtag && CONFIG.GADS_CONVERSIONS[opts.action]) {
        window.gtag('event', 'conversion', {
          send_to: CONFIG.GADS_ID + '/' + CONFIG.GADS_CONVERSIONS[opts.action],
          value:   opts.value || 0,
          currency: 'USD'
        });
      }

      // Facebook Pixel
      if (window.fbq) {
        var fbMap = {
          purchase:            'Purchase',
          email_signup:        'Lead',
          enterprise_form:     'Lead',
          product_click:       'AddToCart',
          api_page_visit:      'ViewContent',
          cta_click:           'InitiateCheckout'
        };
        if (fbMap[opts.action]) {
          window.fbq('track', fbMap[opts.action], { value: opts.value || 0, currency: 'USD' });
        } else {
          window.fbq('trackCustom', opts.action, payload);
        }
      }

      // localStorage event log
      this._logLocal(opts.action, payload);

      if (CONFIG.DEBUG) console.log('[AE] Event:', opts.action, payload);
    },

    _logLocal: function(action, payload) {
      try {
        var log = JSON.parse(localStorage.getItem(CONFIG.EVENTS_KEY)) || [];
        log.push({ ts: Date.now(), action: action, data: payload });
        if (log.length > CONFIG.MAX_EVENTS) log = log.slice(-CONFIG.MAX_EVENTS);
        localStorage.setItem(CONFIG.EVENTS_KEY, JSON.stringify(log));

        // Update conversion counters for admin dashboard
        var counters = JSON.parse(localStorage.getItem('cdb_counters')) || {};
        counters[action] = (counters[action] || 0) + 1;
        counters._total  = (counters._total  || 0) + 1;
        counters._last_updated = Date.now();
        localStorage.setItem('cdb_counters', JSON.stringify(counters));
      } catch(e) {}
    }
  };

  // ─────────────────────────────────────────────
  // § 6. SCROLL DEPTH TRACKER
  // ─────────────────────────────────────────────
  var SCROLL_TRACKER = {
    milestones: [25, 50, 75, 90, 100],
    reached: {},

    init: function() {
      var self = this;
      var ticking = false;

      window.addEventListener('scroll', function() {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(function() {
          self.check();
          ticking = false;
        });
      }, { passive: true });
    },

    check: function() {
      var scrollTop = window.pageYOffset || document.documentElement.scrollTop;
      var docHeight = Math.max(
        document.body.scrollHeight, document.documentElement.scrollHeight,
        document.body.offsetHeight, document.documentElement.offsetHeight
      ) - window.innerHeight;

      if (docHeight <= 0) return;
      var pct = Math.round((scrollTop / docHeight) * 100);

      for (var i = 0; i < this.milestones.length; i++) {
        var m = this.milestones[i];
        if (pct >= m && !this.reached[m]) {
          this.reached[m] = true;
          ANALYTICS.trackEvent({
            category: 'engagement',
            action: 'scroll_depth',
            label: m + '%',
            value: m,
            nonInteraction: true
          });
          SESSION.set('max_scroll', m);
        }
      }
    }
  };

  // ─────────────────────────────────────────────
  // § 7. CTA CLICK TRACKER
  // ─────────────────────────────────────────────
  var CTA_TRACKER = {
    init: function() {
      document.addEventListener('click', function(e) {
        var el = e.target;
        // Walk up 3 levels to find trackable element
        for (var i = 0; i < 3; i++) {
          if (!el) break;
          var text = (el.innerText || '').trim().toLowerCase();
          var href = el.href || '';
          var cls  = el.className || '';

          // Product purchase clicks
          if (cls.indexOf('buy-now') >= 0 || cls.indexOf('purchase') >= 0 ||
              text.indexOf('buy now') >= 0 || text.indexOf('get access') >= 0) {
            ANALYTICS.trackEvent({ category: 'conversion', action: 'product_click', label: text || href });
            break;
          }
          // Email / lead capture
          if (cls.indexOf('lead-cta') >= 0 || text.indexOf('free download') >= 0 ||
              text.indexOf('get free') >= 0 || text.indexOf('subscribe') >= 0) {
            ANALYTICS.trackEvent({ category: 'conversion', action: 'email_signup', label: text });
            break;
          }
          // Enterprise
          if (href.indexOf('enterprise') >= 0 || text.indexOf('enterprise') >= 0 ||
              text.indexOf('talk to analyst') >= 0 || text.indexOf('book a call') >= 0) {
            ANALYTICS.trackEvent({ category: 'conversion', action: 'enterprise_form', label: text });
            break;
          }
          // API
          if (href.indexOf('api') >= 0 || cls.indexOf('api-cta') >= 0) {
            ANALYTICS.trackEvent({ category: 'conversion', action: 'api_page_visit', label: href });
            break;
          }
          // Generic CTA
          if (el.tagName === 'A' || el.tagName === 'BUTTON') {
            ANALYTICS.trackEvent({ category: 'engagement', action: 'cta_click', label: text || href });
            break;
          }
          el = el.parentElement;
        }
      });
    }
  };

  // ─────────────────────────────────────────────
  // § 8. FORM TRACKER
  // ─────────────────────────────────────────────
  var FORM_TRACKER = {
    init: function() {
      document.addEventListener('submit', function(e) {
        var form = e.target;
        var id   = form.id || form.action || 'unknown_form';
        var type = 'form_submit';

        if (id.indexOf('enterprise') >= 0 || form.action.indexOf('enterprise') >= 0) {
          type = 'enterprise_form';
        } else if (id.indexOf('lead') >= 0 || id.indexOf('email') >= 0 || id.indexOf('newsletter') >= 0) {
          type = 'email_signup';
        } else if (id.indexOf('api') >= 0) {
          type = 'api_page_visit';
        }

        ANALYTICS.trackEvent({ category: 'conversion', action: type, label: id });
      });
    }
  };

  // ─────────────────────────────────────────────
  // § 9. PAGE ENGAGEMENT TIMING
  // ─────────────────────────────────────────────
  var ENGAGEMENT_TIMER = {
    start: Date.now(),
    milestones: [30, 60, 120, 300],
    reached: {},
    timer: null,

    init: function() {
      var self = this;
      this.timer = setInterval(function() {
        var elapsed = Math.round((Date.now() - self.start) / 1000);
        for (var i = 0; i < self.milestones.length; i++) {
          var m = self.milestones[i];
          if (elapsed >= m && !self.reached[m]) {
            self.reached[m] = true;
            ANALYTICS.trackEvent({
              category: 'engagement',
              action: 'time_on_page',
              label: m + 's',
              value: m,
              nonInteraction: true
            });
          }
        }
        if (elapsed >= 300) clearInterval(self.timer);
      }, 10000);

      // Save time on page before unload
      window.addEventListener('beforeunload', function() {
        var elapsed = Math.round((Date.now() - self.start) / 1000);
        SESSION.set('last_time_on_page', elapsed);
        try {
          navigator.sendBeacon && navigator.sendBeacon(
            'https://www.google-analytics.com/collect',
            ''
          );
        } catch(e) {}
      });
    }
  };

  // ─────────────────────────────────────────────
  // § 10. TOP PAGES TRACKER (for admin dashboard)
  // ─────────────────────────────────────────────
  var PAGE_TRACKER = {
    init: function() {
      try {
        var pages = JSON.parse(localStorage.getItem('cdb_top_pages')) || {};
        var path  = window.location.pathname;
        pages[path] = (pages[path] || 0) + 1;
        pages._total = (pages._total || 0) + 1;
        localStorage.setItem('cdb_top_pages', JSON.stringify(pages));
      } catch(e) {}

      // Track unique visitors
      try {
        var vid = localStorage.getItem('cdb_visitor_id');
        if (!vid) {
          vid = 'v_' + Date.now() + '_' + Math.random().toString(36).substr(2,9);
          localStorage.setItem('cdb_visitor_id', vid);
          // New visitor event
          ANALYTICS.trackEvent({ category: 'acquisition', action: 'new_visitor',
            label: SESSION.get('referrer') || 'direct', nonInteraction: true });
        }
      } catch(e) {}
    }
  };

  // ─────────────────────────────────────────────
  // § 11. USER SEGMENT SYNC
  // ─────────────────────────────────────────────
  // Reads segment from ai-monetization-engine / conversion-engine and attaches to GA4
  var SEGMENT_SYNC = {
    init: function() {
      // Wait for other engines to classify
      setTimeout(function() {
        var seg = '';
        if (window.AIM && window.AIM.INTENT) {
          var intent = window.AIM.INTENT.classify();
          seg = intent.top || 'unknown';
          SESSION.set('intentScore', intent.score || 0);
        } else if (window.CX && window.CX.SEGMENTS) {
          seg = window.CX.SEGMENTS.detect() || 'unknown';
        }
        if (seg) {
          SESSION.set('segment', seg);
          if (window.gtag && !CONFIG.GA4_ID.startsWith('YOUR_')) {
            window.gtag('set', 'user_properties', { user_segment: seg });
          }
        }
      }, 2000);
    }
  };

  // ─────────────────────────────────────────────
  // § 12. ECOMMERCE TRACKING HELPERS
  // ─────────────────────────────────────────────
  var ECOMMERCE = {

    viewItem: function(product) {
      if (!product) return;
      if (window.gtag && !CONFIG.GA4_ID.startsWith('YOUR_')) {
        window.gtag('event', 'view_item', {
          currency: 'USD',
          value: product.price,
          items: [{
            item_id:   product.id,
            item_name: product.name,
            item_category: 'threat-intel',
            price: product.price,
            quantity: 1
          }]
        });
      }
      if (window.fbq) window.fbq('track', 'ViewContent', { content_ids: [product.id], value: product.price, currency: 'USD' });
    },

    beginCheckout: function(product) {
      if (!product) return;
      if (window.gtag && !CONFIG.GA4_ID.startsWith('YOUR_')) {
        window.gtag('event', 'begin_checkout', {
          currency: 'USD',
          value: product.price,
          items: [{ item_id: product.id, item_name: product.name, price: product.price, quantity: 1 }]
        });
      }
      if (window.fbq) window.fbq('track', 'InitiateCheckout', { value: product.price, currency: 'USD' });
    },

    purchase: function(product, orderId) {
      if (!product) return;
      if (window.gtag && !CONFIG.GA4_ID.startsWith('YOUR_')) {
        window.gtag('event', 'purchase', {
          transaction_id: orderId || 'order_' + Date.now(),
          currency: 'USD',
          value: product.price,
          items: [{ item_id: product.id, item_name: product.name, price: product.price, quantity: 1 }]
        });
      }
      if (window.fbq) window.fbq('track', 'Purchase', { value: product.price, currency: 'USD' });
      ANALYTICS.trackEvent({ category: 'revenue', action: 'purchase', label: product.name, value: product.price });
    }
  };

  // ─────────────────────────────────────────────
  // § 13. INIT
  // ─────────────────────────────────────────────
  function init() {
    SESSION.init();
    loadGtag();
    loadFBPixel();

    // Wait for DOM
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function() {
        SCROLL_TRACKER.init();
        CTA_TRACKER.init();
        FORM_TRACKER.init();
        ENGAGEMENT_TIMER.init();
        PAGE_TRACKER.init();
        SEGMENT_SYNC.init();
      });
    } else {
      SCROLL_TRACKER.init();
      CTA_TRACKER.init();
      FORM_TRACKER.init();
      ENGAGEMENT_TIMER.init();
      PAGE_TRACKER.init();
      SEGMENT_SYNC.init();
    }

    // Track page view manually (backup if gtag not loaded)
    ANALYTICS.trackEvent({ category: 'pageview', action: 'page_view',
      label: window.location.pathname, nonInteraction: true });
  }

  // ─────────────────────────────────────────────
  // § 14. PUBLIC API
  // ─────────────────────────────────────────────
  window.AE = {
    track:     function(opts) { ANALYTICS.trackEvent(opts); },
    ecommerce: ECOMMERCE,
    session:   SESSION,
    config:    CONFIG
  };

  // Expose trackEvent globally so all other engines can call it
  window.trackEvent = function(opts) { ANALYTICS.trackEvent(opts); };

  init();

})();
