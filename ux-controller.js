/**
 * CYBERDUDEBIVASH SENTINEL APEX — UX Controller v1.0
 * ═══════════════════════════════════════════════════════════════════
 * Enforces:
 *   MAX 1 popup per session
 *   MAX 2 inline CTAs
 *   MAX 1 sticky bottom CTA
 *   Single intent-based conversion path
 *   Mobile UX polish (tap enhancement, scroll fatigue)
 *   "Load more" for mobile intel feed
 *
 * Load order: last script before </body>
 * Deploy: <script src="/ux-controller.js" defer></script>
 */
(function () {
  'use strict';

  /* ──────────────────────────────────────────────────────────────
     § CONFIG
  ────────────────────────────────────────────────────────────── */
  var CFG = {
    POPUP_SESSION_KEY: 'ux_popup_shown',  // 1 popup per session
    STICKY_CLASS:      'has-sticky-cta',  // body class when sticky active
    INLINE_CTA_MAX:    2,                 // max inline CTAs per page
    TOAST_MOBILE_MAX:  2,                 // max toasts on mobile
    MOBILE_BP:         767,               // mobile breakpoint px
    TABLET_BP:         1023               // tablet breakpoint px
  };

  /* ──────────────────────────────────────────────────────────────
     § UTILITIES
  ────────────────────────────────────────────────────────────── */
  function isMobile() { return window.innerWidth <= CFG.MOBILE_BP; }
  function isTablet() { return window.innerWidth <= CFG.TABLET_BP; }

  function ls(key, val) {
    try {
      if (val === undefined) return sessionStorage.getItem(key);
      if (val === null) sessionStorage.removeItem(key);
      else sessionStorage.setItem(key, String(val));
    } catch (e) {}
    return null;
  }

  function ready(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  /* ──────────────────────────────────────────────────────────────
     § 1. POPUP GATE — one popup per session across ALL engines
  ────────────────────────────────────────────────────────────── */
  var POPUP_GATE = {
    shown: false,

    canShow: function () {
      if (this.shown) return false;
      if (ls(CFG.POPUP_SESSION_KEY)) return false;
      return true;
    },

    register: function () {
      this.shown = true;
      ls(CFG.POPUP_SESSION_KEY, '1');
    },

    // Intercept all popup-triggering engines
    install: function () {
      var self = this;

      // Proxy CX4 exit intent — only fire if gate allows
      var origExit = null;
      Object.defineProperty(window, 'CX4', {
        configurable: true,
        get: function () { return window._CX4_real; },
        set: function (val) {
          window._CX4_real = val;
          if (val && val.EXIT_INTENT) {
            var origShow = val.EXIT_INTENT.show;
            if (origShow) {
              val.EXIT_INTENT.show = function () {
                if (!self.canShow()) return;
                self.register();
                return origShow.apply(val.EXIT_INTENT, arguments);
              };
            }
          }
        }
      });

      // Proxy AIM social proof toasts — limit on mobile
      var _aimOrigShow = null;
      var toastCount = 0;
      Object.defineProperty(window, 'AIM', {
        configurable: true,
        get: function () { return window._AIM_real; },
        set: function (val) {
          window._AIM_real = val;
          if (val && val.SOCIAL_PROOF) {
            var origShow = val.SOCIAL_PROOF.show;
            if (origShow) {
              val.SOCIAL_PROOF.show = function () {
                if (isMobile() && toastCount >= CFG.TOAST_MOBILE_MAX) return;
                toastCount++;
                return origShow.apply(val.SOCIAL_PROOF, arguments);
              };
            }
          }
        }
      });
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 2. STICKY CTA MANAGER — exactly ONE sticky at bottom
  ────────────────────────────────────────────────────────────── */
  var STICKY_MGR = {
    // Priority order: high-intent strip > upgrade strip > low bar
    PRIORITY: [
      '#aim-high-intent-strip',
      '#aim-upgrade-strip',
      '#aim-low-intent-bar'
    ],

    active: null,

    // Watch DOM for sticky elements appearing, enforce one-at-a-time
    install: function () {
      var self = this;
      var observer = new MutationObserver(function () {
        self.enforce();
      });
      observer.observe(document.body, { childList: true, subtree: true });

      // Also poll every 2s for strips injected via setTimeout
      setInterval(function () { self.enforce(); }, 2000);
    },

    enforce: function () {
      var visible = [];
      for (var i = 0; i < this.PRIORITY.length; i++) {
        var el = document.querySelector(this.PRIORITY[i]);
        if (el && el.style.display !== 'none' && el.style.transform !== 'translateY(100%)') {
          visible.push({ el: el, priority: i });
        }
      }

      if (!visible.length) {
        document.body.classList.remove(CFG.STICKY_CLASS);
        this.active = null;
        return;
      }

      // Keep highest priority (lowest index), hide rest
      var keep = visible[0];
      for (var j = 1; j < visible.length; j++) {
        visible[j].el.style.display = 'none';
      }
      this.active = keep.el;
      document.body.classList.add(CFG.STICKY_CLASS);
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 3. INLINE CTA LIMITER — max 2 per page
  ────────────────────────────────────────────────────────────── */
  var CTA_LIMITER = {
    // Selectors for inline injected CTAs from various engines
    SELECTORS: [
      '.aim-product-inject',
      '.cx-inline-cta',
      '.apex-inline-cta',
      '#aim-intent-banner'
    ],

    // Run after engines have had time to inject (800ms)
    install: function () {
      var self = this;
      setTimeout(function () { self.enforce(); }, 1200);
      setTimeout(function () { self.enforce(); }, 3000);
    },

    enforce: function () {
      var all = [];
      for (var i = 0; i < this.SELECTORS.length; i++) {
        var els = document.querySelectorAll(this.SELECTORS[i]);
        for (var j = 0; j < els.length; j++) {
          all.push(els[j]);
        }
      }

      // Hide anything beyond the max
      for (var k = CFG.INLINE_CTA_MAX; k < all.length; k++) {
        all[k].style.display = 'none';
        all[k].setAttribute('data-ux-hidden', 'cta-limit');
      }
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 4. MOBILE INTEL FEED — "Show More" collapse on mobile
  ────────────────────────────────────────────────────────────── */
  var FEED_COLLAPSE = {
    install: function () {
      if (!isMobile()) return;
      var self = this;
      // Wait for auto-intel-engine to render feed
      setTimeout(function () { self.apply(); }, 2000);
    },

    apply: function () {
      var feed = document.getElementById('intel-feed');
      if (!feed) return;

      var posts = feed.querySelectorAll('.intel-post');
      if (posts.length <= 3) return; // nothing to collapse

      // Show load-more button
      var btn = document.createElement('button');
      btn.id = 'ux-load-more';
      btn.textContent = 'Show More Threats (' + (posts.length - 3) + ' more) ↓';
      btn.style.cssText = [
        'display:block',
        'width:100%',
        'margin:12px 0 0',
        'padding:12px 16px',
        'background:rgba(0,255,224,.06)',
        'border:1px solid rgba(0,255,224,.2)',
        'color:#00ffe0',
        'font-size:.85rem',
        'font-weight:700',
        'border-radius:8px',
        'cursor:pointer',
        'text-align:center',
        '-webkit-tap-highlight-color:transparent'
      ].join(';');

      btn.addEventListener('click', function () {
        feed.classList.add('expanded');
        btn.remove();
        if (window.trackEvent) window.trackEvent('mobile_load_more_click', { count: posts.length - 3 });
      });

      // Add feed collapse class (CSS hides n+4)
      // Already handled by CSS: .intel-feed .intel-post:nth-child(n+4) { display:none }
      feed.classList.add('intel-feed');
      feed.parentNode.insertBefore(btn, feed.nextSibling);
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 5. MOBILE NAV — hamburger toggle
  ────────────────────────────────────────────────────────────── */
  var MOBILE_NAV = {
    install: function () {
      if (!isMobile()) return;

      var header = document.querySelector('header');
      var nav    = document.querySelector('nav');
      if (!header || !nav) return;

      // Add hamburger if it doesn't exist yet
      if (document.getElementById('ux-hamburger')) return;

      var btn = document.createElement('button');
      btn.id = 'ux-hamburger';
      btn.setAttribute('aria-label', 'Toggle navigation');
      btn.setAttribute('aria-expanded', 'false');
      btn.style.cssText = [
        'background:none',
        'border:1px solid rgba(0,255,224,.2)',
        'color:#00ffe0',
        'font-size:18px',
        'padding:6px 10px',
        'border-radius:6px',
        'cursor:pointer',
        'min-height:36px',
        'line-height:1',
        'flex-shrink:0',
        '-webkit-tap-highlight-color:transparent'
      ].join(';');
      btn.innerHTML = '☰';

      var headerInner = document.querySelector('.header-inner');
      if (headerInner) headerInner.appendChild(btn);

      // Nav starts collapsed on mobile (CSS hides n+5)
      // Toggle shows all
      btn.addEventListener('click', function () {
        var expanded = nav.classList.toggle('nav-expanded');
        btn.setAttribute('aria-expanded', String(expanded));
        btn.innerHTML = expanded ? '✕' : '☰';
        if (expanded) {
          nav.style.cssText = [
            'display:flex !important',
            'flex-direction:column',
            'position:absolute',
            'top:100%',
            'left:0',
            'right:0',
            'background:#0d1117',
            'border-bottom:1px solid #1f2937',
            'padding:8px 16px',
            'gap:4px',
            'z-index:999',
            'flex-wrap:nowrap',
            'overflow:visible',
            'max-width:100%'
          ].join(';');
          // Show all hidden nav items
          var allLinks = nav.querySelectorAll('a');
          allLinks.forEach(function (a) { a.style.display = 'inline-flex'; });
        } else {
          nav.removeAttribute('style');
          var allLinks = nav.querySelectorAll('a');
          allLinks.forEach(function (a) { a.style.display = ''; });
        }
        if (window.trackEvent) window.trackEvent('mobile_nav_toggle', { expanded: expanded });
      });

      // Close nav on outside click
      document.addEventListener('click', function (e) {
        if (!nav.contains(e.target) && e.target !== btn && nav.classList.contains('nav-expanded')) {
          btn.click();
        }
      }, { passive: true });
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 6. SKIP LINK — accessibility
  ────────────────────────────────────────────────────────────── */
  function injectSkipLink() {
    if (document.querySelector('.skip-link')) return;
    var skip = document.createElement('a');
    skip.href = '#main-content';
    skip.className = 'skip-link';
    skip.textContent = 'Skip to main content';
    document.body.insertBefore(skip, document.body.firstChild);

    // Make sure main content has an id
    var main = document.querySelector('main, .main');
    if (main && !main.id) main.id = 'main-content';
  }

  /* ──────────────────────────────────────────────────────────────
     § 7. CLICKABLE CARDS — entire card area tappable
  ────────────────────────────────────────────────────────────── */
  function enhanceCards() {
    // Post title links → card click
    var posts = document.querySelectorAll('.intel-post');
    posts.forEach(function (post) {
      if (post.dataset.uxCardified) return;
      post.dataset.uxCardified = '1';

      var titleLink = post.querySelector('.post-title a');
      if (!titleLink) return;

      post.style.cursor = 'pointer';
      post.addEventListener('click', function (e) {
        // Don't intercept clicks on buttons/links within the card
        if (e.target.closest('a, button, .cta-btn, .ctx-btn-primary, .ctx-btn-secondary, .ctx-share-btn')) return;
        titleLink.click();
      });
    });

    // Feature cards already have href — just ensure pointer cursor
    var fiCards = document.querySelectorAll('.fi-card');
    fiCards.forEach(function (card) {
      if (!card.href) return;
      card.style.cursor = 'pointer';
    });
  }

  /* ──────────────────────────────────────────────────────────────
     § 8. INTENT-BASED SINGLE CTA PATH
     Replace generic hero secondary CTA with intent-matched copy
  ────────────────────────────────────────────────────────────── */
  function applyIntentCTA() {
    // Read intent from CX4 or AIM
    var level = 'low';
    try {
      level = localStorage.getItem('cx4_intent_level') || 'low';
    } catch (e) {}

    var primBtn = document.querySelector('.hero-actions .btn-primary');
    if (!primBtn) return;

    var CTAs = {
      high: {
        text: '⚡ Start SOC Pro Free Trial →',
        href: '/pricing.html',
        style: 'background:linear-gradient(135deg,#00ffe0,#00d4ff);color:#000;'
      },
      medium: {
        text: '📦 Get Detection Packs →',
        href: '/products.html',
        style: 'background:linear-gradient(135deg,#00ffe0,#00d4ff);color:#000;'
      },
      low: {
        text: '📧 Get Free Threat Intel',
        href: '/leads.html',
        style: ''  // keep existing style
      }
    };

    var cta = CTAs[level] || CTAs.low;
    if (cta.style) primBtn.style.cssText += cta.style;

    // Only update text/href for non-low intent (avoid changing first-visit experience)
    if (level !== 'low') {
      primBtn.textContent = cta.text;
      primBtn.href = cta.href;
      if (window.trackEvent) window.trackEvent('intent_hero_cta_updated', { level: level });
    }
  }

  /* ──────────────────────────────────────────────────────────────
     § 9. SMOOTH SCROLL — intercept anchor clicks
  ────────────────────────────────────────────────────────────── */
  function installSmoothScroll() {
    document.addEventListener('click', function (e) {
      var link = e.target.closest('a[href^="#"]');
      if (!link) return;
      var id = link.getAttribute('href').slice(1);
      if (!id) return;
      var target = document.getElementById(id);
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, { passive: false });
  }

  /* ──────────────────────────────────────────────────────────────
     § 10. PERFORMANCE — defer heavy ops, batch DOM reads
  ────────────────────────────────────────────────────────────── */
  function scheduleIdleWork(fn) {
    if (typeof requestIdleCallback === 'function') {
      requestIdleCallback(fn, { timeout: 2000 });
    } else {
      setTimeout(fn, 500);
    }
  }

  /* ──────────────────────────────────────────────────────────────
     § 11. LCAB TIMESTAMP UPDATE
  ────────────────────────────────────────────────────────────── */
  function updateLCABTimestamp() {
    var el = document.getElementById('lcab-dt');
    if (!el) return;
    var now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    setInterval(function () {
      el.textContent = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    }, 60000);
  }

  /* ──────────────────────────────────────────────────────────────
     § 12. RESIZE HANDLER — re-evaluate on orientation change
  ────────────────────────────────────────────────────────────── */
  function onResize() {
    // Re-evaluate sticky enforcement on resize
    STICKY_MGR.enforce();
  }

  /* ──────────────────────────────────────────────────────────────
     § BOOT
  ────────────────────────────────────────────────────────────── */
  ready(function () {
    // Immediate
    POPUP_GATE.install();
    STICKY_MGR.install();
    injectSkipLink();
    installSmoothScroll();
    updateLCABTimestamp();

    // After engines inject content
    CTA_LIMITER.install();
    MOBILE_NAV.install();

    // Deferred — no rush
    scheduleIdleWork(function () {
      FEED_COLLAPSE.install();
      enhanceCards();
      applyIntentCTA();
    });

    // Re-check after all deferred scripts have run
    setTimeout(function () {
      CTA_LIMITER.enforce();
      STICKY_MGR.enforce();
      enhanceCards();
    }, 3500);

    // Resize
    window.addEventListener('resize', onResize, { passive: true });
    window.addEventListener('orientationchange', onResize, { passive: true });
  });

  // Expose public API for debugging
  window.UXC = {
    POPUP_GATE:  POPUP_GATE,
    STICKY_MGR:  STICKY_MGR,
    CTA_LIMITER: CTA_LIMITER,
    isMobile:    isMobile
  };

}());
