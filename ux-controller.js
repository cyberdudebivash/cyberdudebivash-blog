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
  /* ── INTENT CTA MAP ── */
  var HERO_INTENT_MAP = {
    low: {
      text:    '\uD83D\uDCE7 Get Free Threat Alerts',
      href:    '/leads.html',
      cls:     '',
      urgency: 'Join 4,800+ security professionals — free forever'
    },
    medium: {
      text:    '\uD83D\uDCE6 Explore Detection Packs',
      href:    '/products.html',
      cls:     'intent-medium',
      urgency: 'Sigma + YARA rules — deploy to SIEM in minutes'
    },
    high: {
      text:    '\u26A1 Start SOC Pro Free Trial \u2192',
      href:    '/pricing.html',
      cls:     'intent-high',
      urgency: '\uD83D\uDD25 23 spots left at $49/mo — normally $129'
    }
  };

  function applyIntentCTA() {
    var level = 'low';
    try { level = localStorage.getItem('cx4_intent_level') || 'low'; } catch (e) {}
    if (level !== 'low' && level !== 'medium' && level !== 'high') level = 'low';

    var btn  = document.getElementById('hero-primary-cta');
    var txt  = document.getElementById('hero-cta-text');
    if (!btn) return;

    var map = HERO_INTENT_MAP[level];

    // Update CTA
    btn.href = map.href;
    if (txt) txt.textContent = map.text;

    // Swap intent class
    btn.classList.remove('intent-low', 'intent-medium', 'intent-high');
    if (map.cls) btn.classList.add(map.cls);

    // Update urgency/social proof micro-copy
    var urgencyEl = document.querySelector('.hero-trust-strip .hero-trust-urgency');
    if (!urgencyEl) {
      urgencyEl = document.createElement('span');
      urgencyEl.className = 'hero-trust-item hero-trust-urgency';
      urgencyEl.style.cssText = 'color:#00ff88;font-weight:700;font-size:12px;';
      var strip = document.querySelector('.hero-trust-strip');
      if (strip) strip.appendChild(urgencyEl);
    }
    urgencyEl.textContent = map.urgency;

    if (window.trackEvent) window.trackEvent('hero_intent_cta_applied', { level: level });
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
    STICKY_MGR.enforce();
  }

  /* ──────────────────────────────────────────────────────────────
     § 13. MOBILE CLEANUP — kill all competing fixed-position banners
     on mobile before they collide with the header and hero.
     CSS handles initial hide; this JS handles dynamically-injected
     elements that arrive after DOMContentLoaded.
  ────────────────────────────────────────────────────────────── */
  var MOBILE_CLEANUP = {
    // All IDs that must be suppressed on mobile
    SUPPRESS_IDS: [
      'apex-sticky',        // monetization.js — top fixed promo bar
      'apex-exit-overlay',  // monetization.js — exit popup
      'apex-bottom-bar',    // monetization.js — bottom bar
      'apex-toast',         // monetization.js — toast popup
      'cx4-return-banner',  // conversion-engine.js — "Welcome back" overlap
      'cx4-overlay',        // conversion-engine.js — "Claim Offer" slide-in
      'cx4-exit-overlay',   // conversion-engine.js — exit intent overlay
      'cx4-scroll-bar',     // conversion-engine.js — progress bar
      'aim-bundle-prompt',  // ai-monetization-engine.js — bundle popup
      'aim-upgrade-strip',  // ai-monetization-engine.js — "You've visited X times" top strip
      'aim-intent-banner',  // ai-monetization-engine.js — intent-driven inline banner
      'aim-toast-container',// ai-monetization-engine.js — social proof toasts
      'cx-return-banner',   // legacy cx- return visitor banner (pre-cx4)
      'cx-smart-overlay',   // legacy cx- smart overlay
      'cx-scroll-bar'       // legacy cx- scroll progress bar
    ],

    hideEl: function (id) {
      var el = document.getElementById(id);
      if (el) {
        el.style.setProperty('display', 'none', 'important');
        el.setAttribute('aria-hidden', 'true');
      }
    },

    // Also fix body padding-top injected by apex-sticky
    fixBodyPadding: function () {
      if (document.body.style.paddingTop) {
        document.body.style.setProperty('padding-top', '0', 'important');
      }
    },

    install: function () {
      if (!isMobile()) return; // desktop: let everything run
      var self = this;

      // 1. Hide immediately (catches pre-loaded elements)
      self.SUPPRESS_IDS.forEach(function (id) { self.hideEl(id); });
      self.fixBodyPadding();

      // 2. MutationObserver: catch elements injected after load
      var obs = new MutationObserver(function (mutations) {
        var changed = false;
        mutations.forEach(function (m) {
          m.addedNodes.forEach(function (node) {
            if (node.nodeType === 1) { // Element node
              var id = node.id;
              if (id && self.SUPPRESS_IDS.indexOf(id) !== -1) {
                self.hideEl(id);
                changed = true;
              }
            }
          });
        });
        if (changed) self.fixBodyPadding();
      });
      obs.observe(document.body, { childList: true });

      // 3. Timed sweeps to catch late injections from deferred scripts
      var sweepTimes = [500, 1000, 1500, 2500, 4000];
      sweepTimes.forEach(function (t) {
        setTimeout(function () {
          self.SUPPRESS_IDS.forEach(function (id) { self.hideEl(id); });
          self.fixBodyPadding();
        }, t);
      });
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 14. JOURNEY ENGINE — Phase 2: scroll-based content reveal
     0–30%  : Education only (no CTAs shown)
     30–60% : Soft CTA revealed (journey-soft-cta)
     60–85% : Strong inline CTA / product highlight
     85%+   : Conversion block visible
  ────────────────────────────────────────────────────────────── */
  var JOURNEY = {
    _milestones: { 30: false, 60: false, 85: false },
    _lastPct: 0,

    getScrollPct: function () {
      var h = document.documentElement.scrollHeight - window.innerHeight;
      return h > 0 ? Math.round((window.scrollY / h) * 100) : 0;
    },

    onScroll: function () {
      var pct = this.getScrollPct();
      if (pct <= this._lastPct) return;
      this._lastPct = pct;

      // 30% — reveal soft CTA
      if (!this._milestones[30] && pct >= 30) {
        this._milestones[30] = true;
        this._revealSoftCTA();
        if (window.trackEvent) window.trackEvent('journey_30pct', { pct: pct });
      }

      // 60% — strong CTA (re-apply intent CTA in case intent upgraded)
      if (!this._milestones[60] && pct >= 60) {
        this._milestones[60] = true;
        applyIntentCTA();
        if (window.trackEvent) window.trackEvent('journey_60pct', { pct: pct });
      }

      // 85% — conversion block: show "Recommended for You" section if hidden
      if (!this._milestones[85] && pct >= 85) {
        this._milestones[85] = true;
        this._revealConversionBlock();
        if (window.trackEvent) window.trackEvent('journey_85pct', { pct: pct });
      }
    },

    _revealSoftCTA: function () {
      var el = document.getElementById('journey-soft-cta');
      if (!el) return;
      el.style.display = 'flex';
      el.removeAttribute('aria-hidden');
      // Fade in
      el.style.opacity = '0';
      el.style.transition = 'opacity .4s ease';
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { el.style.opacity = '1'; });
      });
    },

    _revealConversionBlock: function () {
      // Expand the feed-extended section if not already visible
      var feedBtn = document.getElementById('feed-show-more');
      if (feedBtn && feedBtn.style.display !== 'none') {
        // Don't auto-expand — just track, user can expand themselves
      }
      // Re-show the productization sections if they were hidden
      var trending = document.getElementById('trending-threats');
      var exploited = document.getElementById('most-exploited');
      if (trending) trending.style.opacity = '1';
      if (exploited) exploited.style.opacity = '1';
      if (window.trackEvent) window.trackEvent('journey_conversion_block_shown', {});
    },

    install: function () {
      var self = this;
      var ticking = false;
      window.addEventListener('scroll', function () {
        if (!ticking) {
          requestAnimationFrame(function () {
            self.onScroll();
            ticking = false;
          });
          ticking = true;
        }
      }, { passive: true });
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 14. MICRO-CONVERSION TRACKER — Phase 8
     Tracks: scroll depth, time on page, CTA clicks, card clicks
  ────────────────────────────────────────────────────────────── */
  var MICRO_TRACKER = {
    _sessionStart: Date.now(),
    _maxScroll: 0,
    _ctaClicks: 0,
    _cardClicks: 0,

    // Scroll depth tracking (10% buckets)
    installScrollDepth: function () {
      var self = this;
      var reported = {};
      var buckets = [10, 25, 50, 75, 90, 100];
      window.addEventListener('scroll', function () {
        var h = document.documentElement.scrollHeight - window.innerHeight;
        if (h <= 0) return;
        var pct = Math.round((window.scrollY / h) * 100);
        if (pct > self._maxScroll) self._maxScroll = pct;
        buckets.forEach(function (b) {
          if (!reported[b] && pct >= b) {
            reported[b] = true;
            if (window.trackEvent) window.trackEvent('scroll_depth', { pct: b });
          }
        });
      }, { passive: true });
    },

    // Time on page — report at key intervals
    installTimeTracking: function () {
      var self = this;
      var reported = {};
      var intervals = [15, 30, 60, 120];
      setInterval(function () {
        var secs = Math.round((Date.now() - self._sessionStart) / 1000);
        intervals.forEach(function (t) {
          if (!reported[t] && secs >= t) {
            reported[t] = true;
            if (window.trackEvent) window.trackEvent('time_on_page', { seconds: t });
          }
        });
      }, 5000);
    },

    // CTA click tracking — delegate on all buttons and primary links
    installCTATracking: function () {
      var self = this;
      document.addEventListener('click', function (e) {
        var el = e.target.closest('a[href], button');
        if (!el) return;

        var href  = el.getAttribute('href') || '';
        var text  = (el.textContent || '').trim().slice(0, 60);
        var isCTA = el.classList.contains('btn-primary') ||
                    el.classList.contains('btn-secondary') ||
                    el.classList.contains('cta-btn') ||
                    el.classList.contains('rcb-card-btn') ||
                    el.classList.contains('hero-intent-cta') ||
                    el.classList.contains('journey-soft-cta-btn') ||
                    /pricing|products|leads|trial|subscribe/i.test(href);

        if (isCTA) {
          self._ctaClicks++;
          if (window.trackEvent) window.trackEvent('cta_click', {
            text:  text,
            href:  href,
            scroll: self._maxScroll,
            time_s: Math.round((Date.now() - self._sessionStart) / 1000)
          });
        }

        // Card click tracking
        if (el.classList.contains('post-card') || el.classList.contains('ips-card')) {
          self._cardClicks++;
          if (window.trackEvent) window.trackEvent('card_click', { href: href, text: text });
        }
      }, true); // capture phase for reliability
    },

    install: function () {
      this.installScrollDepth();
      this.installTimeTracking();
      this.installCTATracking();
    }
  };

  /* ──────────────────────────────────────────────────────────────
     § 15. RESIZE HANDLER
  ────────────────────────────────────────────────────────────── */

  /* ──────────────────────────────────────────────────────────────
     § BOOT
  ────────────────────────────────────────────────────────────── */
  ready(function () {
    // Step 0: MOBILE CLEANUP — must run before everything else
    // Kills competing fixed banners that collide with header on mobile
    MOBILE_CLEANUP.install();

    // Immediate — structure + popup safety
    POPUP_GATE.install();
    STICKY_MGR.install();
    injectSkipLink();
    installSmoothScroll();
    updateLCABTimestamp();

    // Phase 8: micro-conversion tracking — start immediately
    MICRO_TRACKER.install();

    // Phase 2: journey engine — scroll-based content reveal
    JOURNEY.install();

    // Navigation + CTA controls
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
      // Re-apply intent CTA in case AIM engine has upgraded level by now
      applyIntentCTA();
    }, 3500);

    // Resize
    window.addEventListener('resize', onResize, { passive: true });
    window.addEventListener('orientationchange', onResize, { passive: true });
  });

  // Expose public API for debugging + inter-engine communication
  window.UXC = {
    POPUP_GATE:     POPUP_GATE,
    STICKY_MGR:     STICKY_MGR,
    CTA_LIMITER:    CTA_LIMITER,
    JOURNEY:        JOURNEY,
    MICRO_TRACKER:  MICRO_TRACKER,
    MOBILE_CLEANUP: MOBILE_CLEANUP,
    isMobile:       isMobile,
    applyIntentCTA: applyIntentCTA  // callable by AIM on intent upgrade
  };

}());
