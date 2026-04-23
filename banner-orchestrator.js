/**
 * CYBERDUDEBIVASH — BANNER ORCHESTRATOR v1.0
 * ══════════════════════════════════════════════════════════════
 * Enforces single-banner-visible policy across all engines:
 *   • ai-monetization-engine.js  (apex-sticky, apex-bottom-bar, aim-*)
 *   • conversion-engine.js       (cx4-return-banner, cx4-overlay)
 *   • live-feed-widget.js
 *
 * Rules (ALL viewports — desktop + tablet + mobile):
 *   1. Header is ALWAYS visible and unobscured
 *   2. Only ONE top-anchored promotional banner at a time
 *   3. Bottom-anchored strips don't count as "top banner"
 *   4. Exit overlays are exempt (fullscreen, intentional)
 *   5. CX4 return banner is suppressed if apex-sticky is live
 *   6. Body padding is set precisely to avoid hero content shift
 *
 * © 2025 CYBERDUDEBIVASH. All rights reserved.
 * ══════════════════════════════════════════════════════════════
 */
;(function () {
  'use strict';

  /* ─────────────────────────────────────────────
   * CONFIG
   * ───────────────────────────────────────────── */
  var BO_CFG = {
    HEADER_SEL: 'header, .site-header',
    // Top-anchored banners — only ONE should be visible at a time
    TOP_BANNERS: ['apex-sticky', 'cx4-return-banner', 'aim-medium-card'],
    // Bottom-anchored — can coexist with a top banner
    BOTTOM_BANNERS: ['apex-bottom-bar', 'aim-high-intent-strip'],
    // Corners — always ok
    CORNER: ['aim-bundle-prompt', 'apex-toast'],
    // Never suppress these
    EXEMPT: ['cx4-exit-overlay', 'apex-exit-overlay', 'cx4-scroll-bar'],
    // Priority order for top banners (index 0 = highest priority)
    PRIORITY: ['apex-sticky', 'aim-medium-card', 'cx4-return-banner'],
    SWEEP_INTERVALS: [200, 500, 1000, 2000, 3500, 6000]
  };

  /* ─────────────────────────────────────────────
   * UTILITIES
   * ───────────────────────────────────────────── */
  function el(id) { return document.getElementById(id); }

  function isVisible(elem) {
    if (!elem) return false;
    var s = window.getComputedStyle(elem);
    if (s.display === 'none' || s.visibility === 'hidden') return false;
    var rect = elem.getBoundingClientRect();
    return rect.height > 0;
  }

  function isTopAnchored(elem) {
    if (!elem) return false;
    var s = window.getComputedStyle(elem);
    if (s.position !== 'fixed' && s.position !== 'sticky') return false;
    var topVal = parseInt(s.top, 10);
    // "Top anchored" = fixed/sticky with top < 120px
    return !isNaN(topVal) && topVal < 120;
  }

  function headerHeight() {
    var h = document.querySelector(BO_CFG.HEADER_SEL);
    if (!h) return 56;
    return h.getBoundingClientRect().height || 56;
  }

  function setCSSVar(name, value) {
    document.documentElement.style.setProperty(name, value);
  }

  /* ─────────────────────────────────────────────
   * CORE: ENFORCE SINGLE TOP BANNER POLICY
   * ───────────────────────────────────────────── */
  function enforceSingleTopBanner() {
    var hh = headerHeight();
    var activeBanner = null;
    var activeBannerHeight = 0;

    // Find the highest-priority visible top banner
    for (var i = 0; i < BO_CFG.PRIORITY.length; i++) {
      var elem = el(BO_CFG.PRIORITY[i]);
      if (elem && isVisible(elem) && isTopAnchored(elem)) {
        activeBanner = BO_CFG.PRIORITY[i];
        activeBannerHeight = elem.getBoundingClientRect().height || 48;
        break;
      }
    }

    // Hide all other top-anchored banners
    for (var j = 0; j < BO_CFG.TOP_BANNERS.length; j++) {
      var id = BO_CFG.TOP_BANNERS[j];
      if (id === activeBanner) continue;
      var e = el(id);
      if (e && isTopAnchored(e)) {
        e.style.setProperty('display', 'none', 'important');
      }
    }

    // Position active banner just below header
    if (activeBanner) {
      var ae = el(activeBanner);
      if (ae) {
        ae.style.setProperty('top', hh + 'px', 'important');
        ae.style.setProperty('z-index', '9950', 'important');
        document.body.classList.add('has-top-banner');
        document.body.classList.add('has-' + activeBanner.replace(/-/g, '_'));
      }
      // Set CSS variable for other elements to reference
      setCSSVar('--active-banner-height', activeBannerHeight + 'px');
      setCSSVar('--cx4-banner-top', (hh + activeBannerHeight) + 'px');
    } else {
      document.body.classList.remove('has-top-banner');
      setCSSVar('--active-banner-height', '0px');
      setCSSVar('--cx4-banner-top', hh + 'px');
    }

    // Fix body padding: header handles its own offset via sticky
    // Remove any programmatic padding that pushes hero content down
    document.body.style.removeProperty('padding-top');
    setCSSVar('--body-banner-offset', '0px');

    // Special rule: if apex-sticky is live, kill cx4-return-banner entirely
    var apexEl = el('apex-sticky');
    if (apexEl && isVisible(apexEl)) {
      document.body.classList.add('has-apex-sticky');
      var cx4El = el('cx4-return-banner');
      if (cx4El) cx4El.style.setProperty('display', 'none', 'important');
    } else {
      document.body.classList.remove('has-apex-sticky');
    }
  }

  /* ─────────────────────────────────────────────
   * HEADER GUARD — ensure header z-index is king
   * ───────────────────────────────────────────── */
  function guardHeader() {
    var h = document.querySelector(BO_CFG.HEADER_SEL);
    if (!h) return;
    h.style.setProperty('z-index', '10000', 'important');
    h.style.setProperty('position', 'sticky', 'important');
    h.style.setProperty('top', '0', 'important');
  }

  /* ─────────────────────────────────────────────
   * MUTATION OBSERVER — catches late-injected banners
   * ───────────────────────────────────────────── */
  function installMutationObserver() {
    if (!window.MutationObserver) return;
    var mo = new MutationObserver(function (mutations) {
      var needsSweep = false;
      for (var i = 0; i < mutations.length; i++) {
        var m = mutations[i];
        for (var j = 0; j < m.addedNodes.length; j++) {
          var node = m.addedNodes[j];
          if (node.nodeType === 1) {
            var id = node.id || '';
            if (BO_CFG.TOP_BANNERS.indexOf(id) !== -1) {
              needsSweep = true;
              break;
            }
          }
        }
        // Also watch style attribute changes (transform: translateY(0) = visible)
        if (m.type === 'attributes' && m.attributeName === 'style') {
          var tid = m.target.id || '';
          if (BO_CFG.TOP_BANNERS.indexOf(tid) !== -1) needsSweep = true;
        }
      }
      if (needsSweep) {
        setTimeout(enforceSingleTopBanner, 50);
        setTimeout(enforceSingleTopBanner, 300);
      }
    });
    mo.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'class']
    });
  }

  /* ─────────────────────────────────────────────
   * TIMED SWEEPS — catch deferred JS banner injections
   * ───────────────────────────────────────────── */
  function installTimedSweeps() {
    BO_CFG.SWEEP_INTERVALS.forEach(function (ms) {
      setTimeout(function () {
        guardHeader();
        enforceSingleTopBanner();
      }, ms);
    });
  }

  /* ─────────────────────────────────────────────
   * SCROLL LISTENER — recheck on scroll (lazy-injected banners)
   * ───────────────────────────────────────────── */
  var lastScrollCheck = 0;
  function onScroll() {
    var now = Date.now();
    if (now - lastScrollCheck < 1000) return;
    lastScrollCheck = now;
    enforceSingleTopBanner();
  }

  /* ─────────────────────────────────────────────
   * BOOT
   * ───────────────────────────────────────────── */
  function boot() {
    guardHeader();
    enforceSingleTopBanner();
    installMutationObserver();
    installTimedSweeps();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', function () {
      setTimeout(enforceSingleTopBanner, 100);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // Expose for debugging
  window.BO = {
    enforce: enforceSingleTopBanner,
    guard: guardHeader,
    cfg: BO_CFG
  };

})();
) {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // Expose for debugging
  window.BO = {
    enforce: enforceSingleTopBanner,
    guard: guardHeader,
    cfg: BO_CFG
  };

})();

  };

})();
