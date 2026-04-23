/**
 * CYBERDUDEBIVASH SENTINEL APEX — Conversion Engine v4.0
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  SECTION 0  CONFIG
 *  SECTION 1  CORE UTILITIES + window.trackEvent()
 *  SECTION 2  SESSION INTELLIGENCE ENGINE
 *  SECTION 3  INTENT CLASSIFICATION  (low / medium / high)
 *  SECTION 4  A/B TESTING FRAMEWORK
 *  SECTION 5  BEHAVIORAL TRACKER
 *  SECTION 6  LEAD SEGMENTATION
 *  SECTION 7  PROGRESSIVE PAYWALL   (70% scroll → blur + overlay)
 *  SECTION 8  EXIT INTENT v2         (intent-adaptive content)
 *  SECTION 9  INTENT-DRIVEN CTA TRIGGERS
 *  SECTION 10 CONTEXT-AWARE PRODUCT ENGINE
 *  SECTION 11 TRUST AMPLIFICATION   (global stats injection)
 *  SECTION 12 RETARGETING PIXEL MANAGER
 *  SECTION 13 BOOT SEQUENCE
 *
 *  Coordination rules:
 *    • monetization.js owns: sticky bar, social toasts, urgency counter,
 *      bottom bar, affiliate CTAs, sidebar capture
 *    • conversion-engine.js v4 owns: session intelligence, intent CTAs,
 *      progressive paywall, enhanced exit intent, trust injection, pixels
 *    • Guard flags prevent double-injection across both files
 *
 *  Deploy:  <script src="/conversion-engine.js" defer></script>
 *  Order:   load AFTER monetization.js
 */
(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 0 — CONFIG
  ═══════════════════════════════════════════════════════════════════════ */
  var CFG = {
    /* Analytics IDs — replace with real values */
    gaId:        'G-XXXXXXXXXX',
    gadsId:      'AW-XXXXXXXXXX',
    fbPixelId:   'XXXXXXXXXXXXXXXXXX',

    /* Endpoints */
    formsubmit:  'https://formsubmit.co/bivash@cyberdudebivash.com',
    formNext:    'https://blog.cyberdudebivash.in/leads.html',

    /* Internal URLs */
    pricing:     '/pricing.html',
    api:         '/api.html',
    products:    '/products.html',
    enterprise:  '/enterprise.html',
    leads:       '/leads.html',
    rss:         '/rss.xml',

    /* Intent thresholds */
    intentMediumSec:   30,
    intentHighSec:     60,
    intentHighPages:   2,
    paywallScrollPct:  70,
    midCTAScrollPct:   40,

    /* Storage keys */
    K_SESSION:   'cx4_session',
    K_VISITS:    'cx4_visits',
    K_AB:        'cx4_ab',
    K_EVENTS:    'cx4_events',
    K_EXIT:      'cx4_exit_shown',
    K_PAYWALL:   'cx4_paywall_shown',
    K_TRUST:     'cx4_trust_injected',

    /* A/B variants */
    abCTA:     ['Get Threat Intel', 'Download IOC Pack', 'Unlock Full Report', 'Access Live Feed'],
    abPrice:   ['anchor', 'direct', 'savings'],
    abUrgency: ['exploited', 'critical', 'advisory'],

    /* Trust stats (update periodically) */
    trust: {
      subscribers: '4,800+',
      cves:        '1,200+',
      updateMin:   '10',
      countries:   '80+'
    }
  };

  var CYAN   = '#00ffe0';
  var page   = window.location.pathname;

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 1 — CORE UTILITIES + window.trackEvent()
  ═══════════════════════════════════════════════════════════════════════ */
  var ls = {
    get:  function (k) { try { return JSON.parse(localStorage.getItem(k)); } catch (e) { return null; } },
    set:  function (k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
    push: function (k, v) {
      var a = ls.get(k) || [];
      a.push(v);
      ls.set(k, a.slice(-300));
    }
  };

  function now () { return Date.now(); }

  function css (rules) {
    var s = document.createElement('style');
    s.textContent = rules;
    document.head.appendChild(s);
  }

  function qs (sel) { return document.querySelector(sel); }

  function el (tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (k === 'html')    { e.innerHTML = v; }
      else if (k === 'cls'){ e.className = v; }
      else if (k === 'sty'){ e.setAttribute('style', v); }
      else if (k[0] === '@') { e.addEventListener(k.slice(1), v); }
      else                 { e.setAttribute(k, v); }
    });
    (kids || []).forEach(function (c) {
      if (!c) return;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return e;
  }

  function rand (arr) { return arr[Math.floor(Math.random() * arr.length)]; }

  /**
   * window.trackEvent(name, data)
   * Global tracking API consumed by all engines on the page.
   */
  window.trackEvent = function (name, data) {
    data = data || {};
    var evt = {
      name:    name,
      data:    data,
      page:    page,
      ts:      now(),
      intent:  INTENT ? INTENT.level : 'unknown',
      segment: typeof SEGMENTS !== 'undefined' ? SEGMENTS.detect() : 'unknown',
      ab:      ls.get(CFG.K_AB) ? ls.get(CFG.K_AB).id : null
    };
    ls.push(CFG.K_EVENTS, evt);

    /* GA4 */
    if (typeof gtag !== 'undefined') {
      try { gtag('event', name, Object.assign({}, data, { platform: 'sentinel_apex' })); } catch (e) {}
    }
    /* FB Pixel */
    if (typeof fbq !== 'undefined') {
      try {
        if (name === 'lead_captured')   fbq('track', 'Lead', data);
        if (name === 'purchase_intent') fbq('track', 'AddToCart', data);
        if (name === 'conversion')      fbq('track', 'Purchase', data);
      } catch (e) {}
    }
    /* Console debug (remove in prod) */
    if (window.CX_DEBUG) {
      console.log('[CX4 trackEvent]', name, data);
    }
  };

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 2 — SESSION INTELLIGENCE ENGINE
  ═══════════════════════════════════════════════════════════════════════ */
  var SESSION = (function () {
    var SESSION_TIMEOUT = 30 * 60 * 1000; // 30 min

    function load () {
      var s = ls.get(CFG.K_SESSION);
      if (!s || (now() - s.lastSeen) > SESSION_TIMEOUT) {
        s = {
          id:          Math.random().toString(36).slice(2, 10),
          start:       now(),
          pages:       [],
          scrollMax:   0,
          clicks:      0,
          formFocused: false,
          lastSeen:    now()
        };
      }
      return s;
    }

    var state  = load();
    var visits = (ls.get(CFG.K_VISITS) || 0) + 1;
    ls.set(CFG.K_VISITS, visits);

    /* Record current page */
    if (state.pages.indexOf(page) === -1) {
      state.pages.push(page);
    }
    state.lastSeen = now();
    ls.set(CFG.K_SESSION, state);

    function save () {
      state.lastSeen = now();
      ls.set(CFG.K_SESSION, state);
    }

    function recordScroll (pct) {
      if (pct > state.scrollMax) {
        state.scrollMax = pct;
        save();
      }
    }

    function recordClick () {
      state.clicks++;
      save();
    }

    function elapsed () { return Math.round((now() - state.start) / 1000); }

    function pageCount () { return state.pages.length; }

    function toReport () {
      return {
        id:         state.id,
        visits:     visits,
        pages:      state.pages,
        pageCount:  pageCount(),
        scrollMax:  state.scrollMax,
        clicks:     state.clicks,
        elapsed:    elapsed(),
        intent:     INTENT ? INTENT.level : 'low'
      };
    }

    return {
      state:       state,
      visits:      visits,
      elapsed:     elapsed,
      pageCount:   pageCount,
      recordScroll: recordScroll,
      recordClick: recordClick,
      save:        save,
      toReport:    toReport
    };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 3 — INTENT CLASSIFICATION
     low  : < 30s on page, 1 page, scroll < 40%
     medium: ≥ 30s OR scroll ≥ 40%
     high : ≥ 60s OR ≥ 2 pages OR explicit product/pricing click
  ═══════════════════════════════════════════════════════════════════════ */
  var INTENT = (function () {
    var level = 'low';
    var upgradeCallbacks = [];

    function upgrade (newLevel) {
      if (level === 'high') return;
      if (newLevel === 'medium' && level === 'low') {
        level = 'medium';
        window.trackEvent('intent_upgrade', { level: 'medium', elapsed: SESSION.elapsed() });
        notify('medium');
      } else if (newLevel === 'high' && level !== 'high') {
        level = 'high';
        window.trackEvent('intent_upgrade', { level: 'high', elapsed: SESSION.elapsed() });
        notify('high');
      }
    }

    function notify (lvl) {
      upgradeCallbacks.forEach(function (cb) {
        try { cb(lvl); } catch (e) {}
      });
    }

    function onUpgrade (cb) { upgradeCallbacks.push(cb); }

    function evaluate () {
      var sec = SESSION.elapsed();
      var pages = SESSION.pageCount();
      var scroll = SESSION.state.scrollMax;

      if (sec >= CFG.intentHighSec || pages >= CFG.intentHighPages) {
        upgrade('high');
      } else if (sec >= CFG.intentMediumSec || scroll >= CFG.midCTAScrollPct) {
        upgrade('medium');
      }
    }

    /* Poll every 5 seconds */
    setInterval(evaluate, 5000);

    /* Also trigger on explicit product/pricing links */
    document.addEventListener('click', function (e) {
      var a = e.target.closest('a');
      if (!a) return;
      var href = (a.getAttribute('href') || '').toLowerCase();
      if (href.indexOf('pricing') !== -1 || href.indexOf('products') !== -1 ||
          href.indexOf('enterprise') !== -1 || href.indexOf('api') !== -1) {
        upgrade('high');
        window.trackEvent('high_intent_click', { href: href });
      }
    });

    return {
      get level () { return level; },
      upgrade:    upgrade,
      onUpgrade:  onUpgrade,
      evaluate:   evaluate
    };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 4 — A/B TESTING FRAMEWORK
  ═══════════════════════════════════════════════════════════════════════ */
  var AB = (function () {
    var stored = ls.get(CFG.K_AB);
    if (!stored) {
      stored = {
        cta:     rand(CFG.abCTA),
        price:   rand(CFG.abPrice),
        urgency: rand(CFG.abUrgency),
        id:      Math.random().toString(36).slice(2, 8)
      };
      ls.set(CFG.K_AB, stored);
    }

    function applyPriceAnchors () {
      document.querySelectorAll('[data-cx-price]').forEach(function (node) {
        var base = parseInt(node.dataset.cxPrice, 10);
        var orig = parseInt(node.dataset.cxOrig  || Math.round(base * 2.6), 10);
        var pct  = Math.round((1 - base / orig) * 100);

        if (stored.price === 'anchor') {
          node.innerHTML =
            '<span style="font-size:1.5rem;font-weight:900;color:' + CYAN + '">$' + base + '</span>' +
            '<span style="text-decoration:line-through;color:#64748b;font-size:.85rem;margin-left:.4rem">$' + orig + '</span>' +
            '<span style="background:rgba(34,197,94,.18);color:#22c55e;font-size:.68rem;padding:.1rem .4rem;border-radius:4px;margin-left:.4rem;font-weight:800">SAVE ' + pct + '%</span>';
        } else if (stored.price === 'savings') {
          node.innerHTML =
            '<span style="font-size:1.5rem;font-weight:900;color:' + CYAN + '">$' + base + '</span>' +
            '<span style="color:#22c55e;font-size:.8rem;margin-left:.5rem;font-weight:700">Save $' + (orig - base) + '</span>';
        }
      });
    }

    function applyCTAText () {
      document.querySelectorAll('[data-cx-cta]').forEach(function (btn) {
        btn.textContent = stored.cta;
      });
    }

    return {
      variant: stored,
      applyPriceAnchors: applyPriceAnchors,
      applyCTAText:      applyCTAText
    };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 5 — BEHAVIORAL TRACKER
  ═══════════════════════════════════════════════════════════════════════ */
  var TRACK = (function () {
    var scrollThrottle;
    var scrollBarEl = null;

    function initScrollBar () {
      if (document.getElementById('cx4-scroll-bar')) return;
      css('#cx4-scroll-bar{position:fixed;top:0;left:0;height:3px;z-index:10001;' +
          'background:linear-gradient(90deg,' + CYAN + ',#00d4ff);width:0%;' +
          'transition:width .1s linear;pointer-events:none}');
      scrollBarEl = el('div', { id: 'cx4-scroll-bar' });
      document.body.appendChild(scrollBarEl);
    }

    function onScroll () {
      clearTimeout(scrollThrottle);
      scrollThrottle = setTimeout(function () {
        var scrollable = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
        var pct = Math.min(100, Math.round((window.scrollY / scrollable) * 100));
        if (scrollBarEl) scrollBarEl.style.width = pct + '%';
        SESSION.recordScroll(pct);
        PAYWALL.checkScroll(pct);
        INTENT.evaluate();
      }, 150);
    }

    function onClickGlobal (e) {
      SESSION.recordClick();
      var target = e.target.closest('a, button, [data-track]');
      if (!target) return;
      var label = target.dataset.track ||
                  target.textContent.trim().slice(0, 50) ||
                  target.getAttribute('href') || '';
      window.trackEvent('click', { label: label, tag: target.tagName });
    }

    function onVisibilityChange () {
      if (document.visibilityState === 'hidden') {
        window.trackEvent('exit', {
          elapsed:  SESSION.elapsed(),
          scroll:   SESSION.state.scrollMax,
          clicks:   SESSION.state.clicks,
          intent:   INTENT.level,
          pages:    SESSION.pageCount()
        });
        SESSION.save();
      }
    }

    function init () {
      initScrollBar();
      window.addEventListener('scroll', onScroll, { passive: true });
      document.addEventListener('click', onClickGlobal);
      document.addEventListener('visibilitychange', onVisibilityChange);
      /* Time milestones */
      [15, 30, 60, 120, 300].forEach(function (sec) {
        setTimeout(function () {
          window.trackEvent('time_milestone', { sec: sec, scroll: SESSION.state.scrollMax });
          INTENT.evaluate();
        }, sec * 1000);
      });
    }

    return { init: init };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 6 — LEAD SEGMENTATION
  ═══════════════════════════════════════════════════════════════════════ */
  var SEGMENTS = (function () {
    function detect () {
      var p   = page.toLowerCase();
      var ref = document.referrer.toLowerCase();
      var evts = ls.get(CFG.K_EVENTS) || [];
      var apiHits = evts.filter(function (e) {
        return e.name === 'click' && e.data && String(e.data.label).toLowerCase().indexOf('api') !== -1;
      }).length;
      var priceHits = evts.filter(function (e) {
        return e.name === 'click' && e.data && String(e.data.label).toLowerCase().indexOf('pric') !== -1;
      }).length;

      if (apiHits >= 2 || p.indexOf('api') !== -1)                                        return 'developer';
      if (priceHits >= 1 || p.indexOf('enterprise') !== -1 || p.indexOf('pricing') !== -1) return 'enterprise';
      if (ref.indexOf('github') !== -1 || ref.indexOf('stackoverflow') !== -1)             return 'developer';
      if (ref.indexOf('linkedin') !== -1 || ref.indexOf('twitter') !== -1 ||
          ref.indexOf('x.com') !== -1)                                                     return 'security_pro';
      return 'soc_analyst';
    }

    var MESSAGES = {
      developer: {
        badge:    '\uD83D\uDD0C API-FIRST THREAT INTELLIGENCE',
        headline: 'Integrate Live CVE & IOC Data Into Your Stack',
        sub:      'REST API: CVE feeds, IOC bundles, risk scores, MITRE ATT&CK mappings. Free tier available — no credit card needed.',
        cta:      'Start Free API Trial \u2192',
        url:      '/api.html'
      },
      enterprise: {
        badge:    '\uD83C\uDFE2 ENTERPRISE INTELLIGENCE PLATFORM',
        headline: 'Enterprise Threat Intel — SLA-Backed, White-Label',
        sub:      'Dedicated analyst support, custom detection engineering, and white-label feeds. Built for Fortune 500 security teams.',
        cta:      'Get Enterprise Proposal \u2192',
        url:      '/enterprise.html'
      },
      soc_analyst: {
        badge:    '\uD83D\uDEE1\uFE0F DETECTION ENGINEERING',
        headline: 'Deploy-Ready Sigma & YARA Rules — April 2026',
        sub:      '1,200+ production detection rules mapped to MITRE ATT&CK. Drop into Splunk, Elastic, or Sentinel in under 60 seconds.',
        cta:      'Browse Detection Packs \u2192',
        url:      '/products.html'
      },
      security_pro: {
        badge:    '\u26A1 SOC PRO MEMBERSHIP',
        headline: 'SOC Pro — 48H Pre-Disclosure Intel + Full IOC Access',
        sub:      'Get critical CVE reports before NVD publication. Full IOC bundles, SIEM rules, and ransomware tracking. $49/month.',
        cta:      'Start 7-Day Free Trial \u2192',
        url:      '/pricing.html'
      }
    };

    function getMessage (seg) { return MESSAGES[seg] || MESSAGES.soc_analyst; }

    return { detect: detect, getMessage: getMessage };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 7 — PROGRESSIVE PAYWALL
     Triggers at CFG.paywallScrollPct (70%) on /posts/ pages.
     Blurs remaining content and offers unlock options.
     Guards: won't run if already paid (ls cx4_soc_pro) or if already shown.
  ═══════════════════════════════════════════════════════════════════════ */
  var PAYWALL = (function () {
    var triggered = false;
    var injected  = false;

    css(
      '#cx4-paywall-wrap{position:relative}' +
      '#cx4-paywall-blur-zone{' +
        'filter:blur(6px);pointer-events:none;user-select:none;' +
        'transition:filter .4s ease;-webkit-filter:blur(6px);' +
      '}' +
      '#cx4-paywall-overlay{' +
        'position:absolute;bottom:0;left:0;right:0;' +
        'background:linear-gradient(to bottom,transparent 0%,rgba(7,9,15,.94) 35%,rgba(7,9,15,1) 100%);' +
        'display:flex;flex-direction:column;align-items:center;justify-content:flex-end;' +
        'padding:2.5rem 1.5rem;text-align:center;z-index:20;min-height:220px;' +
      '}' +
      '#cx4-paywall-overlay .pwo-lock{font-size:2.8rem;margin-bottom:.6rem}' +
      '#cx4-paywall-overlay .pwo-title{' +
        'font-size:1.2rem;font-weight:900;color:#fff;margin-bottom:.4rem;line-height:1.3;' +
      '}' +
      '#cx4-paywall-overlay .pwo-sub{' +
        'font-size:.85rem;color:#94a3b8;line-height:1.6;margin-bottom:1.25rem;max-width:480px;' +
      '}' +
      '#cx4-paywall-overlay .pwo-btns{display:flex;gap:.75rem;flex-wrap:wrap;justify-content:center;margin-bottom:.75rem}' +
      '#cx4-paywall-overlay .pwo-btn{' +
        'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
        'color:#000;font-weight:800;font-size:.85rem;' +
        'padding:.65rem 1.4rem;border-radius:8px;text-decoration:none;transition:opacity .2s;' +
      '}' +
      '#cx4-paywall-overlay .pwo-btn:hover{opacity:.85;text-decoration:none}' +
      '#cx4-paywall-overlay .pwo-btn.outline{' +
        'background:transparent;border:1px solid rgba(0,255,224,.3);color:' + CYAN + ';' +
      '}' +
      '#cx4-paywall-overlay .pwo-btn.outline:hover{background:rgba(0,255,224,.08)}' +
      '#cx4-paywall-lead{' +
        'display:flex;gap:.5rem;flex-wrap:wrap;justify-content:center;' +
      '}' +
      '#cx4-paywall-lead input{' +
        'background:rgba(255,255,255,.07);border:1px solid rgba(0,255,224,.25);' +
        'color:#fff;border-radius:8px;padding:.55rem .9rem;font-size:.82rem;min-width:200px;' +
      '}' +
      '#cx4-paywall-lead input::placeholder{color:#475569}' +
      '#cx4-paywall-lead button{' +
        'background:rgba(0,255,224,.12);border:1px solid rgba(0,255,224,.3);' +
        'color:' + CYAN + ';border-radius:8px;padding:.55rem 1rem;font-size:.8rem;' +
        'font-weight:700;cursor:pointer;white-space:nowrap;' +
      '}' +
      '#cx4-paywall-lead button:hover{background:rgba(0,255,224,.2)}'
    );

    function inject () {
      if (injected) return;
      if (page.indexOf('/posts/') === -1) return;
      if (ls.get('cx4_soc_pro') === '1') return;
      if (ls.get(CFG.K_PAYWALL) === '1') return;

      /* Find the content to blur — paragraphs after 60% of content */
      var allParas = Array.from(document.querySelectorAll(
        'article p, .post-body p, main p, .article-body p, section p'
      ));
      if (allParas.length < 6) return;

      var cutIdx = Math.floor(allParas.length * 0.58);
      var cutEl  = allParas[cutIdx];
      if (!cutEl) return;

      /* Wrap remaining content from cutEl onwards */
      var parent = cutEl.parentNode;
      var siblings = Array.from(parent.childNodes);
      var startIdx = siblings.indexOf(cutEl);
      if (startIdx === -1) return;

      var wrap = el('div', { id: 'cx4-paywall-wrap' });
      var blurZone = el('div', { id: 'cx4-paywall-blur-zone' });

      /* Move elements from cutEl onwards into blur zone */
      var toMove = [];
      for (var i = startIdx; i < siblings.length; i++) {
        toMove.push(siblings[i]);
      }
      toMove.forEach(function (node) { blurZone.appendChild(node); });
      wrap.appendChild(blurZone);

      /* Build overlay */
      var overlay = el('div', { id: 'cx4-paywall-overlay' });
      overlay.innerHTML =
        '<div class="pwo-lock">\uD83D\uDD12</div>' +
        '<div class="pwo-title">Full Intelligence Report — Locked</div>' +
        '<div class="pwo-sub">Complete IOC tables, YARA signatures, SIEM detection queries, and analyst commentary are exclusive to SOC Pro members ($49/mo) and Enterprise clients.</div>' +
        '<div class="pwo-btns">' +
          '<a href="' + CFG.pricing + '" class="pwo-btn" data-track="paywall_pro_click">\u26A1 Unlock with SOC Pro \u2014 $49/mo</a>' +
          '<a href="' + CFG.enterprise + '" class="pwo-btn outline" data-track="paywall_enterprise_click">\uD83C\uDFE2 Enterprise Access</a>' +
        '</div>' +
        '<div id="cx4-paywall-lead">' +
          '<form action="' + CFG.formsubmit + '" method="POST" style="display:flex;gap:.5rem;flex-wrap:wrap;justify-content:center">' +
            '<input type="email" name="email" placeholder="Enter email for free intel pack" required>' +
            '<input type="hidden" name="_subject" value="Paywall Lead Capture">' +
            '<input type="hidden" name="_captcha" value="false">' +
            '<input type="hidden" name="_next" value="' + CFG.formNext + '">' +
            '<button type="submit">\uD83D\uDCE7 Get Free IOC Pack</button>' +
          '</form>' +
        '</div>';

      wrap.appendChild(overlay);
      parent.appendChild(wrap);

      injected = true;
      ls.set(CFG.K_PAYWALL, '1');
      window.trackEvent('paywall_shown', { cutIdx: cutIdx, total: allParas.length });
    }

    function checkScroll (pct) {
      if (triggered) return;
      if (pct >= CFG.paywallScrollPct) {
        triggered = true;
        inject();
      }
    }

    return { checkScroll: checkScroll, inject: inject };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 8 — EXIT INTENT v2
     Coordinates with monetization.js via 'cx4_exit_shown' flag.
     Content adapts to current session intent level.
     Deactivates if already shown this session.
  ═══════════════════════════════════════════════════════════════════════ */
  var EXIT_INTENT = (function () {
    var activated = false;
    var readyAfter = 25000; /* ms — don't fire if user just arrived */
    var startTs    = now();

    css(
      '#cx4-exit-overlay{' +
        'position:fixed;inset:0;z-index:999998;' +
        'background:rgba(0,0,0,.75);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px);' +
        'display:flex;align-items:center;justify-content:center;' +
        'opacity:0;pointer-events:none;transition:opacity .3s;' +
      '}' +
      '#cx4-exit-overlay.show{opacity:1;pointer-events:all}' +
      '#cx4-exit-box{' +
        'background:#0d1117;border:1px solid rgba(0,255,224,.28);border-radius:16px;' +
        'max-width:520px;width:92%;padding:2.25rem 2rem;position:relative;' +
        'box-shadow:0 0 80px rgba(0,255,224,.08),0 40px 80px rgba(0,0,0,.7);' +
        'font-family:"Segoe UI",system-ui,sans-serif;' +
      '}' +
      '#cx4-exit-close{' +
        'position:absolute;top:.85rem;right:1rem;background:none;border:none;' +
        'color:#475569;font-size:1.3rem;cursor:pointer;line-height:1;transition:color .2s;' +
      '}' +
      '#cx4-exit-close:hover{color:#fff}' +
      '.cx4ei-badge{' +
        'display:inline-flex;align-items:center;gap:.4rem;' +
        'background:rgba(255,68,68,.12);border:1px solid rgba(255,68,68,.3);' +
        'color:#ff6b6b;border-radius:50px;padding:.3rem .9rem;' +
        'font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.1em;' +
        'margin-bottom:1rem;animation:cx4pulse 2s infinite;' +
      '}' +
      '@keyframes cx4pulse{0%,100%{opacity:1}50%{opacity:.65}}' +
      '.cx4ei-h{font-size:1.5rem;font-weight:900;color:#fff;line-height:1.2;margin-bottom:.5rem}' +
      '.cx4ei-h span{color:' + CYAN + '}' +
      '.cx4ei-sub{font-size:.88rem;color:#94a3b8;line-height:1.65;margin-bottom:1.25rem}' +
      '.cx4ei-perks{' +
        'display:grid;grid-template-columns:1fr 1fr;gap:.6rem;margin-bottom:1.4rem;' +
      '}' +
      '.cx4ei-perk{' +
        'background:rgba(0,255,224,.05);border:1px solid rgba(0,255,224,.1);' +
        'border-radius:8px;padding:.65rem .85rem;font-size:.78rem;color:#c9d1d9;' +
      '}' +
      '.cx4ei-perk strong{color:' + CYAN + ';display:block;font-size:.72rem;margin-bottom:.2rem;font-weight:800}' +
      '.cx4ei-form{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.75rem}' +
      '.cx4ei-email{' +
        'flex:1;min-width:180px;background:rgba(255,255,255,.05);' +
        'border:1px solid rgba(0,255,224,.22);color:#fff;' +
        'border-radius:8px;padding:.65rem .9rem;font-size:.85rem;' +
      '}' +
      '.cx4ei-email::placeholder{color:#475569}' +
      '.cx4ei-submit{' +
        'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
        'color:#000;border:none;border-radius:8px;' +
        'padding:.65rem 1.25rem;font-size:.85rem;font-weight:800;cursor:pointer;white-space:nowrap;' +
      '}' +
      '.cx4ei-submit:hover{opacity:.85}' +
      '.cx4ei-or{text-align:center;font-size:.78rem;color:#334155;margin:.3rem 0}' +
      '.cx4ei-alt{display:flex;gap:.6rem;justify-content:center;flex-wrap:wrap}' +
      '.cx4ei-alt a{' +
        'background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);' +
        'color:#94a3b8;border-radius:7px;padding:.5rem 1rem;font-size:.78rem;' +
        'font-weight:600;text-decoration:none;transition:all .2s;white-space:nowrap;' +
      '}' +
      '.cx4ei-alt a:hover{border-color:rgba(0,255,224,.3);color:' + CYAN + ';text-decoration:none}' +
      '.cx4ei-skip{text-align:center;margin-top:.9rem;font-size:.73rem;color:#334155}' +
      '.cx4ei-skip a{color:#475569;cursor:pointer}'
    );

    /* Content varies by intent level */
    function buildContent (intentLevel) {
      var offers = {
        high: {
          badge:  '\uD83D\uDEA8 HIGH-INTENT ALERT — Exclusive Offer',
          h1:     'You\'re one step from <span>full intel access</span>',
          sub:    'You\'ve spent significant time here — that tells us you need serious threat intelligence. Get SOC Pro and unlock everything.',
          perk1:  { title: 'Pre-Disclosure CVE',  body: '48H before NVD release' },
          perk2:  { title: 'Full IOC Tables',     body: 'IP / domain / hash bundles' },
          perk3:  { title: 'YARA + Sigma Rules',  body: 'Deploy-ready detection' },
          perk4:  { title: 'SIEM Queries',        body: 'Splunk / Elastic / KQL' },
          altCTA: [
            { href: CFG.pricing,    label: '\u26A1 SOC Pro \u2014 $49/mo' },
            { href: CFG.products,   label: '\uD83D\uDCE6 Products Store' }
          ]
        },
        medium: {
          badge:  '\uD83C\uDFAF THREAT INTELLIGENCE ALERT',
          h1:     'Don\'t miss the next <span>critical zero-day</span>',
          sub:    '3,800+ SOC analysts receive our threat briefings before public disclosure. Free subscription — unsubscribe anytime.',
          perk1:  { title: 'Zero-Day Alerts',     body: '48H before public release' },
          perk2:  { title: 'IOC Bundles',         body: 'Weekly IPs, domains, hashes' },
          perk3:  { title: 'YARA Rules',          body: 'New malware signatures' },
          perk4:  { title: 'Ransomware Tracker',  body: 'Active group campaigns' },
          altCTA: [
            { href: CFG.pricing,    label: '\u26A1 SOC Pro Trial' },
            { href: CFG.leads,      label: '\uD83C\uDFAF Free Intel Pack' }
          ]
        },
        low: {
          badge:  '\uD83D\uDD10 FREE THREAT INTELLIGENCE PACK',
          h1:     'Claim your <span>free IOC bundle</span> before you go',
          sub:    'Get the April 2026 threat pack: active CVEs, IOC bundles, Sigma rules sample, and ransomware IOCs — completely free.',
          perk1:  { title: 'CVE Watchlist',       body: 'Top 10 active exploits' },
          perk2:  { title: 'IOC Starter Pack',    body: '500 IPs + domains + hashes' },
          perk3:  { title: 'Sigma Rules Sample',  body: '50 detection rules' },
          perk4:  { title: 'Ransomware IOCs',     body: 'April 2026 campaigns' },
          altCTA: [
            { href: CFG.products,   label: '\uD83D\uDCE6 Browse Products' },
            { href: CFG.pricing,    label: '\uD83D\uDEE1\uFE0F SOC Pro' }
          ]
        }
      };

      return offers[intentLevel] || offers.low;
    }

    function show () {
      if (activated) return;
      if (ls.get(CFG.K_EXIT) === '1') return;
      if ((now() - startTs) < readyAfter) return;
      activated = true;

      var intentLevel = INTENT.level;
      var o = buildContent(intentLevel);

      var overlay = el('div', { id: 'cx4-exit-overlay' });
      var altLinks = o.altCTA.map(function (a) {
        return '<a href="' + a.href + '" data-track="exit_alt_click">' + a.label + '</a>';
      }).join('');

      overlay.innerHTML =
        '<div id="cx4-exit-box">' +
          '<button id="cx4-exit-close" aria-label="Close">\u00D7</button>' +
          '<div class="cx4ei-badge">' + o.badge + '</div>' +
          '<div class="cx4ei-h">' + o.h1 + '</div>' +
          '<p class="cx4ei-sub">' + o.sub + '</p>' +
          '<div class="cx4ei-perks">' +
            '<div class="cx4ei-perk"><strong>' + o.perk1.title + '</strong>' + o.perk1.body + '</div>' +
            '<div class="cx4ei-perk"><strong>' + o.perk2.title + '</strong>' + o.perk2.body + '</div>' +
            '<div class="cx4ei-perk"><strong>' + o.perk3.title + '</strong>' + o.perk3.body + '</div>' +
            '<div class="cx4ei-perk"><strong>' + o.perk4.title + '</strong>' + o.perk4.body + '</div>' +
          '</div>' +
          '<form class="cx4ei-form" action="' + CFG.formsubmit + '" method="POST">' +
            '<input class="cx4ei-email" type="email" name="email" placeholder="your.soc@company.com" required>' +
            '<input type="hidden" name="_subject" value="Exit Intent Capture - ' + intentLevel + '">' +
            '<input type="hidden" name="_captcha" value="false">' +
            '<input type="hidden" name="_next" value="' + CFG.formNext + '">' +
            '<button class="cx4ei-submit" type="submit">\uD83D\uDCE7 Get Free Intel Pack</button>' +
          '</form>' +
          '<div class="cx4ei-or">or</div>' +
          '<div class="cx4ei-alt">' + altLinks + '</div>' +
          '<div class="cx4ei-skip">No thanks \u2014 <a id="cx4-exit-skip">I\'ll skip free intelligence</a></div>' +
        '</div>';

      document.body.appendChild(overlay);
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { overlay.classList.add('show'); });
      });

      function close () {
        overlay.classList.remove('show');
        ls.set(CFG.K_EXIT, '1');
        setTimeout(function () {
          if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        }, 350);
        window.trackEvent('exit_intent_closed', { intent: intentLevel });
      }

      document.getElementById('cx4-exit-close').onclick = close;
      var skipEl = document.getElementById('cx4-exit-skip');
      if (skipEl) skipEl.onclick = close;
      overlay.onclick = function (e) { if (e.target === overlay) close(); };

      ls.set(CFG.K_EXIT, '1');
      window.trackEvent('exit_intent_shown', { intent: intentLevel, session: SESSION.elapsed() });
    }

    function init () {
      /* Disable monetization.js exit intent so only ours fires */
      ls.set('exit_shown', '0');

      /* Mouse-leave trigger */
      document.addEventListener('mouseleave', function (e) {
        if (e.clientY < 8) show();
      });

      /* Mobile: back-button / tab-switch intent */
      window.addEventListener('pagehide', function () {
        if (!activated) show();
      });
    }

    return { init: init, show: show };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 9 — INTENT-DRIVEN CTA TRIGGERS
     Fires timed overlays based on session intent level changes.
     Prevents duplicates using flags and localStorage.
  ═══════════════════════════════════════════════════════════════════════ */
  var CTA_TRIGGERS = (function () {
    var overlayShown        = false;
    var returnBannerShown   = false;
    var enterpriseShown     = false;

    css(
      '#cx4-overlay{' +
        'position:fixed;bottom:88px;right:20px;z-index:9998;' +
        'width:340px;max-width:calc(100vw - 40px);' +
        'background:rgba(7,9,15,.97);' +
        'border:1px solid rgba(0,255,224,.28);border-radius:16px;padding:1.25rem;' +
        'box-shadow:0 20px 60px rgba(0,0,0,.55),0 0 30px rgba(0,255,224,.07);' +
        'transform:translateX(400px);transition:transform .4s cubic-bezier(.22,.68,0,1.2);' +
        'font-family:"Segoe UI",system-ui,sans-serif;' +
      '}' +
      '#cx4-overlay.show{transform:translateX(0)}' +
      '#cx4-overlay .co-close{' +
        'position:absolute;top:.55rem;right:.7rem;' +
        'background:none;border:none;color:#475569;font-size:1rem;cursor:pointer;' +
      '}' +
      '#cx4-overlay .co-close:hover{color:#fff}' +
      '#cx4-overlay .co-badge{font-size:.63rem;font-weight:800;color:' + CYAN + ';text-transform:uppercase;letter-spacing:.1em;margin-bottom:.4rem}' +
      '#cx4-overlay .co-h{font-size:.93rem;font-weight:800;color:#fff;margin-bottom:.3rem;line-height:1.3}' +
      '#cx4-overlay .co-sub{font-size:.79rem;color:#94a3b8;margin-bottom:.85rem;line-height:1.5}' +
      '#cx4-overlay .co-prog{height:3px;background:rgba(0,255,224,.15);border-radius:2px;margin-bottom:.7rem;overflow:hidden}' +
      '#cx4-overlay .co-prog-bar{height:100%;background:' + CYAN + ';border-radius:2px;transition:width .3s}' +
      '#cx4-overlay .co-cta{' +
        'display:block;width:100%;text-align:center;' +
        'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
        'color:#000;font-weight:800;font-size:.82rem;' +
        'padding:.6rem;border-radius:8px;text-decoration:none;border:none;cursor:pointer;transition:opacity .2s;' +
      '}' +
      '#cx4-overlay .co-cta:hover{opacity:.85;text-decoration:none}' +
      '#cx4-overlay .co-dismiss{display:block;text-align:center;font-size:.7rem;color:#334155;margin-top:.5rem;cursor:pointer}' +
      '#cx4-overlay .co-dismiss:hover{color:#64748b}' +
      '#cx4-return-banner{' +
        'position:fixed;top:56px;left:0;right:0;z-index:9994;' +
        'background:linear-gradient(90deg,rgba(255,215,0,.1),rgba(0,255,224,.07));' +
        'border-bottom:1px solid rgba(255,215,0,.2);padding:.55rem 1.5rem;' +
        'display:flex;align-items:center;justify-content:center;gap:1.25rem;flex-wrap:wrap;' +
        'transform:translateY(-100%);transition:transform .4s;' +
        'font-family:"Segoe UI",system-ui,sans-serif;' +
      '}' +
      '#cx4-return-banner.show{transform:translateY(0)}' +
      '#cx4-return-banner .rb-text{font-size:.82rem;color:#e2e8f0}' +
      '#cx4-return-banner .rb-text strong{color:#ffd700}' +
      '#cx4-return-banner .rb-btn{' +
        'background:linear-gradient(135deg,#ffd700,#ff8c00);' +
        'color:#000;font-weight:800;font-size:.75rem;padding:.32rem .8rem;' +
        'border-radius:6px;text-decoration:none;white-space:nowrap;' +
      '}' +
      '#cx4-return-banner .rb-close{' +
        'background:none;border:none;color:#475569;font-size:.9rem;cursor:pointer;margin-left:.35rem;' +
      '}'
    );

    function showOverlay (msg, trigger) {
      var existing = document.getElementById('cx4-overlay');
      if (existing) existing.parentNode.removeChild(existing);

      var pct = SESSION.state.scrollMax + '%';
      var overlay = el('div', { id: 'cx4-overlay' }, [
        el('button', { cls: 'co-close',
          '@click': function () {
            overlay.classList.remove('show');
            window.trackEvent('overlay_dismissed', { trigger: trigger });
          }
        }, ['\u00D7']),
        el('div', { cls: 'co-prog' }, [
          el('div', { cls: 'co-prog-bar', sty: 'width:' + pct })
        ]),
        el('div', { cls: 'co-badge' }, [msg.badge || '\u26A1 SENTINEL APEX INTEL']),
        el('div', { cls: 'co-h' },     [msg.headline]),
        el('div', { cls: 'co-sub' },   [msg.sub]),
        el('a',   { cls: 'co-cta', href: msg.url, 'data-track': 'overlay_cta_' + trigger,
          '@click': function () { window.trackEvent('overlay_cta_click', { trigger: trigger }); }
        }, [msg.cta]),
        el('span', { cls: 'co-dismiss',
          '@click': function () {
            overlay.classList.remove('show');
            window.trackEvent('overlay_dismissed', { trigger: trigger });
          }
        }, ['Remind me later'])
      ]);

      document.body.appendChild(overlay);
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { overlay.classList.add('show'); });
      });
      window.trackEvent('overlay_shown', { trigger: trigger, intent: INTENT.level });
    }

    function showReturnBanner (visits) {
      if (document.getElementById('cx4-return-banner')) return;
      var offer =
        visits >= 6 ? '25% OFF — code APEX25' :
        visits >= 4 ? '20% OFF — code APEX20' :
        visits >= 2 ? '7-day free Pro trial'  :
                      'free IOC bundle';
      var banner = el('div', { id: 'cx4-return-banner' });
      banner.innerHTML =
        '<span class="rb-text">Welcome back! \uD83D\uDC4B Visit <strong>#' + visits + '</strong> \u2014 claim your <strong>' + offer + '</strong></span>' +
        '<a href="' + CFG.pricing + '" class="rb-btn" data-track="return_banner_click">Claim \u2192</a>' +
        '<button class="rb-close" aria-label="Close">&#x2715;</button>';

      document.body.appendChild(banner);
      banner.querySelector('.rb-close').onclick = function () {
        banner.parentNode.removeChild(banner);
      };
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { banner.classList.add('show'); });
      });
      window.trackEvent('return_banner_shown', { visits: visits, offer: offer });
    }

    function onIntentUpgrade (level) {
      if (overlayShown) return;

      var seg = SEGMENTS.detect();
      var msg = SEGMENTS.getMessage(seg);

      if (level === 'medium') {
        setTimeout(function () {
          showOverlay(msg, 'intent_medium_' + seg);
          overlayShown = true;
        }, 600);
      }

      if (level === 'high') {
        if (!enterpriseShown && (seg === 'enterprise' || SESSION.pageCount() >= 3)) {
          setTimeout(function () {
            showOverlay({
              badge:    '\uD83C\uDFE2 HIGH-INTENT DETECTED',
              headline: 'Enterprise-Grade Intel — Let\'s Talk',
              sub:      'You\'ve explored this platform extensively. Our enterprise team can build a custom solution for your security operations.',
              cta:      'Request Enterprise Proposal \u2192',
              url:      CFG.enterprise
            }, 'intent_high_enterprise');
            enterpriseShown = true;
            overlayShown    = true;
          }, 600);
        } else {
          setTimeout(function () {
            showOverlay(msg, 'intent_high_' + seg);
            overlayShown = true;
          }, 600);
        }
      }
    }

    function init () {
      INTENT.onUpgrade(onIntentUpgrade);

      /* Return visitor banner */
      var v = SESSION.visits;
      if (v >= 2) {
        setTimeout(function () { showReturnBanner(v); }, 3000);
      }
    }

    return { init: init };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 10 — CONTEXT-AWARE PRODUCT ENGINE
     Injects 2 inline product cards mid-post based on page context.
     Guards against monetization.js .apex-inline-cta already injected.
  ═══════════════════════════════════════════════════════════════════════ */
  var CONTEXT_PRODUCTS = (function () {
    var done = false;

    css(
      '.cx4-prod-card{' +
        'background:linear-gradient(135deg,rgba(0,255,224,.05),rgba(0,212,255,.03));' +
        'border:1px solid rgba(0,255,224,.18);border-radius:12px;' +
        'padding:1.2rem 1.4rem;margin:1.75rem 0;' +
        'display:flex;align-items:center;gap:1.1rem;flex-wrap:wrap;' +
        'font-family:"Segoe UI",system-ui,sans-serif;' +
      '}' +
      '.cx4-prod-card .pc-icon{font-size:2rem;flex-shrink:0}' +
      '.cx4-prod-card .pc-body{flex:1;min-width:180px}' +
      '.cx4-prod-card .pc-title{font-size:.92rem;font-weight:800;color:#fff;margin-bottom:.2rem}' +
      '.cx4-prod-card .pc-sub{font-size:.78rem;color:#64748b;line-height:1.5}' +
      '.cx4-prod-card .pc-btn{' +
        'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
        'color:#000;font-weight:800;font-size:.78rem;' +
        'padding:.5rem 1rem;border-radius:8px;text-decoration:none;' +
        'white-space:nowrap;flex-shrink:0;transition:opacity .2s;' +
      '}' +
      '.cx4-prod-card .pc-btn:hover{opacity:.85;text-decoration:none}'
    );

    var CONTEXT_CARDS = {
      cve: [
        {
          icon: '\uD83D\uDEE1\uFE0F',
          title: 'CVE Detection Pack — Sigma + YARA + SIEM Queries',
          sub:   'Get production-ready detection rules for this CVE and 200+ others. Splunk SPL, Elastic KQL, Microsoft Sentinel — deploy in 60 seconds.',
          cta:   'Get CVE Detection Pack \u2192',
          url:   '/products.html',
          track: 'ctx_prod_cve_1'
        },
        {
          icon: '\uD83D\uDD0C',
          title: 'Automate CVE Intelligence into Your SIEM via API',
          sub:   'Real-time CVE data, exploitability scores, and IOC feeds via REST API. Free tier. Production-grade SLA for teams.',
          cta:   'Start Free API Trial \u2192',
          url:   '/api.html',
          track: 'ctx_prod_cve_2'
        }
      ],
      ransomware: [
        {
          icon: '\uD83D\uDCE6',
          title: 'Ransomware Defense Kit — IOC Bundle + Playbook',
          sub:   'April 2026 ransomware IOCs (Qilin, Akira, LockBit, BlackBasta), YARA rules, SIEM detections, and IR playbook — download-ready.',
          cta:   'Get Ransomware Defense Kit \u2192',
          url:   '/products.html',
          track: 'ctx_prod_ransom_1'
        },
        {
          icon: '\uD83D\uDEE1\uFE0F',
          title: 'SOC Pro — Get Ransomware Intel Before Campaigns Hit',
          sub:   'Track active ransomware groups with 48H pre-disclosure intel, IOC feeds updated daily, and a dedicated Slack alerts channel.',
          cta:   'Join SOC Pro \u2014 $49/mo \u2192',
          url:   '/pricing.html',
          track: 'ctx_prod_ransom_2'
        }
      ],
      apt: [
        {
          icon: '\uD83C\uDFAF',
          title: 'APT Intelligence Pack — Nation-State Actor Profiles',
          sub:   'Volt Typhoon, Lazarus, APT28, APT41 — full TTP analysis, C2 infrastructure maps, YARA detection rules, and SIEM queries.',
          cta:   'Get APT Intelligence Pack \u2192',
          url:   '/products.html',
          track: 'ctx_prod_apt_1'
        },
        {
          icon: '\uD83C\uDFE2',
          title: 'Enterprise APT Monitoring — Dedicated Analyst',
          sub:   'Custom threat actor tracking, brand monitoring, and proactive alerts. Built for enterprises defending critical infrastructure.',
          cta:   'Get Enterprise Proposal \u2192',
          url:   '/enterprise.html',
          track: 'ctx_prod_apt_2'
        }
      ],
      ai: [
        {
          icon: '\uD83E\uDD16',
          title: 'AI Security Assessment Pack — LLM Threat Detection',
          sub:   'Prompt injection detection rules, LLM abuse patterns, agentic AI threat models, and enterprise AI governance templates.',
          cta:   'Get AI Security Pack \u2192',
          url:   '/products.html',
          track: 'ctx_prod_ai_1'
        },
        {
          icon: '\uD83D\uDD0C',
          title: 'AI Risk API — Integrate LLM Threat Intelligence',
          sub:   'Structured AI vulnerability data, prompt injection IOCs, and risk scores for AI deployments via REST API.',
          cta:   'Explore AI Risk API \u2192',
          url:   '/api.html',
          track: 'ctx_prod_ai_2'
        }
      ],
      general: [
        {
          icon: '\uD83D\uDCCA',
          title: 'SENTINEL APEX Intelligence Store — Detection Packs',
          sub:   'Sigma rules, YARA signatures, threat reports, and SOC automation scripts. From $9. Deploy-ready in minutes.',
          cta:   'Browse Products \u2192',
          url:   '/products.html',
          track: 'ctx_prod_gen_1'
        },
        {
          icon: '\u26A1',
          title: 'SOC Pro — Full Platform Access at $49/mo',
          sub:   '48H pre-disclosure CVEs, complete IOC bundles, SIEM rules, ransomware tracker, and API access. 7-day free trial.',
          cta:   'Start Free Trial \u2192',
          url:   '/pricing.html',
          track: 'ctx_prod_gen_2'
        }
      ]
    };

    function detectCtx () {
      var p = page.toLowerCase();
      var t = (document.title || '').toLowerCase();
      if (p.indexOf('cve-') !== -1 || t.indexOf('zero-day') !== -1 || t.indexOf(' rce') !== -1) return 'cve';
      if (p.indexOf('ransomware') !== -1 || t.indexOf('ransomware') !== -1 || t.indexOf('lockbit') !== -1) return 'ransomware';
      if (p.indexOf('typhoon') !== -1 || p.indexOf('apt') !== -1 || t.indexOf('nation-state') !== -1) return 'apt';
      if (p.indexOf('ai-') !== -1 || t.indexOf('prompt injection') !== -1 || t.indexOf('llm') !== -1) return 'ai';
      return 'general';
    }

    function inject () {
      if (done) return;
      if (page.indexOf('/posts/') === -1) return;

      /* Don't double-inject if monetization.js already did inline CTAs */
      var existingCTAs = document.querySelectorAll('.apex-inline-cta, .cx-inline-cta');
      if (existingCTAs.length >= 2) {
        done = true;
        return;
      }

      var ctx   = detectCtx();
      var cards = CONTEXT_CARDS[ctx] || CONTEXT_CARDS.general;
      var paras = Array.from(document.querySelectorAll(
        'article p, .post-body p, main p, .article-body p, section p'
      ));
      if (paras.length < 4) return;

      var insertPoints = [
        Math.floor(paras.length * 0.32),
        Math.floor(paras.length * 0.62)
      ];

      insertPoints.forEach(function (idx, i) {
        var card = cards[i];
        if (!card) return;
        var target = paras[idx];
        if (!target || target.dataset.cx4Injected) return;
        target.dataset.cx4Injected = '1';

        var cardEl = el('div', { cls: 'cx4-prod-card' }, [
          el('div', { cls: 'pc-icon' }, [card.icon]),
          el('div', { cls: 'pc-body' }, [
            el('div', { cls: 'pc-title' }, [card.title]),
            el('div', { cls: 'pc-sub'   }, [card.sub])
          ]),
          el('a', { cls: 'pc-btn', href: card.url, 'data-track': card.track,
            '@click': function () { window.trackEvent('ctx_product_click', { ctx: ctx, card: card.track }); }
          }, [card.cta])
        ]);
        target.insertAdjacentElement('afterend', cardEl);
      });

      done = true;
      window.trackEvent('ctx_products_injected', { ctx: ctx, paras: paras.length });
    }

    return { inject: inject, detectCtx: detectCtx };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 11 — TRUST AMPLIFICATION
     Injects a global trust stats strip on index + post pages.
     Fires once per session.
  ═══════════════════════════════════════════════════════════════════════ */
  var TRUST = (function () {
    css(
      '#cx4-trust-strip{' +
        'display:flex;align-items:center;justify-content:center;gap:2rem;flex-wrap:wrap;' +
        'padding:.65rem 1.5rem;' +
        'background:rgba(0,255,224,.04);border-top:1px solid rgba(0,255,224,.1);' +
        'border-bottom:1px solid rgba(0,255,224,.1);' +
        'font-family:"Segoe UI",system-ui,sans-serif;font-size:.78rem;' +
      '}' +
      '#cx4-trust-strip .ts-stat{display:flex;align-items:center;gap:.4rem;color:#64748b}' +
      '#cx4-trust-strip .ts-stat strong{color:#94a3b8;font-weight:700}' +
      '#cx4-trust-strip .ts-live{' +
        'display:flex;align-items:center;gap:.3rem;' +
        'color:' + CYAN + ';font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em;' +
      '}' +
      '#cx4-trust-strip .ts-dot{' +
        'width:7px;height:7px;border-radius:50%;background:#22c55e;' +
        'animation:cx4trustpulse 1.8s infinite;flex-shrink:0;' +
      '}' +
      '@keyframes cx4trustpulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}'
    );

    function inject () {
      if (document.getElementById('cx4-trust-strip')) return;

      /* Find the right insertion point — after nav or first section */
      var after = document.querySelector('nav') ||
                  document.querySelector('header') ||
                  document.querySelector('body > div:first-child') ||
                  document.body.firstElementChild;

      if (!after) return;

      var T = CFG.trust;
      var strip = el('div', { id: 'cx4-trust-strip' });
      strip.innerHTML =
        '<div class="ts-live"><div class="ts-dot"></div>LIVE INTEL</div>' +
        '<div class="ts-stat"><strong>' + T.subscribers + '</strong> security professionals</div>' +
        '<div class="ts-stat"><strong>' + T.cves + '</strong> vulnerabilities tracked</div>' +
        '<div class="ts-stat">Updated every <strong>' + T.updateMin + '</strong> minutes</div>' +
        '<div class="ts-stat"><strong>' + T.countries + '</strong> countries covered</div>';

      if (after.nextSibling) {
        after.parentNode.insertBefore(strip, after.nextSibling);
      } else {
        after.parentNode.appendChild(strip);
      }
      window.trackEvent('trust_strip_shown', {});
    }

    return { inject: inject };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 12 — RETARGETING PIXEL MANAGER
  ═══════════════════════════════════════════════════════════════════════ */
  var PIXELS = (function () {
    function loadGA4 () {
      if (CFG.gaId.indexOf('XXXX') !== -1) return;
      var s = document.createElement('script');
      s.src   = 'https://www.googletagmanager.com/gtag/js?id=' + CFG.gaId;
      s.async = true;
      document.head.appendChild(s);
      window.dataLayer = window.dataLayer || [];
      window.gtag = function () { dataLayer.push(arguments); };
      gtag('js', new Date());
      gtag('config', CFG.gaId, {
        page_title:    document.title,
        page_location: window.location.href,
        custom_map:    { dimension1: 'ab_variant', dimension2: 'user_segment', dimension3: 'intent_level' }
      });
      gtag('set', 'user_properties', {
        ab_variant:    AB.variant.id,
        user_segment:  SEGMENTS.detect(),
        intent_level:  INTENT.level,
        visit_count:   SESSION.visits
      });
    }

    function loadGAds () {
      if (CFG.gadsId.indexOf('XXXX') !== -1) return;
      if (typeof gtag === 'undefined') return;
      gtag('config', CFG.gadsId);
    }

    function loadFB () {
      if (CFG.fbPixelId.indexOf('XXXX') !== -1) return;
      /* eslint-disable */
      !function (f, b, e, v, n, t, s) {
        if (f.fbq) return;
        n = f.fbq = function () { n.callMethod ? n.callMethod.apply(n, arguments) : n.queue.push(arguments); };
        if (!f._fbq) f._fbq = n;
        n.push = n; n.loaded = !0; n.version = '2.0'; n.queue = [];
        t = b.createElement(e); t.async = !0; t.src = v;
        s = b.getElementsByTagName(e)[0]; s.parentNode.insertBefore(t, s);
      }(window, document, 'script', 'https://connect.facebook.net/en_US/fbevents.js');
      /* eslint-enable */
      fbq('init', CFG.fbPixelId);
      fbq('track', 'PageView');
    }

    function fireConversion (type, value) {
      window.trackEvent('conversion', { type: type, value: value });
      if (typeof gtag !== 'undefined' && CFG.gadsId.indexOf('XXXX') === -1) {
        gtag('event', 'conversion', { send_to: CFG.gadsId + '/CONV_LABEL', value: value, currency: 'USD' });
      }
      if (typeof fbq !== 'undefined') {
        fbq('track', 'Purchase', { value: value, currency: 'USD', content_name: type });
      }
    }

    return { init: function () { loadGA4(); loadGAds(); loadFB(); }, fireConversion: fireConversion };
  }());

  /* ═══════════════════════════════════════════════════════════════════════
     SECTION 13 — BOOT SEQUENCE
     Load order: AB → TRACK → EXIT_INTENT → CTA_TRIGGERS →
                 CONTEXT_PRODUCTS → TRUST → PIXELS → debug log
  ═══════════════════════════════════════════════════════════════════════ */
  function boot () {
    /* Performance: skip if page is a redirect/error page */
    if (document.body.innerHTML.length < 200) return;

    AB.applyPriceAnchors();
    AB.applyCTAText();

    TRACK.init();
    EXIT_INTENT.init();
    CTA_TRIGGERS.init();

    if (page.indexOf('/posts/') !== -1) {
      setTimeout(function () { CONTEXT_PRODUCTS.inject(); }, 900);
    }

    TRUST.inject();
    PIXELS.init();

    window.trackEvent('page_view', {
      segment: SEGMENTS.detect(),
      visits:  SESSION.visits,
      ab:      AB.variant.id
    });

    /* Expose global API for admin dashboard + debugging */
    window.CX = {
      SESSION: SESSION,
      INTENT:  INTENT,
      AB:      AB,
      PAYWALL: PAYWALL,
      PIXELS:  PIXELS,
      trackEvent: window.trackEvent,
      report: function () {
        return {
          session:   SESSION.toReport(),
          events:    (ls.get(CFG.K_EVENTS) || []).slice(-20),
          ab:        AB.variant,
          visits:    SESSION.visits
        };
      }
    };

    setTimeout(function () {
      console.info('[SENTINEL APEX CX v4.0] Session report:', window.CX.report());
    }, 4000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

}());
