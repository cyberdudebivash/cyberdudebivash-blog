/**
 * CYBERDUDEBIVASH SENTINEL APEX — Conversion Engine v3.0 (CLEAN REBUILD)
 * ═══════════════════════════════════════════════════════════════════════
 * Systems:
 *   1. A/B Testing Framework     — CTA text, pricing anchors, urgency variants
 *   2. Behavioral Tracker        — Scroll depth, clicks, time on page, exit points
 *   3. Smart CTA Engine          — Trigger-based personalized offers
 *   4. Lead Segmentation         — Developer / SOC / Enterprise persona detection
 *   5. Retargeting Pixel Manager — GA4, Google Ads, FB pixel orchestration
 *   6. Revenue Intelligence      — Conversion event firing + local reporting
 *
 * Deploy: <script src="/conversion-engine.js" defer></script>
 * Load after monetization.js
 */
(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════
     0. CONFIG
  ═══════════════════════════════════════════════════════════════ */
  var CFG = {
    gaId:           'G-XXXXXXXXXX',
    gadsId:         'AW-XXXXXXXXXX',
    fbPixelId:      'XXXXXXXXXXXXXXXXXX',
    formsubmit:     'https://formsubmit.co/bivash@cyberdudebivash.com',
    pricingUrl:     '/pricing.html',
    apiUrl:         '/api.html',
    productsUrl:    '/products.html',
    enterpriseUrl:  '/enterprise.html',
    leadsUrl:       '/leads.html',
    scrollUnlockPct:   70,
    scrollMidCTAPct:   45,
    returnVisitKey:    'cx_visits',
    sessionKey:        'cx_session',
    abKey:             'cx_ab_variant',
    abVariants: {
      cta:     ['Get Threat Intel', 'Download IOC Pack', 'Unlock Full Report', 'Access Live Feed'],
      price:   ['anchor', 'direct', 'savings'],
      urgency: ['exploited', 'critical', 'advisory']
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     1. UTILITIES
  ═══════════════════════════════════════════════════════════════ */
  var CYAN   = '#00ffe0';

  var ls = {
    get:  function(k)    { try { return JSON.parse(localStorage.getItem(k)); } catch(e) { return null; } },
    set:  function(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch(e) {} },
    push: function(k, v) { var a = ls.get(k) || []; a.push(v); ls.set(k, a.slice(-200)); }
  };

  function qs(s)    { return document.querySelector(s); }
  function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
  function now()    { return Date.now(); }
  var page = window.location.pathname;

  function injectStyle(css) {
    var s = document.createElement('style');
    s.textContent = css;
    document.head.appendChild(s);
  }

  function makeEl(tag, attrs, children) {
    var e = document.createElement(tag);
    attrs = attrs || {};
    children = children || [];
    Object.keys(attrs).forEach(function(k) {
      var v = attrs[k];
      if (k === 'style') {
        if (typeof v === 'object') { Object.assign(e.style, v); }
        else { e.setAttribute('style', v); }
      } else if (k === 'class') {
        e.className = v;
      } else if (k === 'html') {
        e.innerHTML = v;
      } else if (k.indexOf('on') === 0) {
        e.addEventListener(k.slice(2), v);
      } else {
        e.setAttribute(k, v);
      }
    });
    children.forEach(function(c) {
      if (typeof c === 'string') { e.appendChild(document.createTextNode(c)); }
      else if (c) { e.appendChild(c); }
    });
    return e;
  }

  /* ═══════════════════════════════════════════════════════════════
     2. A/B TESTING FRAMEWORK
  ═══════════════════════════════════════════════════════════════ */
  var AB = {
    variant: null,
    ctaText: null,
    priceStyle: null,
    urgencyStyle: null,

    init: function() {
      var stored = ls.get(CFG.abKey);
      if (!stored) {
        stored = {
          cta:     rand(CFG.abVariants.cta),
          price:   rand(CFG.abVariants.price),
          urgency: rand(CFG.abVariants.urgency),
          id:      Math.random().toString(36).slice(2, 8)
        };
        ls.set(CFG.abKey, stored);
      }
      this.ctaText      = stored.cta;
      this.priceStyle   = stored.price;
      this.urgencyStyle = stored.urgency;
      this.variant      = stored.id;

      document.querySelectorAll('[data-cx-cta]').forEach(function(btn) {
        btn.textContent = AB.ctaText;
      });
      this.applyPriceAnchors();
      TRACK.event('ab_assigned', { variant: stored });
    },

    applyPriceAnchors: function() {
      if (this.priceStyle === 'anchor') {
        document.querySelectorAll('[data-cx-price]').forEach(function(el) {
          var base = el.dataset.cxPrice;
          var orig = el.dataset.cxOrig || Math.round(parseInt(base) * 2.5);
          var pct  = Math.round((1 - base / orig) * 100);
          el.innerHTML =
            '<span style="font-size:1.5rem;font-weight:900;color:' + CYAN + '">$' + base + '</span>' +
            '<span style="text-decoration:line-through;color:#64748b;font-size:.9rem;margin-left:.3rem">$' + orig + '</span>' +
            '<span style="background:rgba(34,197,94,0.2);color:#22c55e;font-size:.7rem;padding:.1rem .4rem;border-radius:4px;margin-left:.4rem">SAVE ' + pct + '%</span>';
        });
      } else if (this.priceStyle === 'savings') {
        document.querySelectorAll('[data-cx-price]').forEach(function(el) {
          var base = el.dataset.cxPrice;
          var orig = parseInt(el.dataset.cxOrig || Math.round(parseInt(base) * 2.5));
          var save = orig - parseInt(base);
          el.innerHTML =
            '<span style="font-size:1.5rem;font-weight:900;color:' + CYAN + '">$' + base + '</span>' +
            '<span style="color:#22c55e;font-size:.8rem;margin-left:.5rem;font-weight:700">Save $' + save + '</span>';
        });
      }
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     3. BEHAVIORAL TRACKER
  ═══════════════════════════════════════════════════════════════ */
  var TRACK = {
    session:    null,
    startTime:  now(),
    clickCount: 0,
    maxScroll:  0,

    init: function() {
      var s = ls.get(CFG.sessionKey);
      if (!s || (now() - s.lastSeen > 30 * 60 * 1000)) {
        s = { id: Math.random().toString(36).slice(2, 10), start: now(), page: page, pageviews: 0 };
      }
      s.lastSeen  = now();
      s.pageviews = (s.pageviews || 0) + 1;
      ls.set(CFG.sessionKey, s);
      this.session = s;

      var visits = (ls.get(CFG.returnVisitKey) || 0) + 1;
      ls.set(CFG.returnVisitKey, visits);

      var scrollThrottle;
      window.addEventListener('scroll', function() {
        clearTimeout(scrollThrottle);
        scrollThrottle = setTimeout(function() {
          var scrollable = document.documentElement.scrollHeight - window.innerHeight;
          if (scrollable < 1) return;
          var pct = Math.round((window.scrollY / scrollable) * 100);
          if (pct > TRACK.maxScroll) {
            TRACK.maxScroll = pct;
            ls.push('cx_scroll_events', { page: page, pct: pct, t: now() - TRACK.startTime });
            SMART_CTA.checkScroll(pct);
          }
        }, 200);
      });

      document.addEventListener('click', function(e) {
        var target = e.target.closest('a, button, [data-track]');
        if (!target) return;
        var label = target.dataset.track || target.textContent.trim().slice(0, 40) || target.href || '';
        TRACK.clickCount++;
        TRACK.event('click', { label: label, page: page, el: target.tagName });
        var href = (target.href || '').toLowerCase();
        if (href.includes('api') || href.includes('pricing') || href.includes('enterprise')) {
          SMART_CTA.onHighIntent(href);
        }
      });

      document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'hidden') {
          TRACK.event('exit', {
            page: page,
            scrollPct: TRACK.maxScroll,
            timeOnPage: Math.round((now() - TRACK.startTime) / 1000),
            clicks: TRACK.clickCount
          });
        }
      });

      [30, 60, 120, 300].forEach(function(sec) {
        setTimeout(function() {
          TRACK.event('time_milestone', { sec: sec, page: page, scroll: TRACK.maxScroll });
        }, sec * 1000);
      });
    },

    event: function(name, data) {
      data = data || {};
      var evt = {
        name: name, data: data, page: page,
        ts: now(), variant: AB.variant,
        session: TRACK.session ? TRACK.session.id : null
      };
      ls.push('cx_events', evt);
      if (typeof gtag !== 'undefined') {
        try { gtag('event', name, Object.assign({}, data, { platform: 'sentinel_apex' })); } catch(e) {}
      }
      if (typeof fbq !== 'undefined') {
        try {
          if (name === 'lead_captured')   fbq('track', 'Lead', data);
          if (name === 'purchase_intent') fbq('track', 'AddToCart', data);
          if (name === 'api_click')       fbq('track', 'ViewContent', { content_name: 'API Page' });
        } catch(e) {}
      }
    },

    getProfile: function() {
      return {
        visits:     ls.get(CFG.returnVisitKey) || 1,
        maxScroll:  this.maxScroll,
        timeOnPage: Math.round((now() - this.startTime) / 1000),
        clicks:     this.clickCount,
        variant:    AB.variant,
        segment:    SEGMENTS.detect()
      };
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     4. LEAD SEGMENTATION
  ═══════════════════════════════════════════════════════════════ */
  var SEGMENTS = {
    detect: function() {
      var p   = window.location.pathname;
      var ref = document.referrer.toLowerCase();
      var events = ls.get('cx_events') || [];
      var apiClicks     = events.filter(function(e) { return e.name === 'click' && String(e.data && e.data.label).includes('api'); }).length;
      var pricingClicks = events.filter(function(e) { return e.name === 'click' && String(e.data && e.data.label).includes('pric'); }).length;

      if (apiClicks >= 2 || p.includes('api'))                               return 'developer';
      if (pricingClicks >= 1 || p.includes('enterprise') || p.includes('pricing')) return 'enterprise';
      if (ref.includes('github') || ref.includes('stackoverflow'))           return 'developer';
      if (ref.includes('linkedin') || ref.includes('twitter') || ref.includes('x.com')) return 'security_pro';
      return 'soc_analyst';
    },

    getMessage: function(segment) {
      var msgs = {
        developer: {
          badge: '🔌 API-FIRST THREAT INTELLIGENCE',
          headline: 'Integrate CVE & IOC Data Into Your SIEM',
          sub: 'Structured CVE feeds, IOC bundles, and AI risk scoring via REST API. Free tier available.',
          cta: 'Start Free API Trial →',
          url: CFG.apiUrl
        },
        enterprise: {
          badge: '🏢 ENTERPRISE INTELLIGENCE PLATFORM',
          headline: 'Enterprise Threat Intel — SLA-Backed',
          sub: 'White-label feeds, dedicated analyst support, and custom detection rules for your environment.',
          cta: 'Get Enterprise Proposal →',
          url: CFG.enterpriseUrl
        },
        soc_analyst: {
          badge: '🛡️ DETECTION ENGINEERING',
          headline: 'Sigma & YARA Detection Packs — 2026',
          sub: '1,200+ production rules mapped to MITRE ATT&CK. Deploy to Splunk/Elastic in 60 seconds.',
          cta: 'Browse Detection Packs →',
          url: CFG.productsUrl
        },
        security_pro: {
          badge: '⚡ SOC PRO MEMBERSHIP',
          headline: 'SOC Pro — Unlimited Intel Access',
          sub: 'Full IOC packs, SIEM rules, 48H pre-disclosure CVE reports, and monthly threat roundups.',
          cta: 'Start 7-Day Free Trial →',
          url: CFG.pricingUrl
        }
      };
      return msgs[segment] || msgs.soc_analyst;
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     5. SMART CTA ENGINE
  ═══════════════════════════════════════════════════════════════ */

  // Inject styles using string concat to avoid backtick nesting issues
  injectStyle(
    '#cx-smart-overlay{' +
      'position:fixed;bottom:80px;right:20px;z-index:9999;' +
      'width:340px;max-width:calc(100vw - 40px);' +
      'background:rgba(7,9,15,0.97);' +
      'border:1px solid rgba(0,255,224,0.3);' +
      'border-radius:16px;padding:1.25rem;' +
      'box-shadow:0 20px 60px rgba(0,0,0,0.5),0 0 30px rgba(0,255,224,0.08);' +
      'transform:translateX(380px);transition:transform .4s cubic-bezier(.22,.68,0,1.2);' +
      'font-family:"Segoe UI",system-ui,sans-serif;' +
    '}' +
    '#cx-smart-overlay.cx-show{transform:translateX(0)}' +
    '#cx-smart-overlay .cx-close{' +
      'position:absolute;top:.6rem;right:.75rem;' +
      'background:none;border:none;color:#64748b;font-size:1rem;cursor:pointer;line-height:1;' +
    '}' +
    '#cx-smart-overlay .cx-close:hover{color:#fff}' +
    '#cx-smart-overlay .cx-badge{font-size:.65rem;font-weight:800;color:' + CYAN + ';text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem}' +
    '#cx-smart-overlay h4{font-size:.95rem;font-weight:800;color:#fff;margin-bottom:.35rem;line-height:1.3}' +
    '#cx-smart-overlay p{font-size:.8rem;color:#94a3b8;margin-bottom:.85rem;line-height:1.5}' +
    '#cx-smart-overlay .cx-btn{' +
      'display:block;width:100%;' +
      'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
      'color:#000;font-weight:800;font-size:.82rem;' +
      'padding:.6rem 1rem;border-radius:8px;' +
      'text-align:center;text-decoration:none;border:none;cursor:pointer;transition:opacity .2s;' +
    '}' +
    '#cx-smart-overlay .cx-btn:hover{opacity:.88}' +
    '#cx-smart-overlay .cx-dismiss{display:block;text-align:center;font-size:.72rem;color:#475569;margin-top:.5rem;cursor:pointer}' +
    '#cx-smart-overlay .cx-dismiss:hover{color:#94a3b8}' +
    '#cx-smart-overlay .cx-progress{height:3px;background:rgba(0,255,224,0.15);border-radius:2px;margin-bottom:.75rem;overflow:hidden}' +
    '#cx-smart-overlay .cx-progress-bar{height:100%;background:' + CYAN + ';border-radius:2px;transition:width .3s}' +
    '#cx-return-banner{' +
      'position:fixed;top:60px;left:0;right:0;z-index:9995;' +
      'background:linear-gradient(135deg,rgba(255,215,0,0.12),rgba(0,255,224,0.08));' +
      'border-bottom:1px solid rgba(255,215,0,0.25);padding:.6rem 1.5rem;' +
      'display:flex;align-items:center;justify-content:center;gap:1.5rem;flex-wrap:wrap;' +
      'transform:translateY(-100%);transition:transform .4s ease;' +
      'font-family:"Segoe UI",system-ui,sans-serif;' +
    '}' +
    '#cx-return-banner.cx-show{transform:translateY(0)}' +
    '#cx-return-banner span{font-size:.82rem;color:#e2e8f0;font-weight:500}' +
    '#cx-return-banner strong{color:#ffd700}' +
    '#cx-return-banner a{' +
      'background:linear-gradient(135deg,#ffd700,#ff8c00);' +
      'color:#000;font-weight:800;font-size:.75rem;padding:.35rem .85rem;border-radius:6px;text-decoration:none;white-space:nowrap;transition:opacity .2s;' +
    '}' +
    '#cx-return-banner a:hover{opacity:.85}' +
    '#cx-return-banner button{background:none;border:none;color:#475569;font-size:.9rem;cursor:pointer;margin-left:.5rem}' +
    '#cx-scroll-bar{position:fixed;top:0;left:0;height:3px;z-index:10001;background:linear-gradient(90deg,' + CYAN + ',#00d4ff);width:0%;transition:width .1s;pointer-events:none}' +
    '.cx-inline-cta{' +
      'background:linear-gradient(135deg,rgba(0,255,224,0.06),rgba(0,212,255,0.04));' +
      'border:1px solid rgba(0,255,224,0.2);border-radius:12px;' +
      'padding:1.25rem 1.5rem;margin:2rem 0;' +
      'display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;' +
    '}' +
    '.cx-inline-cta .ci-icon{font-size:2rem;flex-shrink:0}' +
    '.cx-inline-cta .ci-body{flex:1;min-width:200px}' +
    '.cx-inline-cta .ci-body strong{display:block;font-size:.95rem;font-weight:800;color:#fff;margin-bottom:.25rem}' +
    '.cx-inline-cta .ci-body span{font-size:.8rem;color:#94a3b8}' +
    '.cx-inline-cta a{' +
      'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
      'color:#000;font-weight:800;font-size:.8rem;' +
      'padding:.55rem 1.1rem;border-radius:8px;text-decoration:none;white-space:nowrap;flex-shrink:0;' +
    '}' +
    '#cx-enterprise-flash{' +
      'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) scale(.9);' +
      'z-index:10000;width:480px;max-width:calc(100vw - 32px);' +
      'background:rgba(7,9,15,0.98);' +
      'border:1px solid rgba(0,255,224,0.3);border-radius:20px;padding:2rem;text-align:center;' +
      'box-shadow:0 40px 100px rgba(0,0,0,0.7),0 0 60px rgba(0,255,224,0.06);' +
      'opacity:0;pointer-events:none;transition:all .35s cubic-bezier(.22,.68,0,1.2);' +
      'font-family:"Segoe UI",system-ui,sans-serif;' +
    '}' +
    '#cx-enterprise-flash.cx-show{opacity:1;pointer-events:all;transform:translate(-50%,-50%) scale(1)}' +
    '#cx-ef-backdrop{position:fixed;inset:0;z-index:9999;background:rgba(0,0,.6);backdrop-filter:blur(4px);opacity:0;pointer-events:none;transition:opacity .3s}' +
    '#cx-ef-backdrop.cx-show{opacity:1;pointer-events:all}'
  );

  var SMART_CTA = {
    overlayShown:        false,
    returnBannerShown:   false,
    enterpriseFlashShown: false,
    inlineCTAsInjected:  false,
    scrollBar:           null,

    init: function() {
      this.scrollBar = makeEl('div', { id: 'cx-scroll-bar' });
      document.body.appendChild(this.scrollBar);
      var self = this;
      window.addEventListener('scroll', function() {
        var scrollable = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
        var pct = Math.round((window.scrollY / scrollable) * 100);
        if (self.scrollBar) self.scrollBar.style.width = pct + '%';
      });

      var visits = ls.get(CFG.returnVisitKey) || 1;
      if (visits >= 2) {
        setTimeout(function() { self.showReturnBanner(visits); }, 2500);
      }

      if (page.includes('/posts/')) {
        setTimeout(function() { self.injectInlineCTAs(); }, 1200);
      }
    },

    checkScroll: function(pct) {
      if (pct >= CFG.scrollMidCTAPct && !this.overlayShown) {
        var seg = SEGMENTS.detect();
        var msg = SEGMENTS.getMessage(seg);
        var self = this;
        setTimeout(function() { self.showOverlay(msg, 'mid_scroll'); }, 500);
        this.overlayShown = true;
      }
      if (pct >= CFG.scrollUnlockPct && !this.overlayShown) {
        this.showOverlay({
          badge:    '⚡ PRO MEMBERS ONLY',
          headline: '🔒 Unlock Full Intelligence Report',
          sub:      'Complete IOC lists, SIEM detection rules, YARA signatures, and analyst commentary — exclusive to SOC Pro members.',
          cta:      'Unlock Full Report — $49/mo',
          url:      CFG.pricingUrl
        }, 'scroll_unlock');
        this.overlayShown = true;
        TRACK.event('scroll_unlock_shown', { pct: pct });
      }
    },

    onHighIntent: function(href) {
      if (this.enterpriseFlashShown) return;
      if (href.includes('enterprise') || href.includes('pricing')) {
        var self = this;
        setTimeout(function() { self.showEnterpriseFlash(); }, 800);
        this.enterpriseFlashShown = true;
        TRACK.event('high_intent_detected', { href: href });
      }
    },

    showOverlay: function(msg, trigger) {
      var existing = document.getElementById('cx-smart-overlay');
      if (existing) existing.remove();

      var progressPct = TRACK.maxScroll + '%';
      var overlay = makeEl('div', { id: 'cx-smart-overlay' }, [
        makeEl('button', { class: 'cx-close', onclick: function() { overlay.classList.remove('cx-show'); } }, ['✕']),
        makeEl('div', { class: 'cx-progress' }, [
          makeEl('div', { class: 'cx-progress-bar', style: 'width:' + progressPct })
        ]),
        makeEl('div', { class: 'cx-badge' }, [msg.badge || '⚡ SENTINEL APEX INTELLIGENCE']),
        makeEl('h4', {}, [msg.headline || 'Upgrade for Full Access']),
        makeEl('p',  {}, [msg.sub || 'Get unrestricted access to IOC packs, SIEM rules, and premium reports.']),
        makeEl('a', { class: 'cx-btn', href: msg.url || CFG.pricingUrl,
          onclick: function() { TRACK.event('smart_cta_click', { trigger: trigger, msg: msg.headline }); }
        }, [msg.cta || AB.ctaText || 'Get Full Access →']),
        makeEl('span', { class: 'cx-dismiss',
          onclick: function() {
            overlay.classList.remove('cx-show');
            TRACK.event('smart_cta_dismissed', { trigger: trigger });
          }
        }, ['Not now — remind me later'])
      ]);
      document.body.appendChild(overlay);
      requestAnimationFrame(function() {
        requestAnimationFrame(function() { overlay.classList.add('cx-show'); });
      });
      TRACK.event('smart_overlay_shown', { trigger: trigger });
    },

    showReturnBanner: function(visits) {
      if (document.getElementById('cx-return-banner')) return;
      var offer = visits >= 5 ? '20% OFF with code APEX20' :
                  visits >= 3 ? '7-day free Pro trial'     :
                                'free threat report';
      var banner = makeEl('div', { id: 'cx-return-banner' }, [
        makeEl('span', { html: 'Welcome back! \uD83D\uDC4B You\'ve visited <strong>' + visits + 'x</strong> \u2014 claim your ' }),
        makeEl('strong', {}, [offer]),
        makeEl('a', { href: CFG.pricingUrl,
          onclick: function() { TRACK.event('return_banner_click', { visits: visits, offer: offer }); }
        }, ['Claim Offer \u2192']),
        makeEl('button', {
          onclick: function() {
            var b = document.getElementById('cx-return-banner');
            if (b) b.remove();
          }
        }, ['\u2715'])
      ]);
      document.body.appendChild(banner);
      requestAnimationFrame(function() {
        requestAnimationFrame(function() { banner.classList.add('cx-show'); });
      });
      TRACK.event('return_banner_shown', { visits: visits });
    },

    showEnterpriseFlash: function() {
      var backdrop = makeEl('div', { id: 'cx-ef-backdrop',
        onclick: function() {
          var f = document.getElementById('cx-enterprise-flash');
          if (f) f.classList.remove('cx-show');
          backdrop.classList.remove('cx-show');
        }
      });
      var flash = makeEl('div', { id: 'cx-enterprise-flash' }, [
        makeEl('div', { style: { fontSize: '2.5rem', marginBottom: '.75rem' } }, ['\uD83C\uDFE2']),
        makeEl('div', { style: { fontSize: '.7rem', fontWeight: '800', color: CYAN, letterSpacing: '.12em', textTransform: 'uppercase', marginBottom: '.5rem' } },
          ['\u26A1 ENTERPRISE INTELLIGENCE PLATFORM']),
        makeEl('h3', { style: { fontSize: '1.4rem', fontWeight: '900', color: '#fff', marginBottom: '.5rem', lineHeight: '1.3' } },
          ['Looks Like You Need Enterprise-Grade Threat Intel']),
        makeEl('p', { style: { fontSize: '.85rem', color: '#94a3b8', marginBottom: '1.5rem', lineHeight: '1.6' } },
          ['White-label feeds, SLA-backed data, dedicated analyst support, and custom detection rules built for your environment.']),
        makeEl('div', { style: { display: 'flex', gap: '.75rem', justifyContent: 'center', flexWrap: 'wrap', marginBottom: '1rem' } }, [
          makeEl('a', { href: CFG.enterpriseUrl,
            style: 'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);color:#000;font-weight:800;font-size:.85rem;padding:.65rem 1.4rem;border-radius:8px;text-decoration:none',
            onclick: function() {
              TRACK.event('enterprise_flash_click', {});
              var f = document.getElementById('cx-enterprise-flash');
              if (f) f.classList.remove('cx-show');
              backdrop.classList.remove('cx-show');
            }
          }, ['\uD83C\uDFE2 Get Enterprise Proposal']),
          makeEl('button', {
            style: 'background:none;border:1px solid rgba(0,255,224,0.2);color:#94a3b8;font-weight:600;font-size:.82rem;padding:.65rem 1.2rem;border-radius:8px;cursor:pointer',
            onclick: function() {
              var f = document.getElementById('cx-enterprise-flash');
              if (f) f.classList.remove('cx-show');
              backdrop.classList.remove('cx-show');
              TRACK.event('enterprise_flash_dismissed', {});
            }
          }, ['Maybe Later'])
        ])
      ]);
      document.body.appendChild(backdrop);
      document.body.appendChild(flash);
      requestAnimationFrame(function() {
        requestAnimationFrame(function() {
          backdrop.classList.add('cx-show');
          flash.classList.add('cx-show');
        });
      });
      TRACK.event('enterprise_flash_shown', {});
    },

    injectInlineCTAs: function() {
      if (this.inlineCTAsInjected) return;
      // Target all paragraph selectors used in current post HTML structure
      var paras = Array.from(document.querySelectorAll(
        'article p, .post-body p, main p, .content p, .article-body p, section p'
      ));
      if (paras.length < 4) return;

      var ctaDefs = [
        {
          after: Math.floor(paras.length * 0.35),
          icon: '\uD83D\uDEE1\uFE0F',
          title: 'Get Detection Rules for This CVE',
          sub:   'Sigma + YARA rules, IOC table, and SIEM queries — downloadable in seconds.',
          cta:   'Get Detection Pack \u2192',
          url:   CFG.productsUrl,
          track: 'inline_cta_detection'
        },
        {
          after: Math.floor(paras.length * 0.65),
          icon: '\uD83D\uDD0C',
          title: 'Integrate This Intel Into Your SIEM',
          sub:   'Access structured CVE data, IOC feeds, and risk scores via the SENTINEL APEX API.',
          cta:   'Start Free API Trial \u2192',
          url:   CFG.apiUrl,
          track: 'inline_cta_api'
        }
      ];

      var self = this;
      ctaDefs.forEach(function(def) {
        var target = paras[def.after];
        if (!target) return;
        var ctaEl = makeEl('div', { class: 'cx-inline-cta' }, [
          makeEl('div', { class: 'ci-icon' }, [def.icon]),
          makeEl('div', { class: 'ci-body' }, [
            makeEl('strong', {}, [def.title]),
            makeEl('span',   {}, [def.sub])
          ]),
          makeEl('a', { href: def.url,
            onclick: function() { TRACK.event(def.track, {}); }
          }, [def.cta])
        ]);
        target.insertAdjacentElement('afterend', ctaEl);
      });

      this.inlineCTAsInjected = true;
      TRACK.event('inline_ctas_injected', { paraCount: paras.length });
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     6. RETARGETING PIXEL MANAGER
  ═══════════════════════════════════════════════════════════════ */
  var PIXELS = {
    init: function() {
      this.loadGA4();
      this.loadGAds();
      this.loadFB();
    },

    loadGA4: function() {
      if (CFG.gaId.indexOf('XXXX') !== -1) return;
      var s = document.createElement('script');
      s.src   = 'https://www.googletagmanager.com/gtag/js?id=' + CFG.gaId;
      s.async = true;
      document.head.appendChild(s);
      window.dataLayer = window.dataLayer || [];
      window.gtag = function() { dataLayer.push(arguments); };
      gtag('js', new Date());
      gtag('config', CFG.gaId, {
        page_title:    document.title,
        page_location: window.location.href,
        custom_map:    { dimension1: 'ab_variant', dimension2: 'user_segment' }
      });
      gtag('set', 'user_properties', {
        ab_variant:    AB.variant,
        user_segment:  SEGMENTS.detect(),
        visit_count:   ls.get(CFG.returnVisitKey) || 1
      });
    },

    loadGAds: function() {
      if (CFG.gadsId.indexOf('XXXX') !== -1) return;
      if (typeof gtag !== 'undefined') gtag('config', CFG.gadsId);
    },

    loadFB: function() {
      if (CFG.fbPixelId.indexOf('XXXX') !== -1) return;
      /* eslint-disable */
      !function(f,b,e,v,n,t,s){
        if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
        if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
        t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)
      }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      /* eslint-enable */
      fbq('init', CFG.fbPixelId);
      fbq('track', 'PageView');
    },

    fireConversion: function(type, value) {
      TRACK.event('conversion', { type: type, value: value });
      if (typeof gtag !== 'undefined' && CFG.gadsId.indexOf('XXXX') === -1) {
        gtag('event', 'conversion', { send_to: CFG.gadsId + '/CONVERSION_LABEL', value: value, currency: 'USD' });
      }
      if (typeof fbq !== 'undefined') {
        fbq('track', 'Purchase', { value: value, currency: 'USD', content_name: type });
      }
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     7. REVENUE INTELLIGENCE REPORTER
  ═══════════════════════════════════════════════════════════════ */
  var REVENUE_INTEL = {
    getReport: function() {
      var events    = ls.get('cx_events')        || [];
      var scrollEvt = ls.get('cx_scroll_events') || [];
      var visits    = ls.get(CFG.returnVisitKey) || 1;
      var abData    = ls.get(CFG.abKey)          || {};
      var exitEvts  = events.filter(function(e) { return e.name === 'exit'; });
      var avgTime   = exitEvts.length ? Math.round(exitEvts.reduce(function(a, e) { return a + (e.data && e.data.timeOnPage ? e.data.timeOnPage : 0); }, 0) / exitEvts.length) : 0;
      return {
        totalEvents:   events.length,
        visits:        visits,
        abVariant:     abData,
        segment:       SEGMENTS.detect(),
        topPages:      Array.from(new Set(events.map(function(e) { return e.page; }))).slice(0, 10),
        clickLabels:   events.filter(function(e) { return e.name === 'click'; }).map(function(e) { return e.data && e.data.label; }).filter(Boolean).slice(-20),
        maxScroll:     Math.max.apply(null, scrollEvt.map(function(e) { return e.pct; }).concat([0])),
        overlaysShown: events.filter(function(e) { return e.name.indexOf('shown') !== -1; }).length,
        ctaClicks:     events.filter(function(e) { return e.name.indexOf('click') !== -1; }).length,
        avgTimeOnPage: avgTime
      };
    }
  };

  // Expose for debugging / admin dashboard
  window.CX = { AB: AB, TRACK: TRACK, SMART_CTA: SMART_CTA, SEGMENTS: SEGMENTS, PIXELS: PIXELS, REVENUE_INTEL: REVENUE_INTEL };

  /* ═══════════════════════════════════════════════════════════════
     8. BOOT SEQUENCE
  ═══════════════════════════════════════════════════════════════ */
  function boot() {
    AB.init();
    TRACK.init();
    SMART_CTA.init();
    PIXELS.init();
    setTimeout(function() {
      console.info('[SENTINEL APEX CX v3.0]', REVENUE_INTEL.getReport());
    }, 3000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})();
