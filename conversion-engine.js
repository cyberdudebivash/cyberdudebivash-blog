/**
 * CYBERDUDEBIVASH SENTINEL APEX — Conversion Engine v2.0
 * ═══════════════════════════════════════════════════════
 * Systems:
 *   1. A/B Testing Framework     — CTA text, pricing anchors, urgency variants
 *   2. Behavioral Tracker        — Scroll depth, clicks, time on page, exit points
 *   3. Smart CTA Engine          — Trigger-based personalized offers
 *   4. Retargeting Pixel Manager — GA4, Ads, FB pixel orchestration
 *   5. Revenue Intelligence      — Conversion event firing
 *
 * Deploy: <script src="/conversion-engine.js" defer></script>
 * Loads AFTER monetization.js
 */
(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════
     0. CONFIG
  ═══════════════════════════════════════════════════════════════ */
  const CFG = {
    gaId:           'G-XXXXXXXXXX',          // ← Replace with your GA4 ID
    gadsId:         'AW-XXXXXXXXXX',         // ← Replace with Google Ads ID
    fbPixelId:      'XXXXXXXXXXXXXXXXXX',    // ← Replace with FB Pixel ID
    formsubmit:     'https://formsubmit.co/bivash@cyberdudebivash.com',
    pricingUrl:     '/pricing.html',
    apiUrl:         '/api.html',
    productsUrl:    '/products.html',
    enterpriseUrl:  '/enterprise.html',
    leadsUrl:       '/leads.html',
    // Behavioral thresholds
    scrollUnlockPct:   70,   // % scroll → show unlock CTA
    scrollMidCTAPct:   45,   // % scroll → show mid-page CTA
    returnVisitKey:    'cx_visits',
    sessionKey:        'cx_session',
    abKey:             'cx_ab_variant',
    // A/B variants
    abVariants: {
      cta:     ['Get Threat Intel', 'Download IOC Pack', 'Unlock Full Report', 'Access Live Feed'],
      price:   ['anchor', 'direct', 'savings'],    // pricing display style
      urgency: ['exploited', 'critical', 'advisory']
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     1. UTILITIES
  ═══════════════════════════════════════════════════════════════ */
  const CYAN   = '#00ffe0';
  const BG     = 'rgba(7,9,15,0.97)';
  const BORDER = '1px solid rgba(0,255,224,0.2)';

  const ls = {
    get:  (k)    => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
    set:  (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
    push: (k, v) => { const a = ls.get(k) || []; a.push(v); ls.set(k, a.slice(-200)); }
  };

  const $ = s => document.querySelector(s);
  const rand = (arr) => arr[Math.floor(Math.random() * arr.length)];
  const now  = () => Date.now();
  const page = window.location.pathname;

  function injectStyle(css) {
    const s = document.createElement('style');
    s.textContent = css;
    document.head.appendChild(s);
  }

  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === 'style') Object.assign(e.style, v);
      else if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    });
    children.forEach(c => e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
    return e;
  }

  /* ═══════════════════════════════════════════════════════════════
     2. A/B TESTING FRAMEWORK
  ═══════════════════════════════════════════════════════════════ */
  const AB = {
    variant: null,
    ctaText:  null,
    priceStyle: null,
    urgencyStyle: null,

    init() {
      // Persist variant so user sees same version on return
      let stored = ls.get(CFG.abKey);
      if (!stored) {
        stored = {
          cta:     rand(CFG.abVariants.cta),
          price:   rand(CFG.abVariants.price),
          urgency: rand(CFG.abVariants.urgency),
          id:      Math.random().toString(36).slice(2, 8)
        };
        ls.set(CFG.abKey, stored);
      }
      this.ctaText    = stored.cta;
      this.priceStyle = stored.price;
      this.urgencyStyle = stored.urgency;
      this.variant    = stored.id;

      // Apply to all existing CTA buttons with data-ab="true"
      document.querySelectorAll('[data-cx-cta]').forEach(btn => {
        btn.textContent = this.ctaText;
      });

      // Apply pricing anchor style
      this.applyPriceAnchors();

      TRACK.event('ab_assigned', { variant: stored });
    },

    applyPriceAnchors() {
      // Find pricing display elements and style them
      if (this.priceStyle === 'anchor') {
        // Show: $499 strike → $149 — "Most popular" variant
        document.querySelectorAll('[data-cx-price]').forEach(el => {
          const base = el.dataset.cxPrice;
          const orig = el.dataset.cxOrig || Math.round(parseInt(base) * 2.5);
          el.innerHTML = `<span style="font-size:1.5rem;font-weight:900;color:${CYAN}">$${base}</span>
            <span style="text-decoration:line-through;color:#64748b;font-size:.9rem;margin-left:.3rem">$${orig}</span>
            <span style="background:rgba(34,197,94,0.2);color:#22c55e;font-size:.7rem;padding:.1rem .4rem;border-radius:4px;margin-left:.4rem">SAVE ${Math.round((1 - base/orig)*100)}%</span>`;
        });
      } else if (this.priceStyle === 'savings') {
        // Show: "Save $350 today" variant
        document.querySelectorAll('[data-cx-price]').forEach(el => {
          const base = el.dataset.cxPrice;
          const orig = parseInt(el.dataset.cxOrig || Math.round(parseInt(base) * 2.5));
          const save = orig - parseInt(base);
          el.innerHTML = `<span style="font-size:1.5rem;font-weight:900;color:${CYAN}">$${base}</span>
            <span style="color:#22c55e;font-size:.8rem;margin-left:.5rem;font-weight:700">Save $${save}</span>`;
        });
      }
      // 'direct' style: leave price as-is
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     3. BEHAVIORAL TRACKER
  ═══════════════════════════════════════════════════════════════ */
  const TRACK = {
    session: null,
    scrollPct: 0,
    startTime: now(),
    clickCount: 0,
    maxScroll: 0,

    init() {
      // Session tracking
      let s = ls.get(CFG.sessionKey);
      if (!s || (now() - s.lastSeen > 30 * 60 * 1000)) {
        s = { id: Math.random().toString(36).slice(2, 10), start: now(), page, pageviews: 0 };
      }
      s.lastSeen = now();
      s.pageviews = (s.pageviews || 0) + 1;
      ls.set(CFG.sessionKey, s);
      this.session = s;

      // Visit counter
      const visits = (ls.get(CFG.returnVisitKey) || 0) + 1;
      ls.set(CFG.returnVisitKey, visits);

      // Scroll tracking
      let scrollThrottle;
      window.addEventListener('scroll', () => {
        clearTimeout(scrollThrottle);
        scrollThrottle = setTimeout(() => {
          const pct = Math.round(
            (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100
          );
          if (pct > this.maxScroll) {
            this.maxScroll = pct;
            ls.push('cx_scroll_events', { page, pct, t: now() - this.startTime });
            SMART_CTA.checkScroll(pct);
          }
        }, 200);
      });

      // Click tracking
      document.addEventListener('click', (e) => {
        const target = e.target.closest('a, button, [data-track]');
        if (!target) return;
        const label = target.dataset.track || target.textContent.trim().slice(0, 40) || target.href || '';
        this.clickCount++;
        this.event('click', { label, page, el: target.tagName });
        // Detect API/pricing/products interest
        const href = (target.href || '').toLowerCase();
        if (href.includes('api') || href.includes('pricing') || href.includes('enterprise')) {
          SMART_CTA.onHighIntent(href);
        }
      });

      // Exit tracking
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
          this.event('exit', {
            page,
            scrollPct: this.maxScroll,
            timeOnPage: Math.round((now() - this.startTime) / 1000),
            clicks: this.clickCount
          });
        }
      });

      // Time milestones
      [30, 60, 120, 300].forEach(sec => {
        setTimeout(() => this.event('time_milestone', { sec, page, scroll: this.maxScroll }), sec * 1000);
      });
    },

    event(name, data = {}) {
      const evt = { name, data, page, ts: now(), variant: AB.variant, session: this.session?.id };
      ls.push('cx_events', evt);

      // Fire GA4 if loaded
      if (typeof gtag !== 'undefined') {
        try {
          gtag('event', name, { ...data, platform: 'sentinel_apex' });
        } catch {}
      }

      // Fire FB Pixel if loaded
      if (typeof fbq !== 'undefined') {
        try {
          if (name === 'lead_captured') fbq('track', 'Lead', data);
          if (name === 'purchase_intent') fbq('track', 'AddToCart', data);
          if (name === 'api_click') fbq('track', 'ViewContent', { content_name: 'API Page' });
        } catch {}
      }
    },

    getProfile() {
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
  const SEGMENTS = {
    detect() {
      const path = window.location.pathname;
      const ref  = document.referrer.toLowerCase();
      const ua   = navigator.userAgent.toLowerCase();
      const events = ls.get('cx_events') || [];
      const apiClicks = events.filter(e => e.name === 'click' && String(e.data?.label).includes('api')).length;
      const pricingClicks = events.filter(e => e.name === 'click' && String(e.data?.label).includes('pric')).length;

      if (apiClicks >= 2 || path.includes('api')) return 'developer';
      if (pricingClicks >= 1 || path.includes('enterprise') || path.includes('pricing')) return 'enterprise';
      if (ref.includes('github') || ref.includes('stackoverflow')) return 'developer';
      if (ref.includes('linkedin') || ref.includes('twitter') || ref.includes('x.com')) return 'security_pro';
      return 'soc_analyst';
    },

    getMessage(segment) {
      const msgs = {
        developer: {
          headline: '🔌 API-First Threat Intelligence',
          sub: 'Integrate CVE feeds, IOC data, and AI risk scoring in minutes. Free tier available.',
          cta: 'Start Free API Trial →',
          url: CFG.apiUrl
        },
        enterprise: {
          headline: '🏢 Enterprise Threat Intelligence Platform',
          sub: 'White-label feeds, SLA-backed data, and dedicated analyst support for enterprise teams.',
          cta: 'Get Enterprise Proposal →',
          url: CFG.enterpriseUrl
        },
        soc_analyst: {
          headline: '🛡️ Sigma & YARA Detection Packs — 2026',
          sub: '1,200+ production rules mapped to MITRE ATT&CK. Deploy to Splunk/Elastic in minutes.',
          cta: 'Browse Detection Packs →',
          url: CFG.productsUrl
        },
        security_pro: {
          headline: '⚡ SOC Pro — Unlimited Intel Access',
          sub: 'Full IOC packs, SIEM rules, early CVE disclosures, and monthly threat reports.',
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
  injectStyle(`
    /* Smart CTA Overlay */
    #cx-smart-overlay {
      position: fixed; bottom: 80px; right: 20px; z-index: 9999;
      width: 340px; max-width: calc(100vw - 40px);
      background: rgba(7,9,15,0.97);
      border: 1px solid rgba(0,255,224,0.3);
      border-radius: 16px; padding: 1.25rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 30px rgba(0,255,224,0.08);
      transform: translateX(380px); transition: transform .4s cubic-bezier(.22,.68,0,1.2);
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    #cx-smart-overlay.cx-show { transform: translateX(0); }
    #cx-smart-overlay .cx-close {
      position: absolute; top: .6rem; right: .75rem;
      background: none; border: none; color: #64748b; font-size: 1rem;
      cursor: pointer; line-height: 1;
    }
    #cx-smart-overlay .cx-close:hover { color: #fff; }
    #cx-smart-overlay .cx-badge {
      font-size: .65rem; font-weight: 800; color: ${CYAN};
      text-transform: uppercase; letter-spacing: .1em; margin-bottom: .5rem;
    }
    #cx-smart-overlay h4 { font-size: .95rem; font-weight: 800; color: #fff; margin-bottom: .35rem; line-height: 1.3; }
    #cx-smart-overlay p { font-size: .8rem; color: #94a3b8; margin-bottom: .85rem; line-height: 1.5; }
    #cx-smart-overlay .cx-btn {
      display: block; width: 100%;
      background: linear-gradient(135deg, ${CYAN}, #00d4ff);
      color: #000; font-weight: 800; font-size: .82rem;
      padding: .6rem 1rem; border-radius: 8px;
      text-align: center; text-decoration: none;
      border: none; cursor: pointer;
      transition: opacity .2s;
    }
    #cx-smart-overlay .cx-btn:hover { opacity: .88; }
    #cx-smart-overlay .cx-dismiss {
      display: block; text-align: center; font-size: .72rem;
      color: #475569; margin-top: .5rem; cursor: pointer;
    }
    #cx-smart-overlay .cx-dismiss:hover { color: #94a3b8; }
    #cx-smart-overlay .cx-progress {
      height: 3px; background: rgba(0,255,224,0.15); border-radius: 2px;
      margin-bottom: .75rem; overflow: hidden;
    }
    #cx-smart-overlay .cx-progress-bar {
      height: 100%; background: ${CYAN}; border-radius: 2px;
      transition: width .3s;
    }

    /* Return visitor banner */
    
    /**
 * CYBERDUDEBIVASH SENTINEL APEX — Conversion Engine v2.0
 * ═══════════════════════════════════════════════════════
 * Systems:
 *   1. A/B Testing Framework     — CTA text, pricing anchors, urgency variants
 *   2. Behavioral Tracker        — Scroll depth, clicks, time on page, exit points
 *   3. Smart CTA Engine          — Trigger-based personalized offers
 *   4. Retargeting Pixel Manager — GA4, Ads, FB pixel orchestration
 *   5. Revenue Intelligence      — Conversion event firing
 *
 * Deploy: <script src="/conversion-engine.js" defer></script>
 * Loads AFTER monetization.js
 */
(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════
     0. CONFIG
  ═══════════════════════════════════════════════════════════════ */
  const CFG = {
    gaId:           'G-XXXXXXXXXX',          // ← Replace with your GA4 ID
    gadsId:         'AW-XXXXXXXXXX',         // ← Replace with Google Ads ID
    fbPixelId:      'XXXXXXXXXXXXXXXXXX',    // ← Replace with FB Pixel ID
    formsubmit:     'https://formsubmit.co/bivash@cyberdudebivash.com',
    pricingUrl:     '/pricing.html',
    apiUrl:         '/api.html',
    productsUrl:    '/products.html',
    enterpriseUrl:  '/enterprise.html',
    leadsUrl:       '/leads.html',
    // Behavioral thresholds
    scrollUnlockPct:   70,   // % scroll → show unlock CTA
    scrollMidCTAPct:   45,   // % scroll → show mid-page CTA
    returnVisitKey:    'cx_visits',
    sessionKey:        'cx_session',
    abKey:             'cx_ab_variant',
    // A/B variants
    abVariants: {
      cta:     ['Get Threat Intel', 'Download IOC Pack', 'Unlock Full Report', 'Access Live Feed'],
      price:   ['anchor', 'direct', 'savings'],    // pricing display style
      urgency: ['exploited', 'critical', 'advisory']
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     1. UTILITIES
  ═══════════════════════════════════════════════════════════════ */
  const CYAN   = '#00ffe0';
  const BG     = 'rgba(7,9,15,0.97)';
  const BORDER = '1px solid rgba(0,255,224,0.2)';

  const ls = {
    get:  (k)    => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
    set:  (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
    push: (k, v) => { const a = ls.get(k) || []; a.push(v); ls.set(k, a.slice(-200)); }
  };

  const $ = s => document.querySelector(s);
  const rand = (arr) => arr[Math.floor(Math.random() * arr.length)];
  const now  = () => Date.now();
  const page = window.location.pathname;

  function injectStyle(css) {
    const s = document.createElement('style');
    s.textContent = css;
    document.head.appendChild(s);
  }

  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === 'style') Object.assign(e.style, v);
      else if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    });
    children.forEach(c => e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
    return e;
  }

  /* ═══════════════════════════════════════════════════════════════
     2. A/B TESTING FRAMEWORK
  ═══════════════════════════════════════════════════════════════ */
  const AB = {
    variant: null,
    ctaText:  null,
    priceStyle: null,
    urgencyStyle: null,

    init() {
      // Persist variant so user sees same version on return
      let stored = ls.get(CFG.abKey);
      if (!stored) {
        stored = {
          cta:     rand(CFG.abVariants.cta),
          price:   rand(CFG.abVariants.price),
          urgency: rand(CFG.abVariants.urgency),
          id:      Math.random().toString(36).slice(2, 8)
        };
        ls.set(CFG.abKey, stored);
      }
      this.ctaText    = stored.cta;
      this.priceStyle = stored.price;
      this.urgencyStyle = stored.urgency;
      this.variant    = stored.id;

      // Apply to all existing CTA buttons with data-ab="true"
      document.querySelectorAll('[data-cx-cta]').forEach(btn => {
        btn.textContent = this.ctaText;
      });

      // Apply pricing anchor style
      this.applyPriceAnchors();

      TRACK.event('ab_assigned', { variant: stored });
    },

    applyPriceAnchors() {
      // Find pricing display elements and style them
      if (this.priceStyle === 'anchor') {
        // Show: $499 strike → $149 — "Most popular" variant
        document.querySelectorAll('[data-cx-price]').forEach(el => {
          const base = el.dataset.cxPrice;
          const orig = el.dataset.cxOrig || Math.round(parseInt(base) * 2.5);
          el.innerHTML = `<span style="font-size:1.5rem;font-weight:900;color:${CYAN}">$${base}</span>
            <span style="text-decoration:line-through;color:#64748b;font-size:.9rem;margin-left:.3rem">$${orig}</span>
            <span style="background:rgba(34,197,94,0.2);color:#22c55e;font-size:.7rem;padding:.1rem .4rem;border-radius:4px;margin-left:.4rem">SAVE ${Math.round((1 - base/orig)*100)}%</span>`;
        });
      } else if (this.priceStyle === 'savings') {
        // Show: "Save $350 today" variant
        document.querySelectorAll('[data-cx-price]').forEach(el => {
          const base = el.dataset.cxPrice;
          const orig = parseInt(el.dataset.cxOrig || Math.round(parseInt(base) * 2.5));
          const save = orig - parseInt(base);
          el.innerHTML = `<span style="font-size:1.5rem;font-weight:900;color:${CYAN}">$${base}</span>
            <span style="color:#22c55e;font-size:.8rem;margin-left:.5rem;font-weight:700">Save $${save}</span>`;
        });
      }
      // 'direct' style: leave price as-is
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     3. BEHAVIORAL TRACKER
  ═══════════════════════════════════════════════════════════════ */
  const TRACK = {
    session: null,
    scrollPct: 0,
    startTime: now(),
    clickCount: 0,
    maxScroll: 0,

    init() {
      // Session tracking
      let s = ls.get(CFG.sessionKey);
      if (!s || (now() - s.lastSeen > 30 * 60 * 1000)) {
        s = { id: Math.random().toString(36).slice(2, 10), start: now(), page, pageviews: 0 };
      }
      s.lastSeen = now();
      s.pageviews = (s.pageviews || 0) + 1;
      ls.set(CFG.sessionKey, s);
      this.session = s;

      // Visit counter
      const visits = (ls.get(CFG.returnVisitKey) || 0) + 1;
      ls.set(CFG.returnVisitKey, visits);

      // Scroll tracking
      let scrollThrottle;
      window.addEventListener('scroll', () => {
        clearTimeout(scrollThrottle);
        scrollThrottle = setTimeout(() => {
          const pct = Math.round(
            (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100
          );
          if (pct > this.maxScroll) {
            this.maxScroll = pct;
            ls.push('cx_scroll_events', { page, pct, t: now() - this.startTime });
            SMART_CTA.checkScroll(pct);
          }
        }, 200);
      });

      // Click tracking
      document.addEventListener('click', (e) => {
        const target = e.target.closest('a, button, [data-track]');
        if (!target) return;
        const label = target.dataset.track || target.textContent.trim().slice(0, 40) || target.href || '';
        this.clickCount++;
        this.event('click', { label, page, el: target.tagName });
        // Detect API/pricing/products interest
        const href = (target.href || '').toLowerCase();
        if (href.includes('api') || href.includes('pricing') || href.includes('enterprise')) {
          SMART_CTA.onHighIntent(href);
        }
      });

      // Exit tracking
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
          this.event('exit', {
            page,
            scrollPct: this.maxScroll,
            timeOnPage: Math.round((now() - this.startTime) / 1000),
            clicks: this.clickCount
          });
        }
      });

      // Time milestones
      [30, 60, 120, 300].forEach(sec => {
        setTimeout(() => this.event('time_milestone', { sec, page, scroll: this.maxScroll }), sec * 1000);
      });
    },

    event(name, data = {}) {
      const evt = { name, data, page, ts: now(), variant: AB.variant, session: this.session?.id };
      ls.push('cx_events', evt);

      // Fire GA4 if loaded
      if (typeof gtag !== 'undefined') {
        try {
          gtag('event', name, { ...data, platform: 'sentinel_apex' });
        } catch {}
      }

      // Fire FB Pixel if loaded
      if (typeof fbq !== 'undefined') {
        try {
          if (name === 'lead_captured') fbq('track', 'Lead', data);
          if (name === 'purchase_intent') fbq('track', 'AddToCart', data);
          if (name === 'api_click') fbq('track', 'ViewContent', { content_name: 'API Page' });
        } catch {}
      }
    },

    getProfile() {
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
  const SEGMENTS = {
    detect() {
      const path = window.location.pathname;
      const ref  = document.referrer.toLowerCase();
      const ua   = navigator.userAgent.toLowerCase();
      const events = ls.get('cx_events') || [];
      const apiClicks = events.filter(e => e.name === 'click' && String(e.data?.label).includes('api')).length;
      const pricingClicks = events.filter(e => e.name === 'click' && String(e.data?.label).includes('pric')).length;

      if (apiClicks >= 2 || path.includes('api')) return 'developer';
      if (pricingClicks >= 1 || path.includes('enterprise') || path.includes('pricing')) return 'enterprise';
      if (ref.includes('github') || ref.includes('stackoverflow')) return 'developer';
      if (ref.includes('linkedin') || ref.includes('twitter') || ref.includes('x.com')) return 'security_pro';
      return 'soc_analyst';
    },

    getMessage(segment) {
      const msgs = {
        developer: {
          headline: '🔌 API-First Threat Intelligence',
          sub: 'Integrate CVE feeds, IOC data, and AI risk scoring in minutes. Free tier available.',
          cta: 'Start Free API Trial →',
          url: CFG.apiUrl
        },
        enterprise: {
          headline: '🏢 Enterprise Threat Intelligence Platform',
          sub: 'White-label feeds, SLA-backed data, and dedicated analyst support for enterprise teams.',
          cta: 'Get Enterprise Proposal →',
          url: CFG.enterpriseUrl
        },
        soc_analyst: {
          headline: '🛡️ Sigma & YARA Detection Packs — 2026',
          sub: '1,200+ production rules mapped to MITRE ATT&CK. Deploy to Splunk/Elastic in minutes.',
          cta: 'Browse Detection Packs →',
          url: CFG.productsUrl
        },
        security_pro: {
          headline: '⚡ SOC Pro — Unlimited Intel Access',
          sub: 'Full IOC packs, SIEM rules, early CVE disclosures, and monthly threat reports.',
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
  injectStyle(`
    /* Smart CTA Overlay */
    #cx-smart-overlay {
      position: fixed; bottom: 80px; right: 20px; z-index: 9999;
      width: 340px; max-width: calc(100vw - 40px);
      background: rgba(7,9,15,0.97);
      border: 1px solid rgba(0,255,224,0.3);
      border-radius: 16px; padding: 1.25rem;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 30px rgba(0,255,224,0.08);
      transform: translateX(380px); transition: transform .4s cubic-bezier(.22,.68,0,1.2);
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    #cx-smart-overlay.cx-show { transform: translateX(0); }
    #cx-smart-overlay .cx-close {
      position: absolute; top: .6rem; right: .75rem;
      background: none; border: none; color: #64748b; font-size: 1rem;
      cursor: pointer; line-height: 1;
    }
    #cx-smart-overlay .cx-close:hover { color: #fff; }
    #cx-smart-overlay .cx-badge {
      font-size: .65rem; font-weight: 800; color: ${CYAN};
      text-transform: uppercase; letter-spacing: .1em; margin-bottom: .5rem;
    }
    #cx-smart-overlay h4 { font-size: .95rem; font-weight: 800; color: #fff; margin-bottom: .35rem; line-height: 1.3; }
    #cx-smart-overlay p { font-size: .8rem; color: #94a3b8; margin-bottom: .85rem; line-height: 1.5; }
    #cx-smart-overlay .cx-btn {
      display: block; width: 100%;
      background: linear-gradient(135deg, ${CYAN}, #00d4ff);
      color: #000; font-weight: 800; font-size: .82rem;
      padding: .6rem 1rem; border-radius: 8px;
      text-align: center; text-decoration: none;
      border: none; cursor: pointer;
      transition: opacity .2s;
    }
    #cx-smart-overlay .cx-btn:hover { opacity: .88; }
    #cx-smart-overlay .cx-dismiss {
      display: block; text-align: center; font-size: .72rem;
      color: #475569; margin-top: .5rem; cursor: pointer;
    }
    #cx-smart-overlay .cx-dismiss:hover { color: #94a3b8; }
    #cx-smart-overlay .cx-progress {
      height: 3px; background: rgba(0,255,224,0.15); border-radius: 2px;
      margin-bottom: .75rem; overflow: hidden;
    }
    #cx-smart-overlay .cx-progress-bar {
      height: 100%; background: ${CYAN}; border-radius: 2px;
      transition: width .3s;
    }

    /* Return visitor banner */
    #cx-return-banner {
      position: fixed; top: 130px; left: 0; right: 0; z-index: 9998;
      background: linear-gradient(135deg, rgba(255,215,0,0.12), rgba(0,255,224,0.08));
      border-bottom: 1px solid rgba(255,215,0,0.25);
      padding: .6rem 1.5rem;
      display: flex; align-items: center; justify-content: center; gap: 1.5rem;
      flex-wrap: wrap; transform: translateY(-100%);
      transition: transform .4s ease;
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    #cx-return-banner.cx-show { transform: translateY(0); }
    #cx-return-banner span { font-size: .82rem; color: #e2e8f0; font-weight: 500; }
    #cx-return-banner strong { color: #ffd700; }
    #cx-return-banner a {
      background: linear-gradient(135deg, #ffd700, #ff8c00);
      color: #000; font-weight: 800; font-size: .75rem;
      padding: .35rem .85rem; border-radius: 6px; text-decoration: none;
      white-space: nowrap; transition: opacity .2s;
    }
    #cx-return-banner a:hover { opacity: .85; }
    #cx-return-banner button {
      background: none; border: none; color: #475569; font-size: .9rem;
      cursor: pointer; margin-left: .5rem;
    }

    /* Scroll progress indicator */
    #cx-scroll-bar {
      position: fixed; top: 0; left: 0; height: 3px; z-index: 10001;
      background: linear-gradient(90deg, ${CYAN}, #00d4ff);
      width: 0%; transition: width .1s; pointer-events: none;
    }

    /* Inline upgrade prompt (injected mid-post) */
    .cx-inline-cta {
      background: linear-gradient(135deg, rgba(0,255,224,0.06), rgba(0,212,255,0.04));
      border: 1px solid rgba(0,255,224,0.2); border-radius: 12px;
      padding: 1.25rem 1.5rem; margin: 2rem 0;
      display: flex; align-items: center; gap: 1.25rem; flex-wrap: wrap;
    }
    .cx-inline-cta .ci-icon { font-size: 2rem; flex-shrink: 0; }
    .cx-inline-cta .ci-body { flex: 1; min-width: 200px; }
    .cx-inline-cta .ci-body strong { display: block; font-size: .95rem; font-weight: 800; color: #fff; margin-bottom: .25rem; }
    .cx-inline-cta .ci-body span { font-size: .8rem; color: #94a3b8; }
    .cx-inline-cta a {
      background: linear-gradient(135deg, ${CYAN}, #00d4ff);
      color: #000; font-weight: 800; font-size: .8rem;
      padding: .55rem 1.1rem; border-radius: 8px; text-decoration: none;
      white-space: nowrap; flex-shrink: 0;
    }

    /* High-intent enterprise flash */
    #cx-enterprise-flash {
      position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) scale(.9);
      z-index: 10000; width: 480px; max-width: calc(100vw - 32px);
      background: rgba(7,9,15,0.98);
      border: 1px solid rgba(0,255,224,0.3); border-radius: 20px;
      padding: 2rem; text-align: center;
      box-shadow: 0 40px 100px rgba(0,0,0,0.7), 0 0 60px rgba(0,255,224,0.06);
      opacity: 0; pointer-events: none;
      transition: all .35s cubic-bezier(.22,.68,0,1.2);
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    #cx-enterprise-flash.cx-show { opacity: 1; pointer-events: all; transform: translate(-50%,-50%) scale(1); }
    #cx-ef-backdrop {
      position: fixed; inset: 0; z-index: 9999;
      background: rgba(0,0,0,.6); backdrop-filter: blur(4px);
      opacity: 0; pointer-events: none; transition: opacity .3s;
    }
    #cx-ef-backdrop.cx-show { opacity: 1; pointer-events: all; }
  `);

  const SMART_CTA = {
    overlayShown: false,
    returnBannerShown: false,
    enterpriseFlashShown: false,
    inlineCTAsInjected: false,
    scrollBar: null,

    init() {
      // Scroll progress bar
      this.scrollBar = el('div', { id: 'cx-scroll-bar' });
      document.body.appendChild(this.scrollBar);
      window.addEventListener('scroll', () => {
        const pct = Math.round(
          (window.scrollY / Math.max(1, document.documentElement.scrollHeight - window.innerHeight)) * 100
        );
        if (this.scrollBar) this.scrollBar.style.width = pct + '%';
      });

      // Return visitor banner
      const visits = ls.get(CFG.returnVisitKey) || 1;
      if (visits >= 2) {
        setTimeout(() => this.showReturnBanner(visits), 2500);
      }

      // Inject inline CTAs into post body after load
      if (page.includes('/posts/')) {
        setTimeout(() => this.injectInlineCTAs(), 1000);
      }
    },

    checkScroll(pct) {
      // 45% → inject mid-page CTA if on post
      if (pct >= CFG.scrollMidCTAPct && !this.overlayShown) {
        const seg = SEGMENTS.detect();
        const msg = SEGMENTS.getMessage(seg);
        setTimeout(() => this.showOverlay(msg, 'mid_scroll'), 500);
        this.overlayShown = true;
      }
      // 70% → show "Unlock Full Report" overlay
      if (pct >= CFG.scrollUnlockPct && !this.overlayShown) {
        this.showOverlay({
          badge: '⚡ PRO MEMBERS ONLY',
          headline: '🔒 Unlock Full Intelligence Report',
          sub: 'Get complete IOC lists, SIEM detection rules, YARA signatures, and analyst commentary — exclusive to SOC Pro members.',
          cta: 'Unlock Full Report — $49/mo',
          url: CFG.pricingUrl
        }, 'scroll_unlock');
        this.overlayShown = true;
        TRACK.event('scroll_unlock_shown', { pct });
      }
    },

    onHighIntent(href) {
      if (this.enterpriseFlashShown) return;
      if (href.includes('enterprise') || href.includes('pricing')) {
        setTimeout(() => this.showEnterpriseFlash(), 800);
        this.enterpriseFlashShown = true;
        TRACK.event('high_intent_detected', { href });
      }
    },

    showOverlay(msg, trigger) {
      const existing = document.getElementById('cx-smart-overlay');
      if (existing) existing.remove();

      const progressPct = TRACK.maxScroll + '%';
      const overlay = el('div', { id: 'cx-smart-overlay' },
        el('button', { class: 'cx-close', onclick: () => overlay.classList.remove('cx-show') }, '✕'),
        el('div', { class: 'cx-progress' },
          el('div', { class: 'cx-progress-bar', style: { width: progressPct } })
        ),
        el('div', { class: 'cx-badge' }, msg.badge || '⚡ CYBERDUDEBIVASH SENTINEL APEX INTELLIGENCE'),
        el('h4', {}, msg.headline || 'Upgrade for Full Access'),
        el('p', {}, msg.sub || 'Get unrestricted access to IOC packs, SIEM rules, and premium reports.'),
        el('a', { class: 'cx-btn', href: msg.url || CFG.pricingUrl,
          onclick: () => TRACK.event('smart_cta_click', { trigger, msg: msg.headline }) },
          msg.cta || AB.ctaText || 'Get Full Access →'
        ),
        el('span', { class: 'cx-dismiss',
          onclick: () => {
            overlay.classList.remove('cx-show');
            TRACK.event('smart_cta_dismissed', { trigger });
          }
        }, 'Not now — remind me later')
      );
      document.body.appendChild(overlay);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => overlay.classList.add('cx-show'));
      });
      TRACK.event('smart_overlay_shown', { trigger });
    },

    showReturnBanner(visits) {
      if (document.getElementById('cx-return-banner')) return;
      const offer = visits >= 5 ? '20% OFF with code APEX20' :
                    visits >= 3 ? '7-day free Pro trial' :
                                  'free threat report';
      const banner = el('div', { id: 'cx-return-banner' },
        el('span', {}, `Welcome back! 👋 You've visited <strong>${visits}x</strong> — claim your `),
        el('strong', {}, offer),
        el('a', { href: CFG.pricingUrl,
          onclick: () => TRACK.event('return_banner_click', { visits, offer }) },
          `Claim Offer →`
        ),
        el('button', {
          onclick: () => {
            const b = document.getElementById('cx-return-banner');
            if (b) b.remove();
          }
        }, '✕')
      );
      document.body.appendChild(banner);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => banner.classList.add('cx-show'));
      });
      TRACK.event('return_banner_shown', { visits });
    },

    showEnterpriseFlash() {
      const backdrop = el('div', { id: 'cx-ef-backdrop',
        onclick: () => {
          document.getElementById('cx-enterprise-flash')?.classList.remove('cx-show');
          backdrop.classList.remove('cx-show');
        }
      });
      const flash = el('div', { id: 'cx-enterprise-flash' },
        el('div', { style: { fontSize: '2.5rem', marginBottom: '.75rem' } }, '🏢'),
        el('div', { style: { fontSize: '.7rem', fontWeight: '800', color: CYAN, letterSpacing: '.12em', textTransform: 'uppercase', marginBottom: '.5rem' } },
          '⚡ ENTERPRISE INTELLIGENCE PLATFORM'),
        el('h3', { style: { fontSize: '1.4rem', fontWeight: '900', color: '#fff', marginBottom: '.5rem', lineHeight: '1.3' } },
          'Looks Like You Need Enterprise-Grade Threat Intel'),
        el('p', { style: { fontSize: '.85rem', color: '#94a3b8', marginBottom: '1.5rem', lineHeight: '1.6' } },
          'White-label feeds, SLA-backed data, dedicated analyst support, and custom detection rules built for your environment.'),
        el('div', { style: { display: 'flex', gap: '.75rem', justifyContent: 'center', flexWrap: 'wrap', marginBottom: '1rem' } },
          el('a', { href: CFG.enterpriseUrl, style: { background: `linear-gradient(135deg,${CYAN},#00d4ff)`, color: '#000', fontWeight: '800', fontSize: '.85rem', padding: '.65rem 1.4rem', borderRadius: '8px', textDecoration: 'none' },
            onclick: () => {
              TRACK.event('enterprise_flash_click', {});
              document.getElementById('cx-enterprise-flash')?.classList.remove('cx-show');
              backdrop.classList.remove('cx-show');
            }
          }, '🏢 Get Enterprise Proposal'),
          el('button', { style: { background: 'none', border: '1px solid rgba(0,255,224,0.2)', color: '#94a3b8', fontWeight: '600', fontSize: '.82rem', padding: '.65rem 1.2rem', borderRadius: '8px', cursor: 'pointer' },
            onclick: () => {
              document.getElementById('cx-enterprise-flash')?.classList.remove('cx-show');
              backdrop.classList.remove('cx-show');
              TRACK.event('enterprise_flash_dismissed', {});
            }
          }, 'Maybe Later')
        )
      );
      document.body.appendChild(backdrop);
      document.body.appendChild(flash);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          backdrop.classList.add('cx-show');
          flash.classList.add('cx-show');
        });
      });
      TRACK.event('enterprise_flash_shown', {});
    },

    injectInlineCTAs() {
      if (this.inlineCTAsInjected) return;
      // Find article body paragraphs
      const paras = [...document.querySelectorAll('article p, .post-body p, main p, .content p')];
      if (paras.length < 4) return;

      const ctaDefs = [
        {
          after: Math.floor(paras.length * 0.35),
          icon: '🛡️', title: 'Get Detection Rules for This CVE',
          sub: 'Sigma + YARA rules, IOC table, and SIEM queries — downloadable in seconds.',
          cta: 'Get Detection Pack →', url: CFG.productsUrl,
          track: 'inline_cta_detection'
        },
        {
          after: Math.floor(paras.length * 0.65),
          icon: '🔌', title: 'Integrate This Intel Into Your SIEM',
          sub: 'Access structured CVE data, IOC feeds, and risk scores via CYBERDUDEBIVASH SENTINEL APEX API.',
          cta: 'Start Free API Trial →', url: CFG.apiUrl,
          track: 'inline_cta_api'
        }
      ];

      ctaDefs.forEach(def => {
        const targetPara = paras[def.after];
        if (!targetPara) return;
        const ctaEl = el('div', { class: 'cx-inline-cta' },
          el('div', { class: 'ci-icon' }, def.icon),
          el('div', { class: 'ci-body' },
            el('strong', {}, def.title),
            el('span', {}, def.sub)
          ),
          el('a', { href: def.url, onclick: () => TRACK.event(def.track, {}) }, def.cta)
        );
        targetPara.insertAdjacentElement('afterend', ctaEl);
      });

      this.inlineCTAsInjected = true;
      TRACK.event('inline_ctas_injected', { paraCount: paras.length });
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     6. RETARGETING PIXEL MANAGER
  ═══════════════════════════════════════════════════════════════ */
  const PIXELS = {
    init() {
      this.loadGA4();
      this.loadGAds();
      this.loadFB();
    },

    loadGA4() {
      if (CFG.gaId.includes('XXXX')) return; // Not configured
      const s = document.createElement('script');
      s.src = `https://www.googletagmanager.com/gtag/js?id=${CFG.gaId}`;
      s.async = true;
      document.head.appendChild(s);
      window.dataLayer = window.dataLayer || [];
      window.gtag = function() { dataLayer.push(arguments); };
      gtag('js', new Date());
      gtag('config', CFG.gaId, {
        page_title: document.title,
        page_location: window.location.href,
        custom_map: { dimension1: 'ab_variant', dimension2: 'user_segment' }
      });
      gtag('set', 'user_properties', {
        ab_variant: AB.variant,
        user_segment: SEGMENTS.detect(),
        visit_count: ls.get(CFG.returnVisitKey) || 1
      });
    },

    loadGAds() {
      if (CFG.gadsId.includes('XXXX')) return;
      window.gtag && gtag('config', CFG.gadsId);
    },

    loadFB() {
      if (CFG.fbPixelId.includes('XXXX')) return;
      !function(f,b,e,v,n,t,s){
        if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
        if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
        t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)
      }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init', CFG.fbPixelId);
      fbq('track', 'PageView');
    },

    fireConversion(type, value) {
      TRACK.event('conversion', { type, value });
      if (typeof gtag !== 'undefined' && !CFG.gadsId.includes('XXXX')) {
        gtag('event', 'conversion', { send_to: `${CFG.gadsId}/CONVERSION_LABEL`, value, currency: 'USD' });
      }
      if (typeof fbq !== 'undefined') {
        fbq('track', 'Purchase', { value, currency: 'USD', content_name: type });
      }
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     7. REVENUE INTELLIGENCE DASHBOARD (localStorage)
  ═══════════════════════════════════════════════════════════════ */
  const REVENUE_INTEL = {
    getReport() {
      const events    = ls.get('cx_events') || [];
      const scrollEvt = ls.get('cx_scroll_events') || [];
      const visits    = ls.get(CFG.returnVisitKey) || 1;
      const abData    = ls.get(CFG.abKey) || {};
      return {
        totalEvents:    events.length,
        visits,
        abVariant:      abData,
        segment:        SEGMENTS.detect(),
        topPages:       [...new Set(events.map(e => e.page))].slice(0, 10),
        clickLabels:    events.filter(e => e.name === 'click').map(e => e.data?.label).filter(Boolean).slice(-20),
        maxScroll:      Math.max(...scrollEvt.map(e => e.pct), 0),
        overlaysShown:  events.filter(e => e.name.includes('shown')).length,
        ctaClicks:      events.filter(e => e.name.includes('click')).length,
        avgTimeOnPage:  Math.round(events.filter(e => e.name === 'exit').reduce((a, e) => a + (e.data?.timeOnPage || 0), 0) / Math.max(1, events.filter(e => e.name === 'exit').length))
      };
    }
  };

  // Expose to window for debugging / analytics endpoint calls
  window.CX = { AB, TRACK, SMART_CTA, SEGMENTS, PIXELS, REVENUE_INTEL };

  /* ═══════════════════════════════════════════════════════════════
     8. BOOT SEQUENCE
  ═══════════════════════════════════════════════════════════════ */
  function boot() {
    AB.init();
    TRACK.init();
    SMART_CTA.init();
    PIXELS.init();
    // Log profile to console for debugging
    setTimeout(() => {
      console.info('[CYBERDUDEBIVASH SENTINEL APEX CX]', REVENUE_INTEL.getReport());
    }, 3000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})();
.Value -replace 'z-index: 9998', 'z-index: 9995'

    #cx-return-banner.cx-show { transform: translateY(0); }
    #cx-return-banner span { font-size: .82rem; color: #e2e8f0; font-weight: 500; }
    #cx-return-banner strong { color: #ffd700; }
    #cx-return-banner a {
      background: linear-gradient(135deg, #ffd700, #ff8c00);
      color: #000; font-weight: 800; font-size: .75rem;
      padding: .35rem .85rem; border-radius: 6px; text-decoration: none;
      white-space: nowrap; transition: opacity .2s;
    }
    #cx-return-banner a:hover { opacity: .85; }
    #cx-return-banner button {
      background: none; border: none; color: #475569; font-size: .9rem;
      cursor: pointer; margin-left: .5rem;
    }

    /* Scroll progress indicator */
    #cx-scroll-bar {
      position: fixed; top: 0; left: 0; height: 3px; z-index: 10001;
      background: linear-gradient(90deg, ${CYAN}, #00d4ff);
      width: 0%; transition: width .1s; pointer-events: none;
    }

    /* Inline upgrade prompt (injected mid-post) */
    .cx-inline-cta {
      background: linear-gradient(135deg, rgba(0,255,224,0.06), rgba(0,212,255,0.04));
      border: 1px solid rgba(0,255,224,0.2); border-radius: 12px;
      padding: 1.25rem 1.5rem; margin: 2rem 0;
      display: flex; align-items: center; gap: 1.25rem; flex-wrap: wrap;
    }
    .cx-inline-cta .ci-icon { font-size: 2rem; flex-shrink: 0; }
    .cx-inline-cta .ci-body { flex: 1; min-width: 200px; }
    .cx-inline-cta .ci-body strong { display: block; font-size: .95rem; font-weight: 800; color: #fff; margin-bottom: .25rem; }
    .cx-inline-cta .ci-body span { font-size: .8rem; color: #94a3b8; }
    .cx-inline-cta a {
      background: linear-gradient(135deg, ${CYAN}, #00d4ff);
      color: #000; font-weight: 800; font-size: .8rem;
      padding: .55rem 1.1rem; border-radius: 8px; text-decoration: none;
      white-space: nowrap; flex-shrink: 0;
    }

    /* High-intent enterprise flash */
    #cx-enterprise-flash {
      position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) scale(.9);
      z-index: 10000; width: 480px; max-width: calc(100vw - 32px);
      background: rgba(7,9,15,0.98);
      border: 1px solid rgba(0,255,224,0.3); border-radius: 20px;
      padding: 2rem; text-align: center;
      box-shadow: 0 40px 100px rgba(0,0,0,0.7), 0 0 60px rgba(0,255,224,0.06);
      opacity: 0; pointer-events: none;
      transition: all .35s cubic-bezier(.22,.68,0,1.2);
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    #cx-enterprise-flash.cx-show { opacity: 1; pointer-events: all; transform: translate(-50%,-50%) scale(1); }
    #cx-ef-backdrop {
      position: fixed; inset: 0; z-index: 9999;
      background: rgba(0,0,0,.6); backdrop-filter: blur(4px);
      opacity: 0; pointer-events: none; transition: opacity .3s;
    }
    #cx-ef-backdrop.cx-show { opacity: 1; pointer-events: all; }
  `);

  const SMART_CTA = {
    overlayShown: false,
    returnBannerShown: false,
    enterpriseFlashShown: false,
    inlineCTAsInjected: false,
    scrollBar: null,

    init() {
      // Scroll progress bar
      this.scrollBar = el('div', { id: 'cx-scroll-bar' });
      document.body.appendChild(this.scrollBar);
      window.addEventListener('scroll', () => {
        const pct = Math.round(
          (window.scrollY / Math.max(1, document.documentElement.scrollHeight - window.innerHeight)) * 100
        );
        if (this.scrollBar) this.scrollBar.style.width = pct + '%';
      });

      // Return visitor banner
      const visits = ls.get(CFG.returnVisitKey) || 1;
      if (visits >= 2) {
        setTimeout(() => this.showReturnBanner(visits), 2500);
      }

      // Inject inline CTAs into post body after load
      if (page.includes('/posts/')) {
        setTimeout(() => this.injectInlineCTAs(), 1000);
      }
    },

    checkScroll(pct) {
      // 45% → inject mid-page CTA if on post
      if (pct >= CFG.scrollMidCTAPct && !this.overlayShown) {
        const seg = SEGMENTS.detect();
        const msg = SEGMENTS.getMessage(seg);
        setTimeout(() => this.showOverlay(msg, 'mid_scroll'), 500);
        this.overlayShown = true;
      }
      // 70% → show "Unlock Full Report" overlay
      if (pct >= CFG.scrollUnlockPct && !this.overlayShown) {
        this.showOverlay({
          badge: '⚡ PRO MEMBERS ONLY',
          headline: '🔒 Unlock Full Intelligence Report',
          sub: 'Get complete IOC lists, SIEM detection rules, YARA signatures, and analyst commentary — exclusive to SOC Pro members.',
          cta: 'Unlock Full Report — $49/mo',
          url: CFG.pricingUrl
        }, 'scroll_unlock');
        this.overlayShown = true;
        TRACK.event('scroll_unlock_shown', { pct });
      }
    },

    onHighIntent(href) {
      if (this.enterpriseFlashShown) return;
      if (href.includes('enterprise') || href.includes('pricing')) {
        setTimeout(() => this.showEnterpriseFlash(), 800);
        this.enterpriseFlashShown = true;
        TRACK.event('high_intent_detected', { href });
      }
    },

    showOverlay(msg, trigger) {
      const existing = document.getElementById('cx-smart-overlay');
      if (existing) existing.remove();

      const progressPct = TRACK.maxScroll + '%';
      const overlay = el('div', { id: 'cx-smart-overlay' },
        el('button', { class: 'cx-close', onclick: () => overlay.classList.remove('cx-show') }, '✕'),
        el('div', { class: 'cx-progress' },
          el('div', { class: 'cx-progress-bar', style: { width: progressPct } })
        ),
        el('div', { class: 'cx-badge' }, msg.badge || '⚡ CYBERDUDEBIVASH SENTINEL APEX INTELLIGENCE'),
        el('h4', {}, msg.headline || 'Upgrade for Full Access'),
        el('p', {}, msg.sub || 'Get unrestricted access to IOC packs, SIEM rules, and premium reports.'),
        el('a', { class: 'cx-btn', href: msg.url || CFG.pricingUrl,
          onclick: () => TRACK.event('smart_cta_click', { trigger, msg: msg.headline }) },
          msg.cta || AB.ctaText || 'Get Full Access →'
        ),
        el('span', { class: 'cx-dismiss',
          onclick: () => {
            overlay.classList.remove('cx-show');
            TRACK.event('smart_cta_dismissed', { trigger });
          }
        }, 'Not now — remind me later')
      );
      document.body.appendChild(overlay);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => overlay.classList.add('cx-show'));
      });
      TRACK.event('smart_overlay_shown', { trigger });
    },

    showReturnBanner(visits) {
      if (document.getElementById('cx-return-banner')) return;
      const offer = visits >= 5 ? '20% OFF with code APEX20' :
                    visits >= 3 ? '7-day free Pro trial' :
                                  'free threat report';
      const banner = el('div', { id: 'cx-return-banner' },
        el('span', {}, `Welcome back! 👋 You've visited <strong>${visits}x</strong> — claim your `),
        el('strong', {}, offer),
        el('a', { href: CFG.pricingUrl,
          onclick: () => TRACK.event('return_banner_click', { visits, offer }) },
          `Claim Offer →`
        ),
        el('button', {
          onclick: () => {
            const b = document.getElementById('cx-return-banner');
            if (b) b.remove();
          }
        }, '✕')
      );
      document.body.appendChild(banner);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => banner.classList.add('cx-show'));
      });
      TRACK.event('return_banner_shown', { visits });
    },

    showEnterpriseFlash() {
      const backdrop = el('div', { id: 'cx-ef-backdrop',
        onclick: () => {
          document.getElementById('cx-enterprise-flash')?.classList.remove('cx-show');
          backdrop.classList.remove('cx-show');
        }
      });
      const flash = el('div', { id: 'cx-enterprise-flash' },
        el('div', { style: { fontSize: '2.5rem', marginBottom: '.75rem' } }, '🏢'),
        el('div', { style: { fontSize: '.7rem', fontWeight: '800', color: CYAN, letterSpacing: '.12em', textTransform: 'uppercase', marginBottom: '.5rem' } },
          '⚡ ENTERPRISE INTELLIGENCE PLATFORM'),
        el('h3', { style: { fontSize: '1.4rem', fontWeight: '900', color: '#fff', marginBottom: '.5rem', lineHeight: '1.3' } },
          'Looks Like You Need Enterprise-Grade Threat Intel'),
        el('p', { style: { fontSize: '.85rem', color: '#94a3b8', marginBottom: '1.5rem', lineHeight: '1.6' } },
          'White-label feeds, SLA-backed data, dedicated analyst support, and custom detection rules built for your environment.'),
        el('div', { style: { display: 'flex', gap: '.75rem', justifyContent: 'center', flexWrap: 'wrap', marginBottom: '1rem' } },
          el('a', { href: CFG.enterpriseUrl, style: { background: `linear-gradient(135deg,${CYAN},#00d4ff)`, color: '#000', fontWeight: '800', fontSize: '.85rem', padding: '.65rem 1.4rem', borderRadius: '8px', textDecoration: 'none' },
            onclick: () => {
              TRACK.event('enterprise_flash_click', {});
              document.getElementById('cx-enterprise-flash')?.classList.remove('cx-show');
              backdrop.classList.remove('cx-show');
            }
          }, '🏢 Get Enterprise Proposal'),
          el('button', { style: { background: 'none', border: '1px solid rgba(0,255,224,0.2)', color: '#94a3b8', fontWeight: '600', fontSize: '.82rem', padding: '.65rem 1.2rem', borderRadius: '8px', cursor: 'pointer' },
            onclick: () => {
              document.getElementById('cx-enterprise-flash')?.classList.remove('cx-show');
              backdrop.classList.remove('cx-show');
              TRACK.event('enterprise_flash_dismissed', {});
            }
          }, 'Maybe Later')
        )
      );
      document.body.appendChild(backdrop);
      document.body.appendChild(flash);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          backdrop.classList.add('cx-show');
          flash.classList.add('cx-show');
        });
      });
      TRACK.event('enterprise_flash_shown', {});
    },

    injectInlineCTAs() {
      if (this.inlineCTAsInjected) return;
      // Find article body paragraphs
      const paras = [...document.querySelectorAll('article p, .post-body p, main p, .content p')];
      if (paras.length < 4) return;

      const ctaDefs = [
        {
          after: Math.floor(paras.length * 0.35),
          icon: '🛡️', title: 'Get Detection Rules for This CVE',
          sub: 'Sigma + YARA rules, IOC table, and SIEM queries — downloadable in seconds.',
          cta: 'Get Detection Pack →', url: CFG.productsUrl,
          track: 'inline_cta_detection'
        },
        {
          after: Math.floor(paras.length * 0.65),
          icon: '🔌', title: 'Integrate This Intel Into Your SIEM',
          sub: 'Access structured CVE data, IOC feeds, and risk scores via CYBERDUDEBIVASH SENTINEL APEX API.',
          cta: 'Start Free API Trial →', url: CFG.apiUrl,
          track: 'inline_cta_api'
        }
      ];

      ctaDefs.forEach(def => {
        const targetPara = paras[def.after];
        if (!targetPara) return;
        const ctaEl = el('div', { class: 'cx-inline-cta' },
          el('div', { class: 'ci-icon' }, def.icon),
          el('div', { class: 'ci-body' },
            el('strong', {}, def.title),
            el('span', {}, def.sub)
          ),
          el('a', { href: def.url, onclick: () => TRACK.event(def.track, {}) }, def.cta)
        );
        targetPara.insertAdjacentElement('afterend', ctaEl);
      });

      this.inlineCTAsInjected = true;
      TRACK.event('inline_ctas_injected', { paraCount: paras.length });
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     6. RETARGETING PIXEL MANAGER
  ═══════════════════════════════════════════════════════════════ */
  const PIXELS = {
    init() {
      this.loadGA4();
      this.loadGAds();
      this.loadFB();
    },

    loadGA4() {
      if (CFG.gaId.includes('XXXX')) return; // Not configured
      const s = document.createElement('script');
      s.src = `https://www.googletagmanager.com/gtag/js?id=${CFG.gaId}`;
      s.async = true;
      document.head.appendChild(s);
      window.dataLayer = window.dataLayer || [];
      window.gtag = function() { dataLayer.push(arguments); };
      gtag('js', new Date());
      gtag('config', CFG.gaId, {
        page_title: document.title,
        page_location: window.location.href,
        custom_map: { dimension1: 'ab_variant', dimension2: 'user_segment' }
      });
      gtag('set', 'user_properties', {
        ab_variant: AB.variant,
        user_segment: SEGMENTS.detect(),
        visit_count: ls.get(CFG.returnVisitKey) || 1
      });
    },

    loadGAds() {
      if (CFG.gadsId.includes('XXXX')) return;
      window.gtag && gtag('config', CFG.gadsId);
    },

    loadFB() {
      if (CFG.fbPixelId.includes('XXXX')) return;
      !function(f,b,e,v,n,t,s){
        if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
        if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
        t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)
      }(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init', CFG.fbPixelId);
      fbq('track', 'PageView');
    },

    fireConversion(type, value) {
      TRACK.event('conversion', { type, value });
      if (typeof gtag !== 'undefined' && !CFG.gadsId.includes('XXXX')) {
        gtag('event', 'conversion', { send_to: `${CFG.gadsId}/CONVERSION_LABEL`, value, currency: 'USD' });
      }
      if (typeof fbq !== 'undefined') {
        fbq('track', 'Purchase', { value, currency: 'USD', content_name: type });
      }
    }
  };

  /* ═══════════════════════════════════════════════════════════════
     7. REVENUE INTELLIGENCE DASHBOARD (localStorage)
  ═══════════════════════════════════════════════════════════════ */
  const REVENUE_INTEL = {
    getReport() {
      const events    = ls.get('cx_events') || [];
      const scrollEvt = ls.get('cx_scroll_events') || [];
      const visits    = ls.get(CFG.returnVisitKey) || 1;
      const abData    = ls.get(CFG.abKey) || {};
      return {
        totalEvents:    events.length,
        visits,
        abVariant:      abData,
        segment:        SEGMENTS.detect(),
        topPages:       [...new Set(events.map(e => e.page))].slice(0, 10),
        clickLabels:    events.filter(e => e.name === 'click').map(e => e.data?.label).filter(Boolean).slice(-20),
        maxScroll:      Math.max(...scrollEvt.map(e => e.pct), 0),
        overlaysShown:  events.filter(e => e.name.includes('shown')).length,
        ctaClicks:      events.filter(e => e.name.includes('click')).length,
        avgTimeOnPage:  Math.round(events.filter(e => e.name === 'exit').reduce((a, e) => a + (e.data?.timeOnPage || 0), 0) / Math.max(1, events.filter(e => e.name === 'exit').length))
      };
    }
  };

  // Expose to window for debugging / analytics endpoint calls
  window.CX = { AB, TRACK, SMART_CTA, SEGMENTS, PIXELS, REVENUE_INTEL };

  /* ═══════════════════════════════════════════════════════════════
     8. BOOT SEQUENCE
  ═══════════════════════════════════════════════════════════════ */
  function boot() {
    AB.init();
    TRACK.init();
    SMART_CTA.init();
    PIXELS.init();
    // Log profile to console for debugging
    setTimeout(() => {
      console.info('[CYBERDUDEBIVASH SENTINEL APEX CX]', REVENUE_INTEL.getReport());
    }, 3000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})();
