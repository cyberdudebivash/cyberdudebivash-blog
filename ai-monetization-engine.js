/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║   SENTINEL APEX — AI MONETIZATION ENGINE v3.0                   ║
 * ║   Maximum Revenue Extraction System                              ║
 * ╠══════════════════════════════════════════════════════════════════╣
 * ║  1. INTENT CLASSIFIER      → Buyer/Researcher/Enterprise/Dev     ║
 * ║  2. DYNAMIC PRICING ENGINE → Visit-count/device/geo discounts    ║
 * ║  3. COUNTDOWN TIMER SYSTEM → Offer urgency triggers              ║
 * ║  4. SCARCITY ENGINE        → Download limits, slot counters      ║
 * ║  5. SOCIAL PROOF ENGINE    → Live activity signals               ║
 * ║  6. CONTENT→MONEY PIPELINE → Topic → Product auto-injector       ║
 * ║  7. BUNDLE CROSS-SELL      → Post-view upsell engine             ║
 * ║  8. SUBSCRIPTION UPGRADE   → Tier-escalation prompts             ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * Deploy: <script src="/ai-monetization-engine.js" defer></script>
 * Load order: monetization.js → conversion-engine.js → seo-engine.js → THIS
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════════
     § CONFIG
  ══════════════════════════════════════════════════════════════ */
  const CFG = {
    email:          'bivash@cyberdudebivash.com',
    pricingUrl:     '/pricing.html',
    apiUrl:         '/api.html',
    productsUrl:    '/products.html',
    enterpriseUrl:  '/enterprise.html',
    leadsUrl:       '/leads.html',
    CYAN:           '#00ffe0',
    BG:             'rgba(7,9,15,0.97)',
    BORDER:         '1px solid rgba(0,255,224,0.2)',
    // Dynamic pricing thresholds
    pricing: {
      base:         49,
      visit2_disc:  0.10,   // 10% off second visit
      visit3_disc:  0.20,   // 20% off third visit
      mobile_disc:  0.05,   // 5% mobile bonus
      countdown_ms: 12 * 60 * 1000,  // 12-min countdown
    },
    // Scarcity pool — resets daily based on date seed
    scarcity: {
      downloads_base: 47,
      downloads_min:  6,
      slots_base:     12,
      slots_min:      2,
    }
  };

  const ls = {
    get:  k    => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
    set:  (k,v)=> { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }
  };

  const $ = s => document.querySelector(s);
  const $$ = s => [...document.querySelectorAll(s)];
  const now = () => Date.now();
  const page = window.location.pathname;

  function css(el, styles) { Object.assign(el.style, styles); }

  function injectStyle(id, cssText) {
    if (document.getElementById(id)) return;
    const s = document.createElement('style');
    s.id = id;
    s.textContent = cssText;
    document.head.appendChild(s);
  }

  /* ══════════════════════════════════════════════════════════════
     § 1. INTENT CLASSIFIER — AI Brain
  ══════════════════════════════════════════════════════════════ */
  const INTENT = {
    profile: null,

    classify() {
      const visits     = ls.get('cx_visits') || 1;
      const events     = ls.get('cx_events') || [];
      const abData     = ls.get('cx_ab_variant') || {};
      const referer    = document.referrer.toLowerCase();
      const ua         = navigator.userAgent.toLowerCase();
      const path       = page.toLowerCase();

      // Score signals
      let scores = { buyer: 0, enterprise: 0, developer: 0, researcher: 0 };

      // Visit depth
      if (visits >= 4) scores.buyer += 30;
      if (visits >= 2) scores.buyer += 15;

      // Click patterns
      const clicks = events.filter(e => e.name === 'click').map(e => (e.data?.label || '').toLowerCase());
      if (clicks.some(c => c.includes('buy') || c.includes('price') || c.includes('$'))) scores.buyer += 40;
      if (clicks.some(c => c.includes('enterprise') || c.includes('proposal'))) scores.enterprise += 50;
      if (clicks.some(c => c.includes('api') || c.includes('trial'))) scores.developer += 40;

      // Page history
      const pages = [...new Set((ls.get('cx_events') || []).map(e => e.page).filter(Boolean))];
      if (pages.some(p => p.includes('pricing') || p.includes('products'))) scores.buyer += 25;
      if (pages.some(p => p.includes('enterprise'))) scores.enterprise += 35;
      if (pages.some(p => p.includes('api'))) scores.developer += 30;
      if (pages.filter(p => p.includes('/posts/')).length >= 3) scores.researcher += 20;

      // Referrer signals
      if (referer.includes('linkedin') || referer.includes('crunchbase')) scores.enterprise += 30;
      if (referer.includes('github') || referer.includes('stackoverflow') || referer.includes('hacker')) scores.developer += 30;
      if (referer.includes('google') && path.includes('cve')) scores.researcher += 20;

      // Scroll depth
      const maxScroll = Math.max(...(ls.get('cx_scroll_events') || []).map(e => e.pct), 0);
      if (maxScroll >= 80) scores.researcher += 15;

      // Current page context
      if (path.includes('enterprise')) scores.enterprise += 20;
      if (path.includes('api')) scores.developer += 20;
      if (path.includes('products') || path.includes('pricing')) scores.buyer += 20;

      // Device
      const isMobile = /android|iphone|ipad|mobile/i.test(ua);

      // Determine dominant intent
      const dominant = Object.entries(scores).sort((a,b) => b[1]-a[1])[0][0];

      this.profile = {
        intent:   dominant,
        scores,
        visits,
        isMobile,
        maxScroll,
        isReturn:  visits >= 2,
        isBuyer:   scores.buyer >= 40,
        isEnterprise: scores.enterprise >= 35,
        isDev:     scores.developer >= 30,
        rawVisits: visits
      };

      // Persist for analytics
      ls.set('aim_profile', this.profile);
      return this.profile;
    },

    getMessage() {
      const p = this.profile;
      const msgs = {
        buyer: {
          headline:  '⚡ Ready to Upgrade Your Detection Coverage?',
          sub:       'You\'ve been exploring our intelligence platform. Lock in the best price now — offer expires soon.',
          cta:       '🛒 Get SOC Pro — Best Price Today',
          ctaUrl:    CFG.pricingUrl,
          badge:     '🔥 BEST SELLER',
          urgency:   true
        },
        enterprise: {
          headline:  '🏢 Enterprise Threat Intelligence — Custom Proposal',
          sub:       'Your browsing pattern suggests enterprise requirements. Get a proposal tailored to your team size and SIEM stack.',
          cta:       '📧 Get Enterprise Proposal →',
          ctaUrl:    CFG.enterpriseUrl,
          badge:     '🏆 ENTERPRISE',
          urgency:   false
        },
        developer: {
          headline:  '🔌 Start Free API Trial — No Credit Card',
          sub:       'Integrate CVE feeds, IOC data, and AI risk scoring in minutes. 100 free requests/day forever.',
          cta:       '⚡ Start Free API Trial →',
          ctaUrl:    CFG.apiUrl,
          badge:     '🔌 DEVELOPER',
          urgency:   false
        },
        researcher: {
          headline:  '📧 Get Weekly Intelligence Briefings — Free',
          sub:       'You\'re clearly a serious security researcher. Join 2,400+ analysts getting weekly CVE + IOC briefings.',
          cta:       '📧 Subscribe Free →',
          ctaUrl:    CFG.leadsUrl,
          badge:     '📚 RESEARCHER',
          urgency:   false
        }
      };
      return msgs[p.intent] || msgs.researcher;
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 2. DYNAMIC PRICING ENGINE
  ══════════════════════════════════════════════════════════════ */
  const DYNPRICE = {
    compute(basePrice) {
      const p       = INTENT.profile;
      const visits  = p?.rawVisits || 1;
      const mobile  = p?.isMobile || false;
      let discount  = 0;
      let label     = '';
      let code      = '';

      if (visits === 2) {
        discount = CFG.pricing.visit2_disc;
        label    = '10% returning visitor discount';
        code     = 'RETURN10';
      } else if (visits === 3) {
        discount = CFG.pricing.visit2_disc + 0.05;
        label    = '15% loyalty discount';
        code     = 'LOYAL15';
      } else if (visits >= 4) {
        discount = CFG.pricing.visit3_disc;
        label    = '20% VIP discount — you deserve it';
        code     = 'VIP20';
      }

      if (mobile) {
        discount += CFG.pricing.mobile_disc;
        label = label ? label + ' + 5% mobile bonus' : '5% mobile bonus';
      }

      const final = Math.round(basePrice * (1 - discount));
      return { base: basePrice, final, discount, label, code, savings: basePrice - final };
    },

    renderTag(base, containerId) {
      const el = document.getElementById(containerId);
      if (!el) return;
      const { final, base: b, discount, label, code, savings } = this.compute(base);
      if (discount === 0) {
        el.innerHTML = `<span style="font-size:1.6rem;font-weight:900;color:${CFG.CYAN}">$${final}</span>`;
        return;
      }
      el.innerHTML = `
        <span style="font-size:1.6rem;font-weight:900;color:${CFG.CYAN}">$${final}</span>
        <span style="text-decoration:line-through;color:#64748b;font-size:.9rem;margin-left:.4rem">$${b}</span>
        <span style="display:block;font-size:.72rem;color:#22c55e;font-weight:700;margin-top:.2rem">
          ${label} — Use code <strong>${code}</strong> to save $${savings}
        </span>`;
    },

    injectPricingBadges() {
      // Find existing price elements and upgrade them
      $$('[data-aim-price]').forEach(el => {
        const base = parseInt(el.dataset.aimPrice);
        if (!base) return;
        const { final, discount, label, code } = this.compute(base);
        if (discount > 0) {
          el.setAttribute('data-original', base);
          el.textContent = '$' + final;
          // Add discount badge next to parent
          const badge = document.createElement('div');
          badge.style.cssText = `font-size:.72rem;color:#22c55e;font-weight:700;margin-top:.25rem`;
          badge.innerHTML = `${label} · Code: <strong>${code}</strong>`;
          el.parentNode?.appendChild(badge);
        }
      });
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 3. COUNTDOWN TIMER SYSTEM
  ══════════════════════════════════════════════════════════════ */
  const COUNTDOWN = {
    timerKey: 'aim_countdown_end',

    getEnd() {
      let end = ls.get(this.timerKey);
      if (!end || end < now()) {
        end = now() + CFG.pricing.countdown_ms;
        ls.set(this.timerKey, end);
      }
      return end;
    },

    format(ms) {
      if (ms <= 0) return '00:00';
      const m = Math.floor(ms / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      return `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
    },

    startAll() {
      const end = this.getEnd();
      const update = () => {
        const remaining = end - now();
        $$('.aim-countdown').forEach(el => {
          el.textContent = this.format(remaining);
          if (remaining <= 0) {
            el.textContent = 'EXPIRED';
            el.style.color = '#ff4d6d';
            // Reset timer and offer
            ls.set(this.timerKey, now() + CFG.pricing.countdown_ms);
          } else if (remaining < 60000) {
            el.style.color = '#ff4d6d';
            el.style.animation = 'aim-blink 1s infinite';
          }
        });
      };
      update();
      setInterval(update, 1000);
    },

    inject(parentEl, offerText) {
      const wrap = document.createElement('div');
      wrap.style.cssText = `display:flex;align-items:center;gap:.6rem;margin:.5rem 0;`;
      wrap.innerHTML = `
        <span style="font-size:.72rem;color:#94a3b8;font-weight:600">${offerText || '⏱ Offer expires in'}</span>
        <span class="aim-countdown" style="font-size:.9rem;font-weight:900;color:${CFG.CYAN};font-variant-numeric:tabular-nums;letter-spacing:.05em;background:rgba(0,255,224,.1);padding:.15rem .5rem;border-radius:4px;">00:00</span>`;
      parentEl.appendChild(wrap);
      this.startAll();
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 4. SCARCITY ENGINE
  ══════════════════════════════════════════════════════════════ */
  const SCARCITY = {
    // Deterministic "random" based on today's date — consistent per day, different each day
    seed() {
      const d = new Date();
      return d.getFullYear() * 10000 + (d.getMonth()+1) * 100 + d.getDate();
    },

    pseudoRand(min, max, salt = 0) {
      const s = (this.seed() + salt) % 997;
      return min + (s % (max - min + 1));
    },

    getDownloadsLeft() {
      const key = 'aim_downloads_' + new Date().toDateString();
      let count = ls.get(key);
      if (!count) {
        count = this.pseudoRand(CFG.scarcity.downloads_min, CFG.scarcity.downloads_base, 1);
        ls.set(key, count);
      }
      return count;
    },

    getSlotsLeft() {
      const key = 'aim_slots_' + new Date().toDateString();
      let count = ls.get(key);
      if (!count) {
        count = this.pseudoRand(CFG.scarcity.slots_min, CFG.scarcity.slots_base, 7);
        ls.set(key, count);
      }
      return count;
    },

    decrementOnClick(type) {
      const key = type === 'download'
        ? 'aim_downloads_' + new Date().toDateString()
        : 'aim_slots_' + new Date().toDateString();
      const current = ls.get(key) || this.getDownloadsLeft();
      if (current > 1) ls.set(key, current - 1);
      this.refreshAll();
    },

    refreshAll() {
      const dl = this.getDownloadsLeft();
      const sl = this.getSlotsLeft();
      $$('.aim-scarcity-downloads').forEach(el => { el.textContent = dl; });
      $$('.aim-scarcity-slots').forEach(el => { el.textContent = sl; });
      // Color code urgency
      $$('[data-aim-scarcity]').forEach(el => {
        const type = el.dataset.aimScarcity;
        const val  = type === 'downloads' ? dl : sl;
        if (val <= 3) { el.style.color = '#ff4d6d'; }
        else if (val <= 7) { el.style.color = '#ff8c42'; }
        else { el.style.color = '#ffd700'; }
      });
    },

    renderBadge(type, label) {
      const count = type === 'downloads' ? this.getDownloadsLeft() : this.getSlotsLeft();
      const color = count <= 3 ? '#ff4d6d' : count <= 7 ? '#ff8c42' : '#ffd700';
      return `<span data-aim-scarcity="${type}" style="display:inline-flex;align-items:center;gap:.3rem;background:rgba(255,77,109,.1);border:1px solid rgba(255,77,109,.3);border-radius:50px;padding:.2rem .65rem;font-size:.72rem;font-weight:800;color:${color};">
        🔥 Only <span class="aim-scarcity-${type}">${count}</span> ${label} left today
      </span>`;
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 5. SOCIAL PROOF ENGINE
  ══════════════════════════════════════════════════════════════ */
  const SOCIAL_PROOF = {
    activities: [
      { t: 'purchase',   msg: 'purchased Sigma Megapack',         who: 'SOC Analyst from Frankfurt' },
      { t: 'purchase',   msg: 'purchased YARA Ransomware Pack',   who: 'IR Lead from London' },
      { t: 'signup',     msg: 'started free API trial',           who: 'Security Engineer from NYC' },
      { t: 'purchase',   msg: 'purchased Enterprise Bundle',      who: 'CISO from Singapore' },
      { t: 'signup',     msg: 'subscribed to Pro plan',           who: 'Threat Hunter from Toronto' },
      { t: 'download',   msg: 'downloaded IOC Pack',              who: 'SOC Analyst from Berlin' },
      { t: 'purchase',   msg: 'purchased Red Team Kit',           who: 'Pentester from Sydney' },
      { t: 'enterprise', msg: 'requested enterprise proposal',    who: 'Security Director from Dubai' },
      { t: 'purchase',   msg: 'purchased Q2 Threat Report',       who: 'CISO from Boston' },
      { t: 'signup',     msg: 'subscribed to weekly briefings',   who: 'Threat Analyst from Tokyo' },
      { t: 'purchase',   msg: 'purchased Complete Arsenal Bundle',who: 'Red Team Lead from Amsterdam' },
      { t: 'signup',     msg: 'started free API trial',           who: 'DevSecOps Eng from Bangalore' },
      { t: 'purchase',   msg: 'purchased SOC Playbook',           who: 'SOC Manager from Chicago' },
      { t: 'enterprise', msg: 'booked analyst call',              who: 'VP Security from Stockholm' },
      { t: 'download',   msg: 'downloaded free Intel Pack',       who: '427 analysts this week' },
    ],

    icons: { purchase: '🛒', signup: '⚡', download: '📥', enterprise: '🏢' },

    queue: [],
    running: false,
    interval: 18000,

    init() {
      this.queue = [...this.activities].sort(() => 0.5 - Math.random());
      this.injectContainer();
      setTimeout(() => this.show(), 8000);
      setInterval(() => this.show(), this.interval);
    },

    injectContainer() {
      if (document.getElementById('aim-toast-container')) return;
      injectStyle('aim-toast-css', `
        #aim-toast-container {
          position: fixed; bottom: 20px; left: 20px; z-index: 10002;
          display: flex; flex-direction: column; gap: .5rem;
          pointer-events: none;
        }
        .aim-toast {
          background: rgba(7,9,15,0.97);
          border: 1px solid rgba(0,255,224,0.2);
          border-radius: 12px; padding: .85rem 1.1rem;
          display: flex; align-items: center; gap: .75rem;
          max-width: 300px; width: 300px;
          box-shadow: 0 10px 40px rgba(0,0,0,.5);
          transform: translateX(-340px); transition: transform .4s cubic-bezier(.22,.68,0,1.2);
          pointer-events: all; cursor: default;
          font-family: 'Segoe UI', system-ui, sans-serif;
        }
        .aim-toast.show { transform: translateX(0); }
        .aim-toast .at-icon {
          width: 36px; height: 36px; border-radius: 50%; flex-shrink: 0;
          background: rgba(0,255,224,0.12);
          display: flex; align-items: center; justify-content: center; font-size: 1.1rem;
        }
        .aim-toast .at-body { flex: 1; }
        .aim-toast .at-action { font-size: .8rem; font-weight: 700; color: #e2e8f0; display: block; }
        .aim-toast .at-who { font-size: .72rem; color: #64748b; display: block; margin-top: .1rem; }
        .aim-toast .at-time { font-size: .68rem; color: #475569; white-space: nowrap; align-self: flex-start; margin-top: .15rem; }
        @keyframes aim-blink { 0%,100%{opacity:1} 50%{opacity:.4} }
      `);
      const container = document.createElement('div');
      container.id = 'aim-toast-container';
      document.body.appendChild(container);
    },

    show() {
      if (!this.queue.length) this.queue = [...this.activities].sort(() => 0.5 - Math.random());
      const activity = this.queue.shift();
      const container = document.getElementById('aim-toast-container');
      if (!container) return;

      const minAgo = Math.floor(Math.random() * 12) + 1;
      const toast = document.createElement('div');
      toast.className = 'aim-toast';
      toast.innerHTML = `
        <div class="at-icon">${this.icons[activity.t] || '⚡'}</div>
        <div class="at-body">
          <span class="at-action">${activity.who}</span>
          <span class="at-who">${activity.msg}</span>
        </div>
        <span class="at-time">${minAgo}m ago</span>`;
      container.appendChild(toast);
      requestAnimationFrame(() => { requestAnimationFrame(() => toast.classList.add('show')); });
      setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 500);
      }, 5000);
    },

    injectCounter(containerSel, type, count) {
      // Inline "X people doing Y" counter
      const containers = $$(containerSel);
      containers.forEach(c => {
        const counter = document.createElement('div');
        counter.style.cssText = `font-size:.75rem;color:#94a3b8;margin:.4rem 0;display:flex;align-items:center;gap:.4rem;`;
        counter.innerHTML = `<span style="display:inline-flex">
          ${[...Array(5)].map((_,i)=>`<span style="width:18px;height:18px;border-radius:50%;background:linear-gradient(135deg,${CFG.CYAN},#00d4ff);display:inline-flex;align-items:center;justify-content:center;font-size:.6rem;font-weight:900;color:#000;margin-left:${i>0?'-4px':'0'}">👤</span>`).join('')}
        </span> <strong style="color:#fff">${count}</strong> ${type}`;
        c.appendChild(counter);
      });
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 6. CONTENT → MONEY PIPELINE
  ══════════════════════════════════════════════════════════════ */
  const CONTENT_PIPELINE = {
    // Map content topics to products/CTAs
    topicMap: [
      { signals: ['cve','zero-day','vulnerability','cvss','patch'],
        product: { icon:'🛡️', title:'Get Detection Rules for This CVE', sub:'Sigma + YARA rules deployable in 5 minutes.', cta:'Download Detection Pack →', url:'/products.html', price:'$49' } },
      { signals: ['ransomware','lockbit','qilin','akira','encrypt','ransom'],
        product: { icon:'🔐', title:'Ransomware Defense Pack', sub:'800+ YARA rules + IR playbook. Stop encryption before it starts.', cta:'Get Ransomware Pack →', url:'/products.html', price:'$89' } },
      { signals: ['apt','volt typhoon','lazarus','nation-state','ics','scada','critical infrastructure'],
        product: { icon:'🏢', title:'Enterprise Threat Intelligence Advisory', sub:'Dedicated analyst + early APT disclosure. Custom proposal for your team.', cta:'Get Enterprise Advisory →', url:'/enterprise.html', price:'Custom' } },
      { signals: ['api','integration','siem','soar','automation','webhook','feed'],
        product: { icon:'🔌', title:'SENTINEL APEX Threat Intelligence API', sub:'Integrate CVE + IOC data into your stack. Free tier available.', cta:'Start Free API Trial →', url:'/api.html', price:'Free' } },
      { signals: ['sigma','yara','detection','rule','splunk','elastic','sentinel','chronicle'],
        product: { icon:'🎯', title:'Sigma Megapack 2026 — 1,200+ Rules', sub:'Production-ready detection rules mapped to MITRE ATT&CK v15.', cta:'Get Sigma Megapack →', url:'/products.html', price:'$149' } },
      { signals: ['ai','llm','prompt injection','generative','gpt','chatgpt','copilot'],
        product: { icon:'🤖', title:'AI Security Risk Report 2026', sub:'Full analysis of LLM attack surfaces, prompt injection TTPs, and enterprise mitigations.', cta:'Get AI Security Report →', url:'/products.html', price:'$49' } },
    ],

    detect() {
      const bodyText = (document.body.innerText || '').toLowerCase();
      const title    = document.title.toLowerCase();
      const combined = bodyText + ' ' + title;
      for (const { signals, product } of this.topicMap) {
        const matchCount = signals.filter(s => combined.includes(s)).length;
        if (matchCount >= 2) return product;
      }
      return null; // default
    },

    buildCard(product, style = 'full') {
      const sc = SCARCITY.getDownloadsLeft();
      const scarcityColor = sc <= 3 ? '#ff4d6d' : sc <= 7 ? '#ff8c42' : '#ffd700';
      const { final, discount, code } = DYNPRICE.compute(parseInt(product.price) || 49);
      const priceDisplay = isNaN(parseInt(product.price))
        ? product.price
        : (discount > 0 ? `<del style="color:#475569;font-size:.8rem">$${parseInt(product.price)}</del> <strong style="color:${CFG.CYAN}">$${final}</strong>` : `<strong style="color:${CFG.CYAN}">$${product.price}</strong>`);

      if (style === 'compact') {
        return `
          <div class="aim-product-inject" style="background:rgba(7,9,15,.95);border:1px solid rgba(0,255,224,.2);border-radius:12px;padding:1.1rem 1.25rem;margin:1.5rem 0;display:flex;align-items:center;gap:1rem;flex-wrap:wrap;font-family:'Segoe UI',system-ui,sans-serif;">
            <span style="font-size:1.5rem;flex-shrink:0">${product.icon}</span>
            <div style="flex:1;min-width:180px">
              <strong style="display:block;font-size:.88rem;color:#fff;font-weight:800;margin-bottom:.2rem">${product.title}</strong>
              <span style="font-size:.77rem;color:#94a3b8">${product.sub}</span>
            </div>
            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:.3rem;flex-shrink:0">
              <span style="font-size:.85rem">${priceDisplay}</span>
              <span style="font-size:.65rem;color:${scarcityColor};font-weight:700">🔥 Only ${sc} left today</span>
              <a href="${product.url}" onclick="window.AIM?.SCARCITY?.decrementOnClick('download')" style="background:linear-gradient(135deg,${CFG.CYAN},#00d4ff);color:#000;font-weight:800;font-size:.78rem;padding:.45rem .95rem;border-radius:7px;text-decoration:none;white-space:nowrap;">${product.cta}</a>
            </div>
          </div>`;
      }

      // Full card
      return `
        <div class="aim-product-inject" style="background:linear-gradient(135deg,rgba(0,255,224,.04),rgba(0,100,200,.03));border:1px solid rgba(0,255,224,.2);border-radius:16px;padding:1.5rem;margin:2rem 0;font-family:'Segoe UI',system-ui,sans-serif;">
          <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem">
            <span style="font-size:1.8rem">${product.icon}</span>
            <div>
              <div style="font-size:.65rem;font-weight:800;color:${CFG.CYAN};text-transform:uppercase;letter-spacing:.1em">⚡ SENTINEL APEX INTELLIGENCE</div>
              <strong style="font-size:.95rem;color:#fff;font-weight:900">${product.title}</strong>
            </div>
          </div>
          <p style="font-size:.82rem;color:#94a3b8;margin-bottom:.85rem;line-height:1.6">${product.sub}</p>
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem">
            <div>
              <div style="font-size:.85rem;margin-bottom:.2rem">${priceDisplay}</div>
              ${SCARCITY.renderBadge('downloads', 'downloads')}
            </div>
            <div style="display:flex;flex-direction:column;gap:.4rem;align-items:flex-end">
              <a href="${product.url}" onclick="window.AIM?.SCARCITY?.decrementOnClick('download')" style="background:linear-gradient(135deg,${CFG.CYAN},#00d4ff);color:#000;font-weight:800;font-size:.85rem;padding:.6rem 1.35rem;border-radius:9px;text-decoration:none;display:inline-flex;align-items:center;gap:.4rem;box-shadow:0 0 20px rgba(0,255,224,.2);">${product.cta}</a>
              ${discount > 0 ? `<span style="font-size:.68rem;color:#22c55e;font-weight:700">✓ ${Math.round(discount*100)}% discount applied · Code: ${code}</span>` : ''}
            </div>
          </div>
        </div>`;
    },

    injectIntoPost() {
      if (!page.includes('/posts/')) return;
      const product = this.detect();
      if (!product) return;

      const paras = $$('article p, .post-content p, main p').filter(p => !p.closest('.aim-product-inject, .cx-inline-cta, nav, footer'));
      if (paras.length < 3) return;

      // Inject full card at 50% through post
      const midPara = paras[Math.floor(paras.length * 0.5)];
      if (midPara) {
        const wrapper = document.createElement('div');
        wrapper.innerHTML = this.buildCard(product, 'full');
        midPara.insertAdjacentElement('afterend', wrapper.firstElementChild);
      }

      // Inject compact card at 80%
      const latePara = paras[Math.floor(paras.length * 0.8)];
      if (latePara && latePara !== midPara) {
        const wrapper2 = document.createElement('div');
        wrapper2.innerHTML = this.buildCard(product, 'compact');
        latePara.insertAdjacentElement('afterend', wrapper2.firstElementChild);
      }

      // Inject enterprise CTA at end
      const lastPara = paras[paras.length - 1];
      if (lastPara) {
        const entCard = document.createElement('div');
        entCard.innerHTML = `
          <div style="background:rgba(255,215,0,.04);border:1px solid rgba(255,215,0,.2);border-radius:14px;padding:1.25rem 1.5rem;margin:1.5rem 0;display:flex;align-items:center;gap:1rem;flex-wrap:wrap;font-family:'Segoe UI',system-ui,sans-serif;">
            <span style="font-size:1.5rem">🏢</span>
            <div style="flex:1;min-width:180px">
              <strong style="display:block;font-size:.88rem;color:#ffd700;font-weight:800">Enterprise Threat Intelligence Advisory</strong>
              <span style="font-size:.78rem;color:#94a3b8">White-label feeds · Dedicated analyst · Custom detection rules for your stack</span>
            </div>
            <a href="${CFG.enterpriseUrl}" style="background:linear-gradient(135deg,#ffd700,#ff8c00);color:#000;font-weight:800;font-size:.8rem;padding:.5rem 1.1rem;border-radius:8px;text-decoration:none;white-space:nowrap;flex-shrink:0">Get Enterprise Proposal →</a>
          </div>`;
        lastPara.insertAdjacentElement('afterend', entCard.firstElementChild);
      }
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 7. BUNDLE CROSS-SELL ENGINE
  ══════════════════════════════════════════════════════════════ */
  const BUNDLE_ENGINE = {
    bundles: [
      { id:'starter',   name:'SOC Starter Bundle',   price:149, orig:227, items:['CVE Detection Pack','SOC Playbook','Automation Scripts','6-Month Updates'], color:CFG.CYAN },
      { id:'detection', name:'Enterprise Detection',  price:249, orig:387, items:['Sigma Megapack','YARA Ransomware Pack','CVE Detection Pack','12-Month Updates'], color:'#ffd700' },
      { id:'arsenal',   name:'Complete Arsenal',       price:499, orig:1241, items:['All 9 Products','12-Month Updates','Private Discord','2x Consulting Calls'], color:'#a855f7' },
    ],

    injectBundlePrompt() {
      // Show bundle prompt on products page and post pages
      if (!page.includes('products') && !page.includes('/posts/')) return;

      const p       = INTENT.profile;
      const bundle  = p?.isEnterprise ? this.bundles[2] : p?.isDev ? this.bundles[0] : this.bundles[1];
      const savings = bundle.orig - bundle.price;
      const sc      = SCARCITY.getSlotsLeft();

      const el = document.createElement('div');
      el.innerHTML = `
        <div id="aim-bundle-prompt" style="position:fixed;bottom:80px;left:20px;z-index:9998;width:300px;max-width:calc(100vw - 40px);background:rgba(7,9,15,.97);border:1px solid ${bundle.color.replace('#','rgba(').replace(/(rgba\()(\w+)/,(_,p,c)=>`rgba(${parseInt(c.slice(0,2),16)},${parseInt(c.slice(2,4),16)},${parseInt(c.slice(4,6),16)}`)},0.35);border-radius:14px;padding:1.1rem;box-shadow:0 20px 60px rgba(0,0,0,.5);transform:translateX(-340px);transition:transform .4s cubic-bezier(.22,.68,0,1.2);font-family:'Segoe UI',system-ui,sans-serif;display:none;">
          <button onclick="document.getElementById('aim-bundle-prompt').style.transform='translateX(-340px)'" style="position:absolute;top:.5rem;right:.6rem;background:none;border:none;color:#475569;cursor:pointer;font-size:.9rem">✕</button>
          <div style="font-size:.65rem;font-weight:800;color:${bundle.color};text-transform:uppercase;letter-spacing:.1em;margin-bottom:.4rem">⚡ BUNDLE OFFER</div>
          <div style="font-size:.9rem;font-weight:900;color:#fff;margin-bottom:.25rem">${bundle.name}</div>
          <div style="font-size:.78rem;color:#94a3b8;margin-bottom:.6rem">${bundle.items.slice(0,3).map(i=>`✓ ${i}`).join(' · ')}</div>
          <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem">
            <span style="font-size:1.3rem;font-weight:900;color:${bundle.color}">$${bundle.price}</span>
            <span style="text-decoration:line-through;color:#475569;font-size:.82rem">$${bundle.orig}</span>
            <span style="background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);color:#22c55e;font-size:.65rem;font-weight:800;padding:.1rem .4rem;border-radius:4px">SAVE $${savings}</span>
          </div>
          <div style="font-size:.7rem;color:#ff8c42;font-weight:700;margin-bottom:.6rem">🔥 Only <span class="aim-scarcity-slots">${sc}</span> bundle slots available today</div>
          <a href="${CFG.productsUrl}#bundles" onclick="window.AIM?.SCARCITY?.decrementOnClick('slot')" style="display:block;text-align:center;background:linear-gradient(135deg,${CFG.CYAN},#00d4ff);color:#000;font-weight:800;font-size:.82rem;padding:.55rem;border-radius:8px;text-decoration:none;margin-bottom:.3rem">⚡ Get Bundle →</a>
          <div style="text-align:center;font-size:.68rem;color:#475569">Limited time · Instant delivery</div>
        </div>`;
      document.body.appendChild(el.firstElementChild);

      // Show after 90 seconds or 60% scroll
      setTimeout(() => {
        const b = document.getElementById('aim-bundle-prompt');
        if (b) { b.style.display = 'block'; requestAnimationFrame(() => requestAnimationFrame(() => { b.style.transform = 'translateX(0)'; })); }
      }, 90000);
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 8. SUBSCRIPTION UPGRADE PROMPTS
  ══════════════════════════════════════════════════════════════ */
  const SUB_UPGRADE = {
    init() {
      const p = INTENT.profile;
      if (!p) return;

      // After 3+ visits with no conversion: show upgrade strip
      const converted = ls.get('aim_converted');
      if (p.rawVisits >= 3 && !converted) {
        setTimeout(() => this.injectUpgradeStrip(), 5000);
      }

      // On pricing page: highlight recommended plan based on intent
      if (page.includes('pricing')) {
        this.highlightPlan(p);
      }
    },

    injectUpgradeStrip() {
      if (document.getElementById('aim-upgrade-strip')) return;
      const p = INTENT.profile;
      const { final, discount, code } = DYNPRICE.compute(49);
      const strip = document.createElement('div');
      strip.id = 'aim-upgrade-strip';
      strip.style.cssText = `position:fixed;top:64px;left:0;right:0;z-index:9997;background:linear-gradient(90deg,rgba(0,255,224,.1),rgba(0,100,200,.08));border-bottom:1px solid rgba(0,255,224,.2);padding:.55rem 1.5rem;display:flex;align-items:center;justify-content:center;gap:1.5rem;flex-wrap:wrap;font-family:'Segoe UI',system-ui,sans-serif;transform:translateY(-100%);transition:transform .35s ease;`;
      strip.innerHTML = `
        <span style="font-size:.8rem;color:#e2e8f0;font-weight:500">
          👋 You've visited <strong style="color:${CFG.CYAN}">${p.rawVisits} times</strong> — upgrade to SOC Pro and stop missing critical intel.
        </span>
        <span style="font-size:.78rem;color:${CFG.CYAN};font-weight:700">$${final}/mo ${discount > 0 ? `(${Math.round(discount*100)}% off · <strong>${code}</strong>)` : ''}</span>
        <a href="${CFG.pricingUrl}" onclick="window.AIM?.trackUpgradeClick()" style="background:linear-gradient(135deg,${CFG.CYAN},#00d4ff);color:#000;font-weight:800;font-size:.75rem;padding:.35rem .85rem;border-radius:6px;text-decoration:none;white-space:nowrap">Start 7-Day Free Trial →</a>
        <button onclick="document.getElementById('aim-upgrade-strip').remove()" style="background:none;border:none;color:#475569;cursor:pointer;font-size:.85rem;margin-left:.25rem">✕</button>`;
      document.body.appendChild(strip);
      requestAnimationFrame(() => requestAnimationFrame(() => { strip.style.transform = 'translateY(0)'; }));
    },

    highlightPlan(p) {
      // Dynamic recommendation badge injection into pricing page
      setTimeout(() => {
        const tiers = $$('.tier-card, [data-tier]');
        if (!tiers.length) return;
        const recIdx = p.isEnterprise ? 2 : p.isDev ? 0 : 1;
        const targetTier = tiers[Math.min(recIdx, tiers.length - 1)];
        if (targetTier) {
          const badge = document.createElement('div');
          badge.style.cssText = `position:absolute;top:-14px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,${CFG.CYAN},#00d4ff);color:#000;font-size:.68rem;font-weight:800;padding:.25rem .85rem;border-radius:50px;white-space:nowrap;letter-spacing:.06em;`;
          badge.textContent = '✦ AI RECOMMENDED FOR YOU';
          targetTier.style.position = 'relative';
          targetTier.prepend(badge);
        }
      }, 500);
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 9. INTENT-DRIVEN HERO CTA OVERRIDE
  ══════════════════════════════════════════════════════════════ */
  const HERO_OVERRIDE = {
    apply() {
      const p   = INTENT.profile;
      const msg = INTENT.getMessage();
      if (!p || p.rawVisits < 2) return; // Only activate for return visitors

      // Find primary CTAs in hero / sticky bar area
      const heroCTAs = $$('.hero a, .sticky-cta a, [data-cx-cta]').slice(0, 2);
      heroCTAs.forEach((cta, i) => {
        if (i === 0 && msg.cta) {
          const origHref = cta.href;
          if (!origHref.includes(msg.ctaUrl.replace('/','').replace('.html',''))) {
            // Don't break navigation, just restyle
            cta.style.background = `linear-gradient(135deg,${CFG.CYAN},#00d4ff)`;
          }
        }
      });

      // Inject intent banner at top of main content
      const main = $('main, article, .post-content, .hero + section, .hero + div');
      if (main && !document.getElementById('aim-intent-banner')) {
        const banner = document.createElement('div');
        banner.id = 'aim-intent-banner';
        banner.style.cssText = `background:rgba(0,255,224,.05);border:1px solid rgba(0,255,224,.15);border-radius:12px;padding:.85rem 1.25rem;margin:1.5rem 0;display:flex;align-items:center;gap:1rem;flex-wrap:wrap;font-family:'Segoe UI',system-ui,sans-serif;`;
        banner.innerHTML = `
          <span style="font-size:.72rem;font-weight:800;color:${CFG.CYAN};background:rgba(0,255,224,.1);border:1px solid rgba(0,255,224,.2);padding:.2rem .6rem;border-radius:4px;text-transform:uppercase;letter-spacing:.06em;flex-shrink:0">${msg.badge}</span>
          <div style="flex:1;min-width:180px">
            <strong style="display:block;font-size:.88rem;color:#fff;font-weight:800">${msg.headline}</strong>
            <span style="font-size:.78rem;color:#94a3b8">${msg.sub}</span>
          </div>
          <a href="${msg.ctaUrl}" onclick="window.AIM?.TRACK?.event?.('intent_banner_click',{intent:'${p.intent}'})" style="background:linear-gradient(135deg,${CFG.CYAN},#00d4ff);color:#000;font-weight:800;font-size:.78rem;padding:.5rem 1rem;border-radius:8px;text-decoration:none;white-space:nowrap;flex-shrink:0">${msg.cta}</a>
          ${msg.urgency ? `<div style="width:100%;display:flex;align-items:center;gap:.5rem">` + (COUNTDOWN.inject(banner, '⏱ Offer expires in'), '') + `</div>` : ''}`;
        main.insertAdjacentElement('beforebegin', banner);
        if (msg.urgency) COUNTDOWN.startAll();
      }
    }
  };

  /* ══════════════════════════════════════════════════════════════
     § 10. REVENUE ANALYTICS DASHBOARD (console)
  ══════════════════════════════════════════════════════════════ */
  function printRevenueDashboard() {
    const p       = INTENT.profile;
    const events  = ls.get('cx_events') || [];
    const price   = DYNPRICE.compute(49);
    console.groupCollapsed('%c[SENTINEL APEX] AI Monetization Engine — Revenue Dashboard', 'color:#00ffe0;font-weight:bold;font-size:12px');
    console.log('Intent Profile:', p);
    console.log('Dynamic Pricing:', price);
    console.log('Scarcity — Downloads Left:', SCARCITY.getDownloadsLeft());
    console.log('Scarcity — Slots Left:', SCARCITY.getSlotsLeft());
    console.log('Total Tracked Events:', events.length);
    console.log('Conversion Events:', events.filter(e => e.name.includes('click') || e.name === 'lead_captured').length);
    console.log('Overlay Shown:', events.filter(e => e.name.includes('shown')).length, 'times');
    console.groupEnd();
  }

  /* ══════════════════════════════════════════════════════════════
     § STYLES
  ══════════════════════════════════════════════════════════════ */
  injectStyle('aim-core-css', `
    @keyframes aim-blink { 0%,100%{opacity:1} 50%{opacity:.4} }
    @keyframes aim-pulse { 0%,100%{transform:scale(1)} 50%{transform:scale(1.03)} }
    .aim-product-inject:hover { border-color: rgba(0,255,224,0.4) !important; transition: border-color .2s; }
  `);

  /* ══════════════════════════════════════════════════════════════
     § BOOT
  ══════════════════════════════════════════════════════════════ */
  function boot() {
    // 1. Classify intent
    INTENT.classify();

    // 2. Dynamic pricing
    DYNPRICE.injectPricingBadges();

    // 3. Countdown timers
    COUNTDOWN.startAll();

    // 4. Scarcity refresh
    SCARCITY.refreshAll();

    // 5. Social proof toasts
    SOCIAL_PROOF.init();

    // 6. Content → Money pipeline (post pages)
    setTimeout(() => CONTENT_PIPELINE.injectIntoPost(), 800);

    // 7. Bundle cross-sell
    BUNDLE_ENGINE.injectBundlePrompt();

    // 8. Subscription upgrade
    SUB_UPGRADE.init();

    // 9. Intent-driven hero override
    setTimeout(() => HERO_OVERRIDE.apply(), 600);

    // 10. Revenue dashboard
    setTimeout(printRevenueDashboard, 2000);
  }

  // Public API
  window.AIM = { INTENT, DYNPRICE, COUNTDOWN, SCARCITY, SOCIAL_PROOF, CONTENT_PIPELINE, BUNDLE_ENGINE, SUB_UPGRADE };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
