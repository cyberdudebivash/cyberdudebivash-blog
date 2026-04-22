/**
 * CYBERDUDEBIVASH SENTINEL APEX — Universal Monetization Engine v1.0
 * Injects: Sticky CTA Bar, Exit Intent Popup, Scroll CTAs, Social Proof Toasts,
 *          Urgency Triggers, Lead Capture, Paywall Gates, Affiliate Triggers
 * Deploy: <script src="/monetization.js" defer></script> on every page
 */
(function () {
  'use strict';

  // ─── CONFIG ────────────────────────────────────────────────────────────────
  const CFG = {
    email: 'bivash@cyberdudebivash.com',
    formsubmit: 'https://formsubmit.co/bivash@cyberdudebivash.com',
    pricingUrl: '/pricing.html',
    apiUrl: '/api.html',
    productsUrl: '/products.html',
    intelUrl: 'https://intel.cyberdudebivash.com',
    patreon: 'https://www.patreon.com/c/CYBERDUDEBIVASH',
    twitter: 'https://x.com/cdbsentinelapex',
    exitDelay: 30000,          // ms before exit intent activates
    scrollCTAInterval: 600,    // px scroll before first inline CTA
    toastInterval: 45000,      // ms between social proof toasts
    stickyShowDelay: 2000,     // ms before sticky bar appears
  };

  // ─── UTILS ─────────────────────────────────────────────────────────────────
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const ls = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
               set: (k, v) => { try { localStorage.setItem(k, v); } catch {} } };

  const CYAN = '#00ffe0';
  const BG   = 'rgba(7,9,15,0.97)';
  const BORDER = '1px solid rgba(0,255,224,0.2)';

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

  // ─── 1. STICKY TOP CTA BAR ────────────────────────────────────────────────
  function buildStickyBar() {
    if (ls.get('sticky_dismissed') === '1') return;
    injectStyle(`
      #apex-sticky { position:fixed;top:0;left:0;right:0;z-index:99999;background:linear-gradient(90deg,#001a12,#0a1628);
        border-bottom:1px solid rgba(0,255,224,0.25);padding:9px 20px;display:flex;align-items:center;
        justify-content:space-between;gap:12px;font-family:'Segoe UI',sans-serif;font-size:13px;
        transform:translateY(-100%);transition:transform .4s cubic-bezier(.4,0,.2,1);flex-wrap:wrap; }
      #apex-sticky.show { transform:translateY(0); }
      body.has-sticky-bar { padding-top:46px; }
      .apex-sticky-msg { color:#c9d1d9;display:flex;align-items:center;gap:8px;flex:1;min-width:200px; }
      .apex-sticky-msg strong { color:${CYAN}; }
      .apex-sticky-badge { background:rgba(255,68,68,0.2);border:1px solid rgba(255,68,68,0.4);
        color:#ff6b6b;border-radius:3px;padding:2px 7px;font-size:10px;font-weight:700;
        text-transform:uppercase;letter-spacing:.8px;margin-right:6px;animation:apex-pulse 2s infinite; }
      @keyframes apex-pulse { 0%,100%{opacity:1}50%{opacity:.6} }
      .apex-sticky-btns { display:flex;gap:8px;align-items:center;flex-wrap:wrap; }
      .apex-sticky-btn { border:none;border-radius:4px;padding:6px 14px;font-size:12px;font-weight:700;
        cursor:pointer;text-decoration:none;display:inline-block;transition:all .2s; }
      .apex-sticky-btn.primary { background:${CYAN};color:#000; }
      .apex-sticky-btn.primary:hover { opacity:.85; }
      .apex-sticky-btn.secondary { background:rgba(0,255,224,0.08);border:1px solid rgba(0,255,224,0.25);
        color:${CYAN};text-decoration:none; }
      .apex-sticky-btn.secondary:hover { background:rgba(0,255,224,0.15); }
      .apex-sticky-close { background:none;border:none;color:#556;cursor:pointer;font-size:18px;
        padding:0 4px;line-height:1;flex-shrink:0; }
      .apex-sticky-close:hover { color:#8892a4; }
    `);

    const bar = el('div', { id: 'apex-sticky' });
    const msgs = [
      `<span class="apex-sticky-badge">🔴 LIVE</span> <strong>CVE-2026-28401 CVSS 10.0</strong> — Ivanti Connect Secure actively exploited. Get instant alerts.`,
      `<span class="apex-sticky-badge">⚡ HOT</span> <strong>Volt Typhoon</strong> pre-positioned in US critical infrastructure. Stay ahead of nation-state threats.`,
      `<span class="apex-sticky-badge">🛡️ PRO</span> Get <strong>48-hour pre-disclosure</strong> CVE reports before public release. SOC Pro — $49/mo.`,
    ];
    const msgDiv = el('div', { class: 'apex-sticky-msg' });
    msgDiv.innerHTML = msgs[Math.floor(Math.random() * msgs.length)];

    const btns = el('div', { class: 'apex-sticky-btns' });
    const btnPrimary = el('a', { href: CFG.pricingUrl, class: 'apex-sticky-btn primary' }, 'Get SOC Pro →');
    const btnApi = el('a', { href: CFG.apiUrl, class: 'apex-sticky-btn secondary' }, 'API Access');
    const closeBtn = el('button', { class: 'apex-sticky-close', onclick: () => {
      bar.style.transform = 'translateY(-100%)';
      document.body.classList.remove('has-sticky-bar');
      ls.set('sticky_dismissed', '1');
      setTimeout(() => bar.remove(), 500);
    }}, '×');

    btns.appendChild(btnPrimary);
    btns.appendChild(btnApi);
    bar.appendChild(msgDiv);
    bar.appendChild(btns);
    bar.appendChild(closeBtn);
    document.body.insertBefore(bar, document.body.firstChild);

    setTimeout(() => {
      bar.classList.add('show');
      document.body.classList.add('has-sticky-bar');
    }, CFG.stickyShowDelay);

    // Rotate messages every 8s
    let mi = 0;
    setInterval(() => {
      mi = (mi + 1) % msgs.length;
      msgDiv.style.opacity = '0';
      setTimeout(() => { msgDiv.innerHTML = msgs[mi]; msgDiv.style.opacity = '1'; }, 300);
    }, 8000);
  }

  // ─── 2. EXIT INTENT POPUP ─────────────────────────────────────────────────
  function buildExitIntent() {
    if (ls.get('exit_shown') === '1') return;
    let activated = false;
    let timer = null;

    injectStyle(`
      #apex-exit-overlay { position:fixed;inset:0;z-index:999999;background:rgba(0,0,0,.75);
        backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;
        opacity:0;pointer-events:none;transition:opacity .3s; }
      #apex-exit-overlay.show { opacity:1;pointer-events:all; }
      #apex-exit-box { background:#0d1117;border:1px solid rgba(0,255,224,.3);border-radius:12px;
        max-width:520px;width:90%;padding:36px 36px 28px;position:relative;
        box-shadow:0 0 60px rgba(0,255,224,.1); }
      .apex-exit-close { position:absolute;top:14px;right:18px;background:none;border:none;
        color:#556;font-size:22px;cursor:pointer;line-height:1; }
      .apex-exit-close:hover { color:#8892a4; }
      .apex-exit-tag { display:inline-block;background:rgba(255,68,68,.12);border:1px solid rgba(255,68,68,.3);
        color:#ff6b6b;border-radius:3px;padding:3px 10px;font-size:10px;font-weight:700;
        text-transform:uppercase;letter-spacing:1px;margin-bottom:16px; }
      .apex-exit-h { font-size:24px;font-weight:900;color:#fff;line-height:1.25;margin-bottom:10px; }
      .apex-exit-h span { color:${CYAN}; }
      .apex-exit-sub { font-size:13px;color:#8892a4;margin-bottom:20px;line-height:1.6; }
      .apex-exit-perks { display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:22px; }
      .apex-exit-perk { background:rgba(0,255,224,.05);border:1px solid rgba(0,255,224,.1);
        border-radius:5px;padding:8px 12px;font-size:12px;color:#c9d1d9; }
      .apex-exit-perk strong { color:${CYAN};display:block;font-size:11px;margin-bottom:2px; }
      .apex-exit-form { display:flex;gap:8px;flex-wrap:wrap; }
      .apex-exit-input { flex:1;min-width:180px;background:rgba(255,255,255,.05);
        border:1px solid rgba(0,255,224,.2);color:#fff;border-radius:5px;
        padding:10px 14px;font-size:13px; }
      .apex-exit-input::placeholder { color:#556; }
      .apex-exit-submit { background:${CYAN};color:#000;border:none;border-radius:5px;
        padding:10px 20px;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap; }
      .apex-exit-submit:hover { opacity:.85; }
      .apex-exit-skip { text-align:center;margin-top:14px;font-size:11px;color:#4a5568; }
      .apex-exit-skip a { color:#556;text-decoration:underline;cursor:pointer; }
    `);

    const overlay = el('div', { id: 'apex-exit-overlay' });
    overlay.innerHTML = `
      <div id="apex-exit-box">
        <button class="apex-exit-close" id="apex-exit-close-btn">×</button>
        <div class="apex-exit-tag">🎯 Wait — Free Intelligence Access</div>
        <div class="apex-exit-h">Don't miss the next <span>critical zero-day</span> alert</div>
        <p class="apex-exit-sub">3,800+ SOC analysts and CISOs get our threat alerts before public disclosure. Join free — unsubscribe anytime.</p>
        <div class="apex-exit-perks">
          <div class="apex-exit-perk"><strong>48H Pre-Disclosure</strong>Critical CVE alerts before NVD</div>
          <div class="apex-exit-perk"><strong>IOC Feed</strong>Weekly IP/domain/hash bundles</div>
          <div class="apex-exit-perk"><strong>YARA Rules</strong>Detection rules for new malware</div>
          <div class="apex-exit-perk"><strong>SIEM Queries</strong>Ready-to-deploy detection logic</div>
        </div>
        <form class="apex-exit-form" action="${CFG.formsubmit}" method="POST">
          <input class="apex-exit-input" type="email" name="email" placeholder="your.soc@company.com" required>
          <input type="hidden" name="_subject" value="Exit Intent Newsletter Signup">
          <input type="hidden" name="_captcha" value="false">
          <button class="apex-exit-submit" type="submit">Get Free Intel →</button>
        </form>
        <div class="apex-exit-skip">No thanks — <a id="apex-exit-skip-link">I'll miss critical threats</a></div>
      </div>`;

    document.body.appendChild(overlay);

    const closeOverlay = () => {
      overlay.classList.remove('show');
      ls.set('exit_shown', '1');
    };

    overlay.querySelector('#apex-exit-close-btn').onclick = closeOverlay;
    overlay.querySelector('#apex-exit-skip-link').onclick = closeOverlay;
    overlay.onclick = (e) => { if (e.target === overlay) closeOverlay(); };

    const activate = () => {
      if (activated) return;
      activated = true;
      overlay.classList.add('show');
    };

    // Mouse leave top of page
    document.addEventListener('mouseleave', (e) => {
      if (e.clientY < 10) activate();
    });

    // Also show after time threshold (mobile)
    timer = setTimeout(activate, CFG.exitDelay);

    // Also show on back button intent (mobile)
    window.addEventListener('beforeunload', () => {
      if (!activated) activate();
    });
  }

  // ─── 3. SOCIAL PROOF TOASTS ──────────────────────────────────────────────
  function buildToasts() {
    injectStyle(`
      #apex-toast { position:fixed;bottom:24px;left:24px;z-index:99990;
        background:#0d1117;border:1px solid rgba(0,255,224,.2);border-radius:8px;
        padding:12px 16px;max-width:300px;font-family:'Segoe UI',sans-serif;font-size:12px;
        display:flex;align-items:center;gap:10px;box-shadow:0 4px 24px rgba(0,0,0,.4);
        transform:translateX(-120%);transition:transform .4s cubic-bezier(.4,0,.2,1); }
      #apex-toast.show { transform:translateX(0); }
      .apex-toast-avatar { width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#001a12,#0a3040);
        border:1px solid rgba(0,255,224,.2);display:flex;align-items:center;justify-content:center;
        font-size:14px;flex-shrink:0; }
      .apex-toast-body { flex:1; }
      .apex-toast-name { color:#c9d1d9;font-weight:700;font-size:12px; }
      .apex-toast-action { color:#8892a4;font-size:11px;margin-top:2px; }
      .apex-toast-time { color:#4a5568;font-size:10px;margin-top:1px; }
    `);

    const toasts = [
      { avatar: '🛡️', name: 'SOC Analyst, Fortune 500', action: 'Subscribed to SOC Pro', time: '2 min ago' },
      { avatar: '🔐', name: 'CISO, Healthcare Org', action: 'Downloaded Ransomware IOC Pack', time: '7 min ago' },
      { avatar: '🤖', name: 'Threat Hunter, Gov Agency', action: 'Activated API access', time: '12 min ago' },
      { avatar: '⚡', name: 'Security Engineer, EU Bank', action: 'Purchased SIEM Detection Pack', time: '18 min ago' },
      { avatar: '🎯', name: 'Red Team Lead, Tech Firm', action: 'Upgraded to Enterprise plan', time: '23 min ago' },
      { avatar: '📊', name: 'IR Analyst, MSSP', action: 'Downloaded Volt Typhoon IOC Bundle', time: '31 min ago' },
      { avatar: '🛡️', name: 'SOC Manager, Finance', action: 'Subscribed to threat alerts', time: '45 min ago' },
    ];

    const toast = el('div', { id: 'apex-toast' });
    document.body.appendChild(toast);

    let ti = 0;
    function showToast() {
      const t = toasts[ti % toasts.length];
      toast.innerHTML = `
        <div class="apex-toast-avatar">${t.avatar}</div>
        <div class="apex-toast-body">
          <div class="apex-toast-name">${t.name}</div>
          <div class="apex-toast-action">${t.action}</div>
          <div class="apex-toast-time">${t.time}</div>
        </div>`;
      toast.classList.add('show');
      setTimeout(() => { toast.classList.remove('show'); }, 5000);
      ti++;
    }

    // First toast after 8s, then every interval
    setTimeout(() => {
      showToast();
      setInterval(showToast, CFG.toastInterval);
    }, 8000);
  }

  // ─── 4. INLINE SCROLL CTAs ───────────────────────────────────────────────
  function buildScrollCTAs() {
    // Only inject in post pages
    const isPost = window.location.pathname.includes('/posts/');
    if (!isPost) return;

    injectStyle(`
      .apex-inline-cta { background:linear-gradient(135deg,rgba(0,255,224,.06),rgba(0,60,50,.08));
        border:1px solid rgba(0,255,224,.18);border-radius:8px;padding:20px 24px;
        margin:32px 0;font-family:'Segoe UI',sans-serif;display:flex;
        align-items:center;gap:16px;flex-wrap:wrap; }
      .apex-inline-cta-icon { font-size:28px;flex-shrink:0; }
      .apex-inline-cta-body { flex:1;min-width:180px; }
      .apex-inline-cta-title { font-size:14px;font-weight:700;color:#fff;margin-bottom:4px; }
      .apex-inline-cta-sub { font-size:12px;color:#8892a4;line-height:1.5; }
      .apex-inline-cta-btn { background:${CYAN};color:#000;border:none;border-radius:4px;
        padding:9px 18px;font-size:12px;font-weight:700;cursor:pointer;
        text-decoration:none;display:inline-block;white-space:nowrap;flex-shrink:0;transition:opacity .2s; }
      .apex-inline-cta-btn:hover { opacity:.85;text-decoration:none; }
      .apex-inline-cta-btn.outline { background:transparent;border:1px solid ${CYAN};color:${CYAN}; }
      .apex-inline-cta-btn.outline:hover { background:rgba(0,255,224,.1); }

      .apex-paywall-gate { position:relative;overflow:hidden;border-radius:6px; }
      .apex-paywall-blur { filter:blur(5px);pointer-events:none;user-select:none; }
      .apex-paywall-overlay { position:absolute;inset:0;background:linear-gradient(to bottom,transparent 0%,rgba(7,9,15,.92) 40%,rgba(7,9,15,1) 100%);
        display:flex;flex-direction:column;align-items:center;justify-content:flex-end;
        padding:24px;text-align:center;z-index:10; }
      .apex-paywall-lock { font-size:32px;margin-bottom:8px; }
      .apex-paywall-title { font-size:15px;font-weight:700;color:#fff;margin-bottom:6px; }
      .apex-paywall-sub { font-size:12px;color:#8892a4;margin-bottom:14px;max-width:340px;line-height:1.5; }
      .apex-paywall-btns { display:flex;gap:8px;flex-wrap:wrap;justify-content:center; }
    `);

    const ctaVariants = [
      { icon: '🛡️', title: 'Get Full IOC Pack + YARA Rules', sub: 'SOC Pro members receive complete IOC bundles, YARA signatures, and SIEM queries for every report published.', btn: 'Unlock with SOC Pro →', url: CFG.pricingUrl },
      { icon: '⚡', title: 'Get Real-Time CVE Alerts via API', sub: 'Integrate our threat intelligence directly into your SIEM. CVE scores, exploitability data, and IOCs via REST API.', btn: 'Explore API Access →', url: CFG.apiUrl },
      { icon: '📦', title: 'Download Detection Rule Pack', sub: 'Pre-built Sigma rules, Splunk SPL, KQL, and Elastic queries ready to deploy. Available in the Products Store.', btn: 'Browse Products →', url: CFG.productsUrl },
      { icon: '🎯', title: '48H Pre-Disclosure Intelligence', sub: 'Get critical CVE reports before NVD publication. 3,800+ security pros trust SENTINEL APEX for early warning.', btn: 'Subscribe SOC Pro →', url: CFG.pricingUrl },
    ];

    const articleBody = $('article') || $('.article-wrap') || $('main') || $('body');
    if (!articleBody) return;

    const paras = $$('h2,p,pre', articleBody);
    const insertAt = [Math.floor(paras.length * 0.35), Math.floor(paras.length * 0.65)];

    insertAt.forEach((idx, i) => {
      const cta = ctaVariants[i % ctaVariants.length];
      const para = paras[Math.min(idx, paras.length - 1)];
      if (!para || para.dataset.ctaInjected) return;
      para.dataset.ctaInjected = '1';

      const ctaEl = document.createElement('div');
      ctaEl.className = 'apex-inline-cta';
      ctaEl.innerHTML = `
        <div class="apex-inline-cta-icon">${cta.icon}</div>
        <div class="apex-inline-cta-body">
          <div class="apex-inline-cta-title">${cta.title}</div>
          <div class="apex-inline-cta-sub">${cta.sub}</div>
        </div>
        <a href="${cta.url}" class="apex-inline-cta-btn">${cta.btn}</a>`;
      para.after(ctaEl);
    });
  }

  // ─── 5. PAYWALL GATES (IOC / YARA sections) ──────────────────────────────
  function buildPaywallGates() {
    const isPost = window.location.pathname.includes('/posts/');
    if (!isPost) return;
    if (ls.get('soc_pro') === '1') return; // Paying users skip

    // Gate the last pre/code block (IOC tables)
    const pres = $$('pre');
    if (pres.length < 2) return;

    // Gate the last 2 code blocks
    const toGate = pres.slice(-2);
    toGate.forEach(pre => {
      const wrapper = document.createElement('div');
      wrapper.className = 'apex-paywall-gate';
      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);
      pre.classList.add('apex-paywall-blur');

      const overlay = document.createElement('div');
      overlay.className = 'apex-paywall-overlay';
      overlay.innerHTML = `
        <div class="apex-paywall-lock">🔒</div>
        <div class="apex-paywall-title">Full IOC Data — SOC Pro Members Only</div>
        <div class="apex-paywall-sub">Complete indicator list, YARA signatures, and SIEM queries available to SOC Pro subscribers ($49/mo) and Enterprise clients.</div>
        <div class="apex-paywall-btns">
          <a href="${CFG.pricingUrl}" class="apex-inline-cta-btn">Unlock with SOC Pro →</a>
          <a href="mailto:${CFG.email}?subject=Free%20Trial%20Request" class="apex-inline-cta-btn outline">Request Free Trial</a>
        </div>`;
      wrapper.appendChild(overlay);
    });
  }

  // ─── 6. URGENCY COUNTER (posts) ──────────────────────────────────────────
  function buildUrgencyCounter() {
    const isPost = window.location.pathname.includes('/posts/');
    if (!isPost) return;

    injectStyle(`
      #apex-urgency { background:rgba(255,68,68,.07);border:1px solid rgba(255,68,68,.2);
        border-radius:6px;padding:10px 16px;margin:20px 0;font-family:'Segoe UI',sans-serif;
        font-size:12px;color:#c9d1d9;display:flex;align-items:center;gap:12px; }
      #apex-urgency .dot { width:8px;height:8px;border-radius:50%;background:#ff4444;
        flex-shrink:0;animation:apex-pulse 1.5s infinite; }
      #apex-urgency strong { color:#ff6b6b; }
    `);

    // Find first h2 after article start
    const h2s = $$('h2');
    if (!h2s.length) return;

    // Random active viewers between 24-89
    const viewers = Math.floor(Math.random() * 65) + 24;
    const urgency = document.createElement('div');
    urgency.id = 'apex-urgency';
    urgency.innerHTML = `
      <div class="dot"></div>
      <span><strong>${viewers} security professionals</strong> are viewing this report right now &mdash;
      <strong>CVE is actively exploited</strong> &mdash;
      <a href="${CFG.pricingUrl}" style="color:#00ffe0;text-decoration:none;font-weight:700;">Get instant alerts →</a></span>`;

    h2s[0].before(urgency);
  }

  // ─── 7. AFFILIATE CTAs ────────────────────────────────────────────────────
  function buildAffiliateCTAs() {
    const isPost = window.location.pathname.includes('/posts/');
    if (!isPost) return;

    injectStyle(`
      .apex-affiliate-bar { background:rgba(0,255,224,.03);border:1px solid rgba(0,255,224,.1);
        border-radius:6px;padding:14px 18px;margin:24px 0;font-family:'Segoe UI',sans-serif; }
      .apex-affiliate-bar h4 { font-size:11px;font-weight:700;color:#8892a4;text-transform:uppercase;
        letter-spacing:1.5px;margin-bottom:10px; }
      .apex-affiliate-links { display:flex;flex-wrap:wrap;gap:8px; }
      .apex-affiliate-link { background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
        color:#c9d1d9;border-radius:4px;padding:5px 12px;font-size:11px;font-weight:600;
        text-decoration:none;transition:all .2s; }
      .apex-affiliate-link:hover { border-color:rgba(0,255,224,.3);color:${CYAN};text-decoration:none; }
    `);

    const affiliates = [
      { name: '🛡️ CrowdStrike Falcon', url: 'https://www.crowdstrike.com', tag: 'EDR' },
      { name: '🔍 Tenable Nessus', url: 'https://www.tenable.com', tag: 'Scanner' },
      { name: '📊 Splunk SIEM', url: 'https://www.splunk.com', tag: 'SIEM' },
      { name: '🤖 SentinelOne', url: 'https://www.sentinelone.com', tag: 'AI EDR' },
      { name: '🌐 Cloudflare Zero Trust', url: 'https://www.cloudflare.com/zero-trust', tag: 'ZT' },
      { name: '🔐 1Password Business', url: 'https://1password.com/business', tag: 'IAM' },
    ];

    const ctaBlocks = $$('.cta-block');
    if (ctaBlocks.length) {
      const bar = document.createElement('div');
      bar.className = 'apex-affiliate-bar';
      bar.innerHTML = `<h4>🤝 Recommended Security Tools</h4>
        <div class="apex-affiliate-links">${affiliates.map(a =>
          `<a href="${a.url}" target="_blank" rel="noopener nofollow" class="apex-affiliate-link" title="${a.tag}">${a.name}</a>`
        ).join('')}</div>`;
      ctaBlocks[0].after(bar);
    }
  }

  // ─── 8. SIDEBAR LEAD CAPTURE (index + intelligence pages) ────────────────
  function buildSidebarCapture() {
    const path = window.location.pathname;
    const isHome = path === '/' || path.endsWith('index.html');
    const isIntel = path.includes('intelligence');
    if (!isHome && !isIntel) return;

    // Find sidebar
    const sidebar = $('aside') || $('.sidebar');
    if (!sidebar) return;

    injectStyle(`
      .apex-lead-widget { background:linear-gradient(135deg,rgba(0,255,224,.05),rgba(0,40,30,.08));
        border:1px solid rgba(0,255,224,.18);border-radius:8px;padding:20px;
        font-family:'Segoe UI',sans-serif;margin-bottom:20px; }
      .apex-lead-widget h3 { font-size:13px;font-weight:700;color:${CYAN};text-transform:uppercase;
        letter-spacing:1.2px;margin-bottom:8px; }
      .apex-lead-widget p { font-size:12px;color:#8892a4;line-height:1.5;margin-bottom:12px; }
      .apex-lead-input { width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(0,255,224,.2);
        color:#fff;border-radius:4px;padding:9px 12px;font-size:12px;box-sizing:border-box;margin-bottom:8px; }
      .apex-lead-input::placeholder { color:#4a5568; }
      .apex-lead-submit { width:100%;background:${CYAN};color:#000;border:none;border-radius:4px;
        padding:9px;font-size:12px;font-weight:700;cursor:pointer;transition:opacity .2s; }
      .apex-lead-submit:hover { opacity:.85; }
      .apex-lead-perks { list-style:none;padding:0;margin:10px 0 0; }
      .apex-lead-perks li { font-size:11px;color:#8892a4;padding:3px 0;display:flex;gap:6px; }
      .apex-lead-perks li::before { content:'✓';color:${CYAN};font-weight:700;flex-shrink:0; }
    `);

    const widget = document.createElement('div');
    widget.className = 'apex-lead-widget';
    widget.innerHTML = `
      <h3>📧 Free Intel Alerts</h3>
      <p>Get zero-day alerts, CVE reports, and IOC bundles before public disclosure.</p>
      <form action="${CFG.formsubmit}" method="POST">
        <input class="apex-lead-input" type="email" name="email" placeholder="soc@yourcompany.com" required>
        <input type="hidden" name="_subject" value="Sidebar Newsletter Signup">
        <input type="hidden" name="_captcha" value="false">
        <button class="apex-lead-submit" type="submit">Get Free Alerts →</button>
      </form>
      <ul class="apex-lead-perks">
        <li>48H pre-disclosure CVE reports</li>
        <li>Weekly IOC + YARA bundles</li>
        <li>Ransomware group tracker</li>
        <li>SIEM detection queries</li>
      </ul>`;

    sidebar.insertBefore(widget, sidebar.firstChild);
  }

  // ─── 9. READING TIME + SHARE BAR ─────────────────────────────────────────
  function buildShareBar() {
    const isPost = window.location.pathname.includes('/posts/');
    if (!isPost) return;

    injectStyle(`
      .apex-share-bar { display:flex;align-items:center;gap:10px;flex-wrap:wrap;
        padding:14px 0;border-top:1px solid rgba(30,36,50,.8);border-bottom:1px solid rgba(30,36,50,.8);
        margin:20px 0;font-family:'Segoe UI',sans-serif;font-size:12px; }
      .apex-share-label { color:#8892a4;font-weight:600; }
      .apex-share-btn { background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
        color:#c9d1d9;border-radius:4px;padding:5px 12px;font-size:11px;font-weight:600;
        cursor:pointer;text-decoration:none;transition:all .2s; }
      .apex-share-btn:hover { border-color:rgba(0,255,224,.3);color:${CYAN};text-decoration:none; }
      .apex-share-btn.x { border-color:rgba(255,255,255,.15); }
      .apex-share-btn.li { border-color:rgba(0,119,181,.3); }
      .apex-read-time { margin-left:auto;color:#8892a4; }
    `);

    const url = encodeURIComponent(window.location.href);
    const title = encodeURIComponent(document.title);
    const wordCount = document.body.innerText.split(/\s+/).length;
    const readTime = Math.ceil(wordCount / 220);

    const bar = document.createElement('div');
    bar.className = 'apex-share-bar';
    bar.innerHTML = `
      <span class="apex-share-label">Share:</span>
      <a class="apex-share-btn x" href="https://x.com/intent/tweet?url=${url}&text=${title}&via=cdbsentinelapex" target="_blank" rel="noopener">𝕏 Tweet</a>
      <a class="apex-share-btn li" href="https://www.linkedin.com/sharing/share-offsite/?url=${url}" target="_blank" rel="noopener">in LinkedIn</a>
      <a class="apex-share-btn" href="mailto:?subject=${title}&body=Security%20Alert%3A%20${url}">📧 Email</a>
      <span class="apex-read-time">⏱ ${readTime} min read</span>`;

    const h1 = $('h1') || $$('.post-meta')[0];
    if (h1) h1.after(bar);
  }

  // ─── 10. BOTTOM STICKY UPGRADE BAR (posts only) ──────────────────────────
  function buildBottomBar() {
    const isPost = window.location.pathname.includes('/posts/');
    if (!isPost) return;
    if (ls.get('bottom_dismissed') === '1') return;

    injectStyle(`
      #apex-bottom-bar { position:fixed;bottom:0;left:0;right:0;z-index:99998;
        background:linear-gradient(90deg,#001a12,#0a1628);
        border-top:1px solid rgba(0,255,224,.25);padding:12px 24px;
        display:flex;align-items:center;justify-content:space-between;gap:12px;
        font-family:'Segoe UI',sans-serif;font-size:13px;flex-wrap:wrap;
        transform:translateY(100%);transition:transform .4s cubic-bezier(.4,0,.2,1); }
      #apex-bottom-bar.show { transform:translateY(0); }
      .apex-bottom-msg { color:#8892a4;flex:1;min-width:200px;font-size:12px; }
      .apex-bottom-msg strong { color:${CYAN}; }
      .apex-bottom-btns { display:flex;gap:8px;align-items:center; }
      .apex-bottom-btn { border:none;border-radius:4px;padding:7px 16px;font-size:12px;
        font-weight:700;cursor:pointer;text-decoration:none;display:inline-block;transition:all .2s; }
      .apex-bottom-btn.primary { background:${CYAN};color:#000; }
      .apex-bottom-btn.secondary { background:rgba(0,255,224,.08);border:1px solid rgba(0,255,224,.2);color:${CYAN}; }
      .apex-bottom-close { background:none;border:none;color:#4a5568;font-size:18px;cursor:pointer; }
    `);

    const bar = el('div', { id: 'apex-bottom-bar' });
    bar.innerHTML = `
      <div class="apex-bottom-msg">
        <strong>🔒 Full IOC data, YARA rules &amp; SIEM queries</strong> locked for SOC Pro members.
        Unlock everything for <strong>$49/month</strong>.
      </div>
      <div class="apex-bottom-btns">
        <a href="${CFG.pricingUrl}" class="apex-bottom-btn primary">Unlock SOC Pro →</a>
        <a href="${CFG.apiUrl}" class="apex-bottom-btn secondary">API Access</a>
        <button class="apex-bottom-close" id="apex-bb-close">×</button>
      </div>`;
    document.body.appendChild(bar);

    // Show after 60% scroll
    let shown = false;
    window.addEventListener('scroll', () => {
      const pct = window.scrollY / (document.body.scrollHeight - window.innerHeight);
      if (pct > 0.6 && !shown) { shown = true; bar.classList.add('show'); }
    }, { passive: true });

    bar.querySelector('#apex-bb-close').onclick = () => {
      bar.style.transform = 'translateY(100%)';
      ls.set('bottom_dismissed', '1');
    };
  }

  // ─── INIT ─────────────────────────────────────────────────────────────────
  function init() {
    try { buildStickyBar(); } catch(e) {}
    try { buildExitIntent(); } catch(e) {}
    try { buildToasts(); } catch(e) {}
    try { buildScrollCTAs(); } catch(e) {}
    try { buildPaywallGates(); } catch(e) {}
    try { buildUrgencyCounter(); } catch(e) {}
    try { buildAffiliateCTAs(); } catch(e) {}
    try { buildSidebarCapture(); } catch(e) {}
    try { buildShareBar(); } catch(e) {}
    try { buildBottomBar(); } catch(e) {}
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
