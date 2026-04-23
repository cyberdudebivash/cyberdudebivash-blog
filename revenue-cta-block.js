/**
 * CYBERDUDEBIVASH SENTINEL APEX — Revenue CTA Block Engine v2.0
 * ═══════════════════════════════════════════════════════════════
 * Injects a full-width conversion section at the bottom of every post.
 * Personalizes CTA copy based on page context (CVE / ransomware / APT / AI).
 * v2.0 upgrades:
 *   - Intent-based card highlighting (CX4 INTENT integration)
 *   - Urgency badges on high-intent sessions (live countdown, scarcity)
 *   - Trust amplification (4,800+ subscribers, 1,200+ CVEs, live dot)
 *   - Return-visitor social proof (personalized copy on v2+ sessions)
 *   - Anchor pricing + savings display on all cards
 *   - Intent upgrade listener → re-highlights cards in real-time
 *
 * Deploy: <script src="/revenue-cta-block.js" defer></script>
 */
(function () {
  'use strict';

  var BASE = 'https://blog.cyberdudebivash.in';
  var CYAN = '#00ffe0';
  var RED  = '#ff4444';

  var LINKS = {
    pricing:    '/pricing.html',
    products:   '/products.html',
    api:        '/api.html',
    enterprise: '/enterprise.html',
    leads:      '/leads.html',
    rss:        '/rss.xml'
  };

  /* ── SESSION HELPERS ──────────────────────────────────────────────── */
  function getVisitCount() {
    try {
      return parseInt(localStorage.getItem('cx4_visits') || '0', 10);
    } catch (e) { return 0; }
  }

  function getIntent() {
    // Use CX4 INTENT engine if available, fallback to stored value
    if (window.CX4 && window.CX4.INTENT && window.CX4.INTENT.level) {
      return window.CX4.INTENT.level;
    }
    try {
      return localStorage.getItem('cx4_intent_level') || 'low';
    } catch (e) { return 'low'; }
  }

  /* ── PAGE CONTEXT DETECTION ───────────────────────────────────────── */
  function detectContext() {
    var p = window.location.pathname.toLowerCase();
    var t = (document.title || '').toLowerCase();
    if (p.includes('cve-') || t.includes('cve-') || t.includes('zero-day') || t.includes('rce')) return 'cve';
    if (p.includes('ransomware') || t.includes('ransomware') || t.includes('lockbit') || t.includes('akira')) return 'ransomware';
    if (p.includes('apt') || p.includes('typhoon') || t.includes('typhoon') || t.includes('nation-state')) return 'apt';
    if (p.includes('ai-') || p.includes('llm') || t.includes('prompt injection') || t.includes('ai security')) return 'ai';
    return 'general';
  }

  /* ── CONTEXT COPY MAP ─────────────────────────────────────────────── */
  var CONTEXT_COPY = {
    cve: {
      headline:       'Get Full Detection Coverage for This CVE',
      sub:            'SOC Pro members receive complete IOC tables, SIEM detection rules (Splunk/Elastic/KQL), YARA signatures, and automated STIX feeds — 48 hours before NVD publication.',
      products_label: '\uD83D\uDCE6 Get Detection Pack',
      api_label:      '\uD83D\uDD0C Automate via API',
      badge:          '\uD83D\uDD34\u00A0ACTIVE CVE THREAT INTELLIGENCE'
    },
    ransomware: {
      headline:       'Stay Ahead of the Next Ransomware Campaign',
      sub:            'Weekly ransomware group tracking: active campaigns, IOC bundles (IP/domain/hash), TTPs, and Sigma rules mapped to MITRE ATT&CK — delivered to your SIEM and inbox.',
      products_label: '\uD83D\uDEE1\uFE0F Get Ransomware IOC Pack',
      api_label:      '\uD83D\uDD0C Integrate Threat Feeds',
      badge:          '\uD83D\uDD34\u00A0LIVE RANSOMWARE TRACKING'
    },
    apt: {
      headline:       'Nation-State Threat Intelligence — Enterprise Grade',
      sub:            'Deep-dive APT tracking: actor TTPs, infrastructure maps, malware signatures, and pre-disclosure campaign alerts. Trusted by SOC teams defending critical infrastructure.',
      products_label: '\uD83C\uDFAF Get APT Intel Pack',
      api_label:      '\uD83D\uDD0C API + STIX Feed Access',
      badge:          '\uD83D\uDD34\u00A0CLASSIFIED APT INTELLIGENCE'
    },
    ai: {
      headline:       'Secure Your AI Stack Against Emerging Attack Vectors',
      sub:            'LLM security, prompt injection defenses, and AI governance intelligence — research-grade analysis with actionable detection rules for enterprise AI deployments.',
      products_label: '\uD83E\uDD16 Get AI Security Pack',
      api_label:      '\uD83D\uDD0C Access AI Risk API',
      badge:          '\u26A1\u00A0AI SECURITY INTELLIGENCE'
    },
    general: {
      headline:       'Upgrade Your Threat Intelligence — SOC Pro',
      sub:            '48H pre-disclosure CVE reports, full IOC bundles, SIEM detection rules, YARA signatures, and ransomware tracking. Used by 4,800+ security professionals globally.',
      products_label: '\uD83D\uDCE6 Browse Products',
      api_label:      '\uD83D\uDD0C API Access',
      badge:          '\u26A1\u00A0CYBERDUDEBIVASH SENTINEL APEX'
    }
  };

  /* ── INTENT CONFIG ────────────────────────────────────────────────── */
  // Which card index to highlight for each intent level (0-indexed):
  // 0=SOC Pro, 1=Detection Packs, 2=API, 3=Enterprise
  var INTENT_HIGHLIGHT = {
    high:   0, // SOC Pro — push premium conversion
    medium: 1, // Detection Packs — lower barrier entry
    low:    2  // API / Free tier — no friction
  };

  var INTENT_URGENCY = {
    high: {
      show:    true,
      badge:   '\uD83D\uDD25 HIGH DEMAND — 23 spots left this month',
      timer:   true,
      timerLabel: 'Trial offer expires in:'
    },
    medium: {
      show:    true,
      badge:   '\u26A1 LIMITED — Offer valid this week only',
      timer:   false,
      timerLabel: ''
    },
    low: {
      show:    false,
      badge:   '',
      timer:   false,
      timerLabel: ''
    }
  };

  /* ── STYLES ───────────────────────────────────────────────────────── */
  function injectStyles() {
    if (document.getElementById('rcb-styles')) return;
    var s = document.createElement('style');
    s.id = 'rcb-styles';
    s.textContent =
      /* section wrapper */
      '.rcb-section{' +
        'background:linear-gradient(135deg,#07090f,#0a1628 50%,#07090f);' +
        'border-top:1px solid rgba(0,255,224,0.15);' +
        'border-bottom:1px solid rgba(0,255,224,0.08);' +
        'padding:3rem 1.5rem;margin-top:3rem;' +
        'font-family:"Segoe UI",system-ui,sans-serif;' +
      '}' +
      '.rcb-inner{max-width:900px;margin:0 auto}' +

      /* urgency strip */
      '.rcb-urgency{' +
        'background:linear-gradient(90deg,rgba(255,68,68,0.1),rgba(255,68,68,0.05));' +
        'border:1px solid rgba(255,68,68,0.3);' +
        'border-radius:8px;padding:.6rem 1rem;margin-bottom:1.25rem;' +
        'display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;' +
      '}' +
      '.rcb-urgency-text{font-size:.8rem;font-weight:700;color:#ff6b6b;flex:1}' +
      '.rcb-urgency-timer{font-size:.8rem;font-weight:800;color:#fff;' +
        'background:rgba(255,68,68,0.2);border:1px solid rgba(255,68,68,0.4);' +
        'border-radius:6px;padding:.2rem .6rem;white-space:nowrap;' +
      '}' +
      '.rcb-countdown{font-size:.85rem;font-weight:900;color:' + RED + ';' +
        'font-variant-numeric:tabular-nums;letter-spacing:.05em;' +
      '}' +

      /* badge */
      '.rcb-badge{display:inline-flex;align-items:center;gap:.5rem;' +
        'background:rgba(0,255,224,0.08);border:1px solid rgba(0,255,224,0.2);' +
        'border-radius:50px;padding:.3rem 1rem;font-size:.7rem;font-weight:800;' +
        'color:' + CYAN + ';text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem;' +
      '}' +
      '.rcb-badge .rcb-live-dot{' +
        'width:6px;height:6px;border-radius:50%;background:' + CYAN + ';' +
        'animation:rcb-pulse 1.4s ease-in-out infinite;' +
      '}' +
      '@keyframes rcb-pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.85)}}' +

      /* headline */
      '.rcb-headline{font-size:clamp(1.4rem,3vw,2rem);font-weight:900;color:#fff;' +
        'line-height:1.2;margin-bottom:.75rem;' +
      '}' +
      '.rcb-sub{font-size:.95rem;color:#94a3b8;line-height:1.7;margin-bottom:2rem;max-width:680px}' +

      /* product grid */
      '.rcb-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem;margin-bottom:2rem}' +
      '.rcb-card{' +
        'background:rgba(0,255,224,0.04);border:1px solid rgba(0,255,224,0.12);' +
        'border-radius:12px;padding:1.25rem;transition:border-color .25s,background .25s,transform .2s;' +
        'position:relative;' +
      '}' +
      '.rcb-card:hover{' +
        'border-color:rgba(0,255,224,0.28);background:rgba(0,255,224,0.07);transform:translateY(-2px);' +
      '}' +
      /* HIGHLIGHTED card (intent-driven) */
      '.rcb-card.rcb-featured{' +
        'border-color:rgba(0,255,224,0.5);' +
        'background:rgba(0,255,224,0.09);' +
        'box-shadow:0 0 24px rgba(0,255,224,0.1),inset 0 0 0 1px rgba(0,255,224,0.2);' +
      '}' +
      '.rcb-card.rcb-featured:hover{border-color:' + CYAN + '}' +

      /* featured badge on card */
      '.rcb-card-featured-badge{' +
        'position:absolute;top:-1px;left:50%;transform:translateX(-50%);' +
        'background:linear-gradient(90deg,' + CYAN + ',#00d4ff);' +
        'color:#000;font-size:.65rem;font-weight:900;' +
        'padding:.2rem .8rem;border-radius:0 0 8px 8px;' +
        'text-transform:uppercase;letter-spacing:.08em;white-space:nowrap;' +
      '}' +

      /* urgency badge on card (high-intent only) */
      '.rcb-card-urgency{' +
        'display:inline-block;background:rgba(255,68,68,0.12);' +
        'border:1px solid rgba(255,68,68,0.3);' +
        'color:#ff6b6b;font-size:.65rem;font-weight:800;' +
        'padding:.15rem .55rem;border-radius:4px;margin-bottom:.6rem;' +
      '}' +

      '.rcb-card-icon{font-size:1.8rem;margin-bottom:.6rem}' +
      '.rcb-card-title{font-size:.9rem;font-weight:800;color:#fff;margin-bottom:.3rem}' +
      '.rcb-card-sub{font-size:.78rem;color:#64748b;line-height:1.5;margin-bottom:.85rem}' +

      /* price row */
      '.rcb-card-price{font-size:1.1rem;font-weight:900;color:' + CYAN + ';margin-bottom:.75rem;line-height:1}' +
      '.rcb-card-price .rcb-orig{font-size:.8rem;color:#475569;font-weight:400;text-decoration:line-through;margin-right:.3rem}' +
      '.rcb-card-price .rcb-save{font-size:.7rem;color:#4ade80;font-weight:700;margin-left:.3rem}' +
      '.rcb-card-price .rcb-unit{font-size:.75rem;color:#64748b;font-weight:400}' +

      '.rcb-card-btn{' +
        'display:block;width:100%;text-align:center;' +
        'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
        'color:#000;font-weight:800;font-size:.8rem;' +
        'padding:.55rem 1rem;border-radius:8px;text-decoration:none;' +
        'transition:opacity .2s;border:none;cursor:pointer;' +
      '}' +
      '.rcb-card-btn:hover{opacity:.85;text-decoration:none}' +
      '.rcb-card-btn.outline{' +
        'background:transparent;border:1px solid rgba(0,255,224,0.3);color:' + CYAN + ';' +
      '}' +
      '.rcb-card-btn.outline:hover{background:rgba(0,255,224,0.08)}' +

      '.rcb-divider{border:none;border-top:1px solid rgba(255,255,255,0.06);margin:2rem 0}' +

      /* trust bar */
      '.rcb-trust{display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap}' +
      '.rcb-trust-stat{display:flex;align-items:center;gap:.5rem;font-size:.82rem;color:#64748b}' +
      '.rcb-trust-stat strong{color:#94a3b8;font-weight:700}' +

      /* newsletter */
      '.rcb-newsletter{' +
        'background:rgba(0,255,224,0.04);border:1px solid rgba(0,255,224,0.12);' +
        'border-radius:12px;padding:1.5rem;display:flex;align-items:center;gap:1.5rem;' +
        'flex-wrap:wrap;margin-top:2rem;' +
      '}' +
      '.rcb-nl-body{flex:1;min-width:200px}' +
      '.rcb-nl-body strong{display:block;font-size:.95rem;font-weight:800;color:#fff;margin-bottom:.25rem}' +
      '.rcb-nl-body span{font-size:.8rem;color:#64748b}' +
      '.rcb-nl-form{display:flex;gap:.5rem;flex-wrap:wrap;min-width:280px}' +
      '.rcb-nl-input{' +
        'flex:1;min-width:180px;background:rgba(255,255,255,0.05);' +
        'border:1px solid rgba(0,255,224,0.2);color:#fff;border-radius:8px;' +
        'padding:.6rem .9rem;font-size:.82rem;' +
      '}' +
      '.rcb-nl-input::placeholder{color:#475569}' +
      '.rcb-nl-btn{' +
        'background:linear-gradient(135deg,' + CYAN + ',#00d4ff);' +
        'color:#000;border:none;border-radius:8px;' +
        'padding:.6rem 1.1rem;font-size:.82rem;font-weight:800;cursor:pointer;white-space:nowrap;' +
      '}' +
      '.rcb-nl-btn:hover{opacity:.85}' +

      /* related links */
      '.rcb-related{margin-top:2rem}' +
      '.rcb-related-title{font-size:.75rem;font-weight:800;color:#475569;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.75rem}' +
      '.rcb-related-links{display:flex;flex-wrap:wrap;gap:.5rem}' +
      '.rcb-related-link{' +
        'background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);' +
        'color:#94a3b8;border-radius:6px;padding:.35rem .75rem;font-size:.78rem;' +
        'text-decoration:none;transition:all .2s;' +
      '}' +
      '.rcb-related-link:hover{border-color:rgba(0,255,224,0.25);color:' + CYAN + ';text-decoration:none}';

    document.head.appendChild(s);
  }

  /* ── URGENCY COUNTDOWN ─────────────────────────────────────────────── */
  function startCountdown() {
    // Random session timer 18-29 min so every visitor sees unique scarcity
    var timerEl = document.getElementById('rcb-countdown');
    if (!timerEl) return;
    var storedEnd = null;
    try { storedEnd = parseInt(localStorage.getItem('rcb_urgency_end') || '0', 10); } catch (e) {}
    var now = Date.now();
    if (!storedEnd || storedEnd < now) {
      var mins = 18 + Math.floor(Math.random() * 12);
      storedEnd = now + mins * 60 * 1000;
      try { localStorage.setItem('rcb_urgency_end', String(storedEnd)); } catch (e) {}
    }
    function tick() {
      var remaining = Math.max(0, storedEnd - Date.now());
      var m = Math.floor(remaining / 60000);
      var s = Math.floor((remaining % 60000) / 1000);
      timerEl.textContent = (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
      if (remaining > 0) setTimeout(tick, 1000);
    }
    tick();
  }

  /* ── APPLY INTENT HIGHLIGHT ───────────────────────────────────────── */
  function applyIntentHighlight(intentLevel) {
    var cards = document.querySelectorAll('#rcb-revenue-block .rcb-card');
    if (!cards.length) return;
    var idx = INTENT_HIGHLIGHT[intentLevel] !== undefined ? INTENT_HIGHLIGHT[intentLevel] : 0;
    // Remove existing highlight
    for (var i = 0; i < cards.length; i++) {
      cards[i].classList.remove('rcb-featured');
      var existing = cards[i].querySelector('.rcb-card-featured-badge');
      if (existing) existing.parentNode.removeChild(existing);
      var existingUrgency = cards[i].querySelector('.rcb-card-urgency');
      if (existingUrgency) existingUrgency.parentNode.removeChild(existingUrgency);
    }
    // Apply to correct card
    var featured = cards[idx];
    if (!featured) return;
    featured.classList.add('rcb-featured');

    var featBadge = document.createElement('div');
    featBadge.className = 'rcb-card-featured-badge';
    featBadge.textContent = intentLevel === 'high' ? '\u2605 RECOMMENDED FOR YOU' : 'MOST POPULAR';
    featured.insertBefore(featBadge, featured.firstChild);

    // Urgency badge on featured card for high/medium intent
    var urg = INTENT_URGENCY[intentLevel];
    if (urg && urg.show) {
      var urgBadge = document.createElement('div');
      urgBadge.className = 'rcb-card-urgency';
      urgBadge.textContent = urg.badge;
      // Insert after icon
      var icon = featured.querySelector('.rcb-card-icon');
      if (icon && icon.nextSibling) {
        featured.insertBefore(urgBadge, icon.nextSibling);
      } else {
        featured.appendChild(urgBadge);
      }
    }
  }

  /* ── BUILD URGENCY STRIP ──────────────────────────────────────────── */
  function buildUrgencyStrip(intentLevel) {
    var urg = INTENT_URGENCY[intentLevel];
    if (!urg || !urg.show) return '';
    var timerHtml = '';
    if (urg.timer) {
      timerHtml =
        '<div class="rcb-urgency-timer">' +
          urg.timerLabel + ' <span class="rcb-countdown" id="rcb-countdown">--:--</span>' +
        '</div>';
    }
    return (
      '<div class="rcb-urgency">' +
        '<div class="rcb-urgency-text">' + urg.badge + '</div>' +
        timerHtml +
      '</div>'
    );
  }

  /* ── BUILD RETURN VISITOR HEADLINE ───────────────────────────────── */
  function buildHeadline(copy, visitCount) {
    if (visitCount >= 3) {
      return 'Welcome Back — Your SOC Pro Trial is Still Available';
    }
    if (visitCount === 2) {
      return copy.headline + ' — Exclusive Returning Reader Offer';
    }
    return copy.headline;
  }

  /* ── BUILD BLOCK HTML ─────────────────────────────────────────────── */
  function buildBlock() {
    if (!window.location.pathname.includes('/posts/')) return;
    if (document.getElementById('rcb-revenue-block')) return;

    var ctx         = detectContext();
    var copy        = CONTEXT_COPY[ctx] || CONTEXT_COPY.general;
    var intentLevel = getIntent();
    var visitCount  = getVisitCount();
    var urgencyHtml = buildUrgencyStrip(intentLevel);
    var headline    = buildHeadline(copy, visitCount);

    var section = document.createElement('section');
    section.id = 'rcb-revenue-block';
    section.className = 'rcb-section';
    section.setAttribute('aria-label', 'Upgrade your threat intelligence');

    section.innerHTML =
      '<div class="rcb-inner">' +

        urgencyHtml +

        // Header
        '<div class="rcb-badge">' +
          '<span class="rcb-live-dot"></span>' +
          copy.badge +
        '</div>' +
        '<h2 class="rcb-headline">' + headline + '</h2>' +
        '<p class="rcb-sub">' + copy.sub + '</p>' +

        // 4-card product grid
        '<div class="rcb-grid" id="rcb-card-grid">' +

          // Card 0: SOC Pro
          '<div class="rcb-card" data-rcb-card="0">' +
            '<div class="rcb-card-icon">\u26A1</div>' +
            '<div class="rcb-card-title">SOC Pro Membership</div>' +
            '<div class="rcb-card-sub">' +
              'Full IOC packs, SIEM rules, 48H pre-disclosure CVE reports, and ransomware tracker. ' +
              'Reduce SOC triage time by 60%.' +
            '</div>' +
            '<div class="rcb-card-price" data-cx-price="49" data-cx-orig="129">' +
              '<span class="rcb-orig">$129</span>$49' +
              '<span class="rcb-unit">/mo</span>' +
              '<span class="rcb-save">Save 62%</span>' +
            '</div>' +
            '<a href="' + LINKS.pricing + '" class="rcb-card-btn" data-track="rcb_soc_pro_click">' +
              'Start 7-Day Free Trial \u2192' +
            '</a>' +
          '</div>' +

          // Card 1: Detection Packs
          '<div class="rcb-card" data-rcb-card="1">' +
            '<div class="rcb-card-icon">\uD83D\uDCE6</div>' +
            '<div class="rcb-card-title">Detection Packs</div>' +
            '<div class="rcb-card-sub">' +
              'Sigma + YARA rules, IOC bundles, playbooks, and SOC automation scripts. ' +
              'Deploy-ready in minutes. One-time purchase.' +
            '</div>' +
            '<div class="rcb-card-price">' +
              'From <span style="font-size:1rem;font-weight:800;color:' + CYAN + '">$9</span>' +
            '</div>' +
            '<a href="' + LINKS.products + '" class="rcb-card-btn" data-track="rcb_products_click">' +
              copy.products_label + ' \u2192' +
            '</a>' +
          '</div>' +

          // Card 2: API
          '<div class="rcb-card" data-rcb-card="2">' +
            '<div class="rcb-card-icon">\uD83D\uDD0C</div>' +
            '<div class="rcb-card-title">Intelligence API</div>' +
            '<div class="rcb-card-sub">' +
              'Structured CVE feeds, IOC data, risk scores, and MITRE ATT&amp;CK mappings via REST. ' +
              'Free tier — no credit card.' +
            '</div>' +
            '<div class="rcb-card-price">Free <span class="rcb-unit">tier + Pro</span></div>' +
            '<a href="' + LINKS.api + '" class="rcb-card-btn outline" data-track="rcb_api_click">' +
              copy.api_label + ' \u2192' +
            '</a>' +
          '</div>' +

          // Card 3: Enterprise
          '<div class="rcb-card" data-rcb-card="3">' +
            '<div class="rcb-card-icon">\uD83C\uDFE2</div>' +
            '<div class="rcb-card-title">Enterprise Platform</div>' +
            '<div class="rcb-card-sub">' +
              'White-label feeds, SLA-backed data, dedicated analyst support, and custom detection engineering.' +
            '</div>' +
            '<div class="rcb-card-price" data-cx-price="299" data-cx-orig="699">' +
              '<span class="rcb-orig">$699</span>$299' +
              '<span class="rcb-unit">/mo</span>' +
              '<span class="rcb-save">Save 57%</span>' +
            '</div>' +
            '<a href="' + LINKS.enterprise + '" class="rcb-card-btn outline" data-track="rcb_enterprise_click">' +
              'Get Proposal \u2192' +
            '</a>' +
          '</div>' +

        '</div>' + // end rcb-grid

        '<hr class="rcb-divider">' +

        // Trust signals
        '<div class="rcb-trust">' +
          '<div class="rcb-trust-stat">\uD83D\uDEE1\uFE0F <strong>4,800+</strong> SOC analysts subscribed</div>' +
          '<div class="rcb-trust-stat">\uD83D\uDCCA <strong>1,200+</strong> CVEs tracked in 2026</div>' +
          '<div class="rcb-trust-stat">\u26A1 <strong>48H</strong> pre-disclosure alerts</div>' +
          '<div class="rcb-trust-stat">\uD83C\uDF10 <strong>Updated</strong> every 10 minutes</div>' +
          '<div class="rcb-trust-stat">\uD83C\uDFE2 <strong>Fortune 500</strong> clients</div>' +
        '</div>' +

        // Newsletter / Lead capture
        '<div class="rcb-newsletter">' +
          '<div class="rcb-nl-body">' +
            '<strong>\uD83D\uDCE7 Get Free Weekly Threat Intel</strong>' +
            '<span>IOC bundles, new CVE summaries, and ransomware IOCs — no spam, unsubscribe anytime.</span>' +
          '</div>' +
          '<form class="rcb-nl-form" ' +
            'action="https://formsubmit.co/bivash@cyberdudebivash.com" method="POST" ' +
            'onsubmit="if(window.trackEvent)trackEvent(\'rcb_newsletter_submit\',{ctx:\'' + ctx + '\'})">' +
            '<input class="rcb-nl-input" type="email" name="email" placeholder="soc@yourcompany.com" required>' +
            '<input type="hidden" name="_subject" value="Post Bottom Newsletter Signup">' +
            '<input type="hidden" name="_captcha" value="false">' +
            '<input type="hidden" name="_next" value="https://blog.cyberdudebivash.in/leads.html">' +
            '<button class="rcb-nl-btn" type="submit">Subscribe Free \u2192</button>' +
          '</form>' +
        '</div>' +

        // Related navigation
        '<div class="rcb-related">' +
          '<div class="rcb-related-title">Explore Intelligence Platform</div>' +
          '<div class="rcb-related-links">' +
            '<a href="/intelligence.html" class="rcb-related-link">\uD83D\uDEF0\uFE0F Intelligence Hub</a>' +
            '<a href="/products.html" class="rcb-related-link">\uD83D\uDCE6 Products Store</a>' +
            '<a href="/pricing.html" class="rcb-related-link">\u26A1 SOC Pro Plans</a>' +
            '<a href="/api.html" class="rcb-related-link">\uD83D\uDD0C API Access</a>' +
            '<a href="/enterprise.html" class="rcb-related-link">\uD83C\uDFE2 Enterprise</a>' +
            '<a href="/rss.xml" class="rcb-related-link">\uD83D\uDCE1 RSS Feed</a>' +
            '<a href="/archive.html" class="rcb-related-link">\uD83D\uDCC2 Full Archive</a>' +
          '</div>' +
        '</div>' +

      '</div>'; // end rcb-inner

    // Insert before footer / end of article
    var insertTarget =
      document.querySelector('.post-footer') ||
      document.querySelector('.article-footer') ||
      document.querySelector('footer') ||
      document.querySelector('main') ||
      document.body;

    if (insertTarget === document.body || insertTarget === document.querySelector('main')) {
      insertTarget.appendChild(section);
    } else {
      insertTarget.parentNode.insertBefore(section, insertTarget);
    }

    // Apply intent highlighting
    applyIntentHighlight(intentLevel);

    // Start countdown if needed
    if (INTENT_URGENCY[intentLevel] && INTENT_URGENCY[intentLevel].timer) {
      startCountdown();
    }

    // Fire trackEvent
    if (window.trackEvent) {
      window.trackEvent('rcb_block_rendered', { ctx: ctx, intent: intentLevel, visits: visitCount });
    }

    // Apply A/B price anchors from CX4 if available
    if (window.CX4 && window.CX4.AB && window.CX4.AB.applyPriceAnchors) {
      window.CX4.AB.applyPriceAnchors();
    }

    // Listen for intent upgrades → re-highlight cards in real-time
    if (window.CX4 && window.CX4.INTENT && window.CX4.INTENT.onUpgrade) {
      window.CX4.INTENT.onUpgrade(function (newLevel) {
        applyIntentHighlight(newLevel);
        if (window.trackEvent) {
          window.trackEvent('rcb_intent_upgrade', { newLevel: newLevel });
        }
      });
    }
  }

  /* ── BOOT ─────────────────────────────────────────────────────────── */
  function boot() {
    injectStyles();
    buildBlock();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

}());
