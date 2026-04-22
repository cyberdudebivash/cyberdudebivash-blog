/**
 * CYBERDUDEBIVASH SENTINEL APEX — Revenue CTA Block Engine v1.0
 * ═════════════════════════════════════════════════════════════
 * Injects a full-width conversion section at the bottom of every post.
 * Personalizes CTA copy based on page context (CVE / ransomware / APT / AI).
 * Links: Products → Pricing → API → Enterprise → Lead Capture
 *
 * Deploy: <script src="/revenue-cta-block.js" defer></script>
 */
(function () {
  'use strict';

  var BASE = 'https://blog.cyberdudebivash.in';
  var CYAN = '#00ffe0';

  var LINKS = {
    pricing:    '/pricing.html',
    products:   '/products.html',
    api:        '/api.html',
    enterprise: '/enterprise.html',
    leads:      '/leads.html',
    rss:        '/rss.xml'
  };

  /* ── PAGE CONTEXT DETECTION ─────────────────────────────────────── */
  function detectContext() {
    var p = window.location.pathname.toLowerCase();
    var t = (document.title || '').toLowerCase();
    if (p.includes('cve-') || t.includes('cve-') || t.includes('zero-day') || t.includes('rce')) return 'cve';
    if (p.includes('ransomware') || t.includes('ransomware') || t.includes('lockbit') || t.includes('akira')) return 'ransomware';
    if (p.includes('apt') || p.includes('typhoon') || t.includes('typhoon') || t.includes('nation-state')) return 'apt';
    if (p.includes('ai-') || p.includes('llm') || t.includes('prompt injection') || t.includes('ai security')) return 'ai';
    return 'general';
  }

  var CONTEXT_COPY = {
    cve: {
      headline: 'Get Full Detection Coverage for This CVE',
      sub: 'SOC Pro members receive complete IOC tables, SIEM detection rules (Splunk/Elastic/KQL), YARA signatures, and automated STIX feeds — 48 hours before NVD publication.',
      products_label: '\uD83D\uDCE6 Get Detection Pack',
      api_label: '\uD83D\uDD0C Automate via API',
    },
    ransomware: {
      headline: 'Stay Ahead of the Next Ransomware Campaign',
      sub: 'Weekly ransomware group tracking: active campaigns, IOC bundles (IP/domain/hash), TTPs, and Sigma rules mapped to MITRE ATT&CK — delivered to your SIEM and inbox.',
      products_label: '\uD83D\uDEE1\uFE0F Get Ransomware IOC Pack',
      api_label: '\uD83D\uDD0C Integrate Threat Feeds',
    },
    apt: {
      headline: 'Nation-State Threat Intelligence — Enterprise Grade',
      sub: 'Deep-dive APT tracking: actor TTPs, infrastructure maps, malware signatures, and pre-disclosure campaign alerts. Trusted by SOC teams defending critical infrastructure.',
      products_label: '\uD83C\uDFAF Get APT Intel Pack',
      api_label: '\uD83D\uDD0C API + STIX Feed Access',
    },
    ai: {
      headline: 'Secure Your AI Stack Against Emerging Attack Vectors',
      sub: 'LLM security, prompt injection defenses, and AI governance intelligence — research-grade analysis with actionable detection rules for enterprise AI deployments.',
      products_label: '\uD83E\uDD16 Get AI Security Pack',
      api_label: '\uD83D\uDD0C Access AI Risk API',
    },
    general: {
      headline: 'Upgrade Your Threat Intelligence — SOC Pro',
      sub: '48H pre-disclosure CVE reports, full IOC bundles, SIEM detection rules, YARA signatures, and ransomware tracking. Used by 3,800+ security professionals globally.',
      products_label: '\uD83D\uDCE6 Browse Products',
      api_label: '\uD83D\uDD0C API Access',
    }
  };

  /* ── STYLES ──────────────────────────────────────────────────────── */
  function injectStyles() {
    var s = document.createElement('style');
    s.textContent =
      '.rcb-section{' +
        'background:linear-gradient(135deg,#07090f,#0a1628 50%,#07090f);' +
        'border-top:1px solid rgba(0,255,224,0.15);' +
        'border-bottom:1px solid rgba(0,255,224,0.08);' +
        'padding:3rem 1.5rem;margin-top:3rem;font-family:"Segoe UI",system-ui,sans-serif;' +
      '}' +
      '.rcb-inner{max-width:900px;margin:0 auto}' +
      '.rcb-badge{display:inline-flex;align-items:center;gap:.5rem;' +
        'background:rgba(0,255,224,0.08);border:1px solid rgba(0,255,224,0.2);' +
        'border-radius:50px;padding:.3rem 1rem;font-size:.7rem;font-weight:800;' +
        'color:' + CYAN + ';text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem;' +
      '}' +
      '.rcb-headline{font-size:clamp(1.4rem,3vw,2rem);font-weight:900;color:#fff;' +
        'line-height:1.2;margin-bottom:.75rem;' +
      '}' +
      '.rcb-sub{font-size:.95rem;color:#94a3b8;line-height:1.7;margin-bottom:2rem;max-width:680px}' +
      '.rcb-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem;margin-bottom:2rem}' +
      '.rcb-card{' +
        'background:rgba(0,255,224,0.04);border:1px solid rgba(0,255,224,0.12);' +
        'border-radius:12px;padding:1.25rem;transition:border-color .2s,background .2s;' +
      '}' +
      '.rcb-card:hover{border-color:rgba(0,255,224,0.28);background:rgba(0,255,224,0.07)}' +
      '.rcb-card-icon{font-size:1.8rem;margin-bottom:.6rem}' +
      '.rcb-card-title{font-size:.9rem;font-weight:800;color:#fff;margin-bottom:.3rem}' +
      '.rcb-card-sub{font-size:.78rem;color:#64748b;line-height:1.5;margin-bottom:.85rem}' +
      '.rcb-card-price{font-size:1.1rem;font-weight:900;color:' + CYAN + ';margin-bottom:.75rem}' +
      '.rcb-card-price span{font-size:.75rem;color:#64748b;font-weight:400}' +
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
      '.rcb-trust{display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap}' +
      '.rcb-trust-stat{display:flex;align-items:center;gap:.5rem;font-size:.82rem;color:#64748b}' +
      '.rcb-trust-stat strong{color:#94a3b8;font-weight:700}' +
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

  /* ── BUILD HTML ──────────────────────────────────────────────────── */
  function buildBlock() {
    if (!window.location.pathname.includes('/posts/')) return;
    if (document.getElementById('rcb-revenue-block')) return;

    var ctx    = detectContext();
    var copy   = CONTEXT_COPY[ctx] || CONTEXT_COPY.general;

    var section = document.createElement('section');
    section.id = 'rcb-revenue-block';
    section.className = 'rcb-section';
    section.setAttribute('aria-label', 'Upgrade your threat intelligence');

    section.innerHTML =
      '<div class="rcb-inner">' +

        // Header
        '<div class="rcb-badge">\u26A1 CYBERDUDEBIVASH SENTINEL APEX INTELLIGENCE</div>' +
        '<h2 class="rcb-headline">' + copy.headline + '</h2>' +
        '<p class="rcb-sub">' + copy.sub + '</p>' +

        // 4-card product grid
        '<div class="rcb-grid">' +

          // Card 1: SOC Pro
          '<div class="rcb-card">' +
            '<div class="rcb-card-icon">\u26A1</div>' +
            '<div class="rcb-card-title">SOC Pro Membership</div>' +
            '<div class="rcb-card-sub">Full IOC packs, SIEM rules, 48H pre-disclosure CVE reports, and ransomware tracker access.</div>' +
            '<div class="rcb-card-price" data-cx-price="49" data-cx-orig="129">$49<span>/mo</span></div>' +
            '<a href="' + LINKS.pricing + '" class="rcb-card-btn" data-track="rcb_soc_pro_click">Start 7-Day Free Trial \u2192</a>' +
          '</div>' +

          // Card 2: Products
          '<div class="rcb-card">' +
            '<div class="rcb-card-icon">\uD83D\uDCE6</div>' +
            '<div class="rcb-card-title">Detection Packs</div>' +
            '<div class="rcb-card-sub">Sigma + YARA rules, IOC bundles, playbooks, and SOC automation scripts. Deploy-ready in minutes.</div>' +
            '<div class="rcb-card-price">From <span style="font-size:1rem;font-weight:800;color:' + CYAN + '">$9</span></div>' +
            '<a href="' + LINKS.products + '" class="rcb-card-btn" data-track="rcb_products_click">' + copy.products_label + ' \u2192</a>' +
          '</div>' +

          // Card 3: API
          '<div class="rcb-card">' +
            '<div class="rcb-card-icon">\uD83D\uDD0C</div>' +
            '<div class="rcb-card-title">Intelligence API</div>' +
            '<div class="rcb-card-sub">Structured CVE feeds, IOC data, risk scores, and MITRE ATT&amp;CK mappings via REST API. Free tier available.</div>' +
            '<div class="rcb-card-price">Free <span>tier + Pro</span></div>' +
            '<a href="' + LINKS.api + '" class="rcb-card-btn outline" data-track="rcb_api_click">' + copy.api_label + ' \u2192</a>' +
          '</div>' +

          // Card 4: Enterprise
          '<div class="rcb-card">' +
            '<div class="rcb-card-icon">\uD83C\uDFE2</div>' +
            '<div class="rcb-card-title">Enterprise Platform</div>' +
            '<div class="rcb-card-sub">White-label feeds, SLA-backed data, dedicated analyst support, and custom detection engineering for your team.</div>' +
            '<div class="rcb-card-price" data-cx-price="299" data-cx-orig="699">$299<span>/mo</span></div>' +
            '<a href="' + LINKS.enterprise + '" class="rcb-card-btn outline" data-track="rcb_enterprise_click">Get Proposal \u2192</a>' +
          '</div>' +

        '</div>' + // end rcb-grid

        '<hr class="rcb-divider">' +

        // Trust signals
        '<div class="rcb-trust">' +
          '<div class="rcb-trust-stat">\uD83D\uDEE1\uFE0F <strong>3,800+</strong> SOC analysts subscribed</div>' +
          '<div class="rcb-trust-stat">\uD83D\uDCCA <strong>500+</strong> CVEs tracked in 2026</div>' +
          '<div class="rcb-trust-stat">\u26A1 <strong>48H</strong> pre-disclosure alerts</div>' +
          '<div class="rcb-trust-stat">\uD83C\uDF0D <strong>Global</strong> fortune 500 clients</div>' +
        '</div>' +

        // Newsletter / Lead capture
        '<div class="rcb-newsletter">' +
          '<div class="rcb-nl-body">' +
            '<strong>\uD83D\uDCE7 Get Free Weekly Threat Intel</strong>' +
            '<span>IOC bundles, new CVE summaries, and ransomware IOCs — no spam, unsubscribe anytime.</span>' +
          '</div>' +
          '<form class="rcb-nl-form" action="https://formsubmit.co/bivash@cyberdudebivash.com" method="POST">' +
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

    // Find post footer / end of article and insert
    var insertTarget =
      document.querySelector('.post-footer') ||
      document.querySelector('.article-footer') ||
      document.querySelector('footer') ||
      document.querySelector('main') ||
      document.body;

    if (insertTarget === document.body || insertTarget === document.querySelector('main')) {
      // Append inside
      insertTarget.appendChild(section);
    } else {
      // Insert before footer
      insertTarget.parentNode.insertBefore(section, insertTarget);
    }

    // Fire CX event if CX engine loaded
    if (window.CX && window.CX.TRACK) {
      window.CX.TRACK.event('rcb_block_rendered', { ctx: ctx });
    }

    // Apply A/B price variants if CX loaded
    if (window.CX && window.CX.AB) {
      window.CX.AB.applyPriceAnchors();
    }
  }

  /* ── BOOT ────────────────────────────────────────────────────────── */
  function boot() {
    injectStyles();
    buildBlock();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})();
