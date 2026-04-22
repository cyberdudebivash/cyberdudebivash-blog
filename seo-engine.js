/**
 * CYBERDUDEBIVASH SENTINEL APEX — SEO Engine v1.0
 * ════════════════════════════════════════════════
 * Systems:
 *   1. Auto Internal Linking     — Inject keyword → post/product/API links
 *   2. Schema Injector           — Article, FAQ, BreadcrumbList, Product JSON-LD
 *   3. Meta Optimizer            — Dynamic OG/Twitter tags, canonical
 *   4. Programmatic CVE Linker   — Every CVE mention → auto-linked
 *   5. Related Posts Widget      — Contextual post recommendations
 *
 * Deploy: <script src="/seo-engine.js" defer></script>
 */
(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════
     CONFIG
  ═══════════════════════════════════════════════════════════════ */
  const SITE = 'https://blog.cyberdudebivash.in';
  const BRAND = 'CyberDudeBivash — CYBERDUDEBIVASH SENTINEL APEX';

  // Internal link map: keyword → { url, title, track }
  const LINK_MAP = [
    // CVE posts
    { kw: /CVE-2026-21497/gi, url: '/posts/cve-2026-21497-vmware-esxi-hypervisor-escape-guest-to-host-rce.html', title: 'VMware ESXi Hypervisor Escape' },
    { kw: /CVE-2026-28401/gi, url: '/posts/cve-2026-28401-ivanti-connect-secure-zero-day-supply-chain.html', title: 'Ivanti Connect Secure Zero-Day' },
    { kw: /CVE-2026-32201/gi, url: '/posts/cve-2026-32201-sharepoint-zero-day-patch-tuesday-april-2026.html', title: 'SharePoint Zero-Day April 2026' },
    { kw: /CVE-2026-33824/gi, url: '/posts/cve-2026-33824-windows-ike-service-rce-critical.html', title: 'Windows IKE Service RCE' },
    { kw: /CVE-2026-33825/gi, url: '/posts/cve-2026-33825-microsoft-defender-zero-day-bluehammer-redsun.html', title: 'Microsoft Defender Zero-Day' },
    { kw: /CVE-2026-35616/gi, url: '/posts/cve-2026-35616-fortinet-forticlient-ems-zero-day.html', title: 'Fortinet FortiClient EMS Zero-Day' },
    { kw: /CVE-2026-5281/gi,  url: '/posts/cve-2026-5281-chrome-zero-day-dawn-webgpu-use-after-free.html', title: 'Chrome Zero-Day Dawn WebGPU' },
    // Topics → products/API
    { kw: /\bSigma rules?\b/gi,  url: '/products.html', title: 'Sigma Detection Rules Pack', anchor: 'Sigma rules' },
    { kw: /\bYARA rules?\b/gi,   url: '/products.html', title: 'YARA Rules Pack', anchor: 'YARA rules' },
    { kw: /\bIOC pack\b/gi,      url: '/products.html', title: 'IOC Intelligence Pack' },
    { kw: /\bplaybook\b/gi,      url: '/products.html', title: 'SOC Playbook', anchor: 'playbook' },
    { kw: /\bSIEM rules?\b/gi,   url: '/products.html', title: 'SIEM Detection Rules Pack', anchor: 'SIEM rules' },
    { kw: /\bthreat intel(?:ligence)? API\b/gi, url: '/api.html', title: 'CYBERDUDEBIVASH SENTINEL APEX Threat Intel API' },
    { kw: /\benterprise (?:SOC|security|intel)\b/gi, url: '/enterprise.html', title: 'Enterprise Threat Intelligence' },
    // Threat actors → related posts
    { kw: /\bVolt Typhoon\b/gi,   url: '/posts/volt-typhoon-2026-ics-scada-critical-infrastructure-attack.html', title: 'Volt Typhoon 2026 ICS/SCADA Attack' },
    { kw: /\bLockBit\b/gi,        url: '/posts/april-2026-ransomware-roundup-qilin-akira-lockbit-blackbasta.html', title: '2026 Ransomware Intelligence Report' },
    { kw: /\bQilin\b/gi,          url: '/posts/april-2026-ransomware-roundup-qilin-akira-lockbit-blackbasta.html', title: '2026 Ransomware Intelligence Report' },
    { kw: /\bBlackBasta\b/gi,     url: '/posts/april-2026-ransomware-roundup-qilin-akira-lockbit-blackbasta.html', title: '2026 Ransomware Intelligence Report' },
    { kw: /\bprompt injection\b/gi, url: '/posts/ai-llm-prompt-injection-enterprise-attack-surface-2026.html', title: 'AI/LLM Prompt Injection Attack Surface 2026' },
  ];

  // FAQ data by page type
  const FAQ_DATA = {
    default: [
      { q: 'What is CYBERDUDEBIVASH SENTINEL APEX?', a: 'CYBERDUDEBIVASH SENTINEL APEX is an elite cybersecurity threat intelligence platform providing real-time CVE analysis, IOC feeds, detection rules, and AI-powered risk scoring.' },
      { q: 'How do I access the Threat Intelligence API?', a: 'Visit the API page at blog.cyberdudebivash.in/api.html to sign up for a free tier or Pro plan. The API provides CVE data, IOC feeds, and AI risk scoring.' },
      { q: 'What detection rules do you sell?', a: 'We offer Sigma rule megapacks (1,200+ rules), YARA ransomware packs (600+ rules), and CVE-specific detection bundles — all mapped to MITRE ATT&CK v15.' },
      { q: 'Is there a free tier?', a: 'Yes — the free tier includes 100 API requests/day, public CVE data, and access to our blog intelligence reports.' }
    ]
  };

  // Related posts map (keyed by partial filename)
  const RELATED = [
    { file: 'vmware',       tags: ['hypervisor', 'esxi', 'CVE', 'virtualization', 'RCE'] },
    { file: 'ivanti',       tags: ['zero-day', 'supply chain', 'VPN', 'CVE', 'remote access'] },
    { file: 'sharepoint',   tags: ['Microsoft', 'CVE', 'Patch Tuesday', 'enterprise'] },
    { file: 'windows-ike',  tags: ['Windows', 'CVE', 'RCE', 'Microsoft', 'patch'] },
    { file: 'defender',     tags: ['Windows', 'AV bypass', 'Microsoft', 'CVE'] },
    { file: 'fortinet',     tags: ['Fortinet', 'VPN', 'CVE', 'zero-day', 'firewall'] },
    { file: 'chrome',       tags: ['browser', 'CVE', 'Google', 'WebGPU', 'use-after-free'] },
    { file: 'ransomware',   tags: ['ransomware', 'LockBit', 'Qilin', 'Akira', 'extortion'] },
    { file: 'prompt-inj',   tags: ['AI', 'LLM', 'prompt injection', 'GenAI', 'enterprise'] },
    { file: 'volt-typhoon', tags: ['APT', 'China', 'ICS', 'SCADA', 'critical infrastructure'] },
    { file: 'supply-chain', tags: ['supply chain', 'zero-day', 'CVE', 'Ivanti'] },
  ];

  /* ═══════════════════════════════════════════════════════════════
     1. INTERNAL LINK INJECTOR
  ═══════════════════════════════════════════════════════════════ */
  function injectInternalLinks() {
    // Only run on post pages
    const contentAreas = [
      ...document.querySelectorAll('article, .post-body, .post-content, main p')
    ].filter(el => !el.closest('nav, footer, header, .cx-inline-cta, script, pre, code'));

    if (!contentAreas.length) return;

    // Merge text nodes — work on paragraphs
    const paragraphs = document.querySelectorAll('article p, .post-content p, main article p');
    const linkedKws = new Set(); // limit 1 link per keyword

    paragraphs.forEach(p => {
      let html = p.innerHTML;
      // Skip if already has links
      if (html.includes('<a ') && html.split('<a ').length > 3) return;

      LINK_MAP.forEach(({ kw, url, title, anchor }) => {
        // Skip if already linked this keyword
        if (linkedKws.has(kw.source)) return;
        // Don't link if on that same page
        if (window.location.pathname === url) return;

        const match = html.match(kw);
        if (match) {
          const linkText = anchor || match[0];
          html = html.replace(kw, (m, idx) => {
            // Only replace first occurrence
            if (linkedKws.has(kw.source)) return m;
            linkedKws.add(kw.source);
            return `<a href="${url}" title="${title}" style="color:#00ffe0;text-decoration:underline;text-underline-offset:3px;font-weight:600;" data-cx-internal="true">${m}</a>`;
          });
        }
      });

      p.innerHTML = html;
    });
  }

  /* ═══════════════════════════════════════════════════════════════
     2. SCHEMA.ORG JSON-LD INJECTOR
  ═══════════════════════════════════════════════════════════════ */
  function injectSchema() {
    const path = window.location.pathname;
    const title = document.title;
    const desc = document.querySelector('meta[name="description"]')?.content || '';
    const canonical = document.querySelector('link[rel="canonical"]')?.href || (SITE + path);

    const schemas = [];

    // Always: BreadcrumbList
    const crumbs = [{ name: 'Home', url: SITE + '/' }];
    if (path.includes('/posts/')) {
      crumbs.push({ name: 'Intelligence Reports', url: SITE + '/archive.html' });
      crumbs.push({ name: title.split('|')[0].trim(), url: canonical });
    } else if (path.includes('products')) {
      crumbs.push({ name: 'Products', url: canonical });
    } else if (path.includes('api')) {
      crumbs.push({ name: 'API Access', url: canonical });
    } else if (path.includes('enterprise')) {
      crumbs.push({ name: 'Enterprise', url: canonical });
    }
    schemas.push({
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: crumbs.map((c, i) => ({
        '@type': 'ListItem', position: i + 1,
        name: c.name, item: c.url
      }))
    });

    // Post page: Article schema
    if (path.includes('/posts/')) {
      const dateEl = document.querySelector('time, .post-date, [datetime]');
      const date = dateEl?.getAttribute('datetime') || dateEl?.textContent || '2026-04-22';
      schemas.push({
        '@context': 'https://schema.org',
        '@type': 'Article',
        headline: title.split('|')[0].trim(),
        description: desc,
        url: canonical,
        datePublished: date,
        dateModified: date,
        author: { '@type': 'Person', name: 'CyberDudeBivash', url: SITE },
        publisher: {
          '@type': 'Organization', name: BRAND, url: SITE,
          logo: { '@type': 'ImageObject', url: SITE + '/og-image.png' }
        },
        image: SITE + '/og-image.png',
        mainEntityOfPage: { '@type': 'WebPage', '@id': canonical },
        keywords: [
          'cybersecurity', 'threat intelligence', 'CVE', 'zero-day',
          'SIEM', 'MITRE ATT&CK', 'SOC', 'malware', 'IOC'
        ].join(', ')
      });

      // NewsArticle for CVE posts
      if (title.toLowerCase().includes('cve') || title.toLowerCase().includes('zero-day')) {
        schemas.push({
          '@context': 'https://schema.org',
          '@type': 'NewsArticle',
          headline: title.split('|')[0].trim(),
          description: desc,
          url: canonical,
          datePublished: date,
          author: { '@type': 'Person', name: 'CyberDudeBivash' },
          publisher: { '@type': 'Organization', name: BRAND }
        });
      }
    }

    // Products page: ItemList + SoftwareApplication
    if (path.includes('products')) {
      schemas.push({
        '@context': 'https://schema.org',
        '@type': 'ItemList',
        name: 'CYBERDUDEBIVASH SENTINEL APEX Cybersecurity Products',
        description: 'Premium Sigma rules, YARA packs, threat reports, and SOC toolkits.',
        url: canonical,
        numberOfItems: 9
      });
    }

    // API page: SoftwareApplication
    if (path.includes('api')) {
      schemas.push({
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        name: 'CYBERDUDEBIVASH SENTINEL APEX Threat Intelligence API',
        applicationCategory: 'SecurityApplication',
        operatingSystem: 'Any',
        offers: [
          { '@type': 'Offer', name: 'Free', price: '0', priceCurrency: 'USD' },
          { '@type': 'Offer', name: 'SOC Pro', price: '49', priceCurrency: 'USD', billingIncrement: 'Monthly' },
          { '@type': 'Offer', name: 'Enterprise', price: '299', priceCurrency: 'USD', billingIncrement: 'Monthly' }
        ]
      });
    }

    // FAQ on every page (bottom)
    const faqItems = FAQ_DATA.default;
    schemas.push({
      '@context': 'https://schema.org',
      '@type': 'FAQPage',
      mainEntity: faqItems.map(({ q, a }) => ({
        '@type': 'Question',
        name: q,
        acceptedAnswer: { '@type': 'Answer', text: a }
      }))
    });

    // Inject all schemas
    schemas.forEach(schema => {
      const s = document.createElement('script');
      s.type = 'application/ld+json';
      s.textContent = JSON.stringify(schema);
      document.head.appendChild(s);
    });
  }

  /* ═══════════════════════════════════════════════════════════════
     3. RELATED POSTS WIDGET
  ═══════════════════════════════════════════════════════════════ */
  function injectRelatedPosts() {
    // Only on post pages
    if (!window.location.pathname.includes('/posts/')) return;

    const currentFile = window.location.pathname;
    const posts = [
      { url: '/posts/cve-2026-21497-vmware-esxi-hypervisor-escape-guest-to-host-rce.html',   title: 'CVE-2026-21497: VMware ESXi Hypervisor Escape', badge: 'CVSS 9.8', badgeColor: '#ff4d6d', tags: ['hypervisor','esxi','RCE','virtualization'] },
      { url: '/posts/cve-2026-28401-ivanti-connect-secure-zero-day-supply-chain.html',        title: 'CVE-2026-28401: Ivanti Zero-Day Supply Chain RCE', badge: 'CVSS 10.0', badgeColor: '#ff4d6d', tags: ['zero-day','supply chain','VPN'] },
      { url: '/posts/cve-2026-32201-sharepoint-zero-day-patch-tuesday-april-2026.html',       title: 'SharePoint Zero-Day — Patch Tuesday April 2026', badge: 'CVSS 9.0', badgeColor: '#ff8c42', tags: ['Microsoft','SharePoint','enterprise'] },
      { url: '/posts/cve-2026-33824-windows-ike-service-rce-critical.html',                   title: 'CVE-2026-33824: Windows IKE Service RCE', badge: 'CVSS 9.8', badgeColor: '#ff4d6d', tags: ['Windows','RCE','Microsoft'] },
      { url: '/posts/cve-2026-33825-microsoft-defender-zero-day-bluehammer-redsun.html',      title: 'Microsoft Defender Zero-Day BluehHammer/RedSun', badge: 'CVSS 9.3', badgeColor: '#ff4d6d', tags: ['Windows','Defender','AV bypass'] },
      { url: '/posts/cve-2026-35616-fortinet-forticlient-ems-zero-day.html',                  title: 'CVE-2026-35616: Fortinet FortiClient Zero-Day', badge: 'CVSS 9.6', badgeColor: '#ff4d6d', tags: ['Fortinet','VPN','zero-day'] },
      { url: '/posts/cve-2026-5281-chrome-zero-day-dawn-webgpu-use-after-free.html',          title: 'Chrome Zero-Day: Dawn WebGPU Use-After-Free', badge: 'CVSS 8.8', badgeColor: '#ff8c42', tags: ['browser','Chrome','WebGPU'] },
      { url: '/posts/april-2026-ransomware-roundup-qilin-akira-lockbit-blackbasta.html',      title: 'April 2026 Ransomware Round-Up: Qilin, Akira, LockBit', badge: 'CRITICAL', badgeColor: '#ff4d6d', tags: ['ransomware','LockBit','Qilin','extortion'] },
      { url: '/posts/ai-llm-prompt-injection-enterprise-attack-surface-2026.html',            title: 'AI/LLM Prompt Injection: Enterprise Attack Surface 2026', badge: 'HIGH', badgeColor: '#ff8c42', tags: ['AI','LLM','prompt injection','GenAI'] },
      { url: '/posts/volt-typhoon-2026-ics-scada-critical-infrastructure-attack.html',        title: 'Volt Typhoon 2026: ICS/SCADA Critical Infrastructure', badge: 'NATION-STATE', badgeColor: '#a855f7', tags: ['APT','China','ICS','SCADA'] },
    ];

    // Filter out current page
    const others = posts.filter(p => !currentFile.includes(p.url.split('/').pop().replace('.html', '')));
    // Pick 3 random
    const shuffle = arr => [...arr].sort(() => 0.5 - Math.random());
    const picks = shuffle(others).slice(0, 3);

    const container = document.createElement('div');
    container.style.cssText = `
      margin: 3rem 0; padding: 1.5rem;
      background: rgba(13,17,23,0.8); border: 1px solid rgba(0,255,224,0.15);
      border-radius: 16px; font-family: 'Segoe UI', system-ui, sans-serif;
    `;
    container.innerHTML = `
      <div style="font-size:.75rem;font-weight:800;color:#00ffe0;text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem;">
        🛰️ Related Intelligence Reports
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:1rem;">
        ${picks.map(p => `
          <a href="${p.url}" style="display:block;background:rgba(7,9,15,0.8);border:1px solid rgba(0,255,224,0.1);border-radius:10px;padding:1rem;text-decoration:none;transition:border-color .2s;"
            onmouseover="this.style.borderColor='rgba(0,255,224,0.35)'"
            onmouseout="this.style.borderColor='rgba(0,255,224,0.1)'">
            <span style="font-size:.65rem;font-weight:800;color:#fff;background:${p.badgeColor};padding:.15rem .45rem;border-radius:4px;margin-bottom:.5rem;display:inline-block;">${p.badge}</span>
            <div style="font-size:.85rem;font-weight:700;color:#e2e8f0;line-height:1.4;">${p.title}</div>
          </a>
        `).join('')}
      </div>
    `;

    // Inject before footer
    const footer = document.querySelector('footer');
    if (footer) footer.insertAdjacentElement('beforebegin', container);
    else document.body.appendChild(container);
  }

  /* ═══════════════════════════════════════════════════════════════
     4. META TAG OPTIMIZER
  ═══════════════════════════════════════════════════════════════ */
  function optimizeMeta() {
    const path = window.location.pathname;
    // Ensure OG image exists
    if (!document.querySelector('meta[property="og:image"]')) {
      const m = document.createElement('meta');
      m.setAttribute('property', 'og:image');
      m.content = SITE + '/og-image.png';
      document.head.appendChild(m);
    }
    // Ensure Twitter image
    if (!document.querySelector('meta[name="twitter:image"]')) {
      const m = document.createElement('meta');
      m.name = 'twitter:image';
      m.content = SITE + '/og-image.png';
      document.head.appendChild(m);
    }
    // Ensure canonical
    if (!document.querySelector('link[rel="canonical"]')) {
      const l = document.createElement('link');
      l.rel = 'canonical';
      l.href = SITE + path;
      document.head.appendChild(l);
    }
    // Add cybersecurity-specific keywords if not present
    const kwMeta = document.querySelector('meta[name="keywords"]');
    if (kwMeta) {
      const existing = kwMeta.content;
      const additions = ['threat intelligence', 'CVE 2026', 'zero-day vulnerability', 'SOC automation', 'cybersecurity blog'];
      const merged = [...new Set([...existing.split(',').map(s => s.trim()), ...additions])].join(', ');
      kwMeta.content = merged;
    }
  }

  /* ═══════════════════════════════════════════════════════════════
     BOOT
  ═══════════════════════════════════════════════════════════════ */
  function boot() {
    try { optimizeMeta(); } catch {}
    try { injectSchema(); } catch {}
    // Only inject links and related posts on post pages (avoid breaking UI pages)
    if (window.location.pathname.includes('/posts/')) {
      setTimeout(() => { try { injectInternalLinks(); } catch {} }, 800);
      setTimeout(() => { try { injectRelatedPosts(); } catch {} }, 600);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
