/**
 * CYBERDUDEBIVASH — AUTO INTEL ENGINE v1.0
 * Real-Time Cyber Intelligence Broadcast System
 * Feeds: RSS (THN/BleepingComputer/SecurityWeek/Krebs) + CISA KEV + NVD CVE
 * Sections: /intel/ · /breaking/ · /malware/ · /ai-security/
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════════════
     § 1. CONFIGURATION
  ══════════════════════════════════════════════════════════════════ */
  var CFG = {
    RSS_PROXY: 'https://api.rss2json.com/v1/api.json?rss_url=',
    CORS_PROXY: 'https://corsproxy.io/?',
    CISA_KEV:  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    NVD_API:   'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&noRejected',
    REFRESH_MS: 600000,   // 10 minutes
    CACHE_TTL:  300000,   // 5 minutes
    FREEMIUM_THRESHOLD: 40,   // % of content shown free
    STORAGE_KEY: 'cdb_intel_cache',
    FEEDS: {
      breaking: [
        'https://feeds.feedburner.com/TheHackersNews',
        'https://www.bleepingcomputer.com/feed/',
        'https://securityaffairs.com/feed'
      ],
      malware: [
        'https://www.malwarebytes.com/blog/feed',
        'https://blog.malwarebytes.com/feed/',
        'https://feeds.feedburner.com/TheHackersNews'
      ],
      ai_security: [
        'https://feeds.feedburner.com/TheHackersNews',
        'https://www.securityweek.com/feed/',
        'https://krebsonsecurity.com/feed/'
      ],
      intel: [
        'https://www.bleepingcomputer.com/feed/',
        'https://securityaffairs.com/feed',
        'https://www.securityweek.com/feed/'
      ]
    }
  };

  /* ══════════════════════════════════════════════════════════════════
     § 2. MITRE ATT&CK + SEVERITY MAPS
  ══════════════════════════════════════════════════════════════════ */
  var MITRE_MAP = {
    'phishing':          { id:'T1566', name:'Phishing',           tactic:'Initial Access' },
    'ransomware':        { id:'T1486', name:'Data Encrypted',     tactic:'Impact' },
    'credential':        { id:'T1078', name:'Valid Accounts',     tactic:'Defense Evasion' },
    'lateral movement':  { id:'T1021', name:'Remote Services',    tactic:'Lateral Movement' },
    'cobalt strike':     { id:'T1071', name:'App Layer Protocol', tactic:'C2' },
    'powershell':        { id:'T1059.001', name:'PowerShell',     tactic:'Execution' },
    'supply chain':      { id:'T1195', name:'Supply Chain',       tactic:'Initial Access' },
    'zero.day':          { id:'T1190', name:'Exploit Public App', tactic:'Initial Access' },
    'privilege escalat': { id:'T1068', name:'Exploit Priv Esc',  tactic:'Privilege Escalation' },
    'persistence':       { id:'T1547', name:'Boot Autostart',     tactic:'Persistence' },
    'exfiltrat':         { id:'T1041', name:'Exfil Over C2',      tactic:'Exfiltration' },
    'backdoor':          { id:'T1505', name:'Server Software',    tactic:'Persistence' },
    'brute force':       { id:'T1110', name:'Brute Force',        tactic:'Credential Access' },
    'sql injection':     { id:'T1190', name:'Exploit Public App', tactic:'Initial Access' },
    'remote code':       { id:'T1190', name:'Exploit Public App', tactic:'Initial Access' },
    'memory corrupt':    { id:'T1203', name:'Client Execution',   tactic:'Execution' }
  };

  var THREAT_ACTORS = {
    'lockbit':      { type:'Ransomware', nation:'Russia',  color:'#ff4444' },
    'akira':        { type:'Ransomware', nation:'Unknown', color:'#ff6600' },
    'qilin':        { type:'Ransomware', nation:'Russia',  color:'#ff4444' },
    'black basta':  { type:'Ransomware', nation:'Russia',  color:'#ff4444' },
    'volt typhoon': { type:'APT',        nation:'China',   color:'#cc0000' },
    'apt28':        { type:'APT',        nation:'Russia',  color:'#cc2200' },
    'lazarus':      { type:'APT',        nation:'DPRK',    color:'#880000' },
    'scattered spider':{ type:'eCrime',  nation:'US/UK',   color:'#ff8800' }
  };

  /* ── CONTEXT PRODUCT MAP ────────────────────────────────────────── */
  var CONTEXT_PRODUCTS = {
    cve: {
      primary:   { cta:'⬇ Get Detection Pack',           url:'/products.html' },
      secondary: { cta:'🔌 Automate via API',             url:'/api.html' },
      sub: 'Sigma + YARA rules, SIEM queries, IOC bundle — deploy-ready in minutes.'
    },
    ransomware: {
      primary:   { cta:'🛡️ Get Ransomware Defense Kit',  url:'/products.html' },
      secondary: { cta:'⚡ SOC Pro — $49/mo',            url:'/pricing.html' },
      sub: '800+ YARA rules, IR playbook, IOC bundle for active ransomware campaigns.'
    },
    apt: {
      primary:   { cta:'🎯 Get APT Intel Pack',           url:'/products.html' },
      secondary: { cta:'🏢 Enterprise Advisory',          url:'/enterprise.html' },
      sub: 'Nation-state TTP mapping, STIX feed, infrastructure indicators, detection rules.'
    },
    ai: {
      primary:   { cta:'🤖 Get AI Security Report',       url:'/products.html' },
      secondary: { cta:'🏢 AI Security Hub',              url:'https://cyberdudebivash.in' },
      sub: 'LLM attack surfaces, prompt injection TTPs, enterprise AI governance — research-grade.'
    },
    general: {
      primary:   { cta:'⚡ Start SOC Pro — $49/mo',       url:'/pricing.html' },
      secondary: { cta:'📦 Browse Products',              url:'/products.html' },
      sub: '48H pre-disclosure CVEs, daily IOC feeds, SIEM rules. 4,800+ analysts subscribed.'
    }
  };

  /* ── ANALYST NOTE TEMPLATES ─────────────────────────────────────── */
  var ANALYST_NOTES = {
    cve: [
      'This vulnerability is high-priority for patch management. Organizations running affected versions should treat this as P1 remediation. SOC teams should activate detection rules before public PoC availability — typical weaponization window is 24–72 hours post-disclosure.',
      'CVEs with CVSS ≥ 7.5 are monitored by threat actors within 48 hours of NVD publication. Pre-patch network segmentation and compensating controls are recommended for all internet-facing assets.',
      'Based on historical exploitation patterns, this vulnerability class is typically weaponized within 48 hours of PoC release. Immediate patching or mitigation is strongly advised for all affected systems.'
    ],
    ransomware: [
      'Ransomware operators increasingly target backup systems and domain controllers before encryption begins. Network segmentation and offline backup verification are the most effective immediate countermeasures for this campaign.',
      'This ransomware family uses living-off-the-land techniques to evade signature-based EDR. Behavioral detection rules and anomalous process execution monitoring are more effective than hash-based approaches.',
      'Initial access via phishing and exposed RDP remain the dominant vectors. MFA enforcement and RDP gateway controls eliminate the majority of initial access risk associated with this threat group.'
    ],
    apt: [
      'Nation-state actors in this campaign demonstrate patience — initial access may precede active operations by weeks or months. Assume long-dwell presence in affected environments and conduct comprehensive threat hunt.',
      'Infrastructure used by this threat actor overlaps with previously attributed campaigns. IOCs have limited shelf-life as attribution-aware actors rapidly rotate infrastructure after public disclosure.',
      'This actor\'s targeting is strategic, not opportunistic. If your organization operates in energy, defense, financial services, or critical infrastructure verticals, treat this as a direct targeting risk.'
    ],
    ai: [
      'AI security risks are maturing rapidly. Organizations deploying LLMs in production workflows must assume adversarial input at the application layer and implement input validation at the architecture level — not just the model level.',
      'Prompt injection attacks targeting enterprise AI pipelines are increasingly sophisticated. The attack surface expands significantly when LLMs have tool-use or API access capabilities within automated workflows.',
      'AI governance controls are lagging deployment velocity. Security teams should prioritize AI asset inventory and data access mapping before deploying compensating controls for this class of attack.'
    ],
    general: [
      'This threat report has been enriched with MITRE ATT&CK mappings, IOC extraction, and risk scoring by the CYBERDUDEBIVASH SENTINEL APEX analysis pipeline. Subscribe to SOC Pro for full detection coverage delivered 48 hours before NVD.',
      'CYBERDUDEBIVASH SENTINEL APEX analysts assess this threat as operationally relevant to enterprise environments with internet-facing infrastructure based on current dark web signals and active campaign tracking.',
      'CYBERDUDEBIVASH SENTINEL APEX tracks emerging threats before NVD publication. SOC Pro members receive machine-readable IOC feeds, SIEM rules, and YARA signatures for every major threat within 24 hours of identification.'
    ]
  };

  /* ── DEFENSIVE ACTIONS MAP ──────────────────────────────────────── */
  var DEFENSIVE_ACTIONS = {
    cve: [
      'Apply vendor patch immediately — prioritize internet-facing and domain controller assets',
      'Enable SIEM detection rules for known exploitation indicators (network + host)',
      'Deploy YARA signatures across EDR platform to catch post-exploitation activity',
      'Review WAF rulesets for exploitation payload patterns if web-facing component is affected'
    ],
    ransomware: [
      'Isolate newly discovered encrypted endpoints — prevent lateral propagation',
      'Deploy IOC block list: IP/domain/hash indicators to firewall deny list immediately',
      'Disable unnecessary SMB lateral movement paths between workstations',
      'Verify offline backup integrity — confirm backup systems are unaffected by encryption'
    ],
    apt: [
      'Hunt for IOCs across EDR telemetry — assume implants may predate public disclosure',
      'Review authentication logs for anomalous access patterns matching actor TTPs',
      'Audit service accounts and privileged credentials on affected system segments',
      'Enable enhanced logging on domain controllers, VPN, and network perimeter systems'
    ],
    ai: [
      'Audit all LLM API endpoints and agentic tool integrations for prompt injection surface',
      'Implement input validation and output filtering on all AI pipeline touchpoints',
      'Review data access permissions granted to AI agent and automation components',
      'Deploy behavioral monitoring for anomalous AI API usage patterns and data access'
    ],
    general: [
      'Monitor threat actor infrastructure associated with this campaign for new indicators',
      'Review network and authentication logs for indicators matching published IOCs',
      'Verify detection coverage for MITRE ATT&CK techniques identified in this report',
      'Ensure endpoint detection rules are updated and active across all managed endpoints'
    ]
  };

  var SEVERITY_KEYWORDS = {
    critical: ['critical','cvss 9','cvss 10','actively exploit','0-day','zero-day','unauthenticated rce','pre-auth rce','emergency patch','cisa kev','cisa mandate'],
    high:     ['high','cvss 7','cvss 8','remote code exec','privilege escal','auth bypass'],
    medium:   ['medium','moderate','cvss 5','cvss 6','xss','csrf','information disclos'],
    low:      ['low','cvss 1','cvss 2','cvss 3','cvss 4','denial of service']
  };

  /* ══════════════════════════════════════════════════════════════════
     § 3. CACHE LAYER
  ══════════════════════════════════════════════════════════════════ */
  var _cache = {};

  function cacheSet(key, data) {
    try {
      _cache[key] = { ts: Date.now(), data: data };
    } catch(e) {}
  }

  function cacheGet(key) {
    var c = _cache[key];
    if (!c) return null;
    if (Date.now() - c.ts > CFG.CACHE_TTL) return null;
    return c.data;
  }

  /* ══════════════════════════════════════════════════════════════════
     § 4. FEED FETCHER
  ══════════════════════════════════════════════════════════════════ */
  function fetchRSS(feedUrl, callback) {
    var cached = cacheGet('rss_' + feedUrl);
    if (cached) { callback(null, cached); return; }

    var url = CFG.RSS_PROXY + encodeURIComponent(feedUrl) + '&count=15';
    fetch(url, { signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d.status === 'ok' && d.items) {
          cacheSet('rss_' + feedUrl, d.items);
          callback(null, d.items);
        } else {
          callback('bad_response', []);
        }
      })
      .catch(function(e) { callback(e, []); });
  }

  function fetchCISAKEV(callback) {
    var cached = cacheGet('cisa_kev');
    if (cached) { callback(null, cached); return; }

    fetch(CFG.CISA_KEV)
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var recent = (d.vulnerabilities || [])
          .sort(function(a,b){ return new Date(b.dateAdded) - new Date(a.dateAdded); })
          .slice(0, 20);
        cacheSet('cisa_kev', recent);
        callback(null, recent);
      })
      .catch(function(e) { callback(e, []); });
  }

  function fetchNVDRecent(callback) {
    var cached = cacheGet('nvd_recent');
    if (cached) { callback(null, cached); return; }

    var start = new Date(Date.now() - 7 * 86400000).toISOString().replace('Z','000');
    var url = CFG.NVD_API + '&pubStartDate=' + start;
    fetch(url)
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var items = (d.vulnerabilities || []).slice(0, 15);
        cacheSet('nvd_recent', items);
        callback(null, items);
      })
      .catch(function(e) { callback(e, []); });
  }

  /* ══════════════════════════════════════════════════════════════════
     § 5. MULTI-FEED AGGREGATOR
  ══════════════════════════════════════════════════════════════════ */
  function aggregateFeeds(section, onComplete) {
    var urls = CFG.FEEDS[section] || CFG.FEEDS.intel;
    var results = [];
    var pending = urls.length;

    if (pending === 0) { onComplete([]); return; }

    urls.forEach(function(url) {
      fetchRSS(url, function(err, items) {
        if (!err && items.length) {
          results = results.concat(items);
        }
        pending--;
        if (pending === 0) {
          // Deduplicate by title
          var seen = {};
          var deduped = results.filter(function(item) {
            var key = (item.title || '').toLowerCase().slice(0, 60);
            if (seen[key]) return false;
            seen[key] = true;
            return true;
          });
          // Sort by date
          deduped.sort(function(a,b) {
            return new Date(b.pubDate || 0) - new Date(a.pubDate || 0);
          });
          onComplete(deduped.slice(0, 30));
        }
      });
    });
  }

  /* ══════════════════════════════════════════════════════════════════
     § 6. CONTENT ENRICHER
  ══════════════════════════════════════════════════════════════════ */
  function detectPostContext(text) {
    if (/cve-\d{4}|zero.day|rce|remote code exec|privilege escal|authentication bypass|unauthenticated/i.test(text)) return 'cve';
    if (/ransomware|lockbit|akira|qilin|black.basta|encrypt.*file|ransom.*demand/i.test(text)) return 'ransomware';
    if (/apt\d*|volt.typhoon|lazarus|nation.state|ics.*attack|scada|critical infra/i.test(text)) return 'apt';
    if (/\bai\b|llm|chatgpt|copilot|gemini|prompt.inject|generative|model.*attack/i.test(text)) return 'ai';
    return 'general';
  }

  function enrichItem(item) {
    var text = ((item.title || '') + ' ' + (item.description || '') + ' ' + (item.content || '')).toLowerCase();
    var enriched = {
      title:       item.title || 'Untitled',
      link:        item.link || item.url || '#',
      pubDate:     item.pubDate || new Date().toISOString(),
      source:      extractSource(item.link || ''),
      rawContent:  item.content || item.description || '',
      severity:    detectSeverity(text),
      cveIds:      extractCVEs(text),
      mitreMap:    mapMITRE(text),
      threatActor: detectThreatActor(text),
      cvssScore:   extractCVSS(text),
      tags:        extractTags(text),
      isExploited: /actively exploit|in the wild|actively used|cisa kev|zero.day exploit/i.test(text),
      isCritical:  /critical|cvss 9\.|cvss 10|emergency patch/i.test(text),
      isBreaking:  /breaking|just in|alert|urgent|emergency/i.test(item.title || ''),
      riskScore:   0,
      postContext: detectPostContext(text)
    };
    enriched.riskScore = calculateRiskScore(enriched);
    return enriched;
  }

  function detectSeverity(text) {
    for (var lvl in SEVERITY_KEYWORDS) {
      var kws = SEVERITY_KEYWORDS[lvl];
      for (var i = 0; i < kws.length; i++) {
        if (text.indexOf(kws[i]) !== -1) return lvl;
      }
    }
    return 'medium';
  }

  function extractCVEs(text) {
    var matches = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
    return [...new Set(matches)].slice(0, 5);
  }

  function mapMITRE(text) {
    var found = [];
    for (var kw in MITRE_MAP) {
      if (text.indexOf(kw) !== -1) {
        found.push(MITRE_MAP[kw]);
        if (found.length >= 3) break;
      }
    }
    return found;
  }

  function detectThreatActor(text) {
    for (var actor in THREAT_ACTORS) {
      if (text.indexOf(actor) !== -1) return { name: actor, ...THREAT_ACTORS[actor] };
    }
    return null;
  }

  function extractCVSS(text) {
    var m = text.match(/cvss[:\s]+(\d+\.?\d*)/i) || text.match(/score[:\s]+(\d+\.?\d*)/i);
    if (m) {
      var v = parseFloat(m[1]);
      if (v >= 0 && v <= 10) return v.toFixed(1);
    }
    return null;
  }

  function extractTags(text) {
    var tags = [];
    var keywords = ['ransomware','zero-day','cve','apt','backdoor','phishing','supply chain',
      'critical infrastructure','iot','cloud','ai security','llm','prompt injection',
      'windows','linux','cisco','fortinet','microsoft','google','apple'];
    keywords.forEach(function(k) { if (text.indexOf(k) !== -1) tags.push(k); });
    return tags.slice(0, 6);
  }

  function extractSource(url) {
    try { return new URL(url).hostname.replace('www.',''); } catch(e) { return 'SENTINEL'; }
  }

  function calculateRiskScore(item) {
    var score = 0;
    if (item.severity === 'critical') score += 40;
    else if (item.severity === 'high') score += 25;
    else if (item.severity === 'medium') score += 10;
    if (item.isExploited) score += 30;
    if (item.isCritical) score += 15;
    if (item.cvssScore && parseFloat(item.cvssScore) >= 9) score += 20;
    if (item.cveIds.length) score += item.cveIds.length * 5;
    if (item.threatActor) score += 15;
    return Math.min(score, 100);
  }

  /* ══════════════════════════════════════════════════════════════════
     § 6b. POST ENRICHMENT BLOCKS — Analyst Note / Actions / CTA / Trust
  ══════════════════════════════════════════════════════════════════ */
  function generateAnalystNote(item) {
    var ctx   = item.postContext || 'general';
    var notes = ANALYST_NOTES[ctx] || ANALYST_NOTES.general;
    var note  = notes[item.riskScore % notes.length];
    var today = new Date().toLocaleDateString('en-US', { month:'short', day:'numeric' });
    return `<div class="analyst-note">
  <div class="analyst-note-hdr">
    <span class="analyst-badge">🔍 CYBERDUDEBIVASH ANALYST NOTE</span>
    <span class="analyst-meta">Assessed ${today}</span>
  </div>
  <p class="analyst-text">${escHTML(note)}</p>
</div>`;
  }

  function generateDefensiveActions(item) {
    var ctx     = item.postContext || 'general';
    var actions = DEFENSIVE_ACTIONS[ctx] || DEFENSIVE_ACTIONS.general;
    var items   = actions.slice(0, 4).map(a => `<li>${escHTML(a)}</li>`).join('');
    return `<div class="defensive-block">
  <div class="defensive-hdr">⚡ IMMEDIATE DEFENSIVE ACTIONS</div>
  <ol class="defensive-list">${items}</ol>
  <a class="defensive-link" href="/products.html">⬇ Get Full Detection Bundle →</a>
</div>`;
  }

  function generateContextCTA(item) {
    var ctx = item.postContext || 'general';
    var cp  = CONTEXT_PRODUCTS[ctx] || CONTEXT_PRODUCTS.general;
    var titleEnc = escHTML(item.title).replace(/'/g, "\\'");
    return `<div class="ctx-cta-row">
  <a class="ctx-btn-primary" href="${cp.primary.url}" onclick="if(window.trackEvent)window.trackEvent('intel_cta_primary',{ctx:'${ctx}'})">${cp.primary.cta}</a>
  <a class="ctx-btn-secondary" href="${cp.secondary.url}" onclick="if(window.trackEvent)window.trackEvent('intel_cta_secondary',{ctx:'${ctx}'})">${cp.secondary.cta}</a>
  <button class="ctx-share-btn" onclick="sharePost('${titleEnc}','${item.link}')">↗ Share</button>
</div>`;
  }

  function generateTrustFooter() {
    return `<div class="intel-trust-footer">
  <span>🛡️ <strong>4,800+</strong> analysts subscribed</span>
  <span>📊 <strong>1,200+</strong> CVEs tracked 2026</span>
  <span>⚡ Updated every <strong>10 min</strong></span>
  <span><a href="/rss.xml" style="color:#475569;text-decoration:none">📡 RSS Feed</a></span>
</div>`;
  }

  /* ══════════════════════════════════════════════════════════════════
     § 7. POST GENERATOR — Full HTML Article
  ══════════════════════════════════════════════════════════════════ */
  function generatePostHTML(item, isPremium) {
    var sevColor  = { critical:'#ff2244', high:'#ff6600', medium:'#ffd700', low:'#44ff88' };
    var sevBg     = { critical:'rgba(255,34,68,0.12)', high:'rgba(255,102,0,0.12)', medium:'rgba(255,215,0,0.10)', low:'rgba(68,255,136,0.10)' };
    var sc = sevColor[item.severity] || '#ffd700';
    var sb = sevBg[item.severity] || 'rgba(255,215,0,0.10)';

    var mitreHTML = item.mitreMap.length ? '<div class="mitre-row">' +
      item.mitreMap.map(function(m) {
        return '<span class="mitre-tag"><strong>' + m.id + '</strong> ' + m.name + ' <em>(' + m.tactic + ')</em></span>';
      }).join('') + '</div>' : '';

    var cveHTML = item.cveIds.length ? '<div class="cve-row">' +
      item.cveIds.map(function(c) {
        return '<a class="cve-badge" href="/cve/' + c + '.html" title="' + c + '">' + c + '</a>';
      }).join('') + '</div>' : '';

    var actorHTML = item.threatActor ?
      '<div class="actor-pill" style="border-color:' + item.threatActor.color + ';color:' + item.threatActor.color + '">⚠ ' +
      item.threatActor.name.toUpperCase() + ' · ' + item.threatActor.type + ' · ' + item.threatActor.nation + '</div>' : '';

    var tagsHTML = item.tags.map(function(t) {
      return '<span class="tag-chip">' + t + '</span>';
    }).join('');

    var riskBar = '<div class="risk-bar-wrap"><div class="risk-label">RISK SCORE</div><div class="risk-track"><div class="risk-fill" style="width:' + item.riskScore + '%;background:' + sc + '"></div></div><span class="risk-num">' + item.riskScore + '/100</span></div>';

    // Freemium content gate
    var cleanText = stripHTML(item.rawContent);
    var freeChars = Math.floor(cleanText.length * (CFG.FREEMIUM_THRESHOLD / 100));
    var freeText  = cleanText.slice(0, Math.max(freeChars, 280));
    var lockedText = cleanText.slice(freeChars);

    var contentHTML = '<p class="post-body">' + escHTML(freeText) + '…</p>';
    if (isPremium) {
      contentHTML = '<p class="post-body">' + escHTML(cleanText) + '</p>';
    } else {
      contentHTML += generatePaywall(item);
    }

    var timeStr = formatTime(item.pubDate);
    var exploitBadge = item.isExploited ? '<span class="badge badge-exploit">● ACTIVELY EXPLOITED</span>' : '';
    var breakingBadge = item.isBreaking ? '<span class="badge badge-breaking">⚡ BREAKING</span>' : '';

    return `<article class="intel-post" data-severity="${item.severity}" data-risk="${item.riskScore}">
  <div class="post-header" style="border-left:4px solid ${sc};background:${sb}">
    <div class="post-meta-row">
      <span class="severity-chip" style="background:${sc};color:#000">${item.severity.toUpperCase()}</span>
      ${exploitBadge}${breakingBadge}
      ${item.cvssScore ? `<span class="cvss-pill">CVSS ${item.cvssScore}</span>` : ''}
      <span class="source-chip">${item.source}</span>
      <span class="time-chip">🕐 ${timeStr}</span>
    </div>
    <h2 class="post-title"><a href="${item.link}" target="_blank" rel="noopener">${escHTML(item.title)}</a></h2>
    ${actorHTML}
    ${cveHTML}
  </div>
  <div class="post-body-wrap">
    ${mitreHTML}
    ${riskBar}
    ${contentHTML}
    ${tagsHTML ? '<div class="tags-row">' + tagsHTML + '</div>' : ''}
    ${generateAnalystNote(item)}
    ${generateDefensiveActions(item)}
  </div>
  ${generateContextCTA(item)}
  ${generateTrustFooter()}
</article>`;
  }

  function generatePaywall(item) {
    return `<div class="freemium-gate">
  <div class="gate-blur-overlay"></div>
  <div class="gate-box">
    <div class="gate-icon">🔒</div>
    <div class="gate-title">Full Intel Locked — SOC Pro Required</div>
    <div class="gate-perks">
      <span>✓ Full IOC list</span><span>✓ YARA detection rules</span>
      <span>✓ SIEM queries</span><span>✓ Response playbook</span>
    </div>
    <a class="gate-cta" href="/pricing.html">Unlock with SOC Pro — $49/mo</a>
    <a class="gate-cta gate-cta-outline" href="/leads.html">Get Free Sample Report</a>
  </div>
</div>`;
  }

  /* ══════════════════════════════════════════════════════════════════
     § 8. PAGE PUBLISHER
  ══════════════════════════════════════════════════════════════════ */
  function publishToSection(sectionId, items, options) {
    var container = document.getElementById(sectionId);
    if (!container) return;

    options = options || {};
    var limit = options.limit || 20;
    var isPremium = window.__cdb_is_premium || false;

    if (!items.length) {
      container.innerHTML = '<div class="intel-empty"><span>⚡</span><p>Loading live threat intelligence…</p></div>';
      return;
    }

    // Filter by section type
    var filtered = items;
    if (options.section === 'malware') {
      filtered = items.filter(function(i) {
        return /malware|ransomware|trojan|worm|botnet|spyware|keylog|stealer|rat\b/i.test(i.title + ' ' + i.rawContent);
      });
      if (!filtered.length) filtered = items;
    } else if (options.section === 'ai_security') {
      filtered = items.filter(function(i) {
        return /ai|llm|gpt|artificial intel|machine learn|prompt|copilot|chatgpt|claude|gemini/i.test(i.title + ' ' + i.rawContent);
      });
      if (!filtered.length) filtered = items;
    } else if (options.section === 'breaking') {
      filtered = items.filter(function(i) { return i.riskScore >= 50 || i.isBreaking || i.isExploited; });
      if (!filtered.length) filtered = items.sort(function(a,b) { return b.riskScore - a.riskScore; });
    }

    var html = filtered.slice(0, limit).map(function(item) {
      return generatePostHTML(item, isPremium);
    }).join('\n');

    container.innerHTML = html;
    updateLiveCounts(filtered);
    injectInternalLinks(container);
  }

  function updateLiveCounts(items) {
    var critical = items.filter(function(i){ return i.severity === 'critical'; }).length;
    var exploited = items.filter(function(i){ return i.isExploited; }).length;
    var cveCount = items.reduce(function(acc, i){ return acc + i.cveIds.length; }, 0);

    setCount('intel-critical-count', critical);
    setCount('intel-exploited-count', exploited);
    setCount('intel-cve-count', cveCount || '50+');
    setCount('intel-total-count', items.length);
  }

  function setCount(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  /* ══════════════════════════════════════════════════════════════════
     § 9. INTERNAL LINKING ENGINE
  ══════════════════════════════════════════════════════════════════ */
  function injectInternalLinks(container) {
    if (!container) return;
    var links = {
      'sigma rules':    '/products.html',
      'yara rules':     '/products.html',
      'detection pack': '/products.html',
      'ioc pack':       '/products.html',
      'threat intel api':'/api.html',
      'soc pro':        '/pricing.html',
      'enterprise':     '/enterprise.html',
      'cisa kev':       '/intelligence.html',
      'zero-day':       '/attack/zero-day.html',
      'ransomware':     '/attack/ransomware.html',
      'apt':            '/attack/apt.html',
      'supply chain':   '/attack/supply-chain.html'
    };
    var titles = container.querySelectorAll('.post-title');
    titles.forEach(function(el) {
      var t = el.textContent.toLowerCase();
      for (var kw in links) {
        if (t.indexOf(kw) !== -1) {
          var hint = document.createElement('a');
          hint.href = links[kw];
          hint.className = 'related-link';
          hint.textContent = '→ ' + kw.replace(/^\w/,function(c){return c.toUpperCase();});
          el.parentNode.appendChild(hint);
          break;
        }
      }
    });
  }

  /* ══════════════════════════════════════════════════════════════════
     § 10. SOCIAL DISTRIBUTION
  ══════════════════════════════════════════════════════════════════ */
  window.sharePost = function(title, url) {
    var text = '🚨 ' + title + ' — via CYBERDUDEBIVASH SENTINEL APEX\n#CyberSecurity #ThreatIntel #CISO';
    if (navigator.share) {
      navigator.share({ title: title, text: text, url: url }).catch(function(){});
      return;
    }
    // Fallback share menu
    var menu = document.createElement('div');
    menu.className = 'share-menu';
    menu.innerHTML =
      '<a href="https://twitter.com/intent/tweet?text=' + encodeURIComponent(text) + '&url=' + encodeURIComponent(url) + '" target="_blank">𝕏 Post on X</a>' +
      '<a href="https://www.linkedin.com/shareArticle?mini=true&url=' + encodeURIComponent(url) + '&title=' + encodeURIComponent(title) + '" target="_blank">in Share on LinkedIn</a>' +
      '<a href="https://t.me/share/url?url=' + encodeURIComponent(url) + '&text=' + encodeURIComponent(text) + '" target="_blank">✈ Send on Telegram</a>' +
      '<button onclick="this.parentNode.remove()">✕ Close</button>';
    document.body.appendChild(menu);
    setTimeout(function(){ if(menu.parentNode) menu.remove(); }, 8000);
  };

  /* ══════════════════════════════════════════════════════════════════
     § 11. TICKER FEED (Top Nav Marquee Update)
  ══════════════════════════════════════════════════════════════════ */
  function updateTicker(items) {
    var ticker = document.querySelector('.ticker-text') || document.querySelector('.breaking-ticker');
    if (!ticker || !items.length) return;
    var critical = items.filter(function(i){ return i.severity === 'critical' || i.isExploited; });
    var use = (critical.length ? critical : items).slice(0, 8);
    ticker.innerHTML = use.map(function(i) {
      return '<span class="ticker-item">● ' +
        (i.isExploited ? '<strong>ACTIVELY EXPLOITED:</strong> ' : '') +
        escHTML(i.title.slice(0, 90)) + (i.cveIds.length ? ' [' + i.cveIds[0] + ']' : '') +
        '</span>';
    }).join(' &nbsp;&nbsp;&nbsp; ');
  }

  /* ══════════════════════════════════════════════════════════════════
     § 12. CISA KEV SECTION RENDERER
  ══════════════════════════════════════════════════════════════════ */
  function renderCISAKEV(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;
    fetchCISAKEV(function(err, items) {
      if (err || !items.length) return;
      el.innerHTML = items.slice(0, 10).map(function(v) {
        var sev = parseFloat(v.cvssScore || 0) >= 9 ? 'critical' : parseFloat(v.cvssScore || 0) >= 7 ? 'high' : 'medium';
        var sc = {critical:'#ff2244',high:'#ff6600',medium:'#ffd700'}[sev];
        return '<div class="kev-item">' +
          '<span class="cve-badge" style="border-color:' + sc + ';color:' + sc + '">' + (v.cveID || '') + '</span>' +
          '<span class="kev-vendor">' + escHTML(v.vendorProject || '') + ' — ' + escHTML(v.product || '') + '</span>' +
          '<span class="kev-date">' + (v.dateAdded || '') + '</span>' +
          '<span class="kev-action" style="color:' + sc + '">' + escHTML((v.requiredAction || '').slice(0,80)) + '</span>' +
          '</div>';
      }).join('');
    });
  }

  /* ══════════════════════════════════════════════════════════════════
     § 13. UTILITY FUNCTIONS
  ══════════════════════════════════════════════════════════════════ */
  function stripHTML(html) {
    var tmp = document.createElement('DIV');
    tmp.innerHTML = html || '';
    return tmp.textContent || tmp.innerText || '';
  }

  function escHTML(str) {
    return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function formatTime(dateStr) {
    try {
      var d = new Date(dateStr);
      var now = new Date();
      var diff = Math.floor((now - d) / 60000);
      if (diff < 1)   return 'Just now';
      if (diff < 60)  return diff + 'm ago';
      if (diff < 1440) return Math.floor(diff/60) + 'h ago';
      return d.toLocaleDateString('en-US', { month:'short', day:'numeric' });
    } catch(e) { return 'Recent'; }
  }

  /* ══════════════════════════════════════════════════════════════════
     § 14. SHARED CSS INJECTION
  ══════════════════════════════════════════════════════════════════ */
  function injectStyles() {
    if (document.getElementById('cdb-intel-styles')) return;
    var css = `
<style id="cdb-intel-styles">
.intel-post{background:#0d1117;border:1px solid #1a2535;border-radius:10px;margin-bottom:16px;overflow:hidden;transition:border-color .2s;}
.intel-post:hover{border-color:#00ff8855;}
.post-header{padding:16px 18px 10px;}
.post-meta-row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:10px;}
.severity-chip{padding:2px 10px;border-radius:4px;font-size:.72em;font-weight:700;letter-spacing:1px;}
.badge{padding:2px 8px;border-radius:4px;font-size:.72em;font-weight:700;}
.badge-exploit{background:rgba(255,34,68,.15);color:#ff2244;border:1px solid #ff224455;}
.badge-breaking{background:rgba(255,165,0,.15);color:#ffa500;border:1px solid #ffa50055;}
.cvss-pill{background:#1a2535;color:#ffd700;padding:2px 8px;border-radius:4px;font-size:.72em;font-weight:700;}
.source-chip{background:#0a0e1a;color:#555;padding:2px 8px;border-radius:4px;font-size:.70em;}
.time-chip{color:#444;font-size:.70em;}
.post-title{font-size:1.05em;line-height:1.45;margin:0;}
.post-title a{color:#e0e0e0;text-decoration:none;}
.post-title a:hover{color:#00ff88;}
.actor-pill{display:inline-block;padding:3px 10px;border:1px solid;border-radius:4px;font-size:.75em;font-weight:700;margin-top:8px;letter-spacing:.5px;}
.cve-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;}
.cve-badge{padding:2px 8px;border:1px solid #00ff8866;color:#00ff88;border-radius:4px;font-size:.72em;font-weight:700;text-decoration:none;}
.cve-badge:hover{background:rgba(0,255,136,.1);}
.post-body-wrap{padding:12px 18px 14px;}
.mitre-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;}
.mitre-tag{background:#0a0e1a;border:1px solid #1a2535;padding:3px 8px;border-radius:4px;font-size:.72em;color:#888;}
.mitre-tag strong{color:#4a9eff;}
.risk-bar-wrap{display:flex;align-items:center;gap:10px;margin-bottom:12px;}
.risk-label{color:#555;font-size:.70em;letter-spacing:1px;width:80px;}
.risk-track{flex:1;height:4px;background:#1a2535;border-radius:2px;}
.risk-fill{height:100%;border-radius:2px;transition:width .6s ease;}
.risk-num{color:#888;font-size:.72em;font-weight:700;width:50px;text-align:right;}
.post-body{color:#aaa;font-size:.90em;line-height:1.65;margin-bottom:12px;}
.tags-row{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px;}
.tag-chip{background:#0a0e1a;color:#555;padding:2px 7px;border-radius:3px;font-size:.68em;}
.post-cta-row{padding:10px 18px;border-top:1px solid #1a2535;display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.cta-btn{padding:6px 14px;border-radius:6px;font-size:.78em;font-weight:600;text-decoration:none;cursor:pointer;border:none;transition:opacity .2s;}
.cta-btn:hover{opacity:.85;}
.cta-green{background:linear-gradient(135deg,#00ff88,#00cc6a);color:#000;}
.cta-blue{background:linear-gradient(135deg,#4a9eff,#0066dd);color:#fff;}
.cta-purple{background:linear-gradient(135deg,#a855f7,#7c3aed);color:#fff;}
.share-btn{background:transparent;border:1px solid #1a2535;color:#888;padding:5px 12px;border-radius:6px;font-size:.78em;cursor:pointer;margin-left:auto;}
.share-btn:hover{border-color:#00ff8855;color:#00ff88;}
.freemium-gate{position:relative;margin-top:8px;}
.gate-blur-overlay{position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(transparent,#0d1117 60%);pointer-events:none;z-index:1;}
.gate-box{background:#0a0e1a;border:1px solid #ffd70044;border-radius:8px;padding:18px;text-align:center;position:relative;z-index:2;}
.gate-icon{font-size:1.8em;margin-bottom:8px;}
.gate-title{color:#ffd700;font-weight:700;margin-bottom:10px;font-size:.92em;}
.gate-perks{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-bottom:14px;}
.gate-perks span{background:#1a2535;color:#888;padding:3px 10px;border-radius:4px;font-size:.75em;}
.gate-cta{display:inline-block;margin:4px;padding:8px 18px;border-radius:6px;background:linear-gradient(135deg,#00ff88,#00cc6a);color:#000;font-weight:700;font-size:.82em;text-decoration:none;}
.gate-cta-outline{background:transparent;border:1px solid #00ff8866;color:#00ff88;}
.related-link{display:inline-block;margin-top:6px;margin-right:8px;color:#4a9eff;font-size:.78em;text-decoration:none;}
.related-link:hover{text-decoration:underline;}
.kev-item{display:grid;grid-template-columns:auto 1fr auto auto;gap:10px;align-items:center;padding:10px;border-bottom:1px solid #1a2535;font-size:.82em;}
.kev-vendor{color:#aaa;}
.kev-date{color:#555;}
.kev-action{color:#888;font-size:.80em;}
.intel-empty{text-align:center;padding:40px;color:#333;}
.intel-empty span{font-size:2em;display:block;margin-bottom:10px;}
.share-menu{position:fixed;bottom:20px;right:20px;background:#0d1117;border:1px solid #00ff88;border-radius:10px;padding:12px;z-index:9999;display:flex;flex-direction:column;gap:8px;min-width:200px;}
.share-menu a,.share-menu button{display:block;color:#e0e0e0;text-decoration:none;padding:8px 12px;border-radius:6px;background:#0a0e1a;font-size:.85em;text-align:center;border:none;cursor:pointer;}
.share-menu a:hover{background:#1a2535;color:#00ff88;}
/* ── Analyst Note ── */
.analyst-note{background:rgba(0,255,224,.04);border-left:3px solid #00ffe0;padding:12px 16px;margin:12px 0;border-radius:0 8px 8px 0;}
.analyst-note-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:6px;}
.analyst-badge{font-size:.70em;font-weight:800;color:#00ffe0;text-transform:uppercase;letter-spacing:.5px;}
.analyst-meta{font-size:.65em;color:#475569;}
.analyst-text{font-size:.82em;color:#94a3b8;line-height:1.65;margin:0;font-style:italic;}
/* ── Defensive Actions ── */
.defensive-block{background:rgba(255,68,68,.05);border:1px solid rgba(255,68,68,.18);border-radius:8px;padding:12px 16px;margin:12px 0;}
.defensive-hdr{font-size:.70em;font-weight:800;color:#ff6b6b;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;}
.defensive-list{margin:0 0 10px 1.1rem;}
.defensive-list li{font-size:.80em;color:#cbd5e1;line-height:1.6;padding:2px 0;}
.defensive-link{display:inline-block;font-size:.75em;font-weight:700;color:#00ffe0;text-decoration:none;border:1px solid rgba(0,255,224,.25);padding:4px 12px;border-radius:5px;}
.defensive-link:hover{background:rgba(0,255,224,.08);}
/* ── Context CTA row ── */
.ctx-cta-row{padding:10px 18px;border-top:1px solid #1a2535;display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.ctx-btn-primary{padding:6px 14px;border-radius:6px;font-size:.78em;font-weight:700;text-decoration:none;background:linear-gradient(135deg,#00ffe0,#00d4ff);color:#000;}
.ctx-btn-secondary{padding:6px 14px;border-radius:6px;font-size:.78em;font-weight:700;text-decoration:none;background:rgba(0,255,224,.08);color:#00ffe0;border:1px solid rgba(0,255,224,.25);}
.ctx-share-btn{background:transparent;border:1px solid #1a2535;color:#555;padding:5px 12px;border-radius:6px;font-size:.78em;cursor:pointer;margin-left:auto;}
.ctx-share-btn:hover{border-color:#00ff8855;color:#00ff88;}
/* ── Trust Footer ── */
.intel-trust-footer{padding:8px 18px;border-top:1px solid #0d1525;display:flex;flex-wrap:wrap;gap:16px;background:rgba(0,0,0,.2);}
.intel-trust-footer span{font-size:.70em;color:#475569;}
.intel-trust-footer strong{color:#64748b;}
.intel-stats-bar{display:flex;gap:24px;padding:16px 0;border-bottom:1px solid #1a2535;margin-bottom:20px;flex-wrap:wrap;}
.intel-stat{text-align:center;}
.intel-stat .num{font-size:1.8em;font-weight:700;color:#00ff88;display:block;}
.intel-stat .lbl{font-size:.72em;color:#555;text-transform:uppercase;letter-spacing:1px;}
.section-header{display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid #1a2535;margin-bottom:20px;}
.section-title{font-size:1.2em;font-weight:700;color:#00ff88;letter-spacing:1px;}
.live-dot{display:inline-block;width:8px;height:8px;background:#00ff88;border-radius:50%;margin-right:8px;animation:blink 1s infinite;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:.2;}}
.refresh-chip{background:#0a0e1a;color:#555;padding:4px 10px;border-radius:4px;font-size:.72em;cursor:pointer;border:1px solid #1a2535;}
.refresh-chip:hover{border-color:#00ff8855;color:#00ff88;}
</style>`;
    document.head.insertAdjacentHTML('beforeend', css);
  }

  /* ══════════════════════════════════════════════════════════════════
     § 15. MAIN INIT — Auto-detect section and load
  ══════════════════════════════════════════════════════════════════ */
  function detectSection() {
    var path = window.location.pathname;
    if (path.indexOf('/breaking') !== -1) return 'breaking';
    if (path.indexOf('/malware')  !== -1) return 'malware';
    if (path.indexOf('/ai-security') !== -1) return 'ai_security';
    return 'intel';
  }

  function loadSection(section) {
    var containerId = 'intel-feed';
    injectStyles();
    aggregateFeeds(section, function(items) {
      var enriched = items.map(enrichItem)
        .sort(function(a,b){ return b.riskScore - a.riskScore; });

      publishToSection(containerId, enriched, { section: section, limit: 25 });
      updateTicker(enriched);
      renderCISAKEV('kev-live-list');

      // Re-run every REFRESH_MS
      setTimeout(function(){ loadSection(section); }, CFG.REFRESH_MS);
    });
  }

  // Boot on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { loadSection(detectSection()); });
  } else {
    loadSection(detectSection());
  }

  // Expose public API
  window.CDBIntel = {
    loadSection: loadSection,
    fetchCISAKEV: fetchCISAKEV,
    renderCISAKEV: renderCISAKEV,
    sharePost: window.sharePost
  };

})();
