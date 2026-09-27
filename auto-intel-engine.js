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
      secondary: { cta:'SOC Intelligence Plans',            url:'/pricing.html' },
      sub: 'Evidence-backed ransomware context and available detection content, subject to validation state and entitlement.'
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
      primary:   { cta:'SOC Intelligence Plans',       url:'/pricing.html' },
      secondary: { cta:'📦 Browse Products',              url:'/products.html' },
      sub: 'Evidence-backed intelligence, detection context, and operational feeds.'
    }
  };

  /* ── ANALYST NOTE TEMPLATES ─────────────────────────────────────── */


  /* ── DEFENSIVE ACTIONS MAP ──────────────────────────────────────── */




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

  function fetchDashboardFeed(section, callback) {
    var url = '/api/v1/intel?action=dashboard&section=' + encodeURIComponent(section || 'intel') + '&limit=25';
    fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    })
      .then(function(r) {
        if (!r.ok) throw new Error('dashboard_http_' + r.status);
        return r.json();
      })
      .then(function(d) {
        if (!d || d.success !== true || !d.data || !Array.isArray(d.data.items)) {
          throw new Error('dashboard_contract_invalid');
        }
        callback(null, d.data);
      })
      .catch(function(err) { callback(err, null); });
  }

  function normalizeDashboardItem(item) {
    var severity = String(item && item.severity || 'NOT_ASSESSED').toLowerCase();
    if (!/^(critical|high|medium|low)$/.test(severity)) severity = 'not_assessed';
    return {
      title:       item && item.title || 'Untitled intelligence record',
      link:        item && (item.source_url || item.report_url) || '#',
      pubDate:     item && item.published || null,
      source:      item && item.source || 'sentinel_apex',
      rawContent:  item && item.description || '',
      severity:    severity,
      cveIds:      item && Array.isArray(item.cves) ? item.cves.slice(0, 5) : [],
      mitreMap:    [],
      threatActor: null,
      cvssScore:   item && Number.isFinite(Number(item.cvss)) ? Number(item.cvss) : null,
      tags:        [],
      isExploited: !!(item && item.exploited),
      ransomware:  !!(item && item.ransomware),
      isCritical:  severity === 'critical',
      isBreaking:  false,
      riskScore:   null,
      postContext: detectPostContext(((item && item.title) || '') + ' ' + ((item && item.description) || '')),
      recordId:    item && item.id || null,
      reportId:    item && item.report_id || null,
      reportUrl:   item && item.report_url || null
    };
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
      pubDate:     item.pubDate || null,
      source:      extractSource(item.link || ''),
      rawContent:  item.content || item.description || '',
      severity:    'not_assessed',
      cveIds:      extractCVEs(text),
      mitreMap:    mapMITRE(text),
      threatActor: detectThreatActor(text),
      cvssScore:   null,
      tags:        extractTags(text),
      isExploited: false,
      isCritical:  false,
      isBreaking:  false,
      riskScore:   null,
      postContext: detectPostContext(text)
    };
    // Risk is not synthesized from keyword heuristics. Use source-backed severity/exploitation evidence only.
    return enriched;
  }

  function extractCVEs(text) {
    var matches = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
    return [...new Set(matches)].slice(0, 5);
  }

  function mapMITRE(text) {
    // ATT&CK mappings require canonical behavioral evidence from ReportX.
    // Browser keyword matching must never manufacture technique claims.
    return [];
  }

  function detectThreatActor(text) {
    // Attribution requires source-bound canonical claims. Do not infer actors
    // or nationality from keyword occurrence in browser-rendered text.
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

  /* ══════════════════════════════════════════════════════════════════
     § 6b. POST ENRICHMENT BLOCKS — Analyst Note / Actions / CTA / Trust
  ══════════════════════════════════════════════════════════════════ */
  function generateAnalystNote(item) {
    return '<div class="analyst-note"><div class="analyst-note-hdr"><span class="analyst-badge">EVIDENCE STATUS</span></div><p class="analyst-text">Automated source enrichment only. No human analyst assessment is asserted by this view. Inspect canonical claim and evidence records before operational action.</p></div>';
  }

  function generateDefensiveActions(item) {
    return '<div class="defensive-block"><div class="defensive-hdr">OPERATIONAL ACTION</div><p class="analyst-text">Validate affected assets, cited evidence, exploitation state and detection maturity before containment, blocking or deployment decisions.</p></div>';
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
    return '<div class="intel-trust-footer"><span>Evidence-first intelligence</span><span>Freshness verified at runtime</span><span>No synthetic customer or coverage metrics</span><span><a href="/rss.xml" style="color:#475569;text-decoration:none">RSS Feed</a></span></div>';
  }

  /* ══════════════════════════════════════════════════════════════════
     § 7. POST GENERATOR — Full HTML Article
  ══════════════════════════════════════════════════════════════════ */
  function generatePostHTML(item, isPremium) {
    var sevColor  = { critical:'#ff2244', high:'#ff6600', medium:'#ffd700', low:'#44ff88', not_assessed:'#94a3b8' };
    var sevBg     = { critical:'rgba(255,34,68,0.12)', high:'rgba(255,102,0,0.12)', medium:'rgba(255,215,0,0.10)', low:'rgba(68,255,136,0.10)', not_assessed:'rgba(148,163,184,0.10)' };
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

    var riskBar = '<div class="risk-bar-wrap"><div class="risk-label">EVIDENCE-BASED PRIORITY</div><span class="risk-num">'+ item.severity.toUpperCase() +'</span></div>';

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
    var sourceUrl = safeExternalUrl(item.link);
    var exploitBadge = item.isExploited ? '<span class="badge badge-exploit">● ACTIVELY EXPLOITED</span>' : '';
    var breakingBadge = item.isBreaking ? '<span class="badge badge-breaking">⚡ BREAKING</span>' : '';

    var reportAttr = item.reportId ? ' data-report-id="' + escHTML(item.reportId) + '"' : '';
    var recordAttr = item.recordId ? ' data-record-id="' + escHTML(item.recordId) + '"' : '';
    var reportUrlAttr = item.reportUrl ? ' data-report-url="' + escHTML(item.reportUrl) + '"' : '';
    return `<article class="intel-post" data-severity="${item.severity}"${recordAttr}${reportAttr}${reportUrlAttr}>
  <div class="post-header" style="border-left:4px solid ${sc};background:${sb}">
    <div class="post-meta-row">
      <span class="severity-chip" style="background:${sc};color:#000">${item.severity.toUpperCase()}</span>
      ${exploitBadge}${breakingBadge}
      ${item.cvssScore ? `<span class="cvss-pill">CVSS ${item.cvssScore}</span>` : ''}
      <span class="source-chip">${escHTML(item.source)}</span>
      <span class="time-chip">🕐 ${timeStr}</span>
    </div>
    <h2 class="post-title">${sourceUrl ? '<a href="' + escHTML(sourceUrl) + '" target="_blank" rel="noopener noreferrer">' + escHTML(item.title) + '</a>' : escHTML(item.title)}</h2>
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
    return '<div class="freemium-gate"><div class="gate-box"><div class="gate-icon">🔒</div><div class="gate-title">Additional Intelligence Requires Entitlement</div><div class="gate-perks"><span>Plan-scoped evidence and operational context are delivered only when available and entitled.</span></div><a class="gate-cta" href="/pricing.html">View Intelligence Plans</a></div></div>';
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
      setRuntimeState('UNAVAILABLE', 'No verified intelligence records are currently available.');
      container.innerHTML = '<div class="intel-empty"><span>⚠</span><p>Intelligence temporarily unavailable. No stale or synthetic records are being substituted.</p></div>';
      return;
    }

    // Filter by section type
    var filtered = items;
    if (options.section === 'malware') {
      filtered = items.filter(function(i) {
        return i.ransomware === true || /malware|ransomware|trojan|worm|botnet|spyware|keylog|stealer|rat\b/i.test(i.title + ' ' + i.rawContent);
      });
    } else if (options.section === 'ai_security') {
      filtered = items.filter(function(i) {
        return /ai|llm|gpt|artificial intel|machine learn|prompt|copilot|chatgpt|claude|gemini/i.test(i.title + ' ' + i.rawContent);
      });
    } else if (options.section === 'breaking') {
      filtered = items.filter(function(i) { return i.isBreaking || i.isExploited || i.severity === 'critical'; });
    }

    if (!filtered.length) {
      container.innerHTML = '<div class="intel-empty"><span>⚠</span><p>No evidence-matched intelligence is currently available for this workspace. Unrelated records are not substituted.</p></div>';
      updateLiveCounts([]);
      return;
    }

    var html = filtered.slice(0, limit).map(function(item) {
      return generatePostHTML(item, isPremium);
    }).join('\n');

    container.innerHTML = html;
    updateLiveCounts(filtered);
    injectInternalLinks(container);
  }

  function setRuntimeState(state, detail) {
    var el = document.getElementById('intel-runtime-state');
    if (!el) {
      el = document.createElement('div');
      el.id = 'intel-runtime-state';
      el.className = 'intel-runtime-state';
      var feed = document.getElementById('intel-feed');
      if (feed && feed.parentNode) feed.parentNode.insertBefore(el, feed);
    }
    el.setAttribute('data-state', state);
    el.textContent = state + (detail ? ' · ' + detail : '');
    var socState = document.getElementById('soc-runtime-state');
    if (socState) {
      socState.setAttribute('data-state', state);
      socState.textContent = state;
      socState.title = detail || '';
    }
  }

  function newestTimestamp(items) {
    var times = items.map(function(i) { return new Date(i.pubDate || i.date || 0).getTime(); })
      .filter(function(t) { return Number.isFinite(t) && t > 0; });
    return times.length ? Math.max.apply(Math, times) : 0;
  }

  function updateRuntimeState(items, generatedAt) {
    var generated = generatedAt ? new Date(generatedAt).getTime() : 0;
    var newest = Number.isFinite(generated) && generated > 0 ? generated : newestTimestamp(items);
    if (!newest) return setRuntimeState('DEGRADED', 'Freshness timestamp unavailable');
    var ageMinutes = Math.max(0, Math.floor((Date.now() - newest) / 60000));
    if (ageMinutes <= 240) return setRuntimeState('LIVE', 'First-party feed verified ' + ageMinutes + 'm ago');
    setRuntimeState('STALE', 'First-party feed last generated ' + ageMinutes + 'm ago');
  }

  function updateLiveCounts(items) {
    var critical = items.filter(function(i){ return i.severity === 'critical'; }).length;
    var exploited = items.filter(function(i){ return i.isExploited; }).length;
    var cveCount = items.reduce(function(acc, i){ return acc + i.cveIds.length; }, 0);

    setCount('intel-critical-count', critical);
    setCount('intel-exploited-count', exploited);
    setCount('intel-cve-count', cveCount);
    setCount('intel-total-count', items.length);
    setCount('soc-critical', critical);
    setCount('soc-exploited', exploited);
    setCount('soc-reports', items.length);
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
  function safeExternalUrl(value) {
    try {
      var u = new URL(String(value || '').trim());
      if (u.protocol !== 'https:' || u.username || u.password) return null;
      return u.href;
    } catch (e) { return null; }
  }

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
      if (!dateStr) return 'Timestamp unavailable';
      var d = new Date(dateStr);
      if (Number.isNaN(d.getTime())) return 'Timestamp unavailable';
      var now = new Date();
      var diff = Math.floor((now - d) / 60000);
      if (diff < 1)   return 'Just now';
      if (diff < 60)  return diff + 'm ago';
      if (diff < 1440) return Math.floor(diff/60) + 'h ago';
      return d.toLocaleDateString('en-US', { month:'short', day:'numeric' });
    } catch(e) { return 'Timestamp unavailable'; }
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
.intel-empty{text-align:center;padding:40px;color:#64748b;}
.intel-runtime-state{margin:0 0 12px;padding:8px 12px;border:1px solid #1a2535;border-radius:6px;font-size:.74em;font-weight:800;letter-spacing:.06em;color:#94a3b8;background:#0a0e1a;}
.intel-runtime-state[data-state="LIVE"]{color:#00ff88;border-color:#00ff8844;}
.intel-runtime-state[data-state="STALE"]{color:#ffd166;border-color:#ffd16644;}
.intel-runtime-state[data-state="DEGRADED"],.intel-runtime-state[data-state="UNAVAILABLE"]{color:#ff6b6b;border-color:#ff6b6b44;}
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
    setRuntimeState('VERIFYING', 'Checking first-party dashboard intelligence');
    fetchDashboardFeed(section, function(err, payload) {
      if (err || !payload) {
        setRuntimeState('UNAVAILABLE', 'First-party dashboard feed unavailable; no synthetic fallback substituted');
        updateLiveCounts([]);
        var container = document.getElementById(containerId);
        if (container) container.innerHTML = '<div class="intel-empty"><span>⚠</span><p>First-party intelligence is temporarily unavailable. The dashboard will retry automatically; no third-party or synthetic records are substituted.</p></div>';
        setTimeout(function(){ loadSection(section); }, Math.min(CFG.REFRESH_MS, 120000));
        return;
      }

      var enriched = payload.items.map(normalizeDashboardItem);
      publishToSection(containerId, enriched, { section: section, limit: 25 });
      updateRuntimeState(enriched, payload.generated_at);
      updateTicker(enriched);
      renderCISAKEV('kev-live-list');

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
