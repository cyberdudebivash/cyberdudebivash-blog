/**
 * CYBERDUDEBIVASH — LIVE FEED WIDGET v4.0
 * ═══════════════════════════════════════════════════════════
 * Multi-source, evidence-preserving feed renderer.
 *
 * Live source: /live-intel.json — first-party source-verified feed.
 * If the feed is stale or unavailable, withhold live cards and link out to
 * the official CISA KEV catalog. Never substitute third-party content as live.
 *
 * © 2025 CYBERDUDEBIVASH. All rights reserved.
 * ═══════════════════════════════════════════════════════════
 */
(function () {
  'use strict';

  /* ── CONFIG ─────────────────────────────────────────────── */
  var CFG = {
    LOCAL_JSON:  '/live-intel.json',
    CONTAINER_ID:'live-intel-feed',
    CACHE_KEY:   'cbd_lfw_v5',
    CACHE_TTL:   55 * 1000,        // 55s — just under refresh interval
    // The intel pipeline publishes every ~1.5-5 h; polling faster only adds
    // requests (docs/operations/CLOUDFLARE-COST-GUARDRAILS.md).
    REFRESH_MS:  15 * 60 * 1000,
    MAX_CARDS:   15,               // v5: show more cards
    LOOKBACK_DAYS: 1
  };

  /* ── HELPERS ─────────────────────────────────────────────── */
  function timeAgo(d) {
    if (!d) return 'recently';
    var diff = Math.floor((Date.now() - new Date(d)) / 1000);
    if (diff < 60)     return diff + 's ago';
    if (diff < 3600)   return Math.floor(diff/60) + 'm ago';
    if (diff < 86400)  return Math.floor(diff/3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff/86400) + 'd ago';
    return new Date(d).toLocaleDateString([],{month:'short',day:'numeric'});
  }

  // Browser retrieval time is not evidence that intelligence was newly
  // generated. Unknown/future timestamps fail closed rather than showing
  // a reassuring green or 'breaking' state.
  function classifyFeedTimestamp(value, nowMillis) {
    var now = Number.isFinite(nowMillis) ? nowMillis : Date.now();
    var stamp = typeof value === 'string' && value.trim() ? Date.parse(value) : NaN;
    if (!Number.isFinite(stamp) || stamp < 0 || stamp > now) {
      return { state: 'unverified', publishedAt: null };
    }
    return {
      state: now - stamp > 180 * 60000 ? 'stale' : 'current',
      publishedAt: stamp
    };
  }

  function esc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // Report links are controlled by intelligence data, not trusted HTML.
  // Restrict them to the actual SENTINEL APEX-owned report hosts and HTTPS.
  // Never render javascript:, data:, userinfo, or third-party redirect URLs.
  var REPORT_HOSTS = Object.freeze({
    'soc.cyberdudebivash.in': true,
    'blog.cyberdudebivash.in': true,
    'cti.cyberdudebivash.in': true,
    'intel.cyberdudebivash.com': true
  });
  function safeReportHref(value) {
    if (typeof value !== 'string' || !value || value.length > 2048 ||
        /[\u0000-\u001f\u007f]/.test(value)) return null;
    try {
      var u = new URL(value, window.location.origin);
      if (u.protocol !== 'https:' || u.username || u.password ||
          !Object.prototype.hasOwnProperty.call(REPORT_HOSTS, u.hostname.toLowerCase())) return null;
      return u.href;
    } catch (e) { return null; }
  }
  function safeThreatColor(value) {
    return typeof value === 'string' && /^#[0-9a-fA-F]{6}$/.test(value) ? value : '#00b4d8';
  }

  function slugify(s) {
    return String(s||'').toLowerCase().replace(/[^a-z0-9\s-]/g,' ').replace(/\s+/g,'-').replace(/-{2,}/g,'-').replace(/^-|-$/g,'').slice(0,90);
  }

  function getCache() {
    try {
      var r = sessionStorage.getItem(CFG.CACHE_KEY);
      if (!r) return null;
      var o = JSON.parse(r);
      if (Date.now() - o.ts > CFG.CACHE_TTL) return null;
      return o.data;
    } catch(e) { return null; }
  }

  function setCache(data) {
    try { sessionStorage.setItem(CFG.CACHE_KEY, JSON.stringify({ts:Date.now(),data:data})); } catch(e){}
  }

  function firstHttpUrl(values) {
    var text = Array.isArray(values) ? values.join(' ') : String(values||'');
    var match = text.match(/https?:\/\/[^\s<>"'`;,)\]]+/i);
    if (!match) return null;
    try {
      var parsed = new URL(match[0].replace(/[.!?:}\]]+$/g,''));
      return /^https?:$/.test(parsed.protocol) ? parsed.href : null;
    } catch(e) { return null; }
  }

  /* ── THREAT CLASSIFIER ───────────────────────────────────── */
  var THREATS = [
    { t:'RCE',         l:'Remote Code Execution', c:'#ff2d55', k:['remote code execution','arbitrary code','execute code','rce'] },
    { t:'LPE',         l:'Privilege Escalation',  c:'#ff6b00', k:['privilege escalation','elevat','local privilege'] },
    { t:'AUTH_BYPASS', l:'Auth Bypass',            c:'#ff9500', k:['authentication bypass','unauthenticated','improper auth'] },
    { t:'UAF',         l:'Use-After-Free',         c:'#ff4757', k:['use-after-free','use after free'] },
    { t:'OVERFLOW',    l:'Buffer Overflow',        c:'#ff6348', k:['buffer overflow','out-of-bounds write','memory corruption'] },
    { t:'SQLI',        l:'SQL Injection',          c:'#cc44ff', k:['sql injection'] },
    { t:'XSS',         l:'XSS',                   c:'#2ed573', k:['cross-site scripting','xss'] },
    { t:'ZERO_DAY',    l:'Zero-Day',               c:'#ff0000', k:['zero-day','0-day','actively exploit','in the wild'] },
    { t:'SUPPLY',      l:'Supply Chain',           c:'#ff6b81', k:['supply chain','malicious package'] },
    { t:'SSRF',        l:'SSRF',                   c:'#e056fd', k:['server-side request forgery','ssrf'] }
  ];

  function classify(desc) {
    var d = (' '+(desc||'')+' ').toLowerCase();
    for (var i=0;i<THREATS.length;i++) {
      var p=THREATS[i];
      for (var j=0;j<p.k.length;j++) {
        if (d.indexOf(p.k[j])!==-1) return {type:p.t,label:p.l,color:p.c};
      }
    }
    return {type:'CVE',label:'Vulnerability',color:'#00b4d8'};
  }

  function sevColor(s) {
    var n=parseFloat(s);
    if (isNaN(n)) return {l:'N/A',c:'#555'};
    if (n>=9) return {l:'CRITICAL',c:'#ff2d55'};
    if (n>=7) return {l:'HIGH',c:'#ff6b00'};
    if (n>=4) return {l:'MEDIUM',c:'#ffd700'};
    return {l:'LOW',c:'#2ed573'};
  }

  /* ── FETCH — with timeout ────────────────────────────────── */
  function xhrFetch(url, timeoutMs) {
    return new Promise(function(resolve) {
      try {
        var xhr = new XMLHttpRequest();
        var done = false;
        var timer = setTimeout(function() {
          if (!done) { done=true; xhr.abort(); resolve(null); }
        }, timeoutMs||10000);
        xhr.open('GET', url);
        xhr.onreadystatechange = function() {
          if (xhr.readyState!==4||done) return;
          done=true; clearTimeout(timer);
          if (xhr.status===200) {
            try { resolve(JSON.parse(xhr.responseText)); }
            catch(e) { resolve(null); }
          } else { resolve(null); }
        };
        xhr.onerror = function() { if(!done){done=true;clearTimeout(timer);resolve(null);} };
        xhr.send();
      } catch(e) { resolve(null); }
    });
  }

  /* ── NORMALISE local-json items → our shape ──────────────── */
  function normaliseLocal(item) {
    if (!item) return null;
    var desc = item.desc||item.description||'';
    var threat = (item.threatLabel&&item.threatColor)
      ? {type:item.threatType||'CVE', label:item.threatLabel, color:item.threatColor}
      : classify(desc);
    // FIX: resolve post URL here so buildCard always has a valid href
    // Priority: item.link (absolute URL) > /posts/{slug}.html > null (shows no button)
    var postLink = item.link || (item.slug ? '/posts/'+item.slug+'.html' : null) || null;
    return {
      id:       item.id||item.cveID||'—',
      desc:     desc,
      score:    item.cvss!=null?item.cvss:(item.score!=null?item.score:null),
      published:item.pubDate||item.published||item.dateAdded||null,
      vendors:  item.vendors||[item.vendor||'Unknown'],
      product:  item.product||'',
      source:   item.source||'SENTINEL',
      exploited:!!item.exploited,
      dueDate:  item.dueDate||null,
      refs:     item.refs||[],
      threat:   threat,
      slug:     item.slug||null,
      link:     postLink
    };
  }

  /* ── RECENT SOURCE SELECTION ──────────────────────────────── */
  // The canonical feed is scored/priority-ranked, not chronological. Rendering
  // it in file order put months-old CVEs ahead of newly verified reports and
  // created up to 150 DOM cards despite the 15-card customer UX ceiling.
  // A new pipeline heartbeat is NOT evidence that its individual reports
  // are newly published; rank by their own recorded creation/publication time.
  // FAIL-CLOSED: the shared runtime is the only authority for the two
  // independent record clocks: first-party ingestion <=24h and source
  // publication <=72h. A timestamp-only fallback can surface an old advisory
  // newly ingested or a zone-less timestamp as "live"; never use one.
  function sharedLiveAuthority() {
    var shared = typeof window !== 'undefined' ? window.SentinelRuntimeState : null;
    return shared && typeof shared.isLiveRecord === 'function' &&
      typeof shared.pipelineAllowsLive === 'function' &&
      typeof shared.classifyFeed === 'function' ? shared : null;
  }
  function selectLocalItems(rawItems, nowMs) {
    var shared = sharedLiveAuthority();
    if (!Array.isArray(rawItems) || !shared) return [];
    var now = Number.isFinite(nowMs) ? nowMs : Date.now();
    var cutoff = now - CFG.LOOKBACK_DAYS * 86400000;
    var dated = rawItems.map(function(raw, index) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
      if (!shared.isLiveRecord(raw, now)) return null;
      var ts = Date.parse(raw._addedAt);
      if (!Number.isFinite(ts) || ts > now || ts < cutoff) return null;
      var item = normaliseLocal(raw);
      if (!item) return null;
      return {item:item, time:ts, index:index,
        priority:Number(raw.priority)||0,
        sourcePublished:raw.pubDate||raw.published||raw.dateAdded||null};
    }).filter(Boolean);
    dated.sort(function(a,b) {
      return b.time-a.time || b.priority-a.priority || a.index-b.index;
    });
    var seen = Object.create(null);
    return dated.filter(function(record) {
      var key = String(record.item.id || record.item.link || record.item.slug || '').trim();
      if (!key || seen[key]) return false;
      seen[key] = true;
      return true;
    }).slice(0, CFG.MAX_CARDS).map(function(record) {
      // Do not rewrite the source's publication date as the ingestion time.
      record.item.published = record.sourcePublished;
      record.item._sourcePublishedAt = record.sourcePublished;
      record.item._reportAddedAt = new Date(record.time).toISOString();
      record.item._contentArchived = false;
      return record.item;
    });
  }

  // Re-evaluate when rendering, restoring browser session cache, and on the
  // 5s UI ticker. A green fetch does not authorize stale DOM cards to survive
  // the time window, and an absent runtime model withholds every "live" card.
  function verifiedLiveItems(items, nowMs) {
    var shared = sharedLiveAuthority();
    if (!shared || !Array.isArray(items) || !items.length) return false;
    var now = Number.isFinite(nowMs) ? nowMs : Date.now();
    var stamp = items[0]._feedGenerated;
    if (typeof stamp !== 'string' || !stamp.trim() ||
        classifyFeedTimestamp(stamp, now).state !== 'current') return false;
    var classification = shared.classifyFeed({
      ok:true, feed:{generatedAt:stamp,metadata:{lastReportGeneratedAt:stamp}}, nowMs:now
    });
    if (!shared.pipelineAllowsLive(classification, now)) return false;
    return items.every(function(item) {
      return item && item._contentArchived !== true &&
        typeof item._reportAddedAt === 'string' &&
        typeof item._sourcePublishedAt === 'string' &&
        item._feedGenerated === stamp &&
        shared.isLiveRecord({_addedAt:item._reportAddedAt,
          pubDate:item._sourcePublishedAt}, now);
    });
  }

  /* ── MAIN FETCH PIPELINE ─────────────────────────────────── */
  function pipeline() {
    // Same-origin first-party evidence only. Never silently replace a failed
    // SOC/CTI source with an unverified external CISA feed and present it in
    // the same LIVE card grid; the official CISA catalog remains a link in
    // the withheld state, not a fabricated first-party release.
    return xhrFetch(CFG.LOCAL_JSON+'?_='+Math.floor(Date.now()/60000), 8000)
      .then(function(data) {
        if (!data || !Array.isArray(data.items)) return [];
        var shared = sharedLiveAuthority();
        var stamp = shared && typeof shared.feedTimestamp === 'function' ?
          shared.feedTimestamp(data) : null;
        var parsed = typeof stamp === 'string' ? Date.parse(stamp) : NaN;
        _lastFetchAt = Number.isFinite(parsed) ? parsed : null;
        if (!shared || !shared.pipelineAllowsLive(
          shared.classifyFeed({ok:true,feed:data}), Date.now())) return [];
        var selected = selectLocalItems(data.items);
        return selected.map(function(item) {
          item._feedGenerated = stamp;
          return item;
        });
      })
      .catch(function(){return [];});
  }

  /* ── RENDER CARD ─────────────────────────────────────────── */
  function stripEntities(s) {
    // Decode multiple entity layers before stripping tags (Reddit/SANS feeds
    // often double-encode HTML fragments).
    var out=String(s||'');
    for(var i=0;i<3;i++) out=out.replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&nbsp;/gi,' ');
    // Strip both well-formed tags and truncated tags such as an upstream
    // '<img src="https://...' fragment. They must never leak as report prose.
    return out.replace(/<\/?[a-z][^>]*(?:>|$)/gi,' ').replace(/\s+/g,' ').trim();
  }

  function card(item) {
    var rawThreat = item.threat || classify(item.desc||'');
    // Feed and session-cache values may be attacker-influenced; reject CSS
    // attribute injection even when the JSON was generated first-party.
    var threat = {
      label: rawThreat.label, color: safeThreatColor(rawThreat.color),
    };
    var sev    = sevColor(item.score);
    var vendor = (item.vendors&&item.vendors[0])||item.product||'Unknown';
    // Strip raw HTML entities from description before display
    var rawDesc = stripEntities(item.desc||'');
    var desc   = rawDesc.slice(0,175) + (rawDesc.length>175?'…':'');
    var product= item.product||(item.desc&&'')||'';
    // Use item.slug directly when available (populated by pipeline),
    // avoiding the ID-hash fallback that generates non-existent post URLs.
    var slug   = item.slug || slugify((item.id||'')+(vendor?'-'+vendor:'')+(product&&product!==vendor?'-'+product:''));
    var href   = safeReportHref(item.link) ||
      safeReportHref(item.slug ? '/posts/'+item.slug+'.html' : null);
    var sourceHref = firstHttpUrl(item.refs);

    var badges = '';
    if (item.exploited) badges += '<span class="lfw-b lfw-b-exploit">⚡ ACTIVELY EXPLOITED</span>';
    if ((item.source||'').indexOf('CISA')!==-1) badges += '<span class="lfw-b lfw-b-cisa">🛡 CISA KEV</span>';
    if (item.dueDate) badges += '<span class="lfw-b lfw-b-due">⏰ Patch by '+esc(item.dueDate)+'</span>';
    if (item.score!=null) {
      badges += '<span class="lfw-b lfw-b-score" style="background:'+sev.c+'15;color:'+sev.c+';border-color:'+sev.c+'40">CVSS '+esc(item.score)+' — '+sev.l+'</span>';
    }

    return '<article class="lfw-card'+(item.exploited?' lfw-card-hot':'')+'" style="--tc:'+threat.color+'">'
      +'<div class="lfw-ct">'
        +'<div class="lfw-ctl">'
          +'<span class="lfw-tag" style="color:'+threat.color+';border-color:'+threat.color+'44">'+esc(threat.label)+'</span>'
          +'<span class="lfw-src">'+esc(item.source||'SENTINEL')+'</span>'
        +'</div>'
        +'<time class="lfw-ago">'+timeAgo(item.published)+'</time>'
      +'</div>'
      +'<div class="lfw-cb">'
        +'<h3 class="lfw-cve">'+esc(item.id)+'</h3>'
        +'<div class="lfw-vendor">🎯 '+esc(vendor)+(item.product&&item.product!==vendor?' · '+esc(item.product):'')+'</div>'
        +(desc?'<p class="lfw-desc">'+esc(desc)+'</p>':'')
        +'<div class="lfw-badges">'+badges+'</div>'
      +'</div>'
      +'<div class="lfw-cf">'
        +(href ? '<a href="'+esc(href)+'" class="lfw-read">🔍 Full Intel Report →</a>' :
          '<span class="lfw-read lfw-unavailable">Report link unavailable</span>')
        +(sourceHref?'<a href="'+esc(sourceHref)+'" class="lfw-ref" target="_blank" rel="noopener noreferrer">Source ↗</a>':'')
      +'</div>'
    +'</article>';
  }

  /* ── RENDER WIDGET ───────────────────────────────────────── */
  function render(items, container, animate) {
    if (!verifiedLiveItems(items)) {
      renderUnavailable(container);
      return;
    }
    _displayedItems = items;
    var exploited = items.filter(function(i){return i.exploited;}).length;
    var critical  = items.filter(function(i){return parseFloat(i.score)>=9;}).length;
    var verdict   = classifyFeedTimestamp(items[0] && items[0]._feedGenerated);
    var archived  = items[0] && items[0]._contentArchived === true;
    var stale     = verdict.state !== 'current' || archived;
    var ts        = verdict.publishedAt !== null ? timeAgo(verdict.publishedAt) : 'timestamp unavailable';
    _lastFetchAt  = verdict.publishedAt;
    var heading   = verdict.state === 'unverified' ? 'SOURCE TIMESTAMP UNVERIFIED' :
      verdict.state === 'stale' ? 'STALE FEED — LAST VERIFIED INTEL' :
      archived ? 'ARCHIVAL INTEL — NO RECENT REPORTS' : 'VERIFIED THREAT INTEL';
    var updateLabel = verdict.state === 'unverified' ? 'Source timestamp unavailable' :
      verdict.state === 'stale' ? 'Feed stale · '+ts :
      archived ? 'No reports added in last '+CFG.LOOKBACK_DAYS+' days · Source generated '+ts :
      'Source generated · '+ts;
    var grid      = items.map(card).join('');

    if (animate) {
      var g = container.querySelector('.lfw-grid');
      if (g) {
        g.style.opacity='0';
        setTimeout(function(){
          if (!verifiedLiveItems(items)) {
            renderUnavailable(container);
            return;
          }
          g.innerHTML=grid; g.style.opacity='1';
          var ns=container.querySelectorAll('.lfw-sn');
          if(ns[0]) ns[0].textContent=exploited;
          if(ns[1]) ns[1].textContent=critical;
          if(ns[2]) ns[2].textContent=items.length;
          var u=container.querySelector('.lfw-upd'); if(u) u.textContent=updateLabel;
          var b=container.querySelector('.lfw-bt'); if(b) b.textContent=heading;
          var dot=container.querySelector('.lfw-dot');
          if(dot) dot.classList.toggle('lfw-dot-load',stale);
        }, 300);
        return;
      }
    }

    container.innerHTML =
      '<div class="lfw-wrap">'
      +'<div class="lfw-hdr">'
        +'<div class="lfw-hdr-r1">'
          +'<div class="lfw-brand"><span class="lfw-dot'+(stale?' lfw-dot-load':'')+'"></span><span class="lfw-bt">'+heading+'</span><span class="lfw-bs">SENTINEL APEX</span></div>'
          +'<button class="lfw-btn-r" id="lfw-refresh-btn" title="Refresh">⟳</button>'
        +'</div>'
        +'<div class="lfw-hdr-r2">'
          +'<span class="lfw-stat"><span class="lfw-sn lfw-sn-e">'+exploited+'</span> Exploited</span>'
          +'<span class="lfw-stat"><span class="lfw-sn lfw-sn-c">'+critical+'</span> Critical</span>'
          +'<span class="lfw-stat"><span class="lfw-sn lfw-sn-t">'+items.length+'</span> Threats</span>'
          +'<span class="lfw-stat lfw-upd">'+updateLabel+'</span>'
        +'</div>'
      +'</div>'
      +'<div class="lfw-grid" style="transition:opacity .3s">'+grid+'</div>'
      +'<div class="lfw-foot">'
        +'<span class="lfw-copy">© 2025 CYBERDUDEBIVASH · Sentinel APEX · cyberdudebivash.com</span>'
        +'<span class="lfw-note">Status reflects the source feed timestamp</span>'
      +'</div>'
    +'</div>';

    var btn=document.getElementById('lfw-refresh-btn');
    if(btn) btn.addEventListener('click',function(){
      btn.style.animation='lfw-spin .7s linear infinite';
      doFetch(container,true).then(function(){ btn.style.animation=''; });
    });
  }

  /* ── SKELETON ────────────────────────────────────────────── */
  function skeleton(container) {
    var s='';
    for(var i=0;i<6;i++) s+='<div class="lfw-card lfw-skel"><div class="lfw-sk s60"></div><div class="lfw-sk s80"></div><div class="lfw-sk s100"></div><div class="lfw-sk s65"></div></div>';
    container.innerHTML='<div class="lfw-wrap"><div class="lfw-hdr"><div class="lfw-hdr-r1"><div class="lfw-brand"><span class="lfw-dot lfw-dot-load"></span><span class="lfw-bt">FETCHING LIVE INTEL…</span></div></div></div><div class="lfw-grid">'+s+'</div></div>';
  }

  function renderUnavailable(container) {
    _displayedItems = [];
    var sourceAge = _lastFetchAt == null ? null : Date.now() - _lastFetchAt;
    var stale = sourceAge != null && sourceAge > 180 * 60000;
    var label = stale ? 'STALE SOURCE — LIVE CARDS WITHHELD' :
      'NO CURRENT VERIFIED INTELLIGENCE';
    var detail = stale ?
      'This first-party feed is past its 180-minute freshness limit. No old records are displayed as live.' :
      'The first-party feed is unavailable or has no source-verified reports in the live window.';
    container.innerHTML='<div class="lfw-wrap"><div class="lfw-hdr"><div class="lfw-brand">'
      +'<span class="lfw-dot lfw-dot-load"></span><span class="lfw-bt">'+label+'</span>'
      +'<span class="lfw-bs">SENTINEL APEX</span></div></div>'
      +'<div role="status" aria-live="polite" style="padding:24px;color:#8899aa;font-size:13px;line-height:1.6">'
      +detail+' Historical reports are available only in the '
      +'<a href="/archive.html" style="color:#00b4d8">Intelligence Archive</a>. '
      +'For independent official advisories, consult the '
      +'<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noopener noreferrer" target="_blank" style="color:#00b4d8">CISA KEV catalog</a>.'
      +'</div></div>';
  }

  /* ── DO FETCH ────────────────────────────────────────────── */
  function doFetch(container, refresh) {
    if (!refresh) {
      var cached = getCache();
      if (cached && verifiedLiveItems(cached)) {
        render(cached, container, false); return Promise.resolve();
      }
      skeleton(container);
    }
    return pipeline().then(function(items) {
      if (items && items.length) {
        setCache(items);
        render(items, container, refresh);
      } else {
        renderUnavailable(container);
      }
      return items;
    });
  }

  /* ── INJECT CSS ──────────────────────────────────────────── */
  function injectCSS() {
    if (document.getElementById('lfw-css')) return;
    var css=[
      '.lfw-wrap{background:#09090f;border:1px solid #16213e;border-radius:14px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0 0 32px}',
      '.lfw-hdr{background:linear-gradient(135deg,#0c0c1a,#091428);border-bottom:1px solid #16213e;padding:16px 20px 12px}',
      '.lfw-hdr-r1{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}',
      '.lfw-brand{display:flex;align-items:center;gap:10px;flex-wrap:wrap}',
      '.lfw-dot{width:10px;height:10px;border-radius:50%;background:#ff2d55;box-shadow:0 0 8px #ff2d55;animation:lfwPulse 2s ease-in-out infinite;flex-shrink:0}',
      '.lfw-dot-load{background:#ffd700;box-shadow:0 0 8px #ffd700;animation:lfwPulse .8s ease-in-out infinite}',
      '@keyframes lfwPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.85)}}',
      '@keyframes lfw-spin{to{transform:rotate(360deg)}}',
      '@keyframes lfwShim{0%{background-position:200% 0}100%{background-position:-200% 0}}',
      '.lfw-bt{font-size:13px;font-weight:800;letter-spacing:2px;color:#fff;text-transform:uppercase}',
      '.lfw-bs{font-size:10px;font-weight:600;letter-spacing:1.5px;color:#00b4d8;text-transform:uppercase;padding:2px 7px;border:1px solid #00b4d830;border-radius:4px}',
      '.lfw-hdr-r2{display:flex;align-items:center;gap:14px;flex-wrap:wrap}',
      '.lfw-stat{font-size:11px;color:#555;letter-spacing:.4px}',
      '.lfw-sn{font-weight:800}',
      '.lfw-sn-e{color:#ff2d55}',
      '.lfw-sn-c{color:#ff6b00}',
      '.lfw-sn-t{color:#00b4d8}',
      '.lfw-upd{margin-left:auto;color:#333;font-size:10px}',
      '.lfw-btn-r{background:#ffffff0d;border:1px solid #ffffff18;color:#777;font-size:16px;line-height:1;border-radius:6px;padding:5px 9px;cursor:pointer;min-height:auto;transition:all .2s}',
      '.lfw-btn-r:hover{background:#ffffff1a;color:#fff}',
      '.lfw-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:1px;background:#16213e}',
      '@media(max-width:767px){.lfw-grid{grid-template-columns:1fr}}',
      '.lfw-card{background:#0c0c18;padding:16px;border-left:3px solid var(--tc,#00b4d8);transition:background .2s}',
      '.lfw-card:hover{background:#10101f}',
      '.lfw-card-hot{background:#100808}',
      '.lfw-card-hot:hover{background:#140a0a}',
      '.lfw-ct{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}',
      '.lfw-ctl{display:flex;align-items:center;gap:8px}',
      '.lfw-tag{font-size:9px;font-weight:800;letter-spacing:.8px;text-transform:uppercase;padding:2px 7px;border-radius:4px;border:1px solid;white-space:nowrap}',
      '.lfw-src{font-size:9px;color:#333;letter-spacing:.3px;text-transform:uppercase}',
      '.lfw-ago{font-size:10px;color:#333;white-space:nowrap}',
      '.lfw-cb{margin-bottom:12px}',
      '.lfw-cve{font-size:15px;font-weight:800;color:#fff;font-family:"SF Mono","Fira Code",monospace;margin:0 0 4px;letter-spacing:.3px}',
      '.lfw-vendor{font-size:11px;color:#00b4d8;margin-bottom:6px}',
      '.lfw-desc{font-size:12px;color:#8899aa;line-height:1.55;margin:0 0 10px}',
      '.lfw-badges{display:flex;flex-wrap:wrap;gap:4px}',
      '.lfw-b{font-size:9px;font-weight:700;letter-spacing:.3px;text-transform:uppercase;padding:2px 7px;border-radius:4px;border:1px solid}',
      '.lfw-b-exploit{background:#ff2d5515;color:#ff2d55;border-color:#ff2d5540}',
      '.lfw-b-cisa{background:#ffd70015;color:#ffd700;border-color:#ffd70040}',
      '.lfw-b-due{background:#ff950015;color:#ff9500;border-color:#ff950040}',
      '.lfw-cf{display:flex;align-items:center;justify-content:space-between;padding-top:10px;border-top:1px solid #ffffff08}',
      '.lfw-read{font-size:11px;font-weight:700;color:#00b4d8;text-decoration:none;letter-spacing:.3px;transition:color .2s}',
      '.lfw-read:hover{color:#fff}',
      '.lfw-ref{font-size:10px;color:#333;text-decoration:none;transition:color .2s}',
      '.lfw-ref:hover{color:#888}',
      '.lfw-skel{pointer-events:none}',
      '.lfw-sk{border-radius:4px;margin-bottom:8px;height:13px;background:linear-gradient(90deg,#ffffff05 25%,#ffffff0d 50%,#ffffff05 75%);background-size:200% 100%;animation:lfwShim 1.6s infinite}',
      '.s60{width:60%}.s65{width:65%}.s80{width:80%}.s100{width:100%}',
      '.lfw-foot{display:flex;align-items:center;justify-content:space-between;padding:10px 20px;background:#07070d;border-top:1px solid #16213e;flex-wrap:wrap;gap:6px}',
      '.lfw-copy{font-size:10px;color:#222230;letter-spacing:.3px}',
      '.lfw-note{font-size:10px;color:#1a1a28}',
      '#lfw-label{display:flex;align-items:center;gap:10px;margin-bottom:12px}',
      '#lfw-label h2{font-size:12px;font-weight:800;letter-spacing:2.5px;text-transform:uppercase;color:#fff;margin:0}',
      '#lfw-label-ts{font-size:10px;color:#334;margin-left:auto}'
    ].join('\n');
    var el=document.createElement('style');
    el.id='lfw-css'; el.textContent=css;
    document.head.appendChild(el);
  }

  /* ── INJECT SECTION LABEL ────────────────────────────────── */
  function injectLabel(container) {
    if (document.getElementById('lfw-label')) return;
    var d=document.createElement('div'); d.id='lfw-label';
    d.innerHTML='<h2>🛰 Threat Intelligence Feed</h2><span id="lfw-label-ts">Fetching…</span>';
    container.parentNode.insertBefore(d, container);
  }

  /* ── PHASE 10: LAST-UPDATED TICKER ──────────────────────── */
  var _lastFetchAt = null;
  var _displayedItems = [];
  function lastVerifiedSourceLabel() {
    if (_lastFetchAt === null) return 'Source timestamp unavailable';
    var age = Date.now() - _lastFetchAt;
    if (age > 180 * 60000) return 'STALE · source generated ' + timeAgo(_lastFetchAt);
    return 'Source generated ' + timeAgo(_lastFetchAt);
  }
  function startFreshnessTicker() {
    var el = document.getElementById('lfw-label-ts');
    if (!el) return;
    setInterval(function() {
      var container = document.getElementById(CFG.CONTAINER_ID);
      if (container && _displayedItems.length && !verifiedLiveItems(_displayedItems)) {
        renderUnavailable(container);
      }
      el.textContent = lastVerifiedSourceLabel();
    }, 5000); // revalidate live evidence every 5s, without network calls
  }

  /* ── BOOT ────────────────────────────────────────────────── */
  function boot() {
    var container=document.getElementById(CFG.CONTAINER_ID);
    if (!container) return;    injectCSS();
    injectLabel(container);
    doFetch(container, false).then(function(){
      var ts=document.getElementById('lfw-label-ts');
      if(ts) ts.textContent=lastVerifiedSourceLabel();
      startFreshnessTicker();
    });
    // Refresh the displayed source state; do not relabel browser fetch time as
    // intelligence publication time.
    setInterval(function(){
      if (document.hidden) return; // no background polling from hidden tabs
      doFetch(container,true).then(function(){
        var ts=document.getElementById('lfw-label-ts');
        if(ts) ts.textContent=lastVerifiedSourceLabel();
      });
    }, CFG.REFRESH_MS);
  }

  if (document.readyState==='loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    setTimeout(boot, 800);
  }

  window.LIVE_FEED_WIDGET = {
    refresh: function(){ var c=document.getElementById(CFG.CONTAINER_ID); if(c) doFetch(c,true); },
    cfg: CFG,
    classifyFeedTimestamp: classifyFeedTimestamp,
    safeReportHref: safeReportHref,
    safeThreatColor: safeThreatColor,
    selectLocalItems: selectLocalItems
  };
})();
