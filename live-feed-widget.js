/**
 * CYBERDUDEBIVASH — LIVE FEED WIDGET v4.0
 * ═══════════════════════════════════════════════════════════
 * Multi-source, evidence-preserving feed renderer.
 *
 * Source chain (each tried in order until data found):
 *   1. /live-intel.json  — same-origin, GitHub Actions-generated
 *   2. CISA KEV (direct) — public CORS-enabled CDN
 *   3. CISA KEV (proxy1) — corsproxy.io
 *   4. CISA KEV (proxy2) — allorigins
 *   5. Explicit unavailable state — never fabricate a healthy feed
 *
 * © 2025 CYBERDUDEBIVASH. All rights reserved.
 * ═══════════════════════════════════════════════════════════
 */
(function () {
  'use strict';

  /* ── CONFIG ─────────────────────────────────────────────── */
  var CFG = {
    LOCAL_JSON:  '/live-intel.json',
    CISA_DIRECT: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    CISA_PROXY1: 'https://corsproxy.io/?https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    CISA_PROXY2: 'https://api.allorigins.win/raw?url=' + encodeURIComponent('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
    CONTAINER_ID:'live-intel-feed',
    CACHE_KEY:   'cbd_lfw_v5',
    CACHE_TTL:   55 * 1000,        // 55s — just under refresh interval
    // The intel pipeline publishes every ~1.5-5 h; polling faster only adds
    // requests (docs/operations/CLOUDFLARE-COST-GUARDRAILS.md).
    REFRESH_MS:  15 * 60 * 1000,
    MAX_CARDS:   15,               // v5: show more cards
    LOOKBACK_DAYS: 30
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

  function esc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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

  /* ── NORMALISE CISA KEV item → our shape ─────────────────── */
  function normaliseCISA(v) {
    var desc = v.shortDescription || v.vulnerabilityName || '';
    var threat = classify(desc);
    return {
      id:       v.cveID,
      desc:     desc,
      score:    null,
      published:v.dateAdded,
      vendors:  [v.vendorProject||'Unknown'],
      product:  v.product||'',
      source:   'CISA-KEV',
      exploited:true,
      dueDate:  v.dueDate||null,
      threat:   threat
    };
  }

  /* ── PARSE CISA JSON — tolerates both shapes ─────────────── */
  function parseCISA(data) {
    if (!data) return null;
    var vulns = null;
    if (data.vulnerabilities) vulns = data.vulnerabilities;
    else if (Array.isArray(data)) vulns = data;
    else return null;
    var cutoff = new Date(Date.now() - CFG.LOOKBACK_DAYS*86400000);
    return vulns
      .filter(function(v){ return v.cveID && new Date(v.dateAdded)>=cutoff; })
      .sort(function(a,b){ return new Date(b.dateAdded)-new Date(a.dateAdded); })
      .slice(0, CFG.MAX_CARDS)
      .map(normaliseCISA);
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

  /* ── MAIN FETCH PIPELINE ─────────────────────────────────── */
  function pipeline() {
    // 1. Same-origin JSON
    return xhrFetch(CFG.LOCAL_JSON+'?_='+Math.floor(Date.now()/60000), 8000)
      .then(function(data) {
        if (data && data.items && data.items.length) {
          var generated = (data.metadata&&data.metadata.generated)||data._heartbeat||data.lastUpdated||null;
          return data.items.map(normaliseLocal).filter(Boolean).map(function(item){ item._feedGenerated=generated; return item; });
        }
        // 2. CISA direct
        return xhrFetch(CFG.CISA_DIRECT, 10000).then(function(d) {
          var items = parseCISA(d);
          if (items && items.length) return items.map(function(item){item._feedGenerated=new Date().toISOString();return item;});
          // 3. CISA proxy 1
          return xhrFetch(CFG.CISA_PROXY1, 10000).then(function(d2) {
            var items2 = parseCISA(d2);
            if (items2 && items2.length) return items2.map(function(item){item._feedGenerated=new Date().toISOString();return item;});
            // 4. CISA proxy 2
            return xhrFetch(CFG.CISA_PROXY2, 10000).then(function(d3) {
              var items3 = parseCISA(d3);
              if (items3 && items3.length) return items3.map(function(item){item._feedGenerated=new Date().toISOString();return item;});
              return [];
            });
          });
        });
      })
      .catch(function() { return []; });
  }

  /* ── RENDER CARD ─────────────────────────────────────────── */
  function stripEntities(s) {
    // Decode multiple entity layers before stripping tags (Reddit/SANS feeds
    // often double-encode HTML fragments).
    var out=String(s||'');
    for(var i=0;i<3;i++) out=out.replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&nbsp;/gi,' ');
    return out.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();
  }

  function card(item) {
    var threat = item.threat || classify(item.desc||'');
    var sev    = sevColor(item.score);
    var vendor = (item.vendors&&item.vendors[0])||item.product||'Unknown';
    // Strip raw HTML entities from description before display
    var rawDesc = stripEntities(item.desc||'');
    var desc   = rawDesc.slice(0,175) + (rawDesc.length>175?'…':'');
    var product= item.product||(item.desc&&'')||'';
    // Use item.slug directly when available (populated by pipeline),
    // avoiding the ID-hash fallback that generates non-existent post URLs.
    var slug   = item.slug || slugify((item.id||'')+(vendor?'-'+vendor:'')+(product&&product!==vendor?'-'+product:''));
    var href   = item.link || (item.slug ? '/posts/'+item.slug+'.html' : null) || '#';
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
        +'<a href="'+esc(href)+'" class="lfw-read">🔍 Full Intel Report →</a>'
        +(sourceHref?'<a href="'+esc(sourceHref)+'" class="lfw-ref" target="_blank" rel="noopener noreferrer">Source ↗</a>':'')
      +'</div>'
    +'</article>';
  }

  /* ── RENDER WIDGET ───────────────────────────────────────── */
  function render(items, container, animate) {
    var exploited = items.filter(function(i){return i.exploited;}).length;
    var critical  = items.filter(function(i){return parseFloat(i.score)>=9;}).length;
    var feedDate  = items[0]&&items[0]._feedGenerated ? new Date(items[0]._feedGenerated) : null;
    var feedValid = feedDate && !isNaN(feedDate.getTime());
    var stale     = feedValid && (Date.now()-feedDate.getTime()) > 180*60000;
    var ts        = feedValid ? timeAgo(feedDate) : 'timestamp unavailable';
    _lastFetchAt  = feedValid ? feedDate.getTime() : null;
    var grid      = items.map(card).join('');

    if (animate) {
      var g = container.querySelector('.lfw-grid');
      if (g) {
        g.style.opacity='0';
        setTimeout(function(){
          g.innerHTML=grid; g.style.opacity='1';
          var ns=container.querySelectorAll('.lfw-sn');
          if(ns[0]) ns[0].textContent=exploited;
          if(ns[1]) ns[1].textContent=critical;
          if(ns[2]) ns[2].textContent=items.length;
          var u=container.querySelector('.lfw-upd'); if(u) u.textContent=(stale?'Feed stale · ':'Feed updated · ')+ts;
        }, 300);
        return;
      }
    }

    container.innerHTML =
      '<div class="lfw-wrap">'
      +'<div class="lfw-hdr">'
        +'<div class="lfw-hdr-r1">'
          +'<div class="lfw-brand"><span class="lfw-dot'+(stale?' lfw-dot-load':'')+'"></span><span class="lfw-bt">'+(stale?'STALE FEED — LAST VERIFIED INTEL':'VERIFIED THREAT INTEL')+'</span><span class="lfw-bs">SENTINEL APEX</span></div>'
          +'<button class="lfw-btn-r" id="lfw-refresh-btn" title="Refresh">⟳</button>'
        +'</div>'
        +'<div class="lfw-hdr-r2">'
          +'<span class="lfw-stat"><span class="lfw-sn lfw-sn-e">'+exploited+'</span> Exploited</span>'
          +'<span class="lfw-stat"><span class="lfw-sn lfw-sn-c">'+critical+'</span> Critical</span>'
          +'<span class="lfw-stat"><span class="lfw-sn lfw-sn-t">'+items.length+'</span> Threats</span>'
          +'<span class="lfw-stat lfw-upd">'+(stale?'Feed stale · ':'Feed updated · ')+ts+'</span>'
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
    container.innerHTML='<div class="lfw-wrap"><div class="lfw-hdr"><div class="lfw-brand"><span class="lfw-dot lfw-dot-load"></span><span class="lfw-bt">INTELLIGENCE FEED UNAVAILABLE</span><span class="lfw-bs">SENTINEL APEX</span></div></div><div style="padding:24px;color:#8899aa;font-size:13px;line-height:1.6">No verified feed could be loaded. Use the <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noopener" target="_blank" style="color:#00b4d8">CISA KEV catalog</a> while service recovery is in progress.</div></div>';
  }

  /* ── DO FETCH ────────────────────────────────────────────── */
  function doFetch(container, refresh) {
    if (!refresh) {
      var cached = getCache();
      if (cached && cached.length) { render(cached, container, false); return Promise.resolve(); }
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
    d.innerHTML='<h2>🛰 Live Breaking Intel</h2><span id="lfw-label-ts">Fetching…</span>';
    container.parentNode.insertBefore(d, container);
  }

  /* ── PHASE 10: LAST-UPDATED TICKER ──────────────────────── */
  var _lastFetchAt = null;
  function startFreshnessTicker() {
    var el = document.getElementById('lfw-label-ts');
    if (!el) return;
    setInterval(function() {
      if (!_lastFetchAt) return;
      var secsAgo = Math.round((Date.now() - _lastFetchAt) / 1000);
      var label;
      if (secsAgo < 60)       label = 'Updated ' + secsAgo + 's ago';
      else if (secsAgo < 3600) label = 'Updated ' + Math.round(secsAgo/60) + 'm ago';
      else                     label = 'Updated ' + Math.round(secsAgo/3600) + 'h ago';
      el.textContent = label;
    }, 5000); // tick every 5s
  }

  /* ── BOOT ────────────────────────────────────────────────── */
  function boot() {
    var container=document.getElementById(CFG.CONTAINER_ID);
    if (!container) return;    injectCSS();
    injectLabel(container);
    doFetch(container, false).then(function(){
      var ts=document.getElementById('lfw-label-ts');
      if(ts) ts.textContent=_lastFetchAt?'Feed updated '+timeAgo(_lastFetchAt):'Feed timestamp unavailable';
      startFreshnessTicker();
    });
    // Refresh the displayed source state; do not relabel browser fetch time as
    // intelligence publication time.
    setInterval(function(){
      if (document.hidden) return; // no background polling from hidden tabs
      doFetch(container,true).then(function(){
        var ts=document.getElementById('lfw-label-ts');
        if(ts) ts.textContent=_lastFetchAt?'Feed updated '+timeAgo(_lastFetchAt):'Feed timestamp unavailable';
      });
    }, CFG.REFRESH_MS);
  }

  if (document.readyState==='loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    setTimeout(boot, 800);
  }

  window.LIVE_FEED_WIDGET = { refresh: function(){ var c=document.getElementById(CFG.CONTAINER_ID); if(c) doFetch(c,true); }, cfg: CFG };
})();
