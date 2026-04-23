/**
 * CYBERDUDEBIVASH — LIVE FEED WIDGET v2.0
 * ═══════════════════════════════════════════════════════════
 * Client-side real-time intel fetcher. Runs entirely in the
 * browser. Fetches CISA KEV + NVD API every 10 minutes.
 * Renders live intel cards on homepage without CI/CD lag.
 *
 * © 2025 CYBERDUDEBIVASH. All rights reserved.
 * cyberdudebivash.com | Sentinel APEX Intelligence Platform
 * ═══════════════════════════════════════════════════════════
 */

(function () {
  'use strict';

  /* ─────────────────────────────────────────────
   * CONFIG
   * ───────────────────────────────────────────── */
  var CFG = {
    NVD_API: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    CISA_KEV: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    REFRESH_MS: 10 * 60 * 1000,   // 10 minutes
    MAX_CARDS: 12,
    LOOKBACK_HOURS: 72,            // NVD lookback window
    CONTAINER_ID: 'live-intel-feed',
    CACHE_KEY: 'cbd_live_intel_v2',
    CACHE_TTL: 8 * 60 * 1000,     // 8 min cache (slightly under refresh)
    DEBUG: false
  };

  /* ─────────────────────────────────────────────
   * HELPERS
   * ───────────────────────────────────────────── */
  function log() {
    if (CFG.DEBUG) console.log.apply(console, ['[LFW]'].concat(Array.prototype.slice.call(arguments)));
  }

  function isoNHoursAgo(n) {
    var d = new Date(Date.now() - n * 3600000);
    return d.toISOString().replace(/\.\d{3}Z$/, '.000 UTC').replace('T', ' ');
  }

  function isoToDate(iso) {
    if (!iso) return null;
    return new Date(iso);
  }

  function timeAgo(dateStr) {
    if (!dateStr) return 'recently';
    var d = new Date(dateStr);
    var diff = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  function escHtml(s) {
    if (!s) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function slugify(s) {
    return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  }

  function getCache() {
    try {
      var raw = sessionStorage.getItem(CFG.CACHE_KEY);
      if (!raw) return null;
      var obj = JSON.parse(raw);
      if (Date.now() - obj.ts > CFG.CACHE_TTL) return null;
      return obj.data;
    } catch (e) { return null; }
  }

  function setCache(data) {
    try { sessionStorage.setItem(CFG.CACHE_KEY, JSON.stringify({ ts: Date.now(), data: data })); } catch (e) {}
  }

  /* ─────────────────────────────────────────────
   * THREAT CLASSIFICATION
   * ───────────────────────────────────────────── */
  var THREAT_PATTERNS = [
    { type: 'RCE', label: 'Remote Code Execution', color: '#ff2d55', keywords: ['remote code execution','arbitrary code','execute code','code execution','rce'] },
    { type: 'LPE', label: 'Privilege Escalation', color: '#ff6b00', keywords: ['privilege escalation','gain privilege','elevat','local privilege','escalate privilege'] },
    { type: 'AUTH_BYPASS', label: 'Auth Bypass', color: '#ff9500', keywords: ['authentication bypass','bypass authentication','unauthenticated','improper authentication','bypass auth'] },
    { type: 'SQLI', label: 'SQL Injection', color: '#cc44ff', keywords: ['sql injection','sqli','database','mysql','postgresql'] },
    { type: 'XXE', label: 'XXE Injection', color: '#9b59b6', keywords: ['xml external entity','xxe','xml injection'] },
    { type: 'SSRF', label: 'SSRF', color: '#e056fd', keywords: ['server-side request forgery','ssrf','internal network'] },
    { type: 'UAF', label: 'Use-After-Free', color: '#ff4757', keywords: ['use-after-free','uaf','use after free'] },
    { type: 'OVERFLOW', label: 'Buffer Overflow', color: '#ff6348', keywords: ['buffer overflow','stack overflow','heap overflow','out-of-bounds write','memory corruption'] },
    { type: 'IDOR', label: 'IDOR', color: '#ffa502', keywords: ['insecure direct object','idor','broken access control'] },
    { type: 'XSS', label: 'Cross-Site Scripting', color: '#2ed573', keywords: ['cross-site scripting','xss','script injection'] },
    { type: 'ZERO_DAY', label: 'Zero-Day', color: '#ff0000', keywords: ['zero-day','0-day','actively exploit','in the wild','zero day'] },
    { type: 'SUPPLY_CHAIN', label: 'Supply Chain', color: '#ff6b81', keywords: ['supply chain','malicious package','dependency','npm','pypi'] }
  ];

  function classifyThreat(desc) {
    if (!desc) return { type: 'CVE', label: 'Vulnerability', color: '#00b4d8' };
    var d = desc.toLowerCase();
    for (var i = 0; i < THREAT_PATTERNS.length; i++) {
      var p = THREAT_PATTERNS[i];
      for (var j = 0; j < p.keywords.length; j++) {
        if (d.indexOf(p.keywords[j]) !== -1) return { type: p.type, label: p.label, color: p.color };
      }
    }
    return { type: 'CVE', label: 'Vulnerability', color: '#00b4d8' };
  }

  function cvssToSeverity(score) {
    if (!score && score !== 0) return { label: 'N/A', color: '#888' };
    score = parseFloat(score);
    if (score >= 9.0) return { label: 'CRITICAL', color: '#ff2d55' };
    if (score >= 7.0) return { label: 'HIGH', color: '#ff6b00' };
    if (score >= 4.0) return { label: 'MEDIUM', color: '#ffd700' };
    return { label: 'LOW', color: '#2ed573' };
  }

  /* ─────────────────────────────────────────────
   * FETCH — NVD CVE API
   * ───────────────────────────────────────────── */
  function fetchNVD() {
    return new Promise(function (resolve) {
      try {
        var now = new Date();
        var past = new Date(now.getTime() - CFG.LOOKBACK_HOURS * 3600000);
        var fmt = function (d) {
          return d.toISOString().split('.')[0] + ' UTC';
        };
        var url = CFG.NVD_API +
          '?cvssV3Severity=CRITICAL' +
          '&pubStartDate=' + encodeURIComponent(fmt(past)) +
          '&pubEndDate=' + encodeURIComponent(fmt(now)) +
          '&resultsPerPage=20';

        log('NVD fetch:', url);
        var xhr = new XMLHttpRequest();
        xhr.timeout = 15000;
        xhr.open('GET', url);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) return;
          try {
            if (xhr.status === 200) {
              var data = JSON.parse(xhr.responseText);
              var items = (data.vulnerabilities || []).map(function (v) {
                var cve = v.cve || {};
                var metrics = cve.metrics || {};
                var score = null;
                var vector = null;
                if (metrics.cvssMetricV31 && metrics.cvssMetricV31[0]) {
                  score = metrics.cvssMetricV31[0].cvssData.baseScore;
                  vector = metrics.cvssMetricV31[0].cvssData.vectorString;
                } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30[0]) {
                  score = metrics.cvssMetricV30[0].cvssData.baseScore;
                  vector = metrics.cvssMetricV30[0].cvssData.vectorString;
                }
                var desc = ((cve.descriptions || []).find(function (d) { return d.lang === 'en'; }) || {}).value || '';
                var refs = (cve.references || []).slice(0, 3).map(function (r) { return r.url; });
                var configs = cve.configurations || [];
                var vendors = [];
                configs.forEach(function (c) {
                  (c.nodes || []).forEach(function (n) {
                    (n.cpeMatch || []).forEach(function (m) {
                      var parts = (m.criteria || '').split(':');
                      if (parts[3] && vendors.indexOf(parts[3]) === -1) vendors.push(parts[3]);
                    });
                  });
                });
                return {
                  id: cve.id,
                  desc: desc,
                  score: score,
                  vector: vector,
                  published: cve.published,
                  modified: cve.lastModified,
                  refs: refs,
                  vendors: vendors,
                  source: 'NVD',
                  exploited: false
                };
              });
              resolve(items);
            } else {
              log('NVD non-200:', xhr.status);
              resolve([]);
            }
          } catch (e) { log('NVD parse err:', e); resolve([]); }
        };
        xhr.onerror = function () { log('NVD network err'); resolve([]); };
        xhr.ontimeout = function () { log('NVD timeout'); resolve([]); };
        xhr.send();
      } catch (e) { log('NVD fetch err:', e); resolve([]); }
    });
  }

  /* ─────────────────────────────────────────────
   * FETCH — CISA KEV
   * ───────────────────────────────────────────── */
  function fetchCISA() {
    return new Promise(function (resolve) {
      try {
        var xhr = new XMLHttpRequest();
        xhr.timeout = 15000;
        xhr.open('GET', CFG.CISA_KEV);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) return;
          try {
            if (xhr.status === 200) {
              var data = JSON.parse(xhr.responseText);
              var cutoff = new Date(Date.now() - 14 * 86400000); // last 14 days
              var items = (data.vulnerabilities || [])
                .filter(function (v) {
                  var d = new Date(v.dateAdded);
                  return d >= cutoff;
                })
                .map(function (v) {
                  return {
                    id: v.cveID,
                    desc: v.shortDescription || v.vulnerabilityName || '',
                    score: null,
                    published: v.dateAdded,
                    modified: v.dateAdded,
                    refs: [],
                    vendors: [v.vendorProject || ''],
                    product: v.product || '',
                    dueDate: v.dueDate,
                    source: 'CISA-KEV',
                    exploited: true
                  };
                })
                .slice(0, 15);
              resolve(items);
            } else {
              log('CISA non-200:', xhr.status);
              resolve([]);
            }
          } catch (e) { log('CISA parse err:', e); resolve([]); }
        };
        xhr.onerror = function () { log('CISA network err'); resolve([]); };
        xhr.ontimeout = function () { log('CISA timeout'); resolve([]); };
        xhr.send();
      } catch (e) { log('CISA fetch err:', e); resolve([]); }
    });
  }

  /* ─────────────────────────────────────────────
   * MERGE & DEDUPLICATE
   * ───────────────────────────────────────────── */
  function mergeIntel(nvd, cisa) {
    var map = {};
    nvd.forEach(function (item) { map[item.id] = item; });
    cisa.forEach(function (item) {
      if (map[item.id]) {
        map[item.id].exploited = true;
        map[item.id].source = 'CISA-KEV+NVD';
        if (item.dueDate) map[item.id].dueDate = item.dueDate;
        if (item.product) map[item.id].product = item.product;
      } else {
        map[item.id] = item;
      }
    });
    var merged = Object.values ? Object.values(map) : Object.keys(map).map(function (k) { return map[k]; });
    merged.sort(function (a, b) {
      if (a.exploited && !b.exploited) return -1;
      if (!a.exploited && b.exploited) return 1;
      var sa = parseFloat(a.score) || 0;
      var sb = parseFloat(b.score) || 0;
      if (sb !== sa) return sb - sa;
      var da = new Date(a.published || 0);
      var db = new Date(b.published || 0);
      return db - da;
    });
    return merged.slice(0, CFG.MAX_CARDS);
  }

  /* ─────────────────────────────────────────────
   * RENDER — SINGLE CARD
   * ───────────────────────────────────────────── */
  function renderCard(item, idx) {
    var threat = classifyThreat(item.desc);
    var sev = cvssToSeverity(item.score);
    var ago = timeAgo(item.published);
    var vendor = (item.vendors && item.vendors[0]) ? item.vendors[0] : (item.product || 'Unknown');
    var desc = item.desc ? (item.desc.length > 160 ? item.desc.substring(0, 157) + '…' : item.desc) : 'No description available.';
    var slug = slugify(item.id + '-' + vendor);
    var postHref = '/posts/' + slug + '.html';
    var exploitBadge = item.exploited
      ? '<span class="lfw-badge lfw-badge-exploit">⚡ EXPLOITED IN WILD</span>'
      : '';
    var cisaBadge = item.source === 'CISA-KEV' || item.source === 'CISA-KEV+NVD'
      ? '<span class="lfw-badge lfw-badge-cisa">🛡 CISA KEV</span>'
      : '';
    var scoreBadge = item.score
      ? '<span class="lfw-badge lfw-badge-score" style="background:' + sev.color + '22;color:' + sev.color + ';border-color:' + sev.color + '44">CVSS ' + item.score + ' — ' + sev.label + '</span>'
      : '<span class="lfw-badge lfw-badge-score" style="background:#ffffff11;color:#aaa;border-color:#333">NO SCORE</span>';

    return '<article class="lfw-card' + (item.exploited ? ' lfw-card-exploit' : '') + '" data-idx="' + idx + '" style="--threat-color:' + threat.color + '">' +
      '<div class="lfw-card-header">' +
        '<div class="lfw-header-left">' +
          '<span class="lfw-threat-type" style="color:' + threat.color + ';border-color:' + threat.color + '44">' + escHtml(threat.label) + '</span>' +
          '<span class="lfw-source">' + escHtml(item.source) + '</span>' +
        '</div>' +
        '<span class="lfw-time">' + ago + '</span>' +
      '</div>' +
      '<div class="lfw-card-body">' +
        '<h3 class="lfw-cve-id">' + escHtml(item.id) + '</h3>' +
        '<div class="lfw-vendor">🎯 ' + escHtml(vendor) + (item.product ? ' · ' + escHtml(item.product) : '') + '</div>' +
        '<p class="lfw-desc">' + escHtml(desc) + '</p>' +
        '<div class="lfw-badges">' + exploitBadge + cisaBadge + scoreBadge + '</div>' +
      '</div>' +
      '<div class="lfw-card-footer">' +
        '<a href="' + postHref + '" class="lfw-read-btn">🔍 Full Intel Report →</a>' +
        (item.refs && item.refs[0] ? '<a href="' + escHtml(item.refs[0]) + '" class="lfw-ref-link" target="_blank" rel="noopener">Source ↗</a>' : '') +
      '</div>' +
    '</article>';
  }

  /* ─────────────────────────────────────────────
   * RENDER — FULL WIDGET
   * ───────────────────────────────────────────── */
  function renderWidget(items, container, isRefresh) {
    var now = new Date();
    var timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    var exploitCount = items.filter(function (i) { return i.exploited; }).length;
    var critCount = items.filter(function (i) { return parseFloat(i.score) >= 9.0; }).length;

    var header = '<div class="lfw-header">' +
      '<div class="lfw-title-row">' +
        '<div class="lfw-title">' +
          '<span class="lfw-live-dot"></span>' +
          '<span class="lfw-title-text">LIVE THREAT INTEL</span>' +
          '<span class="lfw-brand">SENTINEL APEX</span>' +
        '</div>' +
        '<button class="lfw-refresh-btn" id="lfw-refresh-btn" title="Refresh now">⟳</button>' +
      '</div>' +
      '<div class="lfw-stats-row">' +
        '<span class="lfw-stat lfw-stat-exploit"><span>' + exploitCount + '</span> Actively Exploited</span>' +
        '<span class="lfw-stat lfw-stat-crit"><span>' + critCount + '</span> Critical CVEs</span>' +
        '<span class="lfw-stat lfw-stat-total"><span>' + items.length + '</span> Live Threats</span>' +
        '<span class="lfw-stat lfw-stat-time">Updated ' + timeStr + '</span>' +
      '</div>' +
    '</div>';

    var cards = items.map(function (item, i) { return renderCard(item, i); }).join('');

    var footer = '<div class="lfw-footer">' +
      '<span class="lfw-copyright">© 2025 CYBERDUDEBIVASH · Sentinel APEX · cyberdudebivash.com</span>' +
      '<span class="lfw-refresh-note">Auto-refreshes every 10 minutes</span>' +
    '</div>';

    var html = '<div class="lfw-widget">' + header + '<div class="lfw-cards-grid">' + cards + '</div>' + footer + '</div>';

    if (isRefresh) {
      var grid = container.querySelector('.lfw-cards-grid');
      if (grid) {
        grid.style.opacity = '0';
        setTimeout(function () {
          grid.innerHTML = cards;
          grid.style.opacity = '1';
        }, 300);
        var statsRow = container.querySelector('.lfw-stats-row');
        if (statsRow) {
          statsRow.querySelector('.lfw-stat.lfw-stat-exploit span').textContent = exploitCount;
          statsRow.querySelector('.lfw-stat.lfw-stat-crit span').textContent = critCount;
          statsRow.querySelector('.lfw-stat.lfw-stat-total span').textContent = items.length;
          statsRow.querySelector('.lfw-stat.lfw-stat-time').textContent = 'Updated ' + timeStr;
        }
        return;
      }
    }
    container.innerHTML = html;
    // Bind refresh button
    var btn = document.getElementById('lfw-refresh-btn');
    if (btn) btn.addEventListener('click', function () {
      btn.classList.add('lfw-spinning');
      doFetch(container, true).then(function () {
        btn.classList.remove('lfw-spinning');
      });
    });
  }

  /* ─────────────────────────────────────────────
   * RENDER — SKELETON LOADING STATE
   * ───────────────────────────────────────────── */
  function renderSkeleton(container) {
    var skeletons = '';
    for (var i = 0; i < 6; i++) {
      skeletons += '<div class="lfw-card lfw-skeleton">' +
        '<div class="lfw-sk lfw-sk-header"></div>' +
        '<div class="lfw-sk lfw-sk-title"></div>' +
        '<div class="lfw-sk lfw-sk-body"></div>' +
        '<div class="lfw-sk lfw-sk-body lfw-sk-short"></div>' +
      '</div>';
    }
    container.innerHTML = '<div class="lfw-widget">' +
      '<div class="lfw-header">' +
        '<div class="lfw-title-row">' +
          '<div class="lfw-title">' +
            '<span class="lfw-live-dot lfw-dot-loading"></span>' +
            '<span class="lfw-title-text">LOADING LIVE THREAT INTEL…</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="lfw-cards-grid">' + skeletons + '</div>' +
    '</div>';
  }

  /* ─────────────────────────────────────────────
   * RENDER — ERROR STATE
   * ───────────────────────────────────────────── */
  function renderError(container, message) {
    container.innerHTML = '<div class="lfw-widget lfw-error-state">' +
      '<div class="lfw-error-icon">⚠️</div>' +
      '<div class="lfw-error-msg">' + escHtml(message || 'Failed to fetch live intel. Retrying in 2 minutes…') + '</div>' +
      '<button class="lfw-refresh-btn" id="lfw-retry-btn">⟳ Retry Now</button>' +
    '</div>';
    var btn = document.getElementById('lfw-retry-btn');
    if (btn) btn.addEventListener('click', function () { doFetch(container, false); });
  }

  /* ─────────────────────────────────────────────
   * FETCH ORCHESTRATOR
   * ───────────────────────────────────────────── */
  function doFetch(container, isRefresh) {
    log('doFetch, refresh=', isRefresh);

    // Check cache first
    if (!isRefresh) {
      var cached = getCache();
      if (cached && cached.length) {
        log('Using cache, items=', cached.length);
        renderWidget(cached, container, false);
        return Promise.resolve();
      }
    }

    if (!isRefresh) renderSkeleton(container);

    return Promise.all([fetchNVD(), fetchCISA()])
      .then(function (results) {
        var nvd = results[0] || [];
        var cisa = results[1] || [];
        log('NVD items:', nvd.length, 'CISA items:', cisa.length);
        var merged = mergeIntel(nvd, cisa);
        if (!merged.length) {
          renderError(container, 'No critical threats in lookback window. The platform is monitoring — check back in 10 minutes.');
          return;
        }
        setCache(merged);
        renderWidget(merged, container, isRefresh);
      })
      .catch(function (err) {
        log('Fetch error:', err);
        var cached = getCache();
        if (cached && cached.length) {
          log('Falling back to cache');
          renderWidget(cached, container, isRefresh);
        } else {
          renderError(container, 'Live intel fetch failed. CORS or network issue. Retrying automatically.');
        }
      });
  }

  /* ─────────────────────────────────────────────
   * INJECT STYLES
   * ───────────────────────────────────────────── */
  function injectStyles() {
    if (document.getElementById('lfw-styles')) return;
    var css = `
/* ═══ LIVE FEED WIDGET — CYBERDUDEBIVASH ═══ */
.lfw-widget {
  background: #0a0a0f;
  border: 1px solid #1a1a2e;
  border-radius: 12px;
  overflow: hidden;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
  margin: 32px 0;
}
.lfw-header {
  background: linear-gradient(135deg, #0d0d1a 0%, #0a1628 100%);
  border-bottom: 1px solid #1a1a2e;
  padding: 16px 20px 12px;
}
.lfw-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}
.lfw-title {
  display: flex;
  align-items: center;
  gap: 10px;
}
.lfw-live-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #ff2d55;
  box-shadow: 0 0 8px #ff2d55;
  animation: lfwPulse 2s ease-in-out infinite;
  flex-shrink: 0;
}
.lfw-dot-loading { background: #ffd700; box-shadow: 0 0 8px #ffd700; animation: lfwPulse 0.8s ease-in-out infinite; }
@keyframes lfwPulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.85)} }
.lfw-title-text {
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 2px;
  color: #fff;
  text-transform: uppercase;
}
.lfw-brand {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1.5px;
  color: #00b4d8;
  text-transform: uppercase;
  padding: 2px 7px;
  border: 1px solid #00b4d830;
  border-radius: 4px;
}
.lfw-stats-row {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.lfw-stat {
  font-size: 11px;
  color: #888;
  letter-spacing: .5px;
}
.lfw-stat span { font-weight: 700; }
.lfw-stat-exploit span { color: #ff2d55; }
.lfw-stat-crit span { color: #ff6b00; }
.lfw-stat-total span { color: #00b4d8; }
.lfw-stat-time { margin-left: auto; color: #555; }
.lfw-refresh-btn {
  background: #ffffff10;
  border: 1px solid #ffffff20;
  color: #aaa;
  font-size: 16px;
  border-radius: 6px;
  padding: 4px 8px;
  cursor: pointer;
  transition: all .2s;
  line-height: 1;
}
.lfw-refresh-btn:hover { background: #ffffff20; color: #fff; }
.lfw-spinning { animation: lfwSpin .8s linear infinite; }
@keyframes lfwSpin { to { transform: rotate(360deg); } }
.lfw-cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 1px;
  background: #1a1a2e;
  transition: opacity .3s;
}
@media (max-width: 767px) { .lfw-cards-grid { grid-template-columns: 1fr; } }
.lfw-card {
  background: #0d0d18;
  padding: 16px;
  position: relative;
  transition: background .2s;
  border-left: 3px solid var(--threat-color, #00b4d8);
}
.lfw-card:hover { background: #111120; }
.lfw-card-exploit { background: #120808; }
.lfw-card-exploit:hover { background: #160a0a; }
.lfw-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}
.lfw-header-left { display: flex; align-items: center; gap: 8px; }
.lfw-threat-type {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: 4px;
  border: 1px solid;
}
.lfw-source {
  font-size: 9px;
  color: #555;
  letter-spacing: .5px;
  text-transform: uppercase;
}
.lfw-time { font-size: 10px; color: #555; letter-spacing: .5px; }
.lfw-card-body { margin-bottom: 12px; }
.lfw-cve-id {
  font-size: 15px;
  font-weight: 700;
  color: #fff;
  font-family: 'SF Mono', 'Fira Code', monospace;
  margin: 0 0 4px;
}
.lfw-vendor { font-size: 11px; color: #00b4d8; margin-bottom: 6px; }
.lfw-desc { font-size: 12px; color: #aaa; line-height: 1.5; margin: 0 0 10px; }
.lfw-badges { display: flex; flex-wrap: wrap; gap: 5px; }
.lfw-badge {
  font-size: 9px;
  font-weight: 700;
  letter-spacing: .5px;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: 4px;
  border: 1px solid;
}
.lfw-badge-exploit { background: #ff2d5520; color: #ff2d55; border-color: #ff2d5540; }
.lfw-badge-cisa { background: #ffd70020; color: #ffd700; border-color: #ffd70040; }
.lfw-badge-score { /* dynamic inline styles */ }
.lfw-card-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: 10px;
  border-top: 1px solid #ffffff08;
}
.lfw-read-btn {
  font-size: 11px;
  font-weight: 600;
  color: #00b4d8;
  text-decoration: none;
  letter-spacing: .5px;
  transition: color .2s;
}
.lfw-read-btn:hover { color: #fff; }
.lfw-ref-link {
  font-size: 10px;
  color: #555;
  text-decoration: none;
  transition: color .2s;
}
.lfw-ref-link:hover { color: #aaa; }
/* ─── SKELETON ─── */
.lfw-skeleton { cursor: default; pointer-events: none; }
.lfw-sk {
  background: linear-gradient(90deg, #ffffff06 25%, #ffffff10 50%, #ffffff06 75%);
  background-size: 200% 100%;
  animation: lfwShimmer 1.5s infinite;
  border-radius: 4px;
  margin-bottom: 8px;
}
@keyframes lfwShimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
.lfw-sk-header { height: 18px; width: 50%; }
.lfw-sk-title { height: 22px; width: 75%; }
.lfw-sk-body { height: 12px; width: 100%; }
.lfw-sk-short { width: 65%; }
/* ─── ERROR ─── */
.lfw-error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 20px;
  gap: 12px;
}
.lfw-error-icon { font-size: 32px; }
.lfw-error-msg { font-size: 13px; color: #888; text-align: center; max-width: 360px; }
/* ─── FOOTER ─── */
.lfw-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 20px;
  background: #08080f;
  border-top: 1px solid #1a1a2e;
  flex-wrap: wrap;
  gap: 6px;
}
.lfw-copyright { font-size: 10px; color: #333; letter-spacing: .5px; }
.lfw-refresh-note { font-size: 10px; color: #2a2a3e; }
/* ─── Section Label ─── */
.lfw-section-label {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 40px 0 12px;
}
.lfw-section-label h2 {
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: #fff;
  margin: 0;
}
.lfw-section-label span {
  font-size: 10px;
  color: #555;
  margin-left: auto;
}
    `;
    var style = document.createElement('style');
    style.id = 'lfw-styles';
    style.textContent = css;
    document.head.appendChild(style);
  }

  /* ─────────────────────────────────────────────
   * INJECT SECTION HEADER ABOVE WIDGET
   * ───────────────────────────────────────────── */
  function injectSectionLabel(container) {
    var existing = document.getElementById('lfw-section-label');
    if (existing) return;
    var label = document.createElement('div');
    label.id = 'lfw-section-label';
    label.className = 'lfw-section-label';
    label.innerHTML = '<h2>🛰 Live Breaking Intel</h2><span id="lfw-last-updated">Fetching…</span>';
    container.parentNode.insertBefore(label, container);
  }

  /* ─────────────────────────────────────────────
   * BOOT
   * ───────────────────────────────────────────── */
  function boot() {
    var container = document.getElementById(CFG.CONTAINER_ID);
    if (!container) {
      log('Container #' + CFG.CONTAINER_ID + ' not found — widget not loaded');
      return;
    }

    injectStyles();
    injectSectionLabel(container);

    // Initial load
    doFetch(container, false);

    // Auto-refresh every 10 minutes
    setInterval(function () {
      log('Auto-refresh tick');
      doFetch(container, true).then(function () {
        var lbl = document.getElementById('lfw-last-updated');
        if (lbl) {
          var d = new Date();
          lbl.textContent = 'Last updated: ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
      });
    }, CFG.REFRESH_MS);

    log('Boot complete. Container found, fetch scheduled every', CFG.REFRESH_MS / 60000, 'min');
  }

  /* ─────────────────────────────────────────────
   * INIT
   * ───────────────────────────────────────────── */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    // Slight delay to let other scripts settle first
    setTimeout(boot, 400);
  }

  // Expose API for debugging
  window.LIVE_FEED_WIDGET = {
    refresh: function () {
      var c = document.getElementById(CFG.CONTAINER_ID);
      if (c) doFetch(c, true);
    },
    config: CFG
  };

})();
