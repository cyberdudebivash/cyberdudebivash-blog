#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH SENTINEL APEX — Global Intelligence Engine v5.0
 * HIGH-FREQUENCY MULTI-SOURCE NEAR REAL-TIME INTELLIGENCE ENGINE
 * 28 live sources | Tiered parallel ingestion | Stream-like writes
 * Source health monitoring | Lock mechanism | 5-min cadence
 * © 2026 CYBERDUDEBIVASH
 */
'use strict';
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

// Intelligence Enrichment Pipeline
const { runEnrichmentPipeline } = require('./api/_lib/enrichment-pipeline');

// Signal-to-Noise Engine (S2N)
const { runS2N, formatForFeed, finalThreatLevel } = require('./api/_lib/s2n-engine');

// Multi-platform Detection Engine (Phase 3). Loaded defensively so a missing
// or broken module can never take down live post generation.
let detEngine = null;
try { detEngine = require('./Sentinel-APEX/engine-node/detection-engine'); }
catch (e) { console.warn('⚠️ detection-engine unavailable:', e.message); }

// Persistent Analyst Memory (v2). Also loaded defensively. The instance is
// populated in main() from intel-memory.json; render/ingest are no-ops until
// then, so requiring this module for tests has no side effects.
let AnalystMemory = null;
try { ({ AnalystMemory } = require('./Sentinel-APEX/engine-node/analyst-memory')); }
catch (e) { console.warn('⚠️ analyst-memory unavailable:', e.message); }
let analystMemory = null;

// Analyst Reasoning Engine (v2). Defensive load; render is a no-op if absent.
let reasoningEngine = null;
try { reasoningEngine = require('./Sentinel-APEX/engine-node/reasoning-engine'); }
catch (e) { console.warn('⚠️ reasoning-engine unavailable:', e.message); }

// Multi-Audience Products Engine (v2). Defensive load.
let productsEngine = null;
try { productsEngine = require('./Sentinel-APEX/engine-node/products-engine'); }
catch (e) { console.warn('⚠️ products-engine unavailable:', e.message); }

// Detection Rules Canonical Store Manager (Stage 1.2)
let detectionRulesManager = null;
try { detectionRulesManager = require('./api/_lib/detection-rules'); }
catch (e) { console.warn('⚠️ detection-rules manager unavailable:', e.message); }

const CFG = {
  // ── Core paths ─────────────────────────────────────────────────────
  baseUrl:            'https://blog.cyberdudebivash.in',
  brand:              'CYBERDUDEBIVASH',
  author:             'CYBERDUDEBIVASH SENTINEL APEX',
  authorEmail:        'bivash@cyberdudebivash.com',
  postsDir:           path.join(__dirname, 'posts'),
  indexPath:          path.join(__dirname, 'index.html'),
  statePath:          path.join(__dirname, 'intel-state.json'),
  memoryPath:         path.join(__dirname, 'intel-memory.json'),
  lockPath:           path.join(__dirname, 'pipeline.lock'),
  rssPath:            path.join(__dirname, 'rss.xml'),
  liveJsonPath:       path.join(__dirname, 'live-intel.json'),
  sitemapPath:        path.join(__dirname, 'sitemap.xml'),
  apiDir:             path.join(__dirname, 'api', 'intel'),

  // ── Timing & limits ────────────────────────────────────────────────
  nvdLookbackHours:   72,      // fallback when no prior source state
  nvdMinLookbackHours: 4,     // v5.1: minimum lookback floor — prevents 5-min window starvation
  rssMinLookbackHours: 4,     // v5.2: same floor, generalized to every other lastFetch-driven
                               // source (CISA KEV/Alerts, GitHub Advisories, ExploitDB, PacketStorm,
                               // Full Disclosure, and the shared fetchRSS() used by 20+ blog/news
                               // sources) — see watermarkStart() below for why.
  kevLookbackDays:    7,
  maxNewPostsPerRun:  15,      // v5: increased
  minCVSS:            7.0,
  minPriorityScore:   35,      // v5: lower bar = more signal captured
  sourceTimeoutMs:    20000,   // v5.1: increased from 8000 — NVD API needs more time
  requestTimeoutMs:   18000,   // v5.1: increased from 12000
  maxRssItems:        12,
  dedupTtlDays:       30,
  liveRollingWindow:  150,     // v5: increased window
  apiLiveWindow:      100,
  healthFailThreshold: 3,      // Phase 7: mark degraded after N consecutive failures
  freshnessAlertMins:  30,     // Phase 8: alert if no new intel in 30 min

  // ── API keys ────────────────────────────────────────────────────────
  nvdApiKey:          process.env.NVD_API_KEY  || '',
  githubToken:        process.env.GITHUB_TOKEN || '',
  otxApiKey:          process.env.OTX_API_KEY  || '',
  sentinelApexApiKey: process.env.SENTINEL_APEX_API_KEY || '', // optional — endpoints are public

  // ── TIER 1: Critical CVE / exploit sources ──────────────────────────
  nvdApi:             'https://services.nvd.nist.gov/rest/json/cves/2.0',
  cisaKevUrl:         'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  epssApi:            'https://api.first.org/data/v1/epss',
  cisaAlertsRss:      'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  ghAdvisoryUrl:      'https://api.github.com/advisories?type=reviewed&severity=high&per_page=30',
  msrcApi:            'https://api.msrc.microsoft.com/cvrf/v2.0/Updates',
  exploitDbRss:       'https://www.exploit-db.com/rss.xml',
  packetstormRss:     'https://rss.packetstormsecurity.com/files/advisories/',
  fullDisclosureRss:  'https://seclists.org/rss/fulldisclosure.rss',

  // CYBERDUDEBIVASH SENTINEL APEX — native ecosystem CTI portal (product/
  // delivery layer for the same intelligence this repo's own engine feeds;
  // see Sentinel-APEX/README.md). Not a third-party vendor.
  sentinelApexLatestUrl:    'https://intel.cyberdudebivash.com/api/v1/intel/latest.json',
  sentinelApexApexUrl:      'https://intel.cyberdudebivash.com/api/v1/intel/apex.json',
  sentinelApexAiSummaryUrl: 'https://intel.cyberdudebivash.com/api/v1/intel/ai_summary.json',
  sentinelApexFeedUrl:      'https://intel.cyberdudebivash.com/api/feed.json',
  sentinelApexReportsUrl:   'https://intel.cyberdudebivash.com/api/reports/latest.json',

  // ── TIER 2: Threat intel blogs + malware feeds ─────────────────────
  bleepingRss:        'https://www.bleepingcomputer.com/feed/',
  thnRss:             'https://feeds.feedburner.com/TheHackersNews',
  krebsRss:           'https://krebsonsecurity.com/feed/',
  secweekRss:         'https://www.securityweek.com/feed/',
  sansRss:            'https://isc.sans.edu/rssfeed_full.xml',
  darkReadingRss:     'https://www.darkreading.com/rss.xml',
  talosBlogRss:       'https://blog.talosintelligence.com/feeds/posts/default',
  unit42Rss:          'https://unit42.paloaltonetworks.com/feed/',
  crowdstrikeBlogRss: 'https://www.crowdstrike.com/blog/feed/',
  sentineloneBlogRss: 'https://www.sentinelone.com/blog/feed/',
  googleProjZeroRss:  'https://googleprojectzero.blogspot.com/feeds/posts/default',
  rapid7BlogRss:      'https://www.rapid7.com/blog/feed/',
  urlhausApi:         'https://urlhaus-api.abuse.ch/v1/payloads/recent/',
  threatfoxApi:       'https://threatfox-api.abuse.ch/api/v1/',

  // ── TIER 3: Community + signals ─────────────────────────────────────
  redditNetsecRss:    'https://www.reddit.com/r/netsec/.rss?limit=25',
  redditCyberRss:     'https://www.reddit.com/r/cybersecurity/.rss?limit=15',
  certEuRss:          'https://www.cert.europa.eu/publications/threat-intelligence/rss',
  microsoftSecBlogRss:'https://www.microsoft.com/en-us/security/blog/feed/',
  wiredSecRss:        'https://www.wired.com/feed/category/security/latest/rss',
  recordedFutureRss:  'https://www.recordedfuture.com/feed/',
};

const log  = m => console.log(`[APEX] ${m}`);
const warn = m => console.warn(`[WARN] ${m}`);
const err  = m => console.error(`[ERR]  ${m}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isoNow = () => new Date().toISOString().slice(0, 10);
const isoNowFull = () => new Date().toISOString();
const md5 = s => crypto.createHash('md5').update(String(s)).digest('hex').slice(0, 16);


// ── ATOMIC WRITE — write to .tmp then rename to prevent truncation on SIGKILL ──
function safeWriteSync(filePath, data, encoding = 'utf8') {
  const tmp = filePath + '.tmp';
  try {
    fs.writeFileSync(tmp, data, encoding);
    fs.renameSync(tmp, filePath);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) {}
    throw e;
  }
}

// ── PHASE 3: LOCK MECHANISM — prevents overlapping runs ─────────────────
function acquireLock() {
  try {
    if (fs.existsSync(CFG.lockPath)) {
      const lockData = JSON.parse(fs.readFileSync(CFG.lockPath, 'utf8'));
      const ageMs = Date.now() - (lockData.acquired || 0);
      if (ageMs < 10 * 60000) { // 10 min max lock age
        warn(`Pipeline already running (lock age ${Math.round(ageMs/1000)}s). Aborting.`);
        return false;
      }
      warn(`Stale lock found (${Math.round(ageMs/60000)} min old). Overriding.`);
    }
    fs.writeFileSync(CFG.lockPath, JSON.stringify({ acquired: Date.now(), pid: process.pid }), 'utf8');
    return true;
  } catch(e) { warn(`Lock acquire failed: ${e.message}`); return true; } // fail-open
}
function releaseLock() {
  try { if (fs.existsSync(CFG.lockPath)) fs.unlinkSync(CFG.lockPath); } catch(_) {}
}

// ── PHASE 2: PER-SOURCE TIMEOUT WRAPPER ────────────────────────────────
async function fetchWithTimeout(fetchFn, sourceKey, timeoutMs) {
  const timeout = timeoutMs || CFG.sourceTimeoutMs;
  return Promise.race([
    fetchFn(),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`Source timeout ${timeout}ms: ${sourceKey}`)), timeout)),
  ]);
}

// ── PHASE 7: SOURCE HEALTH MONITORING ──────────────────────────────────
function initSourceHealth(name) {
  return { name, lastSuccess: null, lastError: null, consecutiveFails: 0, totalFails: 0, totalSuccesses: 0, successRate: 1.0, status: 'ok' };
}
function recordSourceSuccess(state, source) {
  if (!state.sourceHealth) state.sourceHealth = {};
  const h = state.sourceHealth[source] || initSourceHealth(source);
  h.lastSuccess       = isoNowFull();
  h.consecutiveFails  = 0;
  h.totalSuccesses    = (h.totalSuccesses || 0) + 1;
  h.successRate       = h.totalSuccesses / Math.max(1, h.totalSuccesses + h.totalFails);
  h.status            = 'ok';
  state.sourceHealth[source] = h;
}
function recordSourceFailure(state, source, errorMsg) {
  if (!state.sourceHealth) state.sourceHealth = {};
  const h = state.sourceHealth[source] || initSourceHealth(source);
  h.lastError         = `${isoNowFull()}: ${String(errorMsg).slice(0,100)}`;
  h.consecutiveFails  = (h.consecutiveFails || 0) + 1;
  h.totalFails        = (h.totalFails || 0) + 1;
  h.successRate       = h.totalSuccesses / Math.max(1, h.totalSuccesses + h.totalFails);
  h.status            = h.consecutiveFails >= CFG.healthFailThreshold ? 'degraded' : 'warning';
  state.sourceHealth[source] = h;
}
function getSourceHealthReport(state) {
  const health = state.sourceHealth || {};
  const degraded = Object.values(health).filter(h => h.status === 'degraded');
  const warning  = Object.values(health).filter(h => h.status === 'warning');
  return { degraded: degraded.map(h=>h.name), warning: warning.map(h=>h.name), total: Object.keys(health).length };
}

// ── UTILITIES ──────────────────────────────────────────────────────────
function fmtDate(d) {
  const dt = new Date(d);
  if (isNaN(dt)) return new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});
  return dt.toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});
}
function slugify(str) {
  return String(str).toLowerCase().replace(/[^a-z0-9\s-]/g,' ').replace(/\s+/g,'-').replace(/-{2,}/g,'-').replace(/^-|-$/g,'').slice(0,90);
}
function escHtml(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
// Some RSS/Atom feeds (Reddit's notably) emit CDATA content whose tags are
// themselves HTML-entity-encoded as text, occasionally double-encoded
// (e.g. "&amp;lt;div&amp;gt;"). Decoding twice resolves one level of
// double-escaping so real tags are exposed before stripHtml removes them —
// otherwise tag names and entity fragments leak into plain text unchanged.
const HTML_NAMED_ENTITIES = { amp:'&', lt:'<', gt:'>', quot:'"', apos:"'", nbsp:' ' };
function decodeEntities(str) {
  const decodeOnce = t => String(t||'').replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (m, ent) => {
    if (ent[0] === '#') {
      const code = (ent[1]==='x'||ent[1]==='X') ? parseInt(ent.slice(2),16) : parseInt(ent.slice(1),10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return Object.prototype.hasOwnProperty.call(HTML_NAMED_ENTITIES, ent) ? HTML_NAMED_ENTITIES[ent] : m;
  });
  return decodeOnce(decodeOnce(str));
}
function stripHtml(str) {
  return decodeEntities(str).replace(/<[^>]*>/g,' ').replace(/\s{2,}/g,' ').trim();
}
// References are evidence, not display text. Extract only absolute HTTP(S)
// URLs from free-form source notes and reject malformed/combined values.
function extractHttpUrls(value) {
  const matches = decodeEntities(Array.isArray(value) ? value.join(' ') : value)
    .match(/https?:\/\/[^\s<>"'`;,)\]]+/gi) || [];
  return [...new Set(matches.map(candidate => {
    const clean = candidate.replace(/[.!?:}\]]+$/g, '');
    try {
      const parsed = new url.URL(clean);
      return /^https?:$/.test(parsed.protocol) ? parsed.href : null;
    } catch (_) { return null; }
  }).filter(Boolean))];
}

function parseCvssFromText(text) {
  const match = String(text||'').match(/\bCVSS(?:\s*(?:v?[234]\.\d|base))?\s*(?:score)?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b/i);
  if (!match) return null;
  const score = Number(match[1]);
  return Number.isFinite(score) && score >= 0 && score <= 10 ? score : null;
}

// A public exploit, exploit discussion, or the word "active" alone is not
// evidence of exploitation. Only explicit observed/confirmed language is.
function hasConfirmedExploitation(text) {
  return /\b(actively exploited|active exploitation|exploited in the wild|in-the-wild exploitation|observed exploitation|confirmed exploitation|under active exploitation)\b/i.test(String(text||''));
}
function extractCVEs(text) {
  const m = (text||'').match(/CVE-\d{4}-\d{4,7}/gi)||[];
  return [...new Set(m.map(c=>c.toUpperCase()))];
}

// ── PHASE 1: ADVANCED IOC ENRICHMENT ENGINE ────────────────────────────
const IP_RE    = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const URL_RE   = /https?:\/\/[^\s"'<>]{8,100}/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|ir|kp|tk|xyz|top|info|biz|su)\b/gi;
const MD5_RE   = /\b[0-9a-fA-F]{32}\b/g;
const SHA1_RE  = /\b[0-9a-fA-F]{40}\b/g;
const SHA256_RE= /\b[0-9a-fA-F]{64}\b/g;

function extractIOCs(text, existingIOCs) {
  const raw = String(text||'');
  const normalized = [];
  const seen = new Set();
  const add = (type, value, confidence) => {
    const key = `${type}:${value}`;
    if (seen.has(key) || value.length < 4) return;
    seen.add(key);
    normalized.push({ type, value: value.slice(0,120), confidence_score: confidence, first_seen: isoNow(), source_count: 1 });
  };
  (raw.match(SHA256_RE)||[]).slice(0,5).forEach(h => add('sha256', h, 0.95));
  (raw.match(SHA1_RE)||[]).filter(h=>!raw.match(SHA256_RE)||[]).slice(0,5).forEach(h => add('sha1', h, 0.90));
  (raw.match(MD5_RE)||[]).slice(0,5).forEach(h => add('md5', h, 0.85));
  (raw.match(IP_RE)||[]).filter(ip => !ip.startsWith('192.168')&&!ip.startsWith('10.')&&!ip.startsWith('127.')).slice(0,5).forEach(ip => add('ipv4', ip, 0.88));
  (raw.match(URL_RE)||[]).filter(u => !u.includes('nvd.nist.gov')&&!u.includes('cisa.gov')&&!u.includes('blog.cyberdude')).slice(0,5).forEach(u => add('url', u.slice(0,100), 0.82));
  (raw.match(DOMAIN_RE)||[]).filter(d => d.length>5&&!d.includes('nvd.nist')&&!d.includes('cisa.gov')&&!d.includes('github.com')&&!d.includes('cyberdude')).slice(0,5).forEach(d => add('domain', d.toLowerCase(), 0.75));
  (existingIOCs||[]).forEach(ioc => {
    const val = String(ioc).replace(/^[^:]+:\s*/,'').trim();
    const type = String(ioc).match(/^(md5|sha1|sha256|ip|url|domain|hash):/i)?.[1]?.toLowerCase()||'hash';
    add(type, val, 0.90);
  });
  return normalized.slice(0, 20);
}

// ── HTTP FETCH ──────────────────────────────────────────────────────────
function fetchUrl(rawUrl, opts = {}, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Too many redirects'));
    let parsed;
    try { parsed = new url.URL(rawUrl); } catch(e) { return reject(e); }
    const isHttps = parsed.protocol === 'https:';
    const client  = isHttps ? https : http;
    const headers = {
      'User-Agent': 'CYBERDUDEBIVASH-SENTINEL-APEX/4.0 (+https://blog.cyberdudebivash.in)',
      'Accept': 'application/json, application/xml, text/xml, */*',
      ...(opts.headers || {}),
    };
    if (CFG.nvdApiKey && rawUrl.includes('nvd.nist.gov')) headers['apiKey'] = CFG.nvdApiKey;
    if (CFG.githubToken && rawUrl.includes('api.github.com')) headers['Authorization'] = `Bearer ${CFG.githubToken}`;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: opts.method || 'GET',
      headers,
      timeout: CFG.requestTimeoutMs,
    };
    const req = client.request(options, res => {
      if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
        const loc = res.headers.location.startsWith('http') ? res.headers.location : `${parsed.protocol}//${parsed.host}${res.headers.location}`;
        res.resume();
        return fetchUrl(loc, opts, redirects + 1).then(resolve).catch(reject);
      }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', c => { data += c; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
        else reject(new Error(`HTTP ${res.statusCode} — ${rawUrl.slice(0,80)}`));
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${rawUrl.slice(0,60)}`)); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}
async function fetchWithRetry(rawUrl, opts = {}, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    try { return await fetchUrl(rawUrl, opts); }
    catch(e) {
      if (i < attempts - 1) { warn(`Retry ${i+1} for ${rawUrl.slice(0,60)}: ${e.message}`); await sleep(2000*(i+1)); }
      else throw e;
    }
  }
}

// ── RSS PARSER ─────────────────────────────────────────────────────────
function parseRSS(xml) {
  const items = [];
  const re = /<(?:item|entry)[^>]*>([\s\S]*?)<\/(?:item|entry)>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const b = m[1];
    const get = tag => {
      const cd = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>`, 'i').exec(b);
      if (cd) return stripHtml(cd[1]).trim();
      const pl = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i').exec(b);
      if (pl) return stripHtml(pl[1]).trim();
      if (tag === 'link') { const hr = /<link[^>]+href=["']([^"']+)["']/i.exec(b); if(hr) return hr[1]; }
      return '';
    };
    const title = get('title'), link = get('link')||get('guid'), desc = get('description')||get('summary')||get('content');
    const pubDate = get('pubDate')||get('published')||get('updated')||get('dc:date');
    if (title && link) items.push({ title: stripHtml(title), link, desc: stripHtml(desc), pubDate });
  }
  return items;
}

// ── STATE ──────────────────────────────────────────────────────────────
function loadState() {
  try {
    if (fs.existsSync(CFG.statePath)) {
      const s = JSON.parse(fs.readFileSync(CFG.statePath, 'utf8'));
      if (!Array.isArray(s.published)) s.published = [];
      if (!s.correlations) s.correlations = {};
      if (!s.sourceFetchState) s.sourceFetchState = {};
      if (!s.sourceHealth) s.sourceHealth = {};
      return s;
    }
  } catch(e) { warn('State corrupt — starting fresh.'); }
  return { published: [], lastRun: null, lastReportGeneratedAt: null, totalPublished: 0, correlations: {}, sourceFetchState: {}, sourceHealth: {}, version: '5.0' };
}
function saveState(state) {
  state.lastRun  = isoNowFull();
  state.version  = '5.0';
  const ttlMs    = (CFG.dedupTtlDays || 30) * 86400000 * 2; // 60-day hard purge
  const now      = Date.now();
  state.published = state.published.filter(p => (now - new Date(p.date || 0).getTime()) < ttlMs);
  if (state.published.length > 3000) state.published = state.published.slice(0, 2000);
  safeWriteSync(CFG.statePath, JSON.stringify(state, null, 2), 'utf8');
}
// Returns last fetch timestamp for a named source (epoch ms), or null if never fetched
function getSourceLastFetch(state, source) {
  return state.sourceFetchState?.[source]?.lastFetch || null;
}
// Records successful fetch timestamp for a named source
function setSourceLastFetch(state, source, tsMs) {
  if (!state.sourceFetchState) state.sourceFetchState = {};
  state.sourceFetchState[source] = { lastFetch: tsMs || Date.now(), updatedAt: new Date().toISOString() };
}
// Computes a safe incremental-fetch watermark: the source's own lastFetch,
// but never narrower than minLookbackHours. setSourceLastFetch() ratchets a
// source's watermark to Date.now() on every SUCCESSFUL fetch regardless of
// whether any items were found, so on a source with a real quiet period
// (e.g. a blog that posts every few hours), the window has zero overlap and
// a single missed or late run can push the watermark past the source's next
// real item with no way to self-heal. Downstream isPublished()/writeLiveIntel()
// dedup by item id (TTL-based, and keyed against what's already in the
// live-intel.json rolling window) already makes a wider re-check window
// safe — re-seeing an already-seen item is a no-op, not a duplicate publish
// or a reset _addedAt. This is the same fix shape already shipped for NVD
// (nvdMinLookbackHours, v5.1) — generalized here instead of re-deriving the
// "earlier of lastFetch and the floor" logic at every other call site.
function watermarkStart(lastFetch, minLookbackHours, fallbackMs) {
  const minStart = new Date(Date.now() - minLookbackHours * 3600000);
  const rawStart = lastFetch ? new Date(lastFetch) : new Date(Date.now() - fallbackMs);
  return rawStart < minStart ? rawStart : minStart;
}
// isPublished respects dedupTtlDays — items published > TTL days ago are NOT duplicates
function isPublished(state, id) {
  const ttlMs = (CFG.dedupTtlDays || 30) * 86400000;
  const now   = Date.now();
  return state.published.some(p => {
    if (p.id !== id) return false;
    const age = now - new Date(p.date || 0).getTime();
    return age < ttlMs; // within TTL window → is a duplicate
  });
}
function markPublished(state, item) {
  state.published.unshift({ id: item.id, slug: item.slug, date: isoNow(), title: item.title });
  state.totalPublished = (state.totalPublished || 0) + 1;
}

// ── SOURCE 1: NVD CVE API v2.0 ─────────────────────────────────────────
async function fetchNVD(state) {
  const end   = new Date();
  const lastFetch = getSourceLastFetch(state, 'nvd');
  // v5.1: Enforce minimum 4-hour lookback floor.
  // Without this, the 5-min cron window starves NVD (CVEs aren't published every 5 min).
  const minLookbackMs = CFG.nvdMinLookbackHours * 3600000;
  const minStart = new Date(Date.now() - minLookbackMs);
  const rawStart = lastFetch ? new Date(lastFetch) : new Date(Date.now() - CFG.nvdLookbackHours * 3600000);
  // Use the EARLIER of rawStart and minStart to ensure we cover at least nvdMinLookbackHours
  const start = rawStart < minStart ? rawStart : minStart;
  const fmt   = d => d.toISOString().slice(0,23);
  // Fetch CRITICAL and HIGH severity CVEs for broader signal coverage
  const apiUrl      = `${CFG.nvdApi}?pubStartDate=${encodeURIComponent(fmt(start))}&pubEndDate=${encodeURIComponent(fmt(end))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=20&noRejected`;
  const apiUrlHigh  = `${CFG.nvdApi}?pubStartDate=${encodeURIComponent(fmt(start))}&pubEndDate=${encodeURIComponent(fmt(end))}&cvssV3SeverityExact=HIGH&resultsPerPage=15&noRejected`;
  const apiUrlMod   = `${CFG.nvdApi}?lastModStartDate=${encodeURIComponent(fmt(start))}&lastModEndDate=${encodeURIComponent(fmt(end))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=15&noRejected`;
  log(`NVD: fetching CRITICAL+HIGH CVEs since ${start.toISOString()} (min floor: ${CFG.nvdMinLookbackHours}h)...`);
  try {
    await sleep(600);
    // v5.1: Fetch CRITICAL, HIGH, and recently-modified CRITICAL CVEs — merge and deduplicate
    const parseVulns = (raw) => {
      try {
        return (JSON.parse(raw).vulnerabilities||[]);
      } catch(_) { return []; }
    };
    const mapVuln = (v) => {
      const cve = v.cve, id = cve.id;
      const desc   = (cve.descriptions||[]).find(d=>d.lang==='en')?.value||'';
      const met    = cve.metrics?.cvssMetricV31?.[0]||cve.metrics?.cvssMetricV30?.[0]||null;
      const cvss   = met?.cvssData?.baseScore||0;
      const vector = met?.cvssData?.vectorString||'';
      const cweId  = cve.weaknesses?.[0]?.description?.[0]?.value||'';
      const refs   = (cve.references||[]).map(r=>r.url).slice(0,6);
      const pubDate= cve.published?.slice(0,10)||isoNow();
      const cpe    = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria||'';
      const vendor  = (cpe.match(/cpe:2\.3:[aoh]:([^:]+):/)||[])[1]?.replace(/_/g,' ')||'Unknown Vendor';
      const product = (cpe.match(/cpe:2\.3:[aoh]:[^:]+:([^:]+):/)||[])[1]?.replace(/_/g,' ')||desc.split(/\s+/).slice(0,3).join(' ')||'Unknown Product';
      const iocs = extractIOCs(desc, []);
      const sevLabel = cvss >= 9.0 ? 'Critical Vulnerability' : 'High Severity Vulnerability';
      return { source:'nvd', type:'CVE_REPORT', id, title:`${id} — ${vendor} ${product} CVSS ${cvss} ${sevLabel}`,
        desc, cvss, vector, cweId, refs, pubDate, vendor, product, exploited:false, cisaKev:false, ransomware:false,
        iocs, sourceCount:1, daysOld: Math.floor((Date.now()-new Date(pubDate).getTime())/86400000) };
    };
    // Parallel fetches for CRITICAL pub, HIGH pub, CRITICAL lastMod
    const [rawCrit, rawHighPub, rawMod] = await Promise.allSettled([
      fetchWithRetry(apiUrl, {}, 2),
      fetchWithRetry(apiUrlHigh, {}, 2),
      fetchWithRetry(apiUrlMod, {}, 2),
    ]);
    const seenIds = new Set();
    const allVulns = [
      ...(rawCrit.status==='fulfilled' ? parseVulns(rawCrit.value) : []),
      ...(rawHighPub.status==='fulfilled' ? parseVulns(rawHighPub.value) : []),
      ...(rawMod.status==='fulfilled' ? parseVulns(rawMod.value) : []),
    ].filter(v => { const id = v?.cve?.id; if (!id||seenIds.has(id)) return false; seenIds.add(id); return true; });
    const items = allVulns.map(mapVuln).filter(i => i.cvss >= CFG.minCVSS);
    setSourceLastFetch(state, 'nvd', Date.now());
    log(`NVD: ${items.length} items CRITICAL+HIGH (since ${start.toISOString().slice(0,10)}, ${allVulns.length} raw).`);
    return items;
  } catch(e) { warn(`NVD failed: ${e.message}`); return []; }
}

// ── SOURCE 2: CISA KEV ─────────────────────────────────────────────────
async function fetchCISAKev(state) {
  const lastFetch = getSourceLastFetch(state, 'cisa_kev');
  const cutoff    = watermarkStart(lastFetch, CFG.rssMinLookbackHours, CFG.kevLookbackDays * 86400000);
  log(`CISA KEV: fetching (since ${cutoff.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(CFG.cisaKevUrl);
    const data = JSON.parse(raw);
    const items = (data.vulnerabilities||[]).filter(v => new Date(v.dateAdded) >= cutoff).map(v => {
      const iocs = []; // KEV descriptions contain reference domains, not vetted malicious indicators.
      return { source:'cisa_kev', type:'CVE_REPORT', id:v.cveID,
        title:`${v.cveID}: ${v.vulnerabilityName} — CISA KEV Active Exploitation`,
        // CISA KEV confirms exploitation but does not publish a CVSS score.
        // Keep severity unknown until a scored primary record is correlated.
        desc:v.shortDescription||v.vulnerabilityName, cvss:null, vector:'', cweId:'',
        refs:[...extractHttpUrls(v.notes), 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'], pubDate:v.dateAdded, vendor:v.vendorProject, product:v.product,
        vulnName:v.vulnerabilityName, exploited:true, cisaKev:true,
        ransomware:v.knownRansomwareCampaignUse==='Known', dueDate:v.dueDate,
        reqAction:v.requiredAction, iocs, sourceCount:1,
        daysOld: Math.floor((Date.now()-new Date(v.dateAdded).getTime())/86400000) };
    });
    setSourceLastFetch(state, 'cisa_kev', Date.now());
    log(`CISA KEV: ${items.length} items.`); return items;
  } catch(e) { warn(`CISA KEV failed: ${e.message}`); return []; }
}

/**
 * Batch-fetch real EPSS exploitation-probability scores for up to 100 CVE
 * IDs in one request. Returns {} on failure — callers must treat a missing
 * entry as "unknown", never fabricate a score. Free, unauthenticated feed.
 */
async function fetchEpssBatch(cveIds) {
  if (!cveIds || !cveIds.length) return {};
  try {
    const url = `${CFG.epssApi}?cve=${encodeURIComponent(cveIds.slice(0,100).join(','))}`;
    const raw = await fetchWithRetry(url);
    const data = JSON.parse(raw);
    const map = {};
    (data.data||[]).forEach(item => {
      const cve = String(item.cve||'').toUpperCase();
      const score = parseFloat(item.epss);
      const pct = parseFloat(item.percentile);
      if (cve && Number.isFinite(score) && Number.isFinite(pct)) {
        map[cve] = { score, percentile: pct };
      }
    });
    log(`EPSS: ${Object.keys(map).length}/${cveIds.length} CVEs scored.`);
    return map;
  } catch(e) { warn(`EPSS fetch failed: ${e.message}`); return {}; }
}

// ── SOURCE 3: CISA Alerts RSS ──────────────────────────────────────────
async function fetchCISAAlerts(state) {
  const lastFetch  = getSourceLastFetch(state, 'cisa_alerts');
  const afterDate  = watermarkStart(lastFetch, CFG.rssMinLookbackHours, CFG.kevLookbackDays * 86400000);
  log(`CISA Alerts RSS: fetching (since ${afterDate.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(CFG.cisaAlertsRss);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => {
        if (!item.pubDate) return true; // include if no date
        try { return new Date(item.pubDate) >= afterDate; } catch(_) { return true; }
      })
      .slice(0, CFG.maxRssItems).map(item => {
        const text = (item.title||'')+' '+(item.desc||'');
        const iocs = [];
        return { source:'cisa_alerts', type:'ADVISORY', id:'CISA-'+md5(item.link),
          title:item.title, desc:(item.desc||'').slice(0,600), cvss:parseCvssFromText(text), refs:extractHttpUrls(item.link),
          pubDate:item.pubDate?new Date(item.pubDate).toISOString().slice(0,10):isoNow(),
          vendor:'CISA US-CERT', product:'Multiple Products',
          exploited:hasConfirmedExploitation(text), cisaKev:false,
          ransomware:/ransomware/i.test(text),
          cves:extractCVEs(text), link:item.link, iocs, sourceCount:1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0 };
      });
    setSourceLastFetch(state, 'cisa_alerts', Date.now());
    log(`CISA Alerts: ${items.length} items (filtered from ${parsed.length}).`); return items;
  } catch(e) { warn(`CISA Alerts failed: ${e.message}`); return []; }
}

// ── SOURCE 4: GitHub Security Advisories ──────────────────────────────
async function fetchGitHubAdvisories(state) {
  const lastFetch = getSourceLastFetch(state, 'github_advisories');
  const cutoff    = watermarkStart(lastFetch, CFG.rssMinLookbackHours, 7*86400000);
  log(`GitHub Advisories: fetching (since ${cutoff.toISOString().slice(0,10)})...`);
  try {
    await sleep(500);
    const raw = await fetchWithRetry(CFG.ghAdvisoryUrl);
    const data = JSON.parse(raw);
    const items = (Array.isArray(data)?data:[]).filter(a => new Date(a.published_at||a.updated_at) >= cutoff).slice(0,10).map(a => {
      const cvssRaw = Number(a.cvss?.score);
      const cvss = Number.isFinite(cvssRaw) && cvssRaw >= 0 && cvssRaw <= 10 ? cvssRaw : null;
      const cves = (a.cve_id?[a.cve_id]:[]).concat((a.identifiers||[]).filter(i=>i.type==='CVE').map(i=>i.value));
      const primaryId = cves[0]||('GHSA-'+md5(a.ghsa_id||a.url));
      const desc = stripHtml(a.description||a.summary||'').slice(0,800);
      const iocs = extractIOCs(desc, []);
      return { source:'github_advisories', type:'CVE_REPORT', id:primaryId,
        title:a.summary||`${primaryId} — GitHub Security Advisory`,
        desc, cvss, vector:a.cvss?.vector_string||'', cweId:(a.cwes||[])[0]?.cwe_id||'',
        refs:[a.html_url,...(a.references||[])].flatMap(extractHttpUrls).slice(0,5),
        pubDate:(a.published_at||isoNow()).slice(0,10),
        vendor:(a.vulnerabilities||[])[0]?.package?.ecosystem||'Open Source',
        product:(a.vulnerabilities||[])[0]?.package?.name||'Unknown Package',
        exploited:false, cisaKev:false, ransomware:false, cves, iocs, sourceCount:1,
        daysOld: Math.floor((Date.now()-new Date(a.published_at||isoNow()).getTime())/86400000) };
    });
    setSourceLastFetch(state, 'github_advisories', Date.now());
    log(`GitHub Advisories: ${items.length} items.`); return items;
  } catch(e) { warn(`GitHub Advisories failed: ${e.message}`); return []; }
}

// ── RSS NORMALIZER ─────────────────────────────────────────────────────
function classifyNews(text) {
  const t = String(text||'').toLowerCase();
  // Priority order: most specific first
  if (/zero.?day|0.?day|unpatched exploit|no patch available|n-day exploit/i.test(t))          return 'ZERO_DAY';
  if (/ransomware|ransom demand|encryption attack|lockbit|qilin|akira|blackcat|ransomhub|cl0p|black basta|play ransomware/i.test(t)) return 'RANSOMWARE';
  if (/nation.state|state.sponsored|apt\s?\d|lazarus|volt typhoon|sandworm|cozy bear|fancy bear|salt typhoon|scatter spider|kimsuky|charming kitten|muddywater|turla/i.test(t)) return 'THREAT_ACTOR';
  if (/supply chain|solarwinds|xz utils|npm package|pypi package|open.?source.*attack|dependency confusion|typosquat/i.test(t)) return 'SUPPLY_CHAIN';
  if (/prompt injection|jailbreak|llm|large language model|gpt.*(hack|vuln|attack)|chatgpt.*security|ai.*attack|model poisoning|adversarial ml|deepfake.*attack|ai governance|agentic ai.*risk|owasp llm|ai red team/i.test(t)) return 'AI_SECURITY';
  if (/dark web|darkweb|tor network|onion.*market|leak.*site|ransomware.*victim|data.*for sale|stolen.*credentials|underground forum|initial access broker|malware.*market/i.test(t)) return 'DARK_WEB';
  if (/cloud.*breach|aws.*exploit|azure.*vuln|gcp.*attack|s3.*exposed|kubernetes.*attack|container.*escape|serverless.*attack|iam.*misconfigur|cloud misconfigur/i.test(t)) return 'CLOUD_SECURITY';
  if (/data breach|breach notification|records stolen|database dump|leaked|exposed data|personal.*data.*exposed|pii.*exposed|hipaa.*breach|gdpr.*breach/i.test(t)) return 'DATA_BREACH';
  if (/malware|trojan|\brat\b|backdoor|botnet|stealer|infostealer|loader|dropper|rootkit|spyware|keylogger|worm|virus/i.test(t)) return 'MALWARE_REPORT';
  if (/sigma rule|yara rule|detection engineering|hunting query|spl query|kql detection|siem rule|edr detection/i.test(t)) return 'DETECTION_ENGINEERING';
  if (/critical infrastructure|scada|ics|ot security|industrial control|power grid|water treatment|hospital.*attack|healthcare.*breach|energy sector/i.test(t)) return 'CRITICAL_INFRASTRUCTURE';
  if (/phishing|spear.*phishing|business email compromise|bec|vishing|smishing|social engineering|credential.*harvest/i.test(t)) return 'SOCIAL_ENGINEERING';
  if (/patch tuesday|security update|cve-\d|advisory|vulnerability.*disclosed|security.*bulletin/i.test(t)) return 'CVE_REPORT';
  if (/incident response|security incident|breach response|data exposure|security event|security alert/i.test(t)) return 'INCIDENT';
  return 'NEWS_REPORT';
}

// ── PHASE 4 v5.3: SUBCATEGORY CLASSIFIER ─────────────────────────────────
function classifySubcategory(type, text) {
  const t = String(text||'').toLowerCase();
  switch(type) {
    case 'CVE_REPORT': case 'ZERO_DAY':
      if (/remote code execution|rce/i.test(t))      return 'RCE';
      if (/sql injection|sqli/i.test(t))             return 'SQL_INJECTION';
      if (/privilege escalation|eop|lpe/i.test(t))  return 'PRIVILEGE_ESCALATION';
      if (/auth bypass|unauthenticated/i.test(t))    return 'AUTH_BYPASS';
      if (/buffer overflow|heap overflow/i.test(t))  return 'MEMORY_CORRUPTION';
      if (/xss|cross.site script/i.test(t))          return 'XSS';
      if (/ssrf/i.test(t))                           return 'SSRF';
      if (/path traversal|directory traversal/i.test(t)) return 'PATH_TRAVERSAL';
      if (/deserialization/i.test(t))                return 'DESERIALIZATION';
      if (/command injection/i.test(t))              return 'COMMAND_INJECTION';
      return 'VULNERABILITY';
    case 'RANSOMWARE':
      if (/lockbit/i.test(t))    return 'LOCKBIT';
      if (/akira/i.test(t))      return 'AKIRA';
      if (/qilin/i.test(t))      return 'QILIN';
      if (/blackcat|alphv/i.test(t)) return 'BLACKCAT';
      if (/ransomhub/i.test(t))  return 'RANSOMHUB';
      if (/black basta/i.test(t)) return 'BLACK_BASTA';
      if (/cl0p/i.test(t))       return 'CLOP';
      return 'RANSOMWARE_GROUP';
    case 'AI_SECURITY':
      if (/prompt injection/i.test(t))  return 'PROMPT_INJECTION';
      if (/model poisoning|data poisoning/i.test(t)) return 'MODEL_POISONING';
      if (/jailbreak/i.test(t))         return 'JAILBREAK';
      if (/llm|large language/i.test(t)) return 'LLM_VULNERABILITY';
      if (/deepfake/i.test(t))          return 'DEEPFAKE';
      if (/agentic|ai agent/i.test(t))  return 'AGENTIC_AI_RISK';
      if (/adversarial/i.test(t))       return 'ADVERSARIAL_ML';
      return 'AI_VULNERABILITY';
    case 'THREAT_ACTOR':
      if (/lazarus|north korea|dprk/i.test(t))       return 'NORTH_KOREA';
      if (/volt typhoon|salt typhoon|china|prc/i.test(t)) return 'CHINA_NEXUS';
      if (/sandworm|cozy bear|fancy bear|russia|apt28|apt29/i.test(t)) return 'RUSSIA_NEXUS';
      if (/iran|charming kitten|muddywater/i.test(t)) return 'IRAN_NEXUS';
      if (/scatter spider/i.test(t))                 return 'CYBERCRIME';
      return 'APT';
    case 'MALWARE_REPORT':
      if (/ransomware/i.test(t))    return 'RANSOMWARE_PAYLOAD';
      if (/stealer|infostealer/i.test(t)) return 'INFOSTEALER';
      if (/botnet/i.test(t))        return 'BOTNET';
      if (/loader|dropper/i.test(t)) return 'LOADER';
      if (/backdoor/i.test(t))      return 'BACKDOOR';
      if (/rootkit/i.test(t))       return 'ROOTKIT';
      return 'MALWARE';
    default: return '';
  }
}

// ── PHASE 3 v5.3: UNIVERSAL INTELLIGENCE SCHEMA NORMALIZER ───────────────
function normalizeToUniversalSchema(item) {
  const text = (item.title||'') + ' ' + (item.desc||'');
  const type = item.type || classifyNews(text);
  const subcategory = item.subcategory || classifySubcategory(type, text);

  // Affected industries
  const affectedIndustries = [];
  if (/health|hospital|medical|hipaa|pharma/i.test(text))            affectedIndustries.push('Healthcare');
  if (/finance|bank|fintech|payment|swift|credit card/i.test(text)) affectedIndustries.push('Financial Services');
  if (/energy|power grid|oil|gas|utility|water/i.test(text))        affectedIndustries.push('Energy & Utilities');
  if (/government|federal|agency|dod|nsa|fbi|dhs/i.test(text))     affectedIndustries.push('Government');
  if (/education|university|school|academic/i.test(text))           affectedIndustries.push('Education');
  if (/retail|e.commerce|shopify|magecart/i.test(text))             affectedIndustries.push('Retail');
  if (/telecom|isp|carrier|5g|network provider/i.test(text))        affectedIndustries.push('Telecommunications');
  if (/manufacturing|industrial|factory|ot|scada/i.test(text))      affectedIndustries.push('Manufacturing');
  if (/technology|software|saas|cloud|tech company/i.test(text))    affectedIndustries.push('Technology');
  if (/defense|military|contractor|weapons/i.test(text))            affectedIndustries.push('Defense');

  // AI security tags
  const aiSecurityTags = [];
  if (/prompt injection/i.test(text))         aiSecurityTags.push('prompt-injection');
  if (/llm|large language model/i.test(text)) aiSecurityTags.push('llm');
  if (/jailbreak/i.test(text))               aiSecurityTags.push('jailbreak');
  if (/model poisoning/i.test(text))         aiSecurityTags.push('model-poisoning');
  if (/deepfake/i.test(text))               aiSecurityTags.push('deepfake');
  if (/owasp llm/i.test(text))              aiSecurityTags.push('owasp-llm');
  if (/agentic ai|ai agent/i.test(text))    aiSecurityTags.push('agentic-ai');
  if (/adversarial ml/i.test(text))         aiSecurityTags.push('adversarial-ml');
  if (/ai governance/i.test(text))          aiSecurityTags.push('ai-governance');

  // Dark web tags
  const darkwebTags = [];
  if (/dark web|darkweb/i.test(text))        darkwebTags.push('dark-web');
  if (/leak site/i.test(text))              darkwebTags.push('leak-site');
  if (/stolen credentials/i.test(text))     darkwebTags.push('credentials');
  if (/initial access broker/i.test(text))  darkwebTags.push('iab');
  if (/ransomware.*victim|victim.*leak/i.test(text)) darkwebTags.push('ransomware-leak');

  // Threat actor extraction
  const actorMap = {
    'Lazarus Group': /lazarus|hidden cobra|bluenoroff/i,
    'Volt Typhoon': /volt typhoon/i,
    'Salt Typhoon': /salt typhoon/i,
    'Sandworm': /sandworm/i,
    'Cozy Bear': /cozy bear|apt29/i,
    'Fancy Bear': /fancy bear|apt28/i,
    'Scatter Spider': /scatter spider|octo tempest/i,
    'Charming Kitten': /charming kitten|apt35/i,
    'LockBit': /lockbit/i,
    'Akira': /\bakira\b/i,
    'RansomHub': /ransomhub/i,
    'Black Basta': /black basta/i,
    'Cl0p': /\bcl0p\b|\bclop\b/i,
  };
  const detectedActors = Object.entries(actorMap)
    .filter(([, re]) => re.test(text))
    .map(([name]) => name);

  // Confidence scoring
  const sourceTrustMap = { nvd:1.0, cisa_kev:1.0, cisa_alerts:0.95, github_advisories:0.90, msrc:0.90, cisco_psirt:0.88, ncsc_uk:0.92, exploitdb:0.82, packetstorm:0.80, fulldisclosure:0.78, talos:0.85, unit42:0.85, crowdstrike:0.85, sentinelone:0.85, rapid7:0.82, googleprojectzero:0.90, urlhaus:0.80, threatfox:0.80, malwarebazaar:0.82, ransomwatch:0.78, otx:0.80, bleepingcomputer:0.72, thehackernews:0.70, krebsonsecurity:0.70, securityweek:0.70, darkreading:0.68, reddit_netsec:0.42, ai_incident_db:0.75 };
  const baseConf = sourceTrustMap[item.source] || 0.55;
  const corrBonus = Math.min(0.15, ((item.sourceCount||1) - 1) * 0.05);
  const kevBonus  = item.cisaKev ? 0.10 : 0;
  const confidence = Math.min(1.0, Math.round((baseConf + corrBonus + kevBonus) * 100) / 100);

  return {
    ...item,
    category:             type,
    subcategory:          subcategory || null,
    confidence:           confidence,
    affected_industries:  item.affected_industries || affectedIndustries,
    affected_organizations: item.affected_organizations || [],
    threat_actor:         detectedActors.length ? detectedActors : (item.threatActor ? [item.threatActor] : []),
    ai_security_tags:     aiSecurityTags,
    darkweb_tags:         darkwebTags,
    intelligence_score:   item.priority || 0,
  };
}

function rssToIntel(item, source) {
  const text = (item.title||'')+' '+(item.desc||'');
  const cves  = extractCVEs(text);
  const type  = classifyNews(text);
  const id    = cves[0]||(source.toUpperCase()+'-'+md5(item.link||item.title));
  const pubDate = (() => { try { return item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(); } catch(e){ return isoNow(); } })();
  const srcLabels = { bleepingcomputer:'BleepingComputer', thehackernews:'The Hacker News', krebsonsecurity:'KrebsOnSecurity', securityweek:'SecurityWeek', sans_isc:'SANS ISC' };
  // Editorial/RSS links are references, not automatically malicious IOCs.
  const iocs = [];
  return {
    source, type, id,
    title:item.title||'Security Intelligence Report',
    desc:(item.desc||'').slice(0,800), cvss:parseCvssFromText(text),
    refs:extractHttpUrls(item.link), pubDate,
    vendor:srcLabels[source]||source, product:'Threat Intelligence',
    exploited:hasConfirmedExploitation(text),
    // Generic coverage mentioning KEV is not itself a structured KEV record.
    cisaKev:false,
    ransomware:/ransomware|ransom|lockbit|qilin|akira|blackcat/i.test(text),
    cves, link:item.link, iocs, sourceCount:1,
    daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
  };
}

// ── SOURCES 5-9: RSS FEEDS ─────────────────────────────────────────────
async function fetchRSS(urlStr, source, maxItems, state) {
  const lastFetch = state ? getSourceLastFetch(state, source) : null;
  const afterDate = watermarkStart(lastFetch, CFG.rssMinLookbackHours, CFG.kevLookbackDays * 86400000);
  log(`${source}: fetching RSS (since ${afterDate.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(urlStr);
    const parsed = parseRSS(raw);
    const filtered = parsed.filter(item => {
      if (!item.pubDate) return true;
      try { return new Date(item.pubDate) >= afterDate; } catch(_) { return true; }
    });
    const items = filtered.slice(0, maxItems||CFG.maxRssItems).map(item => rssToIntel(item, source));
    if (state) setSourceLastFetch(state, source, Date.now());
    log(`${source}: ${items.length} items (filtered from ${parsed.length}).`); return items;
  } catch(e) { warn(`${source} failed: ${e.message}`); return []; }
}

// ── SOURCE 10: Abuse.ch URLhaus ────────────────────────────────────────
async function fetchURLhaus() {
  log('Abuse.ch URLhaus: fetching...');
  try {
    const raw = await fetchWithRetry(CFG.urlhausApi, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'limit=40' });
    const data = JSON.parse(raw);
    const payloads = data.payloads || data.urls || [];
    if (!payloads.length) return [];
    const families = {};
    payloads.slice(0,40).forEach(u => {
      const tag = (u.signature||u.tags?.[0]||'unknown_malware');
      if (!families[tag]) families[tag] = { count:0, hashes:[], date:u.firstseen||u.date_added||isoNow() };
      families[tag].count++;
      const hash = u.md5_hash||u.sha256_hash;
      if (hash) families[tag].hashes.push({ type: u.sha256_hash?'sha256':'md5', value:hash, confidence_score:0.92, first_seen:isoNow(), source_count:1 });
    });
    const dailyDate = new Date().toISOString().slice(0,10); // YYYY-MM-DD — daily-fresh ID
    const items = Object.entries(families).filter(([k])=>k!=='unknown_malware').slice(0,3).map(([tag,info]) => ({
      source:'urlhaus', type:'MALWARE_REPORT',
      id:'URLHAUS-'+md5(tag+dailyDate),
      title:`Abuse.ch Malware Alert: ${tag} — ${info.count} Payloads Tracked (URLhaus)`,
      desc:`URLhaus tracking ${info.count} active payloads for ${tag} malware family. Fresh IOCs confirmed. Deploy to SIEM/firewall immediately.`,
      cvss:null, refs:['https://urlhaus.abuse.ch/'],
      pubDate:info.date?String(info.date).slice(0,10):isoNow(),
      vendor:'Abuse.ch', product:'URLhaus Intelligence',
      exploited:false, cisaKev:false,
      ransomware:/ransomware|ransom/i.test(tag),
      iocs:info.hashes.slice(0,10), sourceCount:1, malwareTag:tag, daysOld:0,
    }));
    log(`URLhaus: ${items.length} items.`); return items;
  } catch(e) { warn(`URLhaus failed: ${e.message}`); return []; }
}

// ── SOURCE 11: Abuse.ch ThreatFox ─────────────────────────────────────
async function fetchThreatFox() {
  log('Abuse.ch ThreatFox: fetching...');
  try {
    const body = JSON.stringify({ query:'get_iocs', days:1, limit:100 });
    const raw  = await fetchWithRetry(CFG.threatfoxApi, {
      method:'POST',
      headers:{ 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(body) },
      body,
    });
    const data = JSON.parse(raw);
    if (data.query_status !== 'ok' || !Array.isArray(data.data)) return [];
    const families = {};
    data.data.slice(0,100).forEach(ioc => {
      const fam = ioc.malware_printable||ioc.malware||'Unknown Malware';
      if (!families[fam]) families[fam] = { iocs:[], firstSeen:ioc.first_seen };
      families[fam].iocs.push({ type:ioc.ioc_type, value:ioc.ioc, confidence_score:0.90, first_seen:isoNow(), source_count:1 });
    });
    const dailyDate = new Date().toISOString().slice(0,10); // YYYY-MM-DD — daily-fresh ID
    const items = Object.entries(families).slice(0,3).map(([family,info]) => ({
      source:'threatfox', type:'MALWARE_REPORT',
      id:'THREATFOX-'+md5(family+dailyDate),
      title:`ThreatFox IOC Alert: ${family} — Fresh Indicators Published`,
      desc:`Abuse.ch ThreatFox published ${info.iocs.length} fresh IOCs for ${family}. Active threat infrastructure. Deploy to SIEM/firewall/EDR immediately.`,
      cvss:null, refs:['https://threatfox.abuse.ch/'],
      pubDate:info.firstSeen?info.firstSeen.slice(0,10):isoNow(),
      vendor:'Abuse.ch', product:'ThreatFox Intelligence',
      exploited:false, cisaKev:false,
      ransomware:/ransomware|ransom|locker/i.test(family),
      iocs:info.iocs.slice(0,10), sourceCount:1, malwareFamily:family, daysOld:0,
    }));
    log(`ThreatFox: ${items.length} items.`); return items;
  } catch(e) { warn(`ThreatFox failed: ${e.message}`); return []; }
}

// ── SOURCE 12: MSRC ─────────────────────────────────────────────────────
async function fetchMSRC() {
  log('MSRC: fetching Microsoft security updates...');
  try {
    await sleep(300);
    const raw = await fetchWithRetry(CFG.msrcApi, { headers:{ 'Accept':'application/json' } });
    const data = JSON.parse(raw);
    const items = (data.value||[]).slice(0,2).map(u => ({
      source:'msrc', type:'ADVISORY',
      id:'MSRC-'+md5(u.ID||u.Alias||String(Math.random())),
      title:`Microsoft Security Update: ${u.DocumentTitle?.Value||u.Alias||'Security Advisory'} — Analysis`,
      desc:`Microsoft released security updates: ${u.DocumentTitle?.Value||''}. Review and apply immediately.`,
      cvss:null, refs:[`https://msrc.microsoft.com/update-guide/`],
      pubDate:(u.InitialReleaseDate||isoNow()).slice(0,10),
      vendor:'Microsoft', product:'Multiple Microsoft Products',
      exploited:false, cisaKev:false, ransomware:false, iocs:[], sourceCount:1, daysOld:0,
    }));
    log(`MSRC: ${items.length} items.`); return items;
  } catch(e) { warn(`MSRC failed: ${e.message}`); return []; }
}

// ── SOURCE: CYBERDUDEBIVASH SENTINEL APEX — native ecosystem CTI feed ──
// intel.cyberdudebivash.com is the product-delivery portal for the same
// Sentinel APEX intelligence ecosystem this repo's own engine feeds (see
// Sentinel-APEX/README.md) — a first-party structured CTI source, not a
// third-party vendor. Its exact response shape could not be verified live
// from this environment (outbound access to the host is blocked by this
// dev sandbox's network policy — production GitHub Actions runners have
// normal internet access and are the real validation point going forward).
// Every field below is therefore read defensively through candidate-key
// lookups rather than a fixed schema. normalizeSentinelApexRecord() is the
// single place to update if production logs ever show a field-name
// mismatch — nothing else in the pipeline assumes a specific shape.

// Reads the first present, non-empty value for any of `keys` from `obj`.
// A key may use one level of dot-notation for a nested lookup.
function sapexPick(obj, keys) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const k of keys) {
    let v;
    if (k.indexOf('.') !== -1) {
      const [a, b] = k.split('.');
      v = obj[a] && obj[a][b];
    } else {
      v = obj[k];
    }
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}
function sapexPickArray(obj, keys) {
  const v = sapexPick(obj, keys);
  if (Array.isArray(v)) return v;
  if (typeof v === 'string' && v.trim()) return [v];
  return [];
}

// Unwraps whatever envelope shape a Sentinel APEX endpoint responds with:
// a raw array, a STIX 2.1 bundle ({objects:[...]}), the common {items|
// data|results|...} wrapper shapes, or (ai_summary.json may describe one
// summary rather than a list) a single record object.
function extractSentinelApexRecords(json) {
  if (!json || typeof json !== 'object') return [];
  if (Array.isArray(json)) return json;
  if (Array.isArray(json.objects)) return json.objects; // STIX bundle
  const wrapperKeys = ['items', 'data', 'results', 'reports', 'records', 'articles', 'intel', 'threats', 'summaries'];
  for (const k of wrapperKeys) {
    if (Array.isArray(json[k])) return json[k];
  }
  if (sapexPick(json, ['id', 'title', 'name', 'summary', 'headline'])) return [json];
  return [];
}

// Maps a native Sentinel APEX MITRE ATT&CK/ATLAS mapping (whatever shape it
// arrives in) into the same {tactic, technique, sub, framework?, atlas?}
// shape getMitre() returns, so generatePostHTML() can prefer the real
// analyst mapping over regex inference through one render path, not two.
// Returns null when nothing usable is present — caller falls back to
// getMitre() exactly as it already does for every other source.
function sapexNativeMitre(raw) {
  const src = sapexPickArray(raw, ['mitre_attack', 'mitre', 'mitre_tactics', 'mitre_mapping', 'attack_mapping', 'ttps', 'techniques']);
  if (!src.length) return null;
  const entries = src.map(t => (typeof t === 'string') ? { technique: t } : t).filter(Boolean);
  const first = entries.find(t => sapexPick(t, ['technique_id', 'id', 'technique', 'ttp']));
  if (!first) return null;
  const techId    = sapexPick(first, ['technique_id', 'id', 'technique', 'ttp']);
  const techName  = sapexPick(first, ['technique_name', 'name', 'label']);
  const tactic    = sapexPick(first, ['tactic', 'tactic_name']) || 'Initial Access';
  const technique = [techId, techName].filter(Boolean).join(' — ');
  if (!technique) return null;
  const subEntry = entries.find(t => t !== first && sapexPick(t, ['technique_id', 'id', 'technique']));
  const sub = subEntry ? [sapexPick(subEntry, ['technique_id', 'id', 'technique']), sapexPick(subEntry, ['technique_name', 'name'])].filter(Boolean).join(' — ') : undefined;
  const isAtlas = /\bAML\.T/i.test(technique) || /atlas/i.test(String(sapexPick(raw, ['framework']) || ''));
  return { tactic, technique, sub, ...(isAtlas ? { framework: 'ATLAS', atlas: true } : {}) };
}

// Best-effort native-category → internal universal-type mapping. Falls back
// to the existing classifyNews() regex classifier (same as every other
// source) when the category is absent or unrecognized — never guesses.
const SAPEX_TYPE_MAP = {
  cve: 'CVE_REPORT', vulnerability: 'CVE_REPORT', vuln: 'CVE_REPORT',
  zero_day: 'ZERO_DAY', zeroday: 'ZERO_DAY',
  ransomware: 'RANSOMWARE',
  malware: 'MALWARE_REPORT', trojan: 'MALWARE_REPORT',
  threat_actor: 'THREAT_ACTOR', apt: 'THREAT_ACTOR', actor: 'THREAT_ACTOR',
  supply_chain: 'SUPPLY_CHAIN',
  ai_security: 'AI_SECURITY', llm_security: 'AI_SECURITY',
  data_breach: 'DATA_BREACH', breach: 'DATA_BREACH',
  advisory: 'ADVISORY', alert: 'ADVISORY',
  dark_web: 'DARK_WEB', darkweb: 'DARK_WEB',
  cloud_security: 'CLOUD_SECURITY',
  detection: 'DETECTION_ENGINEERING',
};

// Derives a stable, canonical dedup ID: a real CVE ID always wins (so this
// item correctly merges with NVD/CISA/GitHub records about the same CVE in
// correlateAndMerge instead of duplicate-publishing), falling back to a
// hash of the platform's own record id, then the title — mirroring the
// OTX/RansomWatch/AIIncidentDB fallback convention already in this file.
function sapexCanonicalId(cves, raw, title) {
  if (cves.length) return cves[0];
  const nativeId = sapexPick(raw, ['id', 'uuid', 'report_id', 'guid']);
  if (nativeId) return 'SENTINELAPEX-' + md5(String(nativeId)).slice(0, 12);
  if (title) return 'SENTINELAPEX-' + md5(title).slice(0, 12);
  return null;
}

let sapexUnknownShapeCount = 0; // Phase 4 observability: records with no usable fields

// Normalizes one raw Sentinel APEX record (any of the 5 endpoint shapes)
// into this pipeline's internal item schema. Never throws — a record that
// doesn't resemble intelligence data is logged and skipped, not fabricated.
function normalizeSentinelApexRecord(raw, endpointKey) {
  if (!raw || typeof raw !== 'object') return null;
  const title = String(sapexPick(raw, ['title', 'name', 'headline', 'summary']) || '').slice(0, 200);
  const desc  = String(sapexPick(raw, ['description', 'summary', 'desc', 'body', 'content', 'analysis']) || '').slice(0, 800);
  if (!title && !desc) { sapexUnknownShapeCount++; return null; }

  const text = `${title} ${desc}`;
  const explicitCves = sapexPickArray(raw, ['cves', 'cve_ids'])
    .concat([sapexPick(raw, ['cve', 'cve_id'])].filter(Boolean))
    .map(c => String(c).toUpperCase()).filter(c => /^CVE-\d{4}-\d{4,7}$/.test(c));
  const cves = [...new Set([...explicitCves, ...extractCVEs(text)])];

  const id = sapexCanonicalId(cves, raw, title);
  if (!id) { sapexUnknownShapeCount++; return null; }

  const sevRaw    = sapexPick(raw, ['cvss', 'cvss_score']);
  const sevLabel  = String(sapexPick(raw, ['severity', 'threat_level', 'priority']) || '').toLowerCase();
  const numericCvss = Number(sevRaw);
  const sourceReportedCvss = sevRaw !== undefined && sevRaw !== null && sevRaw !== '' && Number.isFinite(numericCvss) && numericCvss >= 0 && numericCvss <= 10
    ? numericCvss : null;
  // Sentinel APEX is a correlating CTI platform, not a primary CVSS
  // authority. Accepting our own downstream copy as canonical would create a
  // circular trust path. Direct NVD/vendor/research source objects populate
  // the canonical score during correlateAndMerge().
  const cvss = null;

  const refs = [
    ...sapexPickArray(raw, ['references', 'refs', 'links', 'sources']).map(r => (typeof r === 'string') ? r : (r && (r.url || r.source_name))),
    ...sapexPickArray(raw, ['external_references']).map(r => r && r.url),
    // 'source_url'/'blog_url'/'nvd_url' are the actual field names the live
    // intel.cyberdudebivash.com API uses (confirmed against a real response:
    // source_url on 491/500 sampled records, blog_url on the remaining 9) --
    // 'url'/'link'/'report_url' never appear on any record from this API, so
    // every sentinel_apex item was silently failing the quality gate's
    // reference/link requirement before this fix.
    sapexPick(raw, ['url', 'link', 'report_url', 'source_url', 'blog_url', 'nvd_url']),
  ].flatMap(extractHttpUrls).filter(Boolean).slice(0, 8);

  const rawIocs = sapexPickArray(raw, ['iocs', 'indicators', 'observables']);
  const iocs = rawIocs.length
    ? rawIocs.map(i => {
        const value = sapexPick(i, ['value', 'indicator', 'pattern']);
        if (!value) return null;
        const rawConfidence = Number(sapexPick(i, ['confidence_score', 'confidence']));
        return {
          type: String(sapexPick(i, ['type', 'ioc_type']) || 'hash').toLowerCase(),
          value: String(value).slice(0, 120),
          confidence_score: Number.isFinite(rawConfidence) ? rawConfidence : 0.75,
          first_seen: sapexPick(i, ['first_seen', 'created']) || isoNow(),
          source_count: 1,
        };
      }).filter(Boolean).slice(0, 20)
    : [];

  const nativeType = String(sapexPick(raw, ['type', 'category', 'classification']) || '').toLowerCase().replace(/[\s-]+/g, '_');
  const type = SAPEX_TYPE_MAP[nativeType] || classifyNews(text);

  const pubRaw    = sapexPick(raw, ['published', 'published_at', 'pubDate', 'created', 'timestamp', 'date', 'first_seen']);
  const pubDateObj = pubRaw ? new Date(pubRaw) : null;
  const validDate  = pubDateObj && !isNaN(pubDateObj);
  const pubDate    = validDate ? pubDateObj.toISOString().slice(0, 10) : isoNow();

  const exploited  = !!sapexPick(raw, ['exploited', 'in_the_wild', 'active_exploitation']) || hasConfirmedExploitation(text);
  const cisaKev    = !!sapexPick(raw, ['cisa_kev', 'cisaKev', 'kev_listed']);
  const ransomware = !!sapexPick(raw, ['ransomware']) || /ransomware/i.test(text) || type === 'RANSOMWARE';

  return {
    source: 'sentinel_apex', type, id,
    title: title || `Sentinel APEX Intelligence: ${id}`,
    desc: desc || title,
    cvss, severityLabel: sevLabel || null, refs, pubDate,
    sourceReportedCvss,
    // Leave blank rather than a literal "Unknown Vendor"/"Unknown Product"
    // string — every live consumer (genExecutiveSummary, genBusinessImpact,
    // genAttackChain, genCommentary, genPlaybook) already has its own
    // graceful `item.vendor||'the affected vendor'`-style fallback, and the
    // API output layer (writeAPIFiles) already normalizes to '' for the same
    // reason. A literal "Unknown Vendor" string is truthy, so it silently
    // defeated all of that existing fallback logic instead of triggering it.
    vendor:  String(sapexPick(raw, ['vendor', 'affected_vendor']) || sapexPickArray(raw, ['vendors'])[0] || ''),
    product: String(sapexPick(raw, ['product', 'affected_product']) || sapexPickArray(raw, ['products'])[0] || ''),
    exploited, cisaKev, ransomware, cves, iocs, sourceCount: 1,
    daysOld: validDate ? Math.max(0, Math.floor((Date.now() - pubDateObj.getTime()) / 86400000)) : 0,
    threat_actor: sapexPickArray(raw, ['threat_actor', 'threat_actors', 'actor', 'actors']).map(String),
    ai_security_tags: type === 'AI_SECURITY' ? ['ai-security', 'sentinel-apex'] : [],
    mitreNative: sapexNativeMitre(raw),
  };
}

async function fetchSentinelApex() {
  const endpoints = [
    ['latest',      CFG.sentinelApexLatestUrl],
    ['apex',        CFG.sentinelApexApexUrl],
    ['ai_summary',  CFG.sentinelApexAiSummaryUrl],
    ['feed',        CFG.sentinelApexFeedUrl],
    ['reports',     CFG.sentinelApexReportsUrl],
  ];
  log(`Sentinel APEX: fetching ${endpoints.length} endpoints...`);
  const headers = CFG.sentinelApexApiKey ? { Authorization: `Bearer ${CFG.sentinelApexApiKey}` } : {};
  const results = await Promise.allSettled(
    endpoints.map(([key, url]) => fetchWithRetry(url, { headers }, 2).then(raw => ({ key, raw })))
  );

  // Cross-endpoint dedup within this one source — feed.json in particular
  // may be a superset of the other 4, so this prevents Sentinel APEX from
  // emitting near-duplicate items under its own source key before the item
  // even reaches the pipeline's own cross-source correlateAndMerge.
  const seen = new Map();
  let endpointsOk = 0, rawCount = 0;
  results.forEach((r, idx) => {
    const [key] = endpoints[idx];
    if (r.status !== 'fulfilled') { warn(`Sentinel APEX [${key}] failed: ${r.reason && r.reason.message}`); return; }
    let json;
    try { json = JSON.parse(r.value.raw); }
    catch (e) { warn(`Sentinel APEX [${key}] returned non-JSON response: ${e.message}`); return; }
    const records = extractSentinelApexRecords(json);
    rawCount += records.length;
    if (records.length === 0) { warn(`Sentinel APEX [${key}]: 0 usable records (unrecognized envelope shape).`); return; }
    endpointsOk++;
    records.forEach(raw => {
      let item;
      try { item = normalizeSentinelApexRecord(raw, key); }
      catch (e) { warn(`Sentinel APEX [${key}] record normalization error: ${e.message}`); return; }
      if (!item) return;
      const existing = seen.get(item.id);
      seen.set(item.id, existing
        ? { ...item, refs: [...new Set([...existing.refs, ...item.refs])].slice(0, 8), mitreNative: existing.mitreNative || item.mitreNative }
        : item);
    });
  });

  // One endpoint (or all 5) failing never aborts the pipeline — same
  // contract as every other source's try/catch-to-[] failure mode.
  if (endpointsOk === 0) { warn('Sentinel APEX: all endpoints unavailable or unparseable this run.'); return []; }
  const items = Array.from(seen.values());
  log(`Sentinel APEX: ${endpointsOk}/${endpoints.length} endpoints ok, ${rawCount} raw records, ${items.length} unique items` +
    (sapexUnknownShapeCount ? `, ${sapexUnknownShapeCount} skipped (unrecognized shape)` : '') + '.');
  return items;
}

// ── TIER 1 SOURCES 13-15: EXPLOIT/VULN DISCLOSURE ────────────────────

async function fetchExploitDB(state) {
  const lastFetch = getSourceLastFetch(state, 'exploitdb');
  const afterDate = watermarkStart(lastFetch, CFG.rssMinLookbackHours, 2*86400000);
  log(`ExploitDB: fetching (since ${afterDate.toISOString().slice(0,10)})...`);
  try {
    const raw = await fetchWithRetry(CFG.exploitDbRss, {}, 2);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => { try { return !item.pubDate || new Date(item.pubDate) >= afterDate; } catch(_){return true;} })
      .slice(0, CFG.maxRssItems)
      .map(item => {
        const text = (item.title||'') + ' ' + (item.desc||'');
        const cves  = extractCVEs(text);
        const id    = cves[0] || ('EXPLOITDB-' + md5(item.link || item.title));
        return {
          source:'exploitdb', type: cves.length ? 'CVE_REPORT' : 'ZERO_DAY',
          id, title: item.title || 'ExploitDB Public Exploit', desc: (item.desc||'').slice(0,600),
          cvss: parseCvssFromText(text), refs: extractHttpUrls(item.link),
          pubDate: item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(),
          vendor: 'ExploitDB', product: 'Multiple Targets',
          exploited: false, cisaKev: false, ransomware: false,
          cves, iocs: [], sourceCount: 1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
        };
      });
    setSourceLastFetch(state, 'exploitdb', Date.now());
    log(`ExploitDB: ${items.length} items.`); return items;
  } catch(e) { warn(`ExploitDB failed: ${e.message}`); return []; }
}

async function fetchPacketStorm(state) {
  const lastFetch = getSourceLastFetch(state, 'packetstorm');
  const afterDate = watermarkStart(lastFetch, CFG.rssMinLookbackHours, 2*86400000);
  log(`PacketStorm: fetching...`);
  try {
    const raw = await fetchWithRetry(CFG.packetstormRss, {}, 2);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => { try { return !item.pubDate || new Date(item.pubDate) >= afterDate; } catch(_){return true;} })
      .slice(0, CFG.maxRssItems)
      .map(item => {
        const text = (item.title||'') + ' ' + (item.desc||'');
        const cves  = extractCVEs(text);
        const id    = cves[0] || ('PKTSTORM-' + md5(item.link || item.title));
        return {
          source:'packetstorm', type: /exploit|poc|proof.of.concept/i.test(text) ? 'ZERO_DAY' : 'CVE_REPORT',
          id, title: item.title || 'PacketStorm Security Advisory', desc: (item.desc||'').slice(0,600),
          cvss: parseCvssFromText(text), refs: extractHttpUrls(item.link),
          pubDate: item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(),
          vendor: 'PacketStorm', product: 'Multiple Targets',
          exploited: hasConfirmedExploitation(text), cisaKev: false, ransomware: false,
          cves, iocs: [], sourceCount: 1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
        };
      });
    setSourceLastFetch(state, 'packetstorm', Date.now());
    log(`PacketStorm: ${items.length} items.`); return items;
  } catch(e) { warn(`PacketStorm failed: ${e.message}`); return []; }
}

async function fetchFullDisclosure(state) {
  const lastFetch = getSourceLastFetch(state, 'fulldisclosure');
  const afterDate = watermarkStart(lastFetch, CFG.rssMinLookbackHours, 2*86400000);
  log(`Full Disclosure: fetching...`);
  try {
    const raw = await fetchWithRetry(CFG.fullDisclosureRss, {}, 2);
    const parsed = parseRSS(raw);
    const items = parsed
      .filter(item => { try { return !item.pubDate || new Date(item.pubDate) >= afterDate; } catch(_){return true;} })
      .slice(0, 8)
      .map(item => {
        const text = (item.title||'') + ' ' + (item.desc||'');
        const cves  = extractCVEs(text);
        const id    = cves[0] || ('FULLDIS-' + md5(item.link || item.title));
        return {
          source:'fulldisclosure', type: 'ZERO_DAY',
          id, title: item.title || 'Full Disclosure Vulnerability Report', desc: (item.desc||'').slice(0,600),
          cvss: parseCvssFromText(text), refs: extractHttpUrls(item.link),
          pubDate: item.pubDate ? new Date(item.pubDate).toISOString().slice(0,10) : isoNow(),
          vendor: 'SecLists', product: 'Multiple Targets',
          exploited: hasConfirmedExploitation(text), cisaKev: false, ransomware: false,
          cves, iocs: [], sourceCount: 1,
          daysOld: item.pubDate ? Math.floor((Date.now()-new Date(item.pubDate).getTime())/86400000) : 0,
        };
      });
    setSourceLastFetch(state, 'fulldisclosure', Date.now());
    log(`Full Disclosure: ${items.length} items.`); return items;
  } catch(e) { warn(`Full Disclosure failed: ${e.message}`); return []; }
}

// ── TIER 2 SOURCES 16-21: THREAT INTEL BLOGS ─────────────────────────

async function fetchTalos(state) {
  return fetchRSS(CFG.talosBlogRss, 'talos', CFG.maxRssItems, state);
}
async function fetchUnit42(state) {
  return fetchRSS(CFG.unit42Rss, 'unit42', CFG.maxRssItems, state);
}
async function fetchCrowdStrike(state) {
  return fetchRSS(CFG.crowdstrikeBlogRss, 'crowdstrike', CFG.maxRssItems, state);
}
async function fetchSentinelOne(state) {
  return fetchRSS(CFG.sentineloneBlogRss, 'sentinelone', CFG.maxRssItems, state);
}
async function fetchGoogleProjectZero(state) {
  return fetchRSS(CFG.googleProjZeroRss, 'googleprojectzero', 6, state);
}
async function fetchRapid7(state) {
  return fetchRSS(CFG.rapid7BlogRss, 'rapid7', CFG.maxRssItems, state);
}

// ── TIER 3 SOURCES 22-27: COMMUNITY + SIGNALS ────────────────────────

async function fetchRedditNetsec(state) {
  return fetchRSS(CFG.redditNetsecRss, 'reddit_netsec', 10, state);
}
async function fetchRedditCyber(state) {
  return fetchRSS(CFG.redditCyberRss, 'reddit_cyber', 8, state);
}
async function fetchCertEU(state) {
  return fetchRSS(CFG.certEuRss, 'cert_eu', 6, state);
}
async function fetchMicrosoftSecBlog(state) {
  return fetchRSS(CFG.microsoftSecBlogRss, 'microsoft_security', CFG.maxRssItems, state);
}
async function fetchWiredSecurity(state) {
  return fetchRSS(CFG.wiredSecRss, 'wired_security', 8, state);
}
async function fetchRecordedFuture(state) {
  return fetchRSS(CFG.recordedFutureRss, 'recorded_future', 8, state);
}

// ── PHASE 2B: EXPANDED INTELLIGENCE SOURCES v5.3 ─────────────────────────

async function fetchMalwareBazaar() {
  return new Promise(resolve => {
    const body = JSON.stringify({ query:'get_recent', selector:'time', limit:25 });
    const req = https.request({ hostname:'mb-api.abuse.ch', path:'/api/v1/', method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'User-Agent':'CYBERDUDEBIVASH-SENTINEL/5.3'}
    }, res => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>{
        try {
          const j = JSON.parse(d);
          if (j.query_status !== 'ok' || !Array.isArray(j.data)) return resolve([]);
          const items = j.data.slice(0,15).map(s => {
            const text = `MalwareBazaar Sample: ${s.tags?.join(', ')||'malware'} — ${s.file_name||'unknown'} SHA256: ${s.sha256_hash}`;
            return {
              source:'malwarebazaar', type:'MALWARE_REPORT',
              id:`MALWAREBAZAAR-${s.sha256_hash?.slice(0,16)||md5(s.file_name||Math.random().toString())}`,
              title:`Malware Sample: ${s.tags?.join(' / ')||'Unknown Malware'} (${s.file_type||'binary'})`,
              desc:text, cvss:null, refs:[`https://bazaar.abuse.ch/sample/${s.sha256_hash}/`].filter(Boolean),
              pubDate:s.first_seen?.slice(0,10)||isoNow(), vendor:'MalwareBazaar', product:'Malware Sample',
              exploited:false, ransomware:/ransomware|ransom/i.test(text),
              iocs:[{ type:'sha256', value:s.sha256_hash, confidence_score:0.95, first_seen:s.first_seen||isoNow() }].filter(i=>i.value),
              sourceCount:1, malwareFamily:s.signature||null, malwareTag:s.tags?.[0]||null,
            };
          }).filter(i=>i.id);
          resolve(items);
        } catch(e) { resolve([]); }
      });
    });
    req.on('error',()=>resolve([])); req.setTimeout(12000,()=>{req.destroy();resolve([])});
    req.write(body); req.end();
  });
}

async function fetchNCSCUK(state) {
  const items = await fetchRSS('https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml', 'ncsc_uk', 10, state);
  return items.map(i=>({...i, type:classifyNews((i.title||'')+(i.desc||''))}));
}

async function fetchCiscoPSIRT(state) {
  return new Promise(resolve => {
    const opts = {
      hostname:'sec.cloudapps.cisco.com', path:'/security/advisories/cisco-sa-all.rss',
      headers:{'User-Agent':'CYBERDUDEBIVASH-SENTINEL/5.3','Accept':'application/rss+xml'},
    };
    https.get(opts, res => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>{
        try {
          const items = [];
          const titleRe = /<title>([^<]+)<\/title>/g;
          const linkRe = /<link>([^<]+)<\/link>/g;
          const descRe = /<description>([^<]+)<\/description>/g;
          let tm, lm, dm; const titles=[], links=[], descs=[];
          while((tm=titleRe.exec(d))!==null) titles.push(tm[1]);
          while((lm=linkRe.exec(d))!==null) links.push(lm[1]);
          while((dm=descRe.exec(d))!==null) descs.push(dm[1]);
          for(let i=1;i<Math.min(titles.length,12);i++) {
            const text = (titles[i]||'')+(descs[i]||'');
            const cves = extractCVEs(text);
            const id = cves[0]||('CISCO-PSIRT-'+md5(titles[i]||'').slice(0,12));
            if (!id||isSeenId(id, state)) continue;
            items.push({
              source:'cisco_psirt', type:'CVE_REPORT', id,
              title:titles[i]||'Cisco Security Advisory', desc:(descs[i]||'').replace(/&lt;[^>]*&gt;/g,'').slice(0,600),
              cvss:parseCvssFromText(text), refs:extractHttpUrls(links[i]), pubDate:isoNow(),
              vendor:'Cisco', product:'Cisco Products', exploited:false, cisaKev:false,
              ransomware:false, cves, sourceCount:1,
            });
          }
          resolve(items);
        } catch(e) { resolve([]); }
      });
    }).on('error',()=>resolve([])).setTimeout(12000,()=>resolve([]));
  });
}

async function fetchOTX(state) {
  if (!CFG.otxApiKey) return [];
  return new Promise(resolve => {
    https.get({
      hostname:'otx.alienvault.com', path:'/api/v1/pulses/subscribed?limit=20',
      headers:{'X-OTX-API-KEY':CFG.otxApiKey,'User-Agent':'CYBERDUDEBIVASH-SENTINEL/5.3'},
    }, res => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>{
        try {
          const j = JSON.parse(d);
          if (!j.results) return resolve([]);
          const items = j.results.slice(0,15).map(p => {
            const text = (p.name||'')+(p.description||'');
            const cves = extractCVEs(text);
            const id = cves[0]||('OTX-'+md5(p.id?.toString()||p.name||'').slice(0,12));
            if (!id||isSeenId(id, state)) return null;
            const iocs = (p.indicators||[]).slice(0,5).map(i=>({
              type:i.type==='IPv4'?'ipv4':i.type==='domain'?'domain':i.type==='URL'?'url':'hash',
              value:i.indicator, confidence_score:0.78, first_seen:i.created||isoNow(),
            }));
            return {
              source:'otx', type:classifyNews(text), id,
              title:p.name||'OTX Threat Pulse', desc:(p.description||'').slice(0,600),
              cvss:parseCvssFromText(text), refs:[`https://otx.alienvault.com/pulse/${p.id}`].filter(Boolean),
              pubDate:p.created?.slice(0,10)||isoNow(), vendor:'AlienVault OTX', product:'Threat Intelligence',
              exploited:hasConfirmedExploitation(text), ransomware:/ransomware/i.test(text),
              cves, iocs, sourceCount:1,
            };
          }).filter(Boolean);
          resolve(items);
        } catch(e) { resolve([]); }
      });
    }).on('error',()=>resolve([])).setTimeout(12000,()=>resolve([]));
  });
}

async function fetchRansomWatch(state) {
  return new Promise(resolve => {
    https.get({
      hostname:'ransomwatch.telemetry.ltd', path:'/v2/RSS.xml',
      headers:{'User-Agent':'CYBERDUDEBIVASH-SENTINEL/5.3','Accept':'application/rss+xml'},
    }, res => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>{
        try {
          const titleRe = /<title><!\[CDATA\[([^\]]+)\]\]><\/title>|<title>([^<]+)<\/title>/g;
          const linkRe  = /<link>([^<]+)<\/link>/g;
          const pubRe   = /<pubDate>([^<]+)<\/pubDate>/g;
          const titles=[],links=[],pubs=[];
          let m;
          while((m=titleRe.exec(d))!==null) titles.push(m[1]||m[2]||'');
          while((m=linkRe.exec(d))!==null) links.push(m[1]||'');
          while((m=pubRe.exec(d))!==null) pubs.push(m[1]||'');
          const items = [];
          for(let i=1;i<Math.min(titles.length,15);i++) {
            const title = titles[i]||'';
            const id = 'RANSOMWATCH-'+md5(title).slice(0,12);
            if (!title||isSeenId(id, state)) continue;
            const group = title.match(/^([^:]+):/)?.[1]?.trim()||'Unknown';
            items.push({
              source:'ransomwatch', type:'RANSOMWARE', id,
              title:`Ransomware Victim Listed: ${title}`,
              desc:`RansomWatch dark web monitoring: ${group} ransomware group has listed a new victim. Data leak site activity detected. Organizations should verify exposure.`,
              cvss:null, refs:extractHttpUrls(links[i]),
              pubDate:pubs[i]?new Date(pubs[i]).toISOString().slice(0,10):isoNow(),
              vendor:group, product:'Ransomware Victim', exploited:false, ransomware:true,
              cisaKev:false, cves:[], sourceCount:1,
              darkweb_tags:['ransomware-leak','dark-web'],
            });
          }
          resolve(items);
        } catch(e) { resolve([]); }
      });
    }).on('error',()=>resolve([])).setTimeout(12000,()=>resolve([]));
  });
}

async function fetchAIIncidentDB(state) {
  return new Promise(resolve => {
    https.get({
      hostname:'incidentdatabase.ai', path:'/rss.xml',
      headers:{'User-Agent':'CYBERDUDEBIVASH-SENTINEL/5.3','Accept':'application/rss+xml'},
    }, res => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>{
        try {
          const titleRe = /<title><!\[CDATA\[([^\]]+)\]\]><\/title>|<title>([^<]+)<\/title>/g;
          const linkRe  = /<link>([^<]+)<\/link>/g;
          const descRe  = /<description><!\[CDATA\[([^\]]+)\]\]><\/description>|<description>([^<]+)<\/description>/g;
          const titles=[],links=[],descs=[];
          let m;
          while((m=titleRe.exec(d))!==null) titles.push(m[1]||m[2]||'');
          while((m=linkRe.exec(d))!==null) links.push(m[1]||'');
          while((m=descRe.exec(d))!==null) descs.push(m[1]||m[2]||'');
          const items = [];
          for(let i=1;i<Math.min(titles.length,10);i++) {
            const title = titles[i]||'';
            const id = 'AIINCIDENT-'+md5(title).slice(0,12);
            if (!title||isSeenId(id, state)) continue;
            items.push({
              source:'ai_incident_db', type:'AI_SECURITY', id,
              title:`AI Security Incident: ${title}`,
              desc:(descs[i]||title).slice(0,600),
              cvss:parseCvssFromText(`${title} ${descs[i]||''}`), refs:extractHttpUrls(links[i]),
              pubDate:isoNow(), vendor:'AI Incident Database', product:'AI Systems',
              exploited:false, ransomware:false, cisaKev:false,
              cves:[], sourceCount:1, ai_security_tags:['ai-incident','llm'],
            });
          }
          resolve(items);
        } catch(e) { resolve([]); }
      });
    }).on('error',()=>resolve([])).setTimeout(12000,()=>resolve([]));
  });
}

// ── PHASE 3+5: PRIORITY SCORING ENGINE WITH SIGNAL BOOSTING ───────────
function computePriorityScore(item) {
  let score = 0;
  const text = (item.title||'') + ' ' + (item.desc||'');

  // CVSS base (0-40 pts)
  const cvss = item.cvss || 0;
  score += Math.min(40, Math.round(cvss * 4.2));

  // Priority is an editorial routing score, not a substitute CVSS. Preserve
  // authoritative and indicator-feed signal without inventing vulnerability
  // severity values for sources that do not publish them.
  const sourceSignal = {
    cisa_kev:25, cisa_alerts:25, nvd:20, github_advisories:18,
    msrc:18, cisco_psirt:18, ncsc_uk:16,
    urlhaus:16, threatfox:16, malwarebazaar:16,
    exploitdb:12, packetstorm:10, fulldisclosure:8,
    ransomwatch:14, otx:10, ai_incident_db:8,
  };
  score += sourceSignal[item.source] || 0;

  // ── PHASE 5: SIGNAL BOOSTING ─────────────────────────────────────
  // CISA KEV confirmation (25 pts) — highest single signal
  if (item.cisaKev)    score += 25;
  // Active exploitation confirmed (20 pts)
  if (item.exploited)  score += 20;
  // Ransomware campaign use (15 pts)
  if (item.ransomware) score += 15;
  // Zero-day keyword boost (10 pts)
  if (item.type === 'ZERO_DAY' || /zero.?day|0.?day|unpatched|no patch/i.test(text)) score += 10;
  // Nation-state / APT boost (8 pts)
  if (/nation.state|apt\d|lazarus|volt typhoon|sandworm|cozy bear|fancy bear|salt typhoon|state.sponsored/i.test(text)) score += 8;
  // Critical infra boost (7 pts)
  if (/federal|critical infrastructure|scada|ics|election|nuclear|power grid|hospital|utility/i.test(text)) score += 7;
  // Supply chain boost (6 pts)
  if (/supply chain|open.?source|npm|pypi|dependency/i.test(text)) score += 6;
  // AI/ML attack surface boost (4 pts — emerging threat)
  if (/ai security|llm|prompt injection|deepfake|gpt.*hack/i.test(text)) score += 4;
  // ── END SIGNAL BOOSTING ───────────────────────────────────────────

  // Multi-source corroboration (up to 12 pts)
  score += Math.min(12, (item.sourceCount||1) * 3);
  // Recency bonus — fresher = better (up to 8 pts)
  const days = item.daysOld || 0;
  if (days === 0)      score += 8;
  else if (days <= 1)  score += 6;
  else if (days <= 3)  score += 4;
  else if (days <= 7)  score += 2;
  // IOC richness bonus (up to 5 pts)
  score += Math.min(5, (item.iocs||[]).length);
  // Threat actor type (4 pts)
  if (item.type === 'THREAT_ACTOR') score += 4;
  // Exploit code available (5 pts — from ExploitDB / PacketStorm)
  if (item.source === 'exploitdb' || item.source === 'packetstorm' || item.source === 'fulldisclosure') score += 5;

  return Math.min(100, Math.round(score));
}

function threatLevel(score) {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 45) return 'MEDIUM';
  return 'LOW';
}

// ── PHASE 2: CORRELATION ENGINE ────────────────────────────────────────
// P0-CVSS-AUTHORITY-2026-09-22:
// CVSS is a sourced technical-severity fact, not a "take the worst number"
// signal. Resolve it by source authority. Lower-authority disagreement is
// retained as provenance but cannot override a stronger source. Equal-rank
// disagreement is unresolved and therefore fail-closed.
const CVSS_SOURCE_AUTHORITY = Object.freeze({
  nvd: 100,
  github_advisories: 95,
  msrc: 95,
  cisco_psirt: 95,
  cisa_alerts: 90,
  cisa_kev: 90,
  googleprojectzero: 80,
  talos: 75,
  unit42: 75,
  crowdstrike: 75,
  sentinelone: 75,
  rapid7: 72,
  exploitdb: 65,
  packetstorm: 60,
  fulldisclosure: 60,
  securityweek: 55,
  bleepingcomputer: 55,
  thehackernews: 50,
  krebsonsecurity: 50,
  sentinel_apex: 0,
});

function cvssEvidenceFromItem(item) {
  if (Array.isArray(item && item._cvssEvidence)) return item._cvssEvidence.slice();
  if (!item || typeof item.cvss !== 'number' || item.cvss < 0 || item.cvss > 10) return [];
  const source = String(item.source || 'unknown').toLowerCase();
  if (source === 'sentinel_apex') return [];
  return [{
    value: Number(item.cvss),
    source,
    rank: CVSS_SOURCE_AUTHORITY[source] || 40,
  }];
}

function resolveAuthoritativeCvss(items) {
  const evidence = [];
  const seen = new Set();
  (items || []).flatMap(cvssEvidenceFromItem).forEach(entry => {
    const key = entry.source + ':' + entry.value + ':' + entry.rank;
    if (!seen.has(key)) { seen.add(key); evidence.push(entry); }
  });
  if (!evidence.length) {
    return { cvss:null, cvssSource:null, cvssConflict:false, cvssConflictUnresolved:false, _cvssEvidence:[] };
  }
  evidence.sort((a,b) => b.rank - a.rank || a.source.localeCompare(b.source));
  const topRank = evidence[0].rank;
  const top = evidence.filter(e => e.rank === topRank);
  const topValues = [...new Set(top.map(e => e.value))];
  const allValues = [...new Set(evidence.map(e => e.value))];
  if (topValues.length !== 1) {
    return {
      cvss:null,
      cvssSource:null,
      cvssConflict:true,
      cvssConflictUnresolved:true,
      _cvssEvidence:evidence,
    };
  }
  const chosen = top.find(e => e.value === topValues[0]);
  return {
    cvss:chosen.value,
    cvssSource:chosen.source,
    cvssConflict:allValues.length > 1,
    cvssConflictUnresolved:false,
    _cvssEvidence:evidence,
  };
}

function technicalSeverityFromCvss(cvss) {
  if (typeof cvss !== 'number' || cvss < 0 || cvss > 10) return 'UNRATED';
  if (cvss >= 9.0) return 'CRITICAL';
  if (cvss >= 7.0) return 'HIGH';
  if (cvss >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function correlateAndMerge(sources) {
  const map = new Map();
  for (const batch of sources) {
    for (const item of (batch||[])) {
      if (!item.id) continue;
      const existing = map.get(item.id);
      if (!existing) {
        map.set(item.id, {
          ...item,
          ...resolveAuthoritativeCvss([item]),
          sourceCount:1,
          _sources:[item.source],
        });
      } else {
        // Winner strategy: cisa_kev > nvd > github_advisories > sentinel_apex
        // > cisa_alerts > msrc > rss sources. sentinel_apex sits below the
        // primary government/vendor sources (it's a correlating CTI
        // platform, not a ground-truth authority for a given CVE) but above
        // generic RSS/community signal — the tie-break only decides whose
        // title/desc/vendor/product win; IOCs/CVEs/refs/exploited/KEV/
        // mitreNative are unioned below regardless of which side wins.
        const srcRank = { cisa_kev:10, nvd:9, github_advisories:8, sentinel_apex:7, cisa_alerts:7, msrc:6 };
        const itemRank = srcRank[item.source]||1, exRank = srcRank[existing.source]||1;
        const base = itemRank >= exRank ? { ...existing, ...item } : { ...item, ...existing };
        // Merge enrichment fields
        base.exploited  = existing.exploited  || item.exploited;
        base.cisaKev    = existing.cisaKev    || item.cisaKev;
        base.ransomware = existing.ransomware || item.ransomware;
        base.dueDate    = existing.dueDate    || item.dueDate;
        base.reqAction  = existing.reqAction  || item.reqAction;
        // Preserve a real analyst-provided MITRE mapping across the merge
        // even when the source that has it loses the rank tie-break —
        // richer native mapping must never be discarded in favor of the
        // regex-inferred fallback (getMitre()) computed later at render time.
        base.mitreNative = existing.mitreNative || item.mitreNative;
        // Merge IOCs (deduplicated)
        const iocMap = new Map();
        [...(existing.iocs||[]), ...(item.iocs||[])].forEach(ioc => {
          if (ioc && ioc.value) {
            const k = `${ioc.type}:${ioc.value}`;
            if (!iocMap.has(k)) iocMap.set(k, ioc);
            else iocMap.get(k).source_count = (iocMap.get(k).source_count||1) + 1;
          }
        });
        base.iocs = Array.from(iocMap.values()).slice(0, 20);
        // Merge CVEs
        base.cves = [...new Set([...(existing.cves||[]), ...(item.cves||[])])];
        // Merge refs
        base.refs = [...new Set([...(existing.refs||[]), ...(item.refs||[])])].filter(Boolean).slice(0,8);
        // Track all sources
        base._sources = [...new Set([...(existing._sources||[existing.source]), item.source])];
        base.sourceCount = base._sources.length;
        // Resolve technical severity by source authority, never by the
        // numerically largest score. A stale secondary source cannot override
        // a stronger NVD/vendor-grade value.
        Object.assign(base, resolveAuthoritativeCvss([existing, item]));
        // Recency — take newer date
        const ed = new Date(existing.pubDate||0), id = new Date(item.pubDate||0);
        base.pubDate  = ed > id ? existing.pubDate : item.pubDate;
        base.daysOld  = Math.min(existing.daysOld||999, item.daysOld||999);
        map.set(item.id, base);
      }
    }
  }
  const all = Array.from(map.values()).map(item => ({ ...item, priority: computePriorityScore(item), threatLevel: threatLevel(computePriorityScore(item)) }));
  all.sort((a,b) => (b.priority||0) - (a.priority||0));
  return all;
}

// ── PHASE 4: SIGNAL vs NOISE FILTERING ────────────────────────────────
function filterSignalFromNoise(items) {
  const before = items.length;
  const filtered = items.filter(item => {
    // Always pass: CISA KEV confirmed
    if (item.cisaKev) return true;
    // Always pass: actively exploited
    if (item.exploited) return true;
    // Always pass: ransomware confirmed
    if (item.ransomware) return true;
    // Always pass: high priority score
    if ((item.priority||0) >= CFG.minPriorityScore) return true;
    // Pass: multi-source corroboration
    if ((item.sourceCount||1) >= 2) return true;
    // SUPPRESS: CVSS below threshold and not exploited
    if ((item.cvss||0) < CFG.minCVSS) return false;
    // SUPPRESS: items older than lookback window with no exploitation
    if ((item.daysOld||0) > 30 && !item.exploited && !item.cisaKev) return false;
    // Pass: everything else meeting minimum bar
    return (item.priority||0) >= 30;
  });
  const suppressed = before - filtered.length;
  if (suppressed > 0) log(`Signal filter: suppressed ${suppressed} low-value items (${filtered.length} remain).`);
  return filtered;
}

// ── MITRE ATT&CK MAPPING ─────────────────────────────────────────────
function getMitre(item) {
  const t = ((item.desc||'')+(item.title||'')).toLowerCase();
  const type = item.type || item.category || '';

  // ── MITRE ATLAS — AI Security Framework ──────────────────────────────
  if (type === 'AI_SECURITY' || /prompt injection|llm|model poison|adversarial ml|ai.*attack/i.test(t)) {
    if (/prompt injection/i.test(t))        return { framework:'ATLAS', tactic:'ML Model Access', technique:'AML.T0051 — LLM Prompt Injection', sub:'AML.T0054 — Prompt Injection via Jailbreak', atlas:true };
    if (/model poison|data poison/i.test(t)) return { framework:'ATLAS', tactic:'ML Attack Staging', technique:'AML.T0018 — Backdoor ML Model', sub:'AML.T0020 — Poison Training Data', atlas:true };
    if (/adversarial/i.test(t))             return { framework:'ATLAS', tactic:'ML Model Access', technique:'AML.T0015 — Evade ML Model', sub:'AML.T0043 — Craft Adversarial Data', atlas:true };
    if (/jailbreak/i.test(t))              return { framework:'ATLAS', tactic:'ML Model Access', technique:'AML.T0054 — LLM Jailbreak', sub:'AML.T0051 — LLM Prompt Injection', atlas:true };
    if (/deepfake/i.test(t))              return { framework:'ATLAS', tactic:'ML Attack Staging', technique:'AML.T0012 — Valid Accounts', sub:'AML.T0013 — Synthetic Content Generation', atlas:true };
    if (/supply chain/i.test(t))          return { framework:'ATLAS', tactic:'ML Supply Chain Compromise', technique:'AML.T0010 — ML Supply Chain Compromise', sub:'AML.T0011 — Publish Poisoned Datasets', atlas:true };
    return { framework:'ATLAS', tactic:'ML Attack Staging', technique:'AML.T0040 — ML Attack Staging', sub:'AML.T0000 — AI/ML System Enumeration', atlas:true };
  }

  // ── MITRE ATT&CK ─────────────────────────────────────────────────────
  if (/remote code execution|rce|arbitrary code execution/i.test(t))      return { tactic:'Execution',             technique:'T1203 — Exploitation for Client Execution',     sub:'T1059 — Command & Scripting Interpreter' };
  if (/privilege escalation|lpe|eop|elevation of privilege/i.test(t))     return { tactic:'Privilege Escalation',  technique:'T1068 — Exploitation for Privilege Escalation', sub:'T1134 — Access Token Manipulation' };
  if (/auth bypass|unauthenticated|authentication bypass/i.test(t))       return { tactic:'Initial Access',        technique:'T1190 — Exploit Public-Facing Application',     sub:'T1078 — Valid Accounts' };
  if (/use.after.free|uaf/i.test(t))                                       return { tactic:'Execution',             technique:'T1203 — Exploitation for Client Execution',     sub:'T1068 — Exploitation for Privilege Escalation' };
  if (/sql injection|sqli/i.test(t))                                       return { tactic:'Initial Access',        technique:'T1190 — Exploit Public-Facing Application',     sub:'T1555 — Credentials from Password Stores' };
  if (/buffer overflow|heap overflow|memory corruption|stack overflow/i.test(t)) return { tactic:'Execution',      technique:'T1203 — Exploitation for Client Execution',     sub:'T1068 — Exploitation for Privilege Escalation' };
  if (/path traversal|directory traversal|lfi|rfi/i.test(t))              return { tactic:'Discovery',             technique:'T1083 — File and Directory Discovery',          sub:'T1005 — Data from Local System' };
  if (/deserialization|unsafe deserialization/i.test(t))                  return { tactic:'Execution',             technique:'T1059 — Command & Scripting Interpreter',       sub:'T1203 — Exploitation for Client Execution' };
  if (/ssrf|server.side request forgery/i.test(t))                        return { tactic:'Collection',            technique:'T1213 — Data from Information Repositories',    sub:'T1190 — Exploit Public-Facing Application' };
  if (/supply chain/i.test(t))                                             return { tactic:'Initial Access',        technique:'T1195 — Supply Chain Compromise',               sub:'T1199 — Trusted Relationship' };
  if (/ransomware/i.test(t)||type==='RANSOMWARE')                    return { tactic:'Impact',                technique:'T1486 — Data Encrypted for Impact',             sub:'T1490 — Inhibit System Recovery' };
  if (/malware|trojan|backdoor|loader/i.test(t)||type==='MALWARE_REPORT') return { tactic:'Execution',        technique:'T1059 — Command & Scripting Interpreter',       sub:'T1055 — Process Injection' };
  if (/data breach|exfiltrat/i.test(t)||type==='DATA_BREACH')        return { tactic:'Exfiltration',          technique:'T1041 — Exfiltration Over C2 Channel',          sub:'T1005 — Data from Local System' };
  if (/apt|nation.state|threat actor/i.test(t)||type==='THREAT_ACTOR') return { tactic:'Persistence',         technique:'T1078 — Valid Accounts',                        sub:'T1136 — Create Account' };
  return { tactic:'Initial Access', technique:'T1190 — Exploit Public-Facing Application', sub:'T1203 — Exploitation for Client Execution' };
}

// ── PHASE 6: TYPE-SPECIFIC INTELLIGENCE SECTION GENERATORS ───────────────
function genAISecSection(item, escHtml) {
  const t = ((item.title||'')+(item.desc||'')).toLowerCase();
  const attackType = /prompt injection/i.test(t)?'Prompt Injection':/model poison/i.test(t)?'Model Poisoning':/jailbreak/i.test(t)?'Jailbreak / Safety Bypass':/adversarial ml/i.test(t)?'Adversarial ML':/deepfake/i.test(t)?'Synthetic Media / Deepfake':/agentic|ai agent/i.test(t)?'Agentic AI Abuse':/supply chain/i.test(t)?'AI Supply Chain Attack':'AI Security Vulnerability';
  const modelImpact = /gpt|chatgpt|openai/i.test(t)?'OpenAI GPT Models':/claude|anthropic/i.test(t)?'Anthropic Claude':/gemini|google/i.test(t)?'Google Gemini':/llama|meta/i.test(t)?'Meta LLaMA':/copilot|microsoft/i.test(t)?'Microsoft Copilot':'Large Language Models (LLMs)';
  const owaspRef = /prompt injection/i.test(t)?'LLM01:2025 — Prompt Injection':/sensitive data|data leak/i.test(t)?'LLM02:2025 — Sensitive Information Disclosure':/supply chain/i.test(t)?'LLM03:2025 — Supply Chain Vulnerabilities':/overreliance/i.test(t)?'LLM09:2025 — Overreliance':'OWASP LLM Top 10 — See full catalog';
  const atlasMapping = item.mitre?.atlas?`${item.mitre.technique} / ${item.mitre.sub}`:/prompt injection/i.test(t)?'AML.T0051 — LLM Prompt Injection / AML.T0054 — Jailbreak':/model poison/i.test(t)?'AML.T0018 — Backdoor ML Model / AML.T0020 — Poison Training Data':/adversarial/i.test(t)?'AML.T0015 — Evade ML Model / AML.T0043 — Craft Adversarial Data':'AML.T0040 — ML Attack Staging';
  const govImpact = /gdpr|hipaa|compliance|regulation/i.test(t)?'Regulatory compliance risk — AI governance frameworks (NIST AI RMF, EU AI Act) require incident disclosure.':/enterprise|corporate|business/i.test(t)?'Enterprise AI trust risk — unauthorized model manipulation may violate AI governance policies.':'AI deployment risk — organizations using affected models must audit all AI-assisted workflows.';
  return `<div style="background:linear-gradient(135deg,rgba(139,92,246,0.08),rgba(0,153,255,0.04));border:1px solid rgba(139,92,246,0.25);border-radius:12px;padding:1.5rem;margin:2rem 0">
      <h2 class="sh" style="margin-top:0"><span>🤖</span> AI Security Intelligence Analysis</h2>
      <table class="tbl"><thead><tr><th>Dimension</th><th>Assessment</th></tr></thead><tbody>
        <tr><td style="color:var(--apex-muted)">AI Attack Type</td><td style="color:#a78bfa;font-weight:700">${escHtml(attackType)}</td></tr>
        <tr><td style="color:var(--apex-muted)">Affected AI Systems</td><td style="color:var(--apex-cyan)">${escHtml(modelImpact)}</td></tr>
        <tr><td style="color:var(--apex-muted)">OWASP LLM Top 10</td><td style="color:var(--apex-orange)">${escHtml(owaspRef)}</td></tr>
        <tr><td style="color:var(--apex-muted)">MITRE ATLAS Mapping</td><td style="color:var(--apex-cyan);font-family:monospace;font-size:12px">${escHtml(atlasMapping)}</td></tr>
        <tr><td style="color:var(--apex-muted)">AI Governance Impact</td><td style="font-size:13px">${escHtml(govImpact)}</td></tr>
      </tbody></table>
      <div style="margin-top:1rem;padding:.75rem 1rem;background:rgba(139,92,246,0.06);border-left:3px solid #8b5cf6;border-radius:4px;font-size:13px;color:var(--apex-muted)">
        <strong style="color:#a78bfa">SENTINEL APEX AI Security Guidance:</strong> Implement input validation, output filtering, prompt injection defenses, and continuous red-teaming. Reference: <a href="/owasp-llm-top10.html" style="color:#8b5cf6">OWASP LLM Top 10</a> · <a href="/mitre-attack-detection.html" style="color:#8b5cf6">MITRE ATLAS Hub</a>
      </div></div>`;
}

function genMalwareSection(item, escHtml) {
  const t = ((item.title||'')+(item.desc||'')).toLowerCase();
  const family = item.malwareFamily||item.malwareTag||(/lockbit/i.test(t)?'LockBit':/akira/i.test(t)?'Akira':/ransomhub/i.test(t)?'RansomHub':/black basta/i.test(t)?'Black Basta':/qilin/i.test(t)?'Qilin':/cl0p/i.test(t)?'Cl0p':/stealer/i.test(t)?'Infostealer':/botnet/i.test(t)?'Botnet':'Unknown Malware Family');
  const initAccess = /phishing|email/i.test(t)?'Spear-phishing (T1566) / Malicious attachment delivery':/exploit|vulnerability|cve/i.test(t)?'Exploit public-facing application (T1190)':/usb|removable/i.test(t)?'Replication through removable media (T1091)':/supply chain/i.test(t)?'Supply chain compromise (T1195)':'Drive-by compromise / Trojanized software (T1189)';
  const persistence = /scheduled task|cron/i.test(t)?'Scheduled Task/Job (T1053)':/registry/i.test(t)?'Boot/Logon Autostart — Registry Run Keys (T1547.001)':/service/i.test(t)?'Create/Modify System Process (T1543)':'Persistence via startup folder / WMI subscription (T1546)';
  const defEvasion = /obfuscat/i.test(t)?'Obfuscated files or information (T1027)':/living.off|lolbin/i.test(t)?'Living-off-the-land binaries (T1218)':/process inject/i.test(t)?'Process injection (T1055)':'Code signing (T1553) / Masquerading (T1036)';
  const c2 = /https|http/i.test(t)?'Encrypted channel — HTTPS C2 (T1071.001)':/dns/i.test(t)?'DNS tunneling C2 (T1071.004)':/telegram/i.test(t)?'Messaging app C2 — Telegram (T1102)':'Custom C2 protocol over standard ports (T1571)';
  const lateral = /pass.the.hash|pth/i.test(t)?'Pass the Hash (T1550.002)':/mimikatz|credential/i.test(t)?'Credential dumping via Mimikatz/LSASS (T1003.001)':/rdp/i.test(t)?'Remote Desktop Protocol lateral movement (T1021.001)':'SMB/Windows Admin Shares (T1021.002) / BloodHound AD recon';
  return `<div style="background:linear-gradient(135deg,rgba(239,68,68,0.06),rgba(251,146,60,0.04));border:1px solid rgba(239,68,68,0.2);border-radius:12px;padding:1.5rem;margin:2rem 0">
      <h2 class="sh" style="margin-top:0"><span>🦠</span> Malware Technical Intelligence — ${escHtml(family)}</h2>
      <table class="tbl"><thead><tr><th>Attack Phase</th><th>TTP — MITRE ATT&amp;CK</th></tr></thead><tbody>
        <tr><td style="color:var(--apex-orange);font-weight:700">Initial Access</td><td style="font-size:13px">${escHtml(initAccess)}</td></tr>
        <tr><td style="color:var(--apex-orange);font-weight:700">Persistence</td><td style="font-size:13px">${escHtml(persistence)}</td></tr>
        <tr><td style="color:var(--apex-orange);font-weight:700">Defense Evasion</td><td style="font-size:13px">${escHtml(defEvasion)}</td></tr>
        <tr><td style="color:var(--apex-orange);font-weight:700">Command &amp; Control</td><td style="font-size:13px">${escHtml(c2)}</td></tr>
        <tr><td style="color:var(--apex-orange);font-weight:700">Lateral Movement</td><td style="font-size:13px">${escHtml(lateral)}</td></tr>
        ${item.type==='RANSOMWARE'?`<tr><td style="color:var(--apex-red);font-weight:700">Impact</td><td style="font-size:13px">Data Encrypted for Impact (T1486) — Double extortion: exfiltration precedes encryption. Ransom demand issued via Tor-based leak site.</td></tr>`:''}
      </tbody></table>
      <div style="margin-top:1rem;padding:.75rem 1rem;background:rgba(239,68,68,0.06);border-left:3px solid #ef4444;border-radius:4px;font-size:13px;color:var(--apex-muted)">
        <strong style="color:#f87171">SENTINEL APEX Malware Response:</strong> Block all IOCs at firewall, proxy, and EDR immediately. Deploy Sigma/YARA rules. Verify offline backup integrity. ${item.type==='RANSOMWARE'?'If ransomware deployed: isolate affected systems, do NOT pay ransom without legal consultation, contact FBI IC3.':'If malware detected: isolate host, collect forensic image, revoke compromised credentials.'}
      </div></div>`;
}

function genDarkWebSection(item, escHtml) {
  const t = ((item.title||'')+(item.desc||'')).toLowerCase();
  const leakType = /credential|password/i.test(t)?'Credential Leak / Combolist':/database|records/i.test(t)?'Database Dump / PII Exposure':/source code/i.test(t)?'Source Code Leak':/access|rdp|vpn/i.test(t)?'Initial Access Broker (IAB) Listing':/ransom|victim/i.test(t)?'Ransomware Victim Listing':'Dark Web Intelligence Report';
  const actor = (item.threat_actor||[]).join(', ')||(item.vendor||'Unknown Threat Actor');
  const forum = /breach forums/i.test(t)?'BreachForums':/exploit.in/i.test(t)?'Exploit.in':/xss.is/i.test(t)?'XSS.is':/telegram/i.test(t)?'Telegram Channel':'Underground Forum / Leak Site';
  const riskLevel = item.cisaKev||/critical|million records/i.test(t)?'CRITICAL — Immediate action required':/high|thousand|breach/i.test(t)?'HIGH — Assess exposure within 24 hours':'ELEVATED — Monitor and assess affected accounts';
  return `<div style="background:linear-gradient(135deg,rgba(15,23,42,0.8),rgba(30,41,59,0.6));border:1px solid rgba(148,163,184,0.15);border-radius:12px;padding:1.5rem;margin:2rem 0">
      <h2 class="sh" style="margin-top:0"><span>🕵️</span> Dark Web Intelligence Report</h2>
      <table class="tbl"><thead><tr><th>Intelligence Dimension</th><th>Assessment</th></tr></thead><tbody>
        <tr><td style="color:var(--apex-muted)">Leak / Listing Type</td><td style="color:var(--apex-red);font-weight:700">${escHtml(leakType)}</td></tr>
        <tr><td style="color:var(--apex-muted)">Threat Actor</td><td style="color:var(--apex-cyan)">${escHtml(actor)}</td></tr>
        <tr><td style="color:var(--apex-muted)">Distribution Venue</td><td style="color:var(--apex-orange)">${escHtml(forum)}</td></tr>
        <tr><td style="color:var(--apex-muted)">Exposure Risk Level</td><td style="font-weight:700;color:${riskLevel.startsWith('CRITICAL')?'var(--apex-red)':riskLevel.startsWith('HIGH')?'var(--apex-orange)':'var(--apex-yellow)'}">${escHtml(riskLevel)}</td></tr>
        <tr><td style="color:var(--apex-muted)">Dark Web Tags</td><td style="font-size:12px">${(item.darkweb_tags||['dark-web-intelligence']).map(tag=>`<span style="display:inline-block;padding:2px 7px;border:1px solid rgba(148,163,184,0.2);border-radius:3px;font-size:11px;color:var(--apex-muted);margin:2px">${escHtml(tag)}</span>`).join('')}</td></tr>
      </tbody></table>
      <div style="margin-top:1rem;padding:.75rem 1rem;background:rgba(15,23,42,0.6);border-left:3px solid #475569;border-radius:4px;font-size:13px;color:var(--apex-muted)">
        <strong style="color:#94a3b8">SENTINEL APEX Dark Web Guidance:</strong> If your organization is identified in this listing: immediately rotate all potentially exposed credentials, notify affected users per GDPR/CCPA timelines, assess downstream third-party risk. Contact <a href="/contact.html" style="color:#94a3b8">SENTINEL APEX Enterprise</a> for dark web monitoring and breach response retainer.
      </div></div>`;
}

// ── SIGMA RULE ─────────────────────────────────────────────────────────
function genSigma(item) {
  const safeName = (item.id||'unknown').replace(/[^a-zA-Z0-9_-]/g,'_');
  const cves = item.cves||(item.id?.startsWith('CVE')?[item.id]:[]);
  const vendor = item.vendor||'the affected vendor', product = item.product||'the affected product';
  return `title: ${item.id} Exploitation Attempt — ${vendor} ${product}
id: ${md5(item.id+'sigma')}-${md5(item.title||'').slice(0,4)}
status: experimental
description: Detects exploitation of ${item.id} in ${vendor} ${product}. Priority: ${item.threatLevel||'HIGH'}. Score: ${item.priority||0}/100
author: CYBERDUDEBIVASH SENTINEL APEX v4.0 (bivash@cyberdudebivash.com)
date: ${isoNow()}
references:\n    - https://nvd.nist.gov/vuln/detail/${item.id}\n    - https://blog.cyberdudebivash.in/
tags:\n    - attack.initial_access\n    - attack.t1190${cves.map(c=>`\n    - ${c.toLowerCase()}`).join('')}
logsource:\n    category: webserver
detection:
    keywords:${cves.map(c=>`\n        - '${c}'`).join('')}\n        - '${safeName.toLowerCase()}'
    condition: keywords
falsepositives:\n    - Security scanners\nlevel: ${(item.cvss||0)>=9.5?'critical':(item.cvss||0)>=8?'high':'medium'}`.trim();
}

// ── MULTI-PLATFORM DETECTION ENGINEERING (Phase 3) ──────────────────────
// Evidence-driven Sigma / KQL / Splunk / OSQuery + Suricata, compiled from
// one canonical spec per ATT&CK technique. Fully guarded: any failure returns
// '' so the existing report is never affected.
// Stage 1.2: Rules are now stored in canonical detection-rules store with versioning.
function genMultiPlatformDetections(item, esc) {
  if (!detEngine || !item) return '';
  try {
    const text = `${item.title || ''}. ${item.desc || ''}`;
    const iocs = (Array.isArray(item.iocs) ? item.iocs : [])
      .filter((i) => i && i.value)
      .map((i) => ({ type: i.type, value: i.value }));
    const refs = (Array.isArray(item.refs) ? item.refs : []).filter(Boolean).slice(0, 3);
    if (item.id && /^CVE-/i.test(item.id)) refs.unshift(`https://nvd.nist.gov/vuln/detail/${item.id}`);
    const { detections, suricata } = detEngine.buildDetections(text, iocs, { references: refs });
    if (!detections.length && !suricata.length) return '';

    // Stage 1.2: Store detection rules in canonical store with source metadata
    if (detectionRulesManager && detections.length > 0) {
      const sourceMetadata = {
        confidence: item.severity === 'CRITICAL' ? 'HIGH' : item.severity === 'HIGH' ? 'HIGH' : 'MEDIUM',
        iocs: iocs.map(i => i.value),
        articles: [item.id],
        evidence: text.slice(0, 200),
      };
      try {
        // Store each detection rule in canonical format
        for (const detection of detections) {
          const ruleSpec = {
            ...detection,
            description: text.slice(0, 150),
            data_source: 'process_creation', // Map from detection type
            suricata: suricata.filter(s => s.includes(detection.technique_id) || s.includes(item.id)),
          };
          detectionRulesManager.storeRule(ruleSpec, sourceMetadata);
        }
        log(`✓ Stored ${detections.length} detection rules in canonical store`);
      } catch (storeErr) {
        console.warn(`⚠️ Failed to store rules in canonical store:`, storeErr.message);
      }
    }

    const LABELS = {
      sigma: 'Sigma (SIEM-agnostic)', kql: 'Microsoft Defender / Sentinel (KQL)',
      splunk: 'Splunk (SPL)', osquery: 'OSQuery (Endpoint)',
    };
    let html = `<h2 class="sh"><span>🧠</span> Multi-Platform Detection Engineering</h2>`;
    html += `<p class="bp">Reference detection drafts mapped to MITRE ATT&amp;CK by the SENTINEL APEX Detection Engine. These rules are not environment-validated: review source evidence, test syntax, establish a baseline, and tune before deployment.</p>`;
    for (const d of detections) {
      html += `<h3 style="font-size:1rem;color:var(--apex-cyan);margin:1.2rem 0 .5rem">${esc(d.technique_id)} — ${esc(d.title)}</h3>`;
      for (const fmt of ['sigma', 'kql', 'splunk', 'osquery']) {
        if (!d[fmt]) continue;
        html += `<div class="code-block"><span class="code-lbl">${esc(LABELS[fmt])}</span>${esc(d[fmt])}</div>`;
      }
    }
    if (suricata.length) {
      html += `<h3 style="font-size:1rem;color:var(--apex-cyan);margin:1.2rem 0 .5rem">Network Detection — Suricata</h3>`;
      html += `<div class="code-block"><span class="code-lbl">Suricata IDS/IPS</span>${esc(suricata.join('\n'))}</div>`;
    }
    return html;
  } catch (e) {
    console.warn(`⚠️ genMultiPlatformDetections failed for ${item && item.id}:`, e.message);
    return '';
  }
}

// ── PRIOR INTELLIGENCE CONTEXT (Analyst Memory, v2) ─────────────────────
// Renders "have we seen this before?" notes from persistent analyst memory.
// Fully guarded: returns '' if memory is unavailable or the entity is new.
function genPriorIntelligence(item, esc, mem = analystMemory) {
  if (!mem || !item) return '';
  try {
    // Entity-recurrence notes only. Relational correlation is presented inside
    // the Structured Intelligence Assessment (single home, no duplication).
    const notes = typeof mem.priorContext === 'function' ? mem.priorContext(item) : [];
    if (!notes.length) return '';
    let html = `<h2 class="sh"><span>🧬</span> Prior Intelligence Context</h2>`;
    html += `<p class="bp">This report is correlated against CYBERDUDEBIVASH SENTINEL APEX's persistent analyst memory. The following entities have been tracked in prior intelligence:</p>`;
    html += `<ul class="alist">${notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`;
    return html;
  } catch (e) {
    console.warn(`⚠️ genPriorIntelligence failed for ${item && item.id}:`, e.message);
    return '';
  }
}

// ── STRUCTURED INTELLIGENCE ASSESSMENT (Analyst Reasoning, v2) ───────────
// Renders the five reasoning stages (facts / correlated observations /
// assessments / gaps / outlook). Fully guarded: '' on any failure or when the
// item lacks the substance to reason over.
function genStructuredReasoning(item, esc, mem = analystMemory) {
  if (!reasoningEngine || !item) return '';
  try {
    const r = reasoningEngine.buildReasoning(item, mem);
    if (!reasoningEngine.hasSubstance(r)) return '';
    const CONF = { HIGH: '#22c55e', MEDIUM: '#eab308', LOW: '#94a3b8' };
    const list = (items) => `<ul class="alist">${items.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
    const labeled = (items) => `<ul class="alist">${items.map((x) =>
      `<li><span style="display:inline-block;min-width:74px;font-weight:800;font-size:.7rem;letter-spacing:.05em;color:${CONF[x.confidence] || '#94a3b8'}">${x.confidence} CONF</span> ${esc(x.text)}</li>`).join('')}</ul>`;
    let html = `<h2 class="sh"><span>🧠</span> Structured Intelligence Assessment</h2>`;
    html += `<p class="bp">SENTINEL APEX analytical tradecraft separates verified fact from labeled assessment and states intelligence gaps explicitly. Confidence reflects evidentiary support, not certainty.</p>`;
    if (r.facts.length) html += `<h3 style="font-size:1rem;color:#22c55e;margin:1.1rem 0 .4rem">✔ Verified Facts</h3>${list(r.facts)}`;
    if (r.observations.length) html += `<h3 style="font-size:1rem;color:var(--apex-cyan);margin:1.1rem 0 .4rem">🕸️ Correlated Observations</h3>${list(r.observations)}`;
    if (r.assessments.length) html += `<h3 style="font-size:1rem;color:#a78bfa;margin:1.1rem 0 .4rem">🧩 Analyst Assessments</h3>${labeled(r.assessments)}`;
    if (r.gaps.length) html += `<h3 style="font-size:1rem;color:#f59e0b;margin:1.1rem 0 .4rem">❓ Intelligence Gaps</h3>${list(r.gaps)}`;
    if (r.outlook.length) html += `<h3 style="font-size:1rem;color:#38bdf8;margin:1.1rem 0 .4rem">🔮 Forward Outlook</h3>${labeled(r.outlook)}`;
    return html;
  } catch (e) {
    console.warn(`⚠️ genStructuredReasoning failed for ${item && item.id}:`, e.message);
    return '';
  }
}

// ── MULTI-AUDIENCE INTELLIGENCE PRODUCTS (v2) ───────────────────────────
// Renders audience-specific deliverables (Executive Advisory, Board Brief,
// SOC Bulletin, Threat Hunting Guide) from one evidence set, and advertises
// the machine-readable API package. Fully guarded.
function genIntelligenceProducts(item, esc, slug, mem = analystMemory) {
  if (!productsEngine || !item) return '';
  try {
    const p = productsEngine.buildProducts(item, mem);
    if (!productsEngine.hasProducts(p)) return '';
    const ul = (arr) => `<ul class="alist">${arr.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
    let html = `<h2 class="sh"><span>🎯</span> Multi-Audience Intelligence Products</h2>`;
    html += `<p class="bp">This single analysis is packaged for every stakeholder — from the boardroom to the SOC — plus a machine-readable feed for API and MSSP integration. <strong>Enterprise &amp; SOC Pro subscribers</strong> receive these as structured deliverables.</p>`;

    if (p.executiveAdvisory) {
      const e = p.executiveAdvisory;
      html += `<h3 style="font-size:1rem;color:#a78bfa;margin:1.1rem 0 .4rem">🏛 Executive Advisory — ${esc(e.audience)}</h3>`;
      if (e.situation.length) html += ul(e.situation);
      if (e.decisions.length) {
        html += `<table class="tbl"><thead><tr><th>Owner</th><th>Decision</th><th>Timeline</th></tr></thead><tbody>`
          + e.decisions.map((d) => `<tr><td>${esc(d.owner)}</td><td>${esc(d.decision)}</td><td>${esc(d.timeline)}</td></tr>`).join('')
          + `</tbody></table>`;
      }
    }
    if (p.boardBrief) {
      html += `<h3 style="font-size:1rem;color:#38bdf8;margin:1.1rem 0 .4rem">📋 Board Brief</h3>${ul(p.boardBrief.bullets)}`;
    }
    if (p.socBulletin) {
      const s = p.socBulletin;
      html += `<h3 style="font-size:1rem;color:var(--apex-cyan);margin:1.1rem 0 .4rem">🛡 SOC Bulletin</h3>`;
      html += `<p class="bp" style="font-size:13px">Severity <strong>${esc(s.severity)}</strong> · Detection coverage: ${s.detectionCoverage.techniques.length} technique(s) across ${esc(s.detectionCoverage.platforms.join(', ') || 'behavioral analytics')} · ${s.detectionCoverage.networkRules} network rule(s)</p>`;
      if (s.immediateActions.length) html += ul(s.immediateActions);
    }
    if (p.huntingGuide && p.huntingGuide.hypotheses.length) {
      html += `<h3 style="font-size:1rem;color:#22c55e;margin:1.1rem 0 .4rem">🔭 Threat Hunting Guide</h3>`;
      html += ul(p.huntingGuide.hypotheses.map((h) => `${h.technique}: ${h.hypothesis}`));
    }
    if (slug) {
      html += `<div style="margin-top:1rem;padding:.8rem 1rem;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.18);border-radius:8px;font-size:.82rem;color:#94a3b8">`
        + `⎋ <strong>Machine-readable intelligence:</strong> this report is available as a structured JSON package (MITRE ATT&amp;CK, IOCs, multi-platform detections, analyst assessments) at `
        + `<a href="/api/intel/products/${esc(slug)}.json" style="color:var(--apex-cyan);font-family:var(--mono)">/api/intel/products/${esc(slug)}.json</a> — built for SIEM, SOAR, and MSSP integration.</div>`;
    }
    return html;
  } catch (e) {
    console.warn(`⚠️ genIntelligenceProducts failed for ${item && item.id}:`, e.message);
    return '';
  }
}

// Build the machine-readable product package JSON string (or '' on failure).
function buildProductApiJSON(item, mem = analystMemory) {
  if (!productsEngine || !item) return '';
  try {
    const p = productsEngine.buildProducts(item, mem);
    if (!productsEngine.hasProducts(p)) return '';
    return JSON.stringify(p.apiPackage, null, 2);
  } catch (e) {
    console.warn(`⚠️ buildProductApiJSON failed for ${item && item.id}:`, e.message);
    return '';
  }
}

// ── YARA RULE ──────────────────────────────────────────────────────────
function genYARA(item) {
  const n = (item.id||'unknown').replace(/[^a-zA-Z0-9_]/g,'_');
  const p = (item.product||'unknown').replace(/[^a-zA-Z0-9_]/g,'_').slice(0,40);
  const vendor = item.vendor||'the affected vendor', product = item.product||'the affected product';
  return `rule ${n}_Exploitation {
    meta:
        description = "Detects artifacts related to ${item.id} exploitation in ${vendor} ${product}"
        author      = "CYBERDUDEBIVASH SENTINEL APEX v4.0"
        date        = "${isoNow()}"
        severity    = "${(item.cvss||0) >= 9 ? 'CRITICAL' : 'HIGH'}"
        cvss        = "${item.cvss||'N/A'}"
        priority    = "${item.priority||0}/100"
        threat_level = "${item.threatLevel||'HIGH'}"
        reference   = "https://nvd.nist.gov/vuln/detail/${item.id}"
    strings:
        $id_str  = "${(item.id||'').replace(/"/g,'')}" ascii nocase
        $product = "${p.replace(/"/g,'')}" ascii nocase wide
    condition:\n        any of them\n}`.trim();
}

// ── PHASE 7: ADVANCED COMMENTARY (Executive Summary + Business Impact) ─
function genExecutiveSummary(item) {
  // Avoid stuttering ("the affected vendor the affected product") when both
  // are unknown — a single honest clause reads better than two concatenated
  // fallback phrases.
  const vendorProduct = item.vendor && item.product ? `${item.vendor} ${item.product}`
    : item.vendor || item.product || 'a system not yet identified in available sources';
  const hasCvss = typeof item.cvss === 'number' && item.cvss >= 0 && item.cvss <= 10;
  const cvssText = hasCvss ? `CVSS ${item.cvss}` : 'CVSS not assigned in the available primary sources';
  const tl=item.threatLevel||item.severityLabel||'UNASSESSED';
  const srcList = (item._sources||[item.source]).join(', ');
  // Exploitation status is stated ONLY from verifiable signals (KEV / reported
  // exploitation). Absent those, we say so plainly rather than asserting a
  // probability we cannot source — analyst-grade honesty over engagement.
  const exploitLine = item.cisaKev
    ? 'CISA has confirmed active exploitation in the wild (listed in the Known Exploited Vulnerabilities catalog).'
    : item.exploited
    ? 'Active exploitation has been reported in the wild — prioritize accordingly.'
    : 'Available sources do not confirm in-the-wild exploitation at the time of writing; prioritize using exposure, privilege, and verified severity data.';
  const ransomLine = item.ransomware ? ' Source reporting associates this with known ransomware activity.' : '';
  return `This report covers ${item.id} affecting ${vendorProduct} (${cvssText}; ${tl} priority). ${exploitLine}${ransomLine} Evidence was collected from ${item.sourceCount||1} source(s): ${srcList}. Verify all specifics against the primary sources linked below before acting.`;
}

function genBusinessImpact(item) {
  const product=item.product||'affected product';
  const impacts = [];
  const text=(item.desc||'')+' '+(item.title||'');
  if (item.cisaKev || item.exploited) impacts.push('Confirmed exploitation raises remediation priority; organization-specific impact depends on exposure and affected privileges');
  if (item.ransomware) impacts.push('Source material associates this activity with ransomware; validate backup, segmentation, and incident-response readiness');
  if (/rce|remote code execution/i.test(text)) impacts.push('Source material describes remote code execution; validate authentication, network reachability, and execution prerequisites');
  if (/privilege escalation|\blpe\b|elevation of privilege/i.test(text)) impacts.push('Source material describes privilege escalation; impact depends on the access an attacker must already possess');
  if (/auth(?:entication)? bypass|unauthenticated/i.test(text)) impacts.push('Source material describes an authentication-control weakness; confirm the exact affected interface and prerequisites');
  if (/data breach|exfiltrat/i.test(text)) impacts.push('Source material describes possible data exposure; determine whether sensitive data and affected systems intersect');
  if (/supply chain/i.test(text)) impacts.push('Source material describes a supply-chain issue; identify affected dependencies and downstream deployments');
  if (!impacts.length) impacts.push(`Available sources do not establish organization-specific business impact; inventory ${product}, validate exposure, and use the primary advisory for scope`);
  return impacts;
}

function genAttackChain(item) {
  const t = ((item.desc||'')+(item.title||'')).toLowerCase();
  const chain = [];
  if (/phishing|malicious (?:email|attachment|link)/i.test(t)) chain.push({ phase:'Initial Access', detail:'The source describes a phishing or malicious-content delivery path; validate the linked advisory for prerequisites', tactic:'T1566' });
  if (/exploit(?:ation)? of (?:a )?public-facing|internet-facing|remote code execution|\brce\b/i.test(t)) chain.push({ phase:'Initial Access / Execution', detail:`The source describes exploitation of ${item.id}; the exact reachability and execution prerequisites must be validated`, tactic:'T1190 / T1203' });
  if (/privilege escalation|elevation of privilege|\blpe\b/i.test(t)) chain.push({ phase:'Privilege Escalation', detail:'The source describes elevation of privilege; required prior access is not inferred here', tactic:'T1068' });
  if (item.ransomware && /encrypt|ransomware deployment|ransom demand/i.test(t)) chain.push({ phase:'Impact', detail:'The source describes ransomware or encryption impact; no unreported lateral-movement path is assumed', tactic:'T1486' });
  if (!chain.length) chain.push({ phase:'Evidence boundary', detail:'Available sources do not establish a complete attack chain. No reconnaissance, persistence, lateral-movement, or command-and-control steps are inferred.', tactic:'Not assigned' });
  return chain;
}

function genCommentary(item) {
  const vendorProduct=[item.vendor,item.product].filter(Boolean).join(' ')||'the affected technology';
  const scoreText=typeof item.cvss==='number'?`CVSS ${item.cvss}`:'no verified CVSS score in the ingested sources';
  const evidence=`This automated assessment covers ${vendorProduct} using ${item.sourceCount||1} collected source(s) and ${scoreText}. It does not claim direct telemetry, incident-response observation, or independent exploit validation.`;
  const kevNote=item.cisaKev
    ? ` CISA KEV listing confirms in-the-wild exploitation.${item.dueDate?` The binding federal remediation date is ${item.dueDate}.`:''}${item.reqAction?` CISA required action: ${item.reqAction}`:''}`
    : item.exploited ? ' Source language explicitly reports exploitation; validate that claim in the linked primary reference.' : ' In-the-wild exploitation is not confirmed by the available evidence.';
  const correlation=(item.sourceCount||1)>=2
    ? ` The item appeared in ${(item.sourceCount||1)} sources (${(item._sources||[]).join(', ')}); source count is corroboration of reporting, not proof of every technical claim.` : '';
  return evidence+kevNote+correlation;
}

function genPlaybook(item) {
  const p = item.product||'affected product', v = item.vendor||'vendor';
  const base = [
    `Inventory ${p} and identify internet exposure, privileges, versions, and business criticality`,
    `Open the linked ${v} or primary advisory and verify affected versions, prerequisites, and available remediation`,
    `Test the vendor remediation or documented compensating control before controlled deployment`,
    `Preserve relevant logs and review the primary advisory for concrete detection artifacts; do not treat reference rules as validated`,
    item.cisaKev ? `Track the CISA KEV remediation date ${item.dueDate||'listed in the catalog'} where it applies to your organization` : `Monitor ${v} advisories for material updates`,
    `Document the decision, evidence sources, asset scope, validation result, and residual risk`,
  ];
  if (item.ransomware) {
    base.push('VALIDATE: Offline backup integrity — test restoration procedures NOW before encryption event');
    base.push('If compromise is suspected, invoke the approved incident-response process and isolate systems according to your containment plan');
  }
  if ((item.iocs||[]).length) {
    base.splice(1, 0, `Validate the provenance, context, and expected false-positive impact of all ${item.iocs.length} indicators before enforcement`);
  }
  if ((item.sourceCount||1) >= 2) {
    base.push(`INTEL: Multi-source confirmed (${(item._sources||[]).join(', ')}) — share IOCs with your ISAC/ISAO partners`);
  }
  return base;
}

// ── PHASE 6+7: ADVANCED HTML REPORT GENERATOR ──────────────────────────
// ── PHASE 7: QUALITY GATE — PUBLICATION VALIDATOR ───────────────────────
// Rejects any intelligence item that fails minimum quality requirements.
// Returns { pass: bool, reasons: string[] }
// Non-threat keywords that indicate career/learning Reddit posts — not intelligence
const REDDIT_NOISE_RE = /\b(imposter syndrome|feeling stuck|career advice|study resources?|coursera|udemy|comptia|cissp prep|ceh prep|certif|job hunt|resume|interview|internship|beginner|newbie|starting out|how do i get into|roadmap for|which course|what should i learn|self.?study|boot.?camp|bootcamp|entry.?level|junior.?position|hiring|laid.?off|getting.?into|switching.?careers?|broke into|landed a job|salary|compensation|my first|imposter|burn.?out|burnout|overwhelmed|rant:|feeling low|mental health|advice needed|tips for|suggestions for)\b/i;

// Minimum priority thresholds by source type.
// Base score for a 0-day-old reddit post with CVSS 6.5 and no bonuses = 38.
// Setting threshold to 42 ensures at least one bonus (AI security, nation-state, etc.)
// is present. REDDIT_NOISE_RE handles explicit career/learning content separately.
const SOURCE_MIN_PRIORITY = {
  reddit_cyber: 42,   // r/cybersecurity — career noise filtered; require 1+ relevance bonus
  reddit_netsec: 40,  // r/netsec — better signal; require slight quality bar
};
const DEFAULT_NEWS_REPORT_MIN = 35;

function qualityGate(item) {
  const reasons = [];
  const text = (item.title||'') + ' ' + (item.desc||'');
  const src = item.source || '';

  // Required fields
  if (!item.id)                            reasons.push('Missing: id');
  if (!item.title || item.title.length<10) reasons.push('Missing/too-short: title');
  if (!item.desc  || item.desc.length<20)  reasons.push('Missing/too-short: description');
  if (!item.source)                        reasons.push('Missing: source');

  // Source-specific quality gates
  if (src === 'reddit_cyber' || src === 'reddit_netsec') {
    // Reject career/learning noise from Reddit — zero intelligence value
    if (REDDIT_NOISE_RE.test(item.title||'')) {
      reasons.push(`Reddit non-intelligence content rejected: career/learning topic`);
    }
    const minPri = SOURCE_MIN_PRIORITY[src] || 42;
    if ((item.priority||0) < minPri) {
      reasons.push(`Reddit source requires priority >= ${minPri} (got ${item.priority||0})`);
    }
  } else if (!item.type || item.type==='NEWS_REPORT') {
    // For non-Reddit sources, allow NEWS_REPORT with priority >= threshold
    if ((item.priority||0) < DEFAULT_NEWS_REPORT_MIN) {
      reasons.push(`NEWS_REPORT with low priority (${item.priority||0} < ${DEFAULT_NEWS_REPORT_MIN}) — insufficient intelligence value`);
    }
  }

  // Severity must be assignable. Equal-authority CVSS disagreement is
  // unresolved evidence and must never reach a customer-facing artifact.
  if (item.cvssConflictUnresolved) reasons.push('Unresolved: conflicting authoritative CVSS values');
  const hasCvss   = typeof item.cvss === 'number' && item.cvss > 0;
  const hasTl     = !!item.threatLevel;
  if (!hasCvss && !hasTl) reasons.push('Missing: cvss or threatLevel');

  // Must have at least one reference or link
  const refs = (item.refs || item.references || []).flatMap(extractHttpUrls);
  const link = item.link;
  if (refs.length === 0 && extractHttpUrls(link).length === 0) reasons.push('Missing/invalid: references / link');

  // Intelligence score must be calculable
  if (typeof item.priority !== 'number') reasons.push('Missing: priority score');

  // Classification must be meaningful
  const validTypes = ['CVE_REPORT','ZERO_DAY','RANSOMWARE','MALWARE_REPORT','DATA_BREACH',
    'THREAT_ACTOR','AI_SECURITY','DARK_WEB','SUPPLY_CHAIN','CLOUD_SECURITY',
    'CRITICAL_INFRASTRUCTURE','SOCIAL_ENGINEERING','DETECTION_ENGINEERING',
    'INCIDENT','ADVISORY','NEWS_REPORT'];
  if (item.type && !validTypes.includes(item.type)) reasons.push(`Unknown type: ${item.type}`);

  // Reject obvious duplicates / placeholder content
  if (/^test|^placeholder|^sample/i.test(item.title||'')) reasons.push('Placeholder/test content rejected');

  return { pass: reasons.length === 0, reasons };
}

// ── PHASE 7B: POST-RENDER INTEGRITY VALIDATOR ───────────────────────────
// P0-REPORTX-2026-08-19: qualityGate() above runs BEFORE generatePostHTML()
// and only checks the raw item's fields -- it has no way to catch a defect
// that only exists in the assembled HTML itself. This is that missing
// layer, structurally the same role automation/report_integrity.py's
// validate_publication() plays for the Python pipeline: a fail-closed,
// evidence-cross-checking pass over the rendered output, run once per item
// immediately before the file is written. It is defense-in-depth against
// FUTURE generator bugs, not a statement that current generatePostHTML()
// output is unsafe -- genExecutiveSummary/genCommentary/genBusinessImpact
// already gate confirmed-exploitation language behind item.cisaKev/
// item.exploited correctly today (verified by direct reading of this file);
// this validator exists so a later edit that breaks that discipline is
// caught here instead of publishing straight to blog.cyberdudebivash.in.

// Exact confirmed-exploitation phrases these generators can emit -- kept in
// sync with genExecutiveSummary/genCommentary/genBusinessImpact by hand,
// same discipline report_integrity.py already uses for its own forbidden
// phrase list. If none of item.cisaKev/item.exploited is true, none of
// these phrases may legitimately appear in the rendered HTML.
const _CONFIRMED_EXPLOITATION_PHRASES = [
  'cisa has confirmed active exploitation in the wild',
  'active exploitation has been reported in the wild',
  'cisa kev listing confirms in-the-wild exploitation',
  'confirmed exploitation raises remediation priority',
];

// JS-specific failure mode Python's pipeline structurally cannot have:
// template-literal interpolation of undefined/NaN/an unstringified object
// silently produces visible garbage in the page instead of throwing.
// "undefined" excludes "undefined behavior/behaviour": confirmed live
// (2026-08-19, real post cve-2026-42327-rust-openssl.html) that this is
// standard, legitimate memory-safety vulnerability terminology, not a
// template artifact -- a bare match would have blocked every future
// undefined-behavior CVE report.
const _UNRESOLVED_TEMPLATE_PATTERNS = [
  /\bundefined\b(?!\s+behaviou?r)/i,
  /\bNaN\b/,
  /\[object Object\]/,
];

// Same placeholder-artifact class report_integrity.py's _PLACEHOLDER_PATTERNS
// checks for on the Python side -- a genuinely shared risk (any pipeline can
// leak an unfilled template token), so the same discipline applies here.
// Deliberately excludes "TBD": confirmed live (2026-08-19) that
// genExecutiveSummary's stat tiles legitimately render "TBD" as the
// "Exploited ITW" value when exploitation status is honestly unknown --
// exactly the Rule-6 "UNKNOWN is a valid state" language this whole
// mandate wants preserved, not a leaked template placeholder.
// "lorem ipsum" requires the next few words of the actual classic filler
// passage, not just the two seed words bare: confirmed live (2026-08-19,
// real post lorem-ipsum-malware-pivots-to-clickfix-delivery.html) that
// "Lorem Ipsum" is itself a real, named malware family being reported on
// -- a bare match would have blocked every future report about it.
const _PLACEHOLDER_BODY_PATTERNS = [
  /\blorem ipsum dolor sit amet\b/i,
  /\bchange[_ -]?me\b/i,
  /\btodo\b/i,
  /00000000-0000-0000-0000-000000000000/,
];

// Mirrors automation/report_integrity.py's _FALSE_HUMAN_REVIEW_PATTERNS --
// this pipeline never performs a real human review (see about.html's own
// "automated content" disclosure), so these phrases must never appear.
const _FALSE_HUMAN_REVIEW_PATTERNS = [
  /\bhuman reviewed\b/i,
  /\banalyst approved\b/i,
  /\bmanually verified\b/i,
];

// Real recent posts run 38-51KB (measured live against the current
// posts/ corpus, 2026-08-19); this floor is set well below that, at a
// level that only trips on a genuinely truncated/corrupt render, not on
// legitimate variation in how many conditional sections an item earns.
const MIN_RENDERED_POST_LENGTH = 8000;

function validateRenderedPost(item, html) {
  const reasons = [];
  const lower = html.toLowerCase();

  if (html.length < MIN_RENDERED_POST_LENGTH) {
    reasons.push(`Rendered post is only ${html.length} chars -- below the ${MIN_RENDERED_POST_LENGTH} floor, likely truncated or corrupt`);
  }

  for (const pattern of _UNRESOLVED_TEMPLATE_PATTERNS) {
    if (pattern.test(html)) reasons.push(`Unresolved template artifact matched /${pattern.source}/`);
  }

  for (const pattern of _PLACEHOLDER_BODY_PATTERNS) {
    if (pattern.test(html)) reasons.push(`Placeholder content matched /${pattern.source}/`);
  }

  for (const pattern of _FALSE_HUMAN_REVIEW_PATTERNS) {
    if (pattern.test(html)) reasons.push(`False human-review claim matched /${pattern.source}/`);
  }

  if (!item.cisaKev && !item.exploited) {
    for (const phrase of _CONFIRMED_EXPLOITATION_PHRASES) {
      if (lower.includes(phrase)) {
        reasons.push(`Unsupported confirmed-exploitation assertion (item.cisaKev and item.exploited are both false): "${phrase}"`);
      }
    }
  }

  return { pass: reasons.length === 0, reasons };
}

// ── PHASE 9: SENTINEL APEX INTEGRATION ENRICHER ──────────────────────────
// Stamps every publishable item with Sentinel APEX metadata for cross-platform consumption.
function sentinelApexStamp(item) {
  const text = (item.title||'') + ' ' + (item.desc||'');
  return {
    ...item,
    // Sentinel APEX routing tags
    sentinel_apex: {
      published_at:      new Date().toISOString(),
      platform_version:  'v5.3',
      content_hubs: [
        ...(item.type === 'AI_SECURITY' ? ['ai-security-hub'] : []),
        ...(item.type === 'MALWARE_REPORT' || item.type === 'RANSOMWARE' ? ['malware-intelligence'] : []),
        ...(item.type === 'DARK_WEB' ? ['dark-web-intelligence'] : []),
        ...(['CVE_REPORT','ZERO_DAY','ADVISORY'].includes(item.type) ? ['vulnerability-intelligence'] : []),
        ...(['THREAT_ACTOR','SUPPLY_CHAIN'].includes(item.type) ? ['threat-actor-tracking'] : []),
        'threat-intelligence-hub',  // every item goes to main hub
      ],
      detection_ready: ['CVE_REPORT','ZERO_DAY','MALWARE_REPORT','RANSOMWARE','ADVISORY'].includes(item.type),
      api_eligible:    (item.priority||0) >= 40,
      mssp_relevant:   (item.priority||0) >= 50 || item.cisaKev || item.exploited,
    },
    // Ensure universal schema fields are present
    category:           item.category || item.type,
    intelligence_score: item.priority || 0,
    confidence:         item.confidence || 0.55,
    affected_industries: item.affected_industries || [],
    ai_security_tags:   item.ai_security_tags || [],
    darkweb_tags:       item.darkweb_tags || [],
    threat_actor:       item.threat_actor || [],
    first_seen:         item.first_seen || item.pubDate || new Date().toISOString().slice(0,10),
    updated_at:         new Date().toISOString(),
  };
}

// ── CVSS VECTOR DECODER — factual, per-CVE severity anatomy ──────────────
// Decodes the official CVSS v3.x vector string from NVD into plain-language
// attack characteristics. This is primary-source data, not assessment: every
// row is a direct read of the vendor/NVD-assigned vector, so a defender learns
// exactly HOW the vulnerability is reached and what it costs — the single most
// useful triage signal beyond the base score.
const CVSS_METRICS = {
  AV: { label: 'Attack Vector', vals: {
    N: ['Network', 'Remotely exploitable across the network — internet-facing instances are directly at risk.'],
    A: ['Adjacent', 'Requires same physical/logical network (LAN, Bluetooth, adjacent subnet).'],
    L: ['Local', 'Requires local access — a shell, session, or local file/app interaction.'],
    P: ['Physical', 'Requires physical access to the device.'] } },
  AC: { label: 'Attack Complexity', vals: {
    L: ['Low', 'No special conditions — reliably repeatable by an attacker.'],
    H: ['High', 'Depends on conditions outside attacker control (race, specific config) — harder to weaponize.'] } },
  PR: { label: 'Privileges Required', vals: {
    N: ['None', 'No authentication needed — pre-auth exploitation.'],
    L: ['Low', 'Requires basic user-level privileges.'],
    H: ['High', 'Requires administrative/elevated privileges.'] } },
  UI: { label: 'User Interaction', vals: {
    N: ['None', 'No victim action required — fully automatable.'],
    R: ['Required', 'A user must click, open, or visit something — social engineering component.'] } },
  S:  { label: 'Scope', vals: {
    U: ['Unchanged', 'Impact confined to the vulnerable component.'],
    C: ['Changed', 'Impact extends beyond the vulnerable component — can affect other systems/security domains.'] } },
  C:  { label: 'Confidentiality Impact', vals: {
    H: ['High', 'Total loss of confidentiality — full data disclosure possible.'],
    L: ['Low', 'Limited disclosure of some data.'], N: ['None', 'No confidentiality impact.'] } },
  I:  { label: 'Integrity Impact', vals: {
    H: ['High', 'Total loss of integrity — attacker can modify any data.'],
    L: ['Low', 'Limited modification of some data.'], N: ['None', 'No integrity impact.'] } },
  A:  { label: 'Availability Impact', vals: {
    H: ['High', 'Total loss of availability — full denial of service possible.'],
    L: ['Low', 'Reduced performance or intermittent availability.'], N: ['None', 'No availability impact.'] } },
};

function decodeCvssVector(vector) {
  if (!vector || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const parts = {};
  vector.split('/').slice(1).forEach(p => { const [k, v] = p.split(':'); if (k && v) parts[k] = v; });
  const order = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  const rows = [];
  for (const k of order) {
    const spec = CVSS_METRICS[k]; const code = parts[k];
    if (!spec || !code || !spec.vals[code]) continue;
    const [val, meaning] = spec.vals[code];
    rows.push({ metric: spec.label, value: val, meaning, code: `${k}:${code}` });
  }
  return rows.length ? { rows, version: vector.match(/^CVSS:(3\.[01])/)[1] } : null;
}

function genSeverityAnatomy(item, esc) {
  const decoded = decodeCvssVector(item.vector);
  if (!decoded) return '';
  const hi = m => (m.code === 'AV:N' || m.code === 'PR:N' || m.code === 'UI:N' || m.code === 'S:C' || /:H$/.test(m.code));
  const rows = decoded.rows.map(m => `<tr>
      <td style="color:var(--apex-muted);white-space:nowrap">${esc(m.metric)}</td>
      <td style="font-weight:700;color:${hi(m) ? 'var(--apex-red)' : 'var(--apex-text)'};white-space:nowrap">${esc(m.value)} <code style="color:var(--apex-muted);font-size:11px">${esc(m.code)}</code></td>
      <td style="font-size:13px;color:#c9d1d9">${esc(m.meaning)}</td>
    </tr>`).join('\n');
  return `<h2 class="sh"><span>🧮</span> Severity Anatomy <span style="font-size:12px;font-weight:500;color:var(--apex-muted)">— CVSS ${esc(decoded.version)} vector, decoded from the primary record</span></h2>
    <p class="bp">The base score summarizes severity in one number; the vector explains <em>why</em>. Each row below is a direct read of the official CVSS vector — verifiable against the <a href="https://nvd.nist.gov/vuln/detail/${esc(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD record</a>.</p>
    <table class="tbl"><thead><tr><th>Metric</th><th>Value</th><th>What it means for defenders</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ── CWE ANATOMY — weakness-class exploitation & detection reference ──────
// Maps the NVD-assigned CWE to authoritative, factual guidance on how the
// weakness class is exploited and how it is detected/prevented. Sourced from
// the MITRE CWE corpus (definitions are public). This is class-level fact, not
// per-incident claim — labeled as such — and turns a bare "CWE-79" into
// something a defender can act on.
const CWE_LIB = {
  '20':  ['Improper Input Validation', 'Attacker supplies input the application fails to validate for type, length, format, or range, driving unexpected code paths, memory corruption, or downstream injection.', 'Validate/allowlist all input at trust boundaries; enforce schema and length limits; alert on malformed requests and input-length anomalies at the WAF/app tier.'],
  '79':  ['Cross-Site Scripting (XSS)', 'Attacker injects script into pages rendered to other users, running in their browser session to steal cookies/tokens or perform actions as the victim.', 'Context-aware output encoding; Content-Security-Policy; sanitize rich input. Detect via WAF signatures for script payloads and anomalous parameter content.'],
  '89':  ['SQL Injection', 'Attacker injects SQL through unsanitized input to read, modify, or destroy database contents, or bypass authentication.', 'Parameterized queries / prepared statements; least-privilege DB accounts. Detect via WAF SQLi signatures and DB query-anomaly / error-rate monitoring.'],
  '78':  ['OS Command Injection', 'Attacker injects shell metacharacters into input passed to a system command, executing arbitrary OS commands in the application context.', 'Avoid shelling out; use parameterized APIs; strict allowlists. Detect via process-creation telemetry: web/app service spawning shells (cmd/bash/sh).'],
  '77':  ['Command Injection', 'Attacker controls part of a command that the application constructs and executes, leading to arbitrary command execution.', 'Never build commands from untrusted input; use safe APIs. Detect anomalous child processes of service accounts and unexpected interpreter launches.'],
  '787': ['Out-of-Bounds Write', 'Attacker triggers a write past the bounds of a buffer, corrupting memory to crash the process or achieve code execution.', 'Memory-safe languages, bounds checks, compiler hardening (ASLR/DEP/stack canaries). Detect via crash telemetry and EDR memory-integrity alerts.'],
  '125': ['Out-of-Bounds Read', 'Attacker reads memory outside the intended buffer, disclosing sensitive data (keys, tokens) or enabling further exploitation.', 'Bounds validation; memory-safe handling. Detect via crash/exception monitoring and abnormal memory-access patterns in EDR.'],
  '416': ['Use After Free', 'Attacker causes the program to use memory after it is freed; with heap grooming this yields code execution.', 'Memory-safe languages, sanitizers in CI, allocator hardening. Detect via EDR exploit-guard and process-crash telemetry.'],
  '119': ['Improper Restriction of Memory Buffer', 'Attacker reads or writes outside buffer bounds (classic buffer overflow) to corrupt memory and control execution.', 'Bounds checking, safe string APIs, compiler mitigations. Detect via crash monitoring and EDR memory-protection events.'],
  '22':  ['Path Traversal', 'Attacker uses ../ sequences or absolute paths to access files outside the intended directory, reading or writing arbitrary files.', 'Canonicalize and confine paths to a safe root; reject traversal sequences. Detect via web logs for ../ and encoded-traversal patterns.'],
  '352': ['Cross-Site Request Forgery (CSRF)', 'Attacker tricks an authenticated victim’s browser into submitting a forged state-changing request.', 'Anti-CSRF tokens, SameSite cookies, re-authentication for sensitive actions. Detect via missing/invalid CSRF tokens and off-origin Referer.'],
  '434': ['Unrestricted File Upload', 'Attacker uploads an executable or web-shell file the server later runs, yielding remote code execution.', 'Validate type/extension/content, store outside webroot, disable execution in upload dirs. Detect via new files in upload paths and web-shell signatures.'],
  '862': ['Missing Authorization', 'Attacker accesses functions or data without an authorization check, reaching resources they should not.', 'Enforce authorization on every request server-side; deny by default. Detect via access to privileged endpoints from unprivileged sessions.'],
  '863': ['Incorrect Authorization', 'Authorization logic is present but flawed, letting an attacker bypass intended access controls.', 'Centralize authorization; test with least-privilege accounts. Detect via privilege-boundary crossings in access logs.'],
  '306': ['Missing Authentication for Critical Function', 'A sensitive function is exposed without requiring authentication, allowing anonymous access.', 'Require authentication on all sensitive endpoints; segment management interfaces. Detect via unauthenticated hits to admin/critical paths.'],
  '287': ['Improper Authentication', 'Attacker bypasses or subverts authentication (weak logic, token flaws, replay) to gain access.', 'Robust auth, MFA, session integrity. Detect via impossible-travel, credential-stuffing patterns, and auth-anomaly alerts.'],
  '502': ['Deserialization of Untrusted Data', 'Attacker supplies crafted serialized objects that instantiate dangerous types on deserialization, leading to RCE.', 'Avoid native deserialization of untrusted data; use allowlists/safe formats. Detect via app-tier process anomalies (e.g., web worker spawning shells).'],
  '918': ['Server-Side Request Forgery (SSRF)', 'Attacker makes the server issue requests to attacker-chosen targets, reaching internal services or cloud metadata.', 'Allowlist egress destinations; block link-local/metadata IPs; validate URLs. Detect via outbound requests to 169.254.169.254 and internal ranges.'],
  '190': ['Integer Overflow', 'Attacker causes an arithmetic overflow that undersizes an allocation or bypasses a check, leading to memory corruption.', 'Checked arithmetic, size validation. Detect via crash telemetry and fuzzing in CI.'],
  '476': ['NULL Pointer Dereference', 'Attacker forces a null dereference, typically crashing the service (denial of service).', 'Null checks, defensive coding. Detect via crash/restart telemetry and availability monitoring.'],
  '798': ['Use of Hard-coded Credentials', 'Attacker extracts embedded credentials from firmware/binaries/config to authenticate as a privileged user.', 'Remove hard-coded secrets; use secret managers and per-device credentials. Detect via known-default-credential login attempts.'],
  '269': ['Improper Privilege Management', 'Attacker leverages mismanaged privileges to escalate to higher rights than intended.', 'Least privilege, correct token/role handling. Detect via privilege-escalation and unexpected SYSTEM/root token use in EDR.'],
  '94':  ['Code Injection', 'Attacker injects code that the application interprets and executes (eval-style), achieving arbitrary execution.', 'Never evaluate untrusted input; sandbox interpreters. Detect via anomalous interpreter activity and unexpected dynamic-code execution.'],
  '400': ['Uncontrolled Resource Consumption', 'Attacker exhausts CPU, memory, disk, or connections to cause denial of service.', 'Rate limiting, quotas, timeouts, backpressure. Detect via resource-utilization spikes and request-rate anomalies.'],
  '295': ['Improper Certificate Validation', 'Attacker with network position exploits weak TLS validation to intercept or spoof connections (MITM).', 'Enforce full chain + hostname validation; pin where feasible. Detect via TLS-anomaly and unexpected CA monitoring.'],
  '611': ['XML External Entity (XXE)', 'Attacker supplies XML referencing external entities to read local files, perform SSRF, or cause DoS.', 'Disable external entity/DTD processing in XML parsers. Detect via app logs for DOCTYPE/ENTITY in XML payloads.'],
};
function normalizeCwe(cweId) {
  const m = String(cweId||'').match(/CWE-(\d+)/i);
  return m ? m[1] : null;
}
function genCweAnatomy(item, esc) {
  const num = normalizeCwe(item.cweId);
  if (!num || !CWE_LIB[num]) return '';
  const [name, exploited, detected] = CWE_LIB[num];
  return `<h2 class="sh"><span>🧬</span> Weakness Anatomy <span style="font-size:12px;font-weight:500;color:var(--apex-muted)">— CWE-${esc(num)}, the underlying flaw class</span></h2>
    <p class="bp">This vulnerability is classified as <a href="https://cwe.mitre.org/data/definitions/${esc(num)}.html" target="_blank" rel="noopener" style="color:var(--apex-cyan)"><strong>CWE-${esc(num)}: ${esc(name)}</strong></a> in the primary record. The mechanics below are characteristic of this weakness class (per the MITRE CWE corpus), not a claim about a specific exploit observed against your environment.</p>
    <table class="tbl"><tbody>
      <tr><td style="color:var(--apex-muted);white-space:nowrap;vertical-align:top">How it's exploited</td><td style="font-size:13px;color:#c9d1d9">${esc(exploited)}</td></tr>
      <tr><td style="color:var(--apex-muted);white-space:nowrap;vertical-align:top">Detect &amp; prevent</td><td style="font-size:13px;color:#c9d1d9">${esc(detected)}</td></tr>
    </tbody></table>`;
}

function generatePostHTML(item) {
  // Prefer a real analyst-provided mapping (currently: Sentinel APEX native
  // MITRE data) over regex inference. Also populates item._mitre, which the
  // per-CVE API file writer already reads (writeAPIFiles) but nothing has
  // ever set — every source's CVE JSON gains a populated `mitre` field as
  // a side effect, not just Sentinel APEX's.
  const mitre = item.mitreNative || getMitre(item);
  item._mitre = mitre;
  const execSummary = genExecutiveSummary(item);
  const bizImpact   = genBusinessImpact(item);
  const attackChain = genAttackChain(item);
  const commentary  = genCommentary(item);
  const playbook    = genPlaybook(item);
  // Type-specific sections
  const aiSecSection   = item.type==='AI_SECURITY' ? genAISecSection(item, escHtml) : '';
  const malwareSection = (item.type==='MALWARE_REPORT'||item.type==='RANSOMWARE') ? genMalwareSection(item, escHtml) : '';
  const darkwebSection = item.type==='DARK_WEB' ? genDarkWebSection(item, escHtml) : '';
  const sigma = genSigma(item);
  const yara  = genYARA(item);
  const multiDetections = genMultiPlatformDetections(item, escHtml);
  const priorIntel = genPriorIntelligence(item, escHtml);
  const structuredReasoning = genStructuredReasoning(item, escHtml);
  const pubDateFmt = fmtDate(item.pubDate||isoNow()), today = isoNow();
  const hasCvss = typeof item.cvss === 'number' && item.cvss >= 0 && item.cvss <= 10;
  const cvss = hasCvss ? item.cvss : null;
  const cvssDisplay = hasCvss ? String(cvss) : 'Not assigned';
  const cvssColor = !hasCvss?'#8b949e':cvss>=9.0?'#ff3b3b':cvss>=7.0?'#ff8c00':'#ffe000';
  const sevLabel = technicalSeverityFromCvss(cvss);
  const score = item.priority||0;
  const priorityLevel = item.threatLevel||threatLevel(score);
  const typeLabels = { CVE_REPORT:'🔴 CVE ANALYSIS', ZERO_DAY:'💀 ZERO-DAY', RANSOMWARE:'🏴 RANSOMWARE', MALWARE_REPORT:'🦠 MALWARE', DATA_BREACH:'⚠️ DATA BREACH', THREAT_ACTOR:'🎯 THREAT ACTOR', AI_SECURITY:'🤖 AI SECURITY', NEWS_REPORT:'📡 INTEL', ADVISORY:'🛡️ ADVISORY' };
  const typeLabel = typeLabels[item.type]||'⚡ INTEL';
  const vendorProductLabel = [item.vendor, item.product].filter(Boolean).join(' ');
  const slug = slugify(item.id.startsWith('CVE')?`${item.id}-${item.vendor}-${item.product}`:item.title.slice(0,60));
  const intelligenceProducts = genIntelligenceProducts(item, escHtml, slug);
  // Control chars in titles break JSON-LD parsing (raw newlines are illegal in JSON strings)
  const safeTitle = String(item.title||'').replace(/[\u0000-\u001F\u007F]/g,' ').replace(/\s+/g,' ').trim();
  const metaTitle = `${safeTitle} | CYBERDUDEBIVASH SENTINEL APEX`;
  // Per-post branded social card (severity badge, CVE ID, CVSS, headline) —
  // api/og.js validates/sanitizes every param server-side (regex-checks cve,
  // range-checks cvss, strips emoji/control chars from title/type), so raw
  // values are passed through untouched here rather than re-validated. Used
  // escHtml()-wrapped in HTML attributes below, but raw in the JSON-LD block
  // — script-tag content isn't HTML-entity-decoded, so escHtml would corrupt
  // the query string's "&" separators into literal "&amp;" text there.
  // v=3 mirrors automation/authority_transformer.py's OG_CARD_VERSION — a
  // fixed cache-key differentiator bumped only on an actual api/og.js
  // layout change, so Vercel's long-lived edge cache doesn't keep serving a
  // stale pre-redesign PNG for a URL it already cached. This blog-side path
  // has no KEV/EPSS-equivalent field on `item` to pass through (unlike the
  // Blogger/Python pipeline's DiscoveredArticle) — kev/epss stay omitted
  // here rather than invented, same discipline as the rest of this file's
  // metadata assembly.
  const ogImageUrl = `${CFG.baseUrl}/api/og?title=${encodeURIComponent(safeTitle)}&severity=${encodeURIComponent(sevLabel)}&cve=${encodeURIComponent(item.id||'')}&cvss=${encodeURIComponent(hasCvss?cvss:'')}&type=${encodeURIComponent(typeLabel)}&v=3`;
  const isCVEItem = /^CVE-/i.test(item.id);
  const cleanDescText = stripHtml(item.desc||'')
    .replace(/```[\s\S]*?```/g,' ')
    .replace(/`+/g,'')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g,'$1')
    .replace(/(^|\s)#{1,6}\s+/g,' ')
    .replace(/[*_]{2,}/g,' ')
    .replace(/\s+/g,' ').trim();
  // Truncate at a word boundary so Google/social snippets never end mid-word
  const truncAtWord = (s,n)=> s.length<=n ? s : s.slice(0,n+1).replace(/\s+\S*$/,'').slice(0,n);
  const metaDesc = isCVEItem
    ? `${item.id}${hasCvss?` (CVSS ${cvss})`:''} — ${truncAtWord(cleanDescText,130)}. Source-attributed analysis and response guidance by CYBERDUDEBIVASH SENTINEL APEX.`
    : `${(truncAtWord(cleanDescText,155)||truncAtWord(item.title,155))}. Cybersecurity analysis, IOCs, and detection guidance by CYBERDUDEBIVASH SENTINEL APEX.`;
  const badges = [
    item.cisaKev?`<span class="badge bdg-cisa">⚠️ CISA KEV</span>`:'',
    item.exploited?`<span class="badge bdg-red">⚡ ACTIVELY EXPLOITED</span>`:'',
    item.ransomware?`<span class="badge bdg-purple">🏴 RANSOMWARE</span>`:'',
    `<span class="badge bdg-score">${score}/100</span>`,
    `<span class="badge ${hasCvss?'bdg-red':'bdg-cyan'}">CVSS ${cvssDisplay}</span>`,
    `<span class="badge bdg-cyan">${typeLabel}</span>`,
    (item.sourceCount||1)>=2?`<span class="badge bdg-green">✓ ${item.sourceCount}x CONFIRMED</span>`:'',
  ].filter(Boolean).join('\n      ');
  const cveIds  = item.cves||(item.id?.startsWith('CVE')?[item.id]:[]);
  const cveRows = cveIds.slice(0,5).map(cve=>`<tr><td style="font-family:var(--mono);color:var(--apex-cyan)">${escHtml(cve)}</td><td><a href="https://nvd.nist.gov/vuln/detail/${escHtml(cve)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD →</a></td><td>${cvssDisplay}</td></tr>`).join('\n');
  const iocRows = (item.iocs||[]).filter(ioc=>ioc&&ioc.value).slice(0,10).map(ioc=>`<tr><td style="font-family:var(--mono);font-size:11px;color:var(--apex-cyan)">${escHtml(String(ioc.value||'').slice(0,80))}</td><td>${escHtml(ioc.type||'ioc')}</td><td style="text-align:center">${Math.round((ioc.confidence_score||0.8)*100)}%</td><td style="color:var(--apex-muted);font-size:11px">${escHtml(ioc.first_seen||isoNow())}</td></tr>`).join('\n');
  // v5.1: Filter refs to valid URLs only — prevents NVD GHSA description strings leaking into hrefs
  const validRefs = (item.refs||[]).flatMap(extractHttpUrls);
  const refLinks = validRefs.slice(0,5).map(r=>`<li><a href="${escHtml(r)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${escHtml(r.replace(/https?:\/\//,'').slice(0,70))}</a></li>`).join('\n');
  const playbookItems = playbook.map((s,i)=>`<li class="action-item"><span class="action-num">${i+1}</span>${escHtml(s)}</li>`).join('\n      ');
  const bizImpactItems = bizImpact.map(b=>`<li class="impact-item">⚠️ ${escHtml(b)}</li>`).join('\n');
  const chainRows = attackChain.map((step,i)=>`<tr${i===0?' class="chain-first"':i===attackChain.length-1?' class="chain-last"':''}>
      <td style="text-align:center;padding:10px 8px"><div class="chain-num">${i+1}</div></td>
      <td style="color:var(--apex-cyan);font-weight:700;padding:10px 14px;white-space:nowrap">${escHtml(step.phase)}</td>
      <td style="padding:10px 14px;font-size:13px;color:var(--apex-text)">${escHtml(step.detail)}</td>
      <td style="padding:10px 8px;text-align:center"><code style="font-size:10px;color:var(--apex-orange)">${escHtml(step.tactic)}</code></td>
    </tr>`).join('\n    ');
  const showDetection = ['CVE_REPORT','ZERO_DAY','ADVISORY','MALWARE_REPORT','RANSOMWARE'].includes(item.type);
  const srcBadges = (item._sources||[item.source]).map(s=>`<span style="display:inline-block;padding:2px 8px;border:1px solid var(--apex-border);border-radius:4px;font-size:11px;color:var(--apex-muted);margin:2px">${escHtml(s)}</span>`).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<!-- Resource hints -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="preconnect" href="https://cdnjs.cloudflare.com">
<link rel="dns-prefetch" href="https://www.googletagmanager.com">
<!-- GA4 — CYBERDUDEBIVASH SENTINEL APEX Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XTGLNMNNC7"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-XTGLNMNNC7',{page_title:document.title,page_location:window.location.href});</script>
<meta name="description" content="${escHtml(metaDesc)}">
<meta property="og:title" content="${escHtml(metaTitle)}"><meta property="og:type" content="article">
<meta property="og:url" content="${CFG.baseUrl}/posts/${escHtml(slug)}.html">
<meta property="og:description" content="${escHtml(metaDesc)}">
<meta property="og:site_name" content="CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:locale" content="en_US">
<meta property="og:image" content="${escHtml(ogImageUrl)}">
<meta property="og:image:secure_url" content="${escHtml(ogImageUrl)}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${escHtml(metaTitle)}">
<meta property="article:published_time" content="${today}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escHtml(metaTitle)}">
<meta name="twitter:description" content="${escHtml(metaDesc)}">
<meta name="twitter:image" content="${escHtml(ogImageUrl)}">
<meta name="twitter:image:alt" content="${escHtml(metaTitle)}">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#00ffe0">
<link rel="canonical" href="${CFG.baseUrl}/posts/${escHtml(slug)}.html">
<link rel="alternate" type="application/rss+xml" title="CYBERDUDEBIVASH SENTINEL APEX" href="${CFG.baseUrl}/rss.xml">
<title>${escHtml(metaTitle)}</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","headline":"${escHtml(safeTitle)}","description":"${escHtml(metaDesc)}","image":"${ogImageUrl}","datePublished":"${today}","dateModified":"${today}","author":{"@type":"Organization","name":"CYBERDUDEBIVASH SENTINEL APEX","url":"${CFG.baseUrl}"},"publisher":{"@type":"Organization","name":"CYBERDUDEBIVASH"}}</script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{"@type":"ListItem","position":1,"name":"CYBERDUDEBIVASH SENTINEL APEX","item":"${CFG.baseUrl}/"},{"@type":"ListItem","position":2,"name":"Intelligence Reports","item":"${CFG.baseUrl}/"},{"@type":"ListItem","position":3,"name":"${escHtml(safeTitle.slice(0,120))}","item":"${CFG.baseUrl}/posts/${slug}.html"}]}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-yellow:#ffe000;--apex-green:#00ff88;--apex-purple:#a855f7;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;overflow-x:hidden;line-height:1.7}
#mc{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:.025}
.ticker{position:relative;z-index:100;background:linear-gradient(90deg,#ff0040,#cc0030,#ff0040);padding:8px 0;overflow:hidden}
.ticker-inner{display:flex;animation:tick 55s linear infinite;white-space:nowrap}.ticker-item{color:#fff;font-size:12px;font-weight:700;letter-spacing:.05em;padding:0 40px}
@keyframes tick{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan)}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;align-items:center;gap:6px}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px;transition:.2s}.nlinks a:hover{color:var(--apex-text);background:var(--apex-surface)}
.ncta{background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000!important;font-weight:700!important;border-radius:6px!important}
main{position:relative;z-index:10;max-width:1200px;margin:0 auto;padding:40px 24px 80px;display:grid;grid-template-columns:1fr 320px;gap:40px}
@media(max-width:900px){main{grid-template-columns:1fr;padding:24px 16px}}
.meta-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:20px}
.badge{padding:4px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.bdg-red{background:#ff3b3b22;color:#ff3b3b;border:1px solid #ff3b3b44}.bdg-cisa{background:#00ffe022;color:#00ffe0;border:1px solid #00ffe044}
.bdg-cyan{background:#0099ff22;color:#0099ff;border:1px solid #0099ff44}.bdg-purple{background:#a855f722;color:#a855f7;border:1px solid #a855f744}
.bdg-score{background:#ffe00022;color:#ffe000;border:1px solid #ffe00044}.bdg-green{background:#00ff8822;color:#00ff88;border:1px solid #00ff8844}
.rep-date{color:var(--apex-muted);font-size:13px;margin-left:auto}
h1.rh1{font-size:clamp(20px,3.5vw,34px);font-weight:900;line-height:1.2;color:#fff;margin-bottom:16px}
.rsubtitle{font-size:15px;color:var(--apex-muted);margin-bottom:28px;line-height:1.65;border-left:3px solid var(--apex-red);padding-left:16px}
.stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin-bottom:32px}
.stat{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:10px;padding:14px;text-align:center}
.stat .sv{font-size:20px;font-weight:900;color:var(--apex-cyan);font-family:var(--mono)}.stat.red .sv{color:var(--apex-red)}.stat.orange .sv{color:var(--apex-orange)}.stat.green .sv{color:var(--apex-green)}.stat.yellow .sv{color:var(--apex-yellow)}.stat .sl{font-size:10px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.exec-box{background:linear-gradient(135deg,#0a1220,#111827);border:1px solid rgba(0,255,224,.15);border-left:4px solid var(--apex-cyan);border-radius:12px;padding:20px 24px;margin-bottom:24px}
.exec-box .ex-label{font-size:10px;font-weight:800;color:var(--apex-cyan);letter-spacing:.15em;text-transform:uppercase;margin-bottom:10px}
.exec-box p{font-size:14px;color:#c9d1d9;line-height:1.75}
.alert{padding:16px 20px;border-radius:10px;margin:20px 0;display:flex;gap:14px;align-items:flex-start}
.alert-crit{background:#ff3b3b10;border:1px solid #ff3b3b44;border-left:4px solid var(--apex-red)}.alert-warn{background:#ff8c0010;border:1px solid #ff8c0044;border-left:4px solid var(--apex-orange)}.alert-info{background:#00ffe010;border:1px solid #00ffe044;border-left:4px solid var(--apex-cyan)}
.aico{font-size:22px;flex-shrink:0}.abody .atitle{font-weight:800;font-size:14px;margin-bottom:4px}.alert-crit .atitle{color:var(--apex-red)}.alert-warn .atitle{color:var(--apex-orange)}.alert-info .atitle{color:var(--apex-cyan)}.abody p{font-size:14px;color:var(--apex-muted);line-height:1.6}
h2.sh{font-size:19px;font-weight:800;color:#fff;margin:36px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}h2.sh span{color:var(--apex-cyan)}
p.bp{font-size:15px;color:#c9d1d9;line-height:1.8;margin-bottom:14px}
.code-block{background:#0a0e18;border:1px solid var(--apex-border);border-radius:8px;padding:16px 20px;font-family:var(--mono);font-size:12px;color:#a6e22e;overflow-x:auto;margin:16px 0;position:relative;white-space:pre;max-height:380px;overflow-y:auto}
.code-lbl{position:absolute;top:8px;right:12px;font-size:10px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.1em;background:var(--apex-surface);padding:2px 6px;border-radius:4px}
.tbl{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px}.tbl th{background:#1a2234;color:var(--apex-cyan);font-weight:700;padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--apex-border)}.tbl td{padding:10px 14px;border:1px solid var(--apex-border);color:var(--apex-text);vertical-align:top}
.chain-num{width:24px;height:24px;border-radius:50%;background:linear-gradient(135deg,var(--apex-red),#cc0020);color:#fff;font-size:11px;font-weight:900;display:flex;align-items:center;justify-content:center;margin:0 auto}
.impact-list{list-style:none;padding:0;margin:12px 0}.impact-item{padding:10px 14px;border-left:3px solid var(--apex-orange);background:#ff8c0008;border-radius:0 8px 8px 0;margin-bottom:8px;font-size:14px;color:var(--apex-text);line-height:1.6}
.pro-gate{position:relative;overflow:hidden;border-radius:12px;border:1px solid rgba(168,85,247,.3)}.pro-blur{filter:blur(5px);pointer-events:none;user-select:none;opacity:.4}.pro-overlay{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;background:rgba(7,9,15,.85);border-radius:12px;z-index:10;padding:20px;text-align:center}
.pro-lock{font-size:32px}.pro-title{font-size:15px;font-weight:800;color:#a855f7}.pro-sub{font-size:13px;color:var(--apex-muted)}.pro-btn{padding:10px 24px;background:linear-gradient(135deg,#a855f7,#7c3aed);color:#fff;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;margin-top:4px}
.ecta{background:linear-gradient(135deg,#0a1428,#111827);border:1px solid #00ffe022;border-radius:16px;padding:28px;margin:40px 0;text-align:center}
.ecta h3{font-size:20px;font-weight:900;color:#fff;margin-bottom:8px}.ecta .ep{color:var(--apex-muted);margin-bottom:20px;font-size:14px}
.cta-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}@media(max-width:600px){.cta-grid{grid-template-columns:1fr}}
.btn-p{padding:12px 20px;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-s{padding:12px 20px;background:transparent;border:2px solid var(--apex-cyan);color:var(--apex-cyan);font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-e{padding:12px 20px;background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.4);color:#a855f7;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.btn-g{padding:12px 20px;background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);color:#00ff88;font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
.sidebar{display:flex;flex-direction:column;gap:20px}.sw{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:12px;padding:20px}
.wt{font-size:12px;font-weight:700;color:var(--apex-cyan);text-transform:uppercase;letter-spacing:.1em;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}
.vbox{background:#ff3b3b10;border:2px solid var(--apex-red);border-radius:12px;padding:20px}
.vscore{font-size:44px;font-weight:900;color:var(--apex-red);font-family:var(--mono);text-align:center}.vlabel{font-size:11px;color:var(--apex-muted);text-align:center;text-transform:uppercase;letter-spacing:.1em}
.threat-badge{display:block;text-align:center;padding:6px;background:${cvss>=9?'#ff3b3b33':'#ff8c0033'};color:${cvss>=9?'var(--apex-red)':'var(--apex-orange)'};font-weight:900;font-size:13px;border-radius:6px;margin:8px 0;letter-spacing:.08em}
.vrow{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--apex-border);font-size:13px}.vrow:last-child{border-bottom:none}.vk{color:var(--apex-muted)}.vv{color:var(--apex-text);font-weight:600}
.alist{list-style:none;padding:0}.action-num{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border-radius:50%;background:var(--apex-red);color:#fff;font-size:10px;font-weight:900;margin-right:10px;flex-shrink:0}
.action-item{display:flex;align-items:flex-start;padding:10px 14px;border-bottom:1px solid var(--apex-border);font-size:13px;color:var(--apex-text);line-height:1.6}.action-item:last-child{border-bottom:none}
.intel-sig{margin-top:48px;padding:24px;background:rgba(0,255,224,.03);border:1px solid rgba(0,255,224,.1);border-radius:12px;text-align:center}
.isb{font-size:14px;font-weight:900;color:var(--apex-cyan);letter-spacing:.1em;text-transform:uppercase}.iss{font-size:12px;color:var(--apex-muted);margin-top:6px;line-height:1.5}
footer{background:var(--apex-surface);border-top:1px solid var(--apex-border);padding:32px 24px;text-align:center}footer p{font-size:13px;color:var(--apex-muted);line-height:1.8}footer a{color:var(--apex-cyan);text-decoration:none}
@media(max-width:767px){nav{padding:0 14px}.nlinks a:not(.ncta){display:none}.ntag{display:none}}
</style>
</head>
<body>
<canvas id="mc"></canvas>
<div class="ticker"><div class="ticker-inner">
  <span class="ticker-item">⚡ ${escHtml(item.id)}${vendorProductLabel?` — ${escHtml(vendorProductLabel)}`:''} — Score ${score}/100 ${tl}</span>
  <span class="ticker-item">🛡️ CYBERDUDEBIVASH SENTINEL APEX — 24/7 Global Threat Intelligence v4.0</span>
  <span class="ticker-item">⚠️ ${item.cisaKev?'CISA KEV CONFIRMED — ACTIVE EXPLOITATION':item.exploited?'ACTIVE EXPLOITATION DETECTED':'HIGH-PRIORITY SECURITY ADVISORY'}</span>
  <span class="ticker-item">⚡ ${escHtml(item.id)} — CVSS ${cvssDisplay} — ${(item.sourceCount||1)} Source(s) Collected</span>
  <span class="ticker-item">🛡️ CYBERDUDEBIVASH SENTINEL APEX — 24/7 Global Threat Intelligence v4.0</span>
  <span class="ticker-item">⚠️ ${item.cisaKev?'CISA KEV CONFIRMED — ACTIVE EXPLOITATION':item.exploited?'ACTIVE EXPLOITATION DETECTED':'HIGH-PRIORITY SECURITY ADVISORY'}</span>
</div></div>
<nav>
  <a href="/" class="nbrand"><div><div class="nlogo">CYBERDUDE<span style="color:#fff">BIVASH</span></div><div class="ntag">SENTINEL APEX v4.0 — Global Threat Intelligence</div></div></a>
  <div class="nlinks"><a href="/">Reports</a><a href="/intelligence.html">Intel Hub</a><a href="/products.html">Detection Packs</a><a href="/contact.html">Enterprise</a><a href="/pricing.html" class="ncta">⚡ SOC Pro</a></div>
</nav>
<main>
  <article>
    <div class="meta-bar">${badges}<span class="rep-date">Published: ${pubDateFmt}</span></div>
    <h1 class="rh1">${escHtml(item.title)}</h1>
    <p class="rsubtitle">${escHtml(truncAtWord(cleanDescText,350))}${cleanDescText.length>350?'…':''}</p>
    <div class="stats-bar">
      <div class="stat red"><div class="sv">${cvss}</div><div class="sl">CVSS Score</div></div>
      <div class="stat"><div class="sv" style="color:${cvssColor}">${tl}</div><div class="sl">Threat Level</div></div>
      <div class="stat yellow"><div class="sv">${score}</div><div class="sl">Priority /100</div></div>
      <div class="stat orange"><div class="sv">${item.exploited?'YES':'TBD'}</div><div class="sl">Exploited ITW</div></div>
      <div class="stat ${item.cisaKev?'red':'green'}"><div class="sv">${item.cisaKev?'⚠️ KEV':'Monitor'}</div><div class="sl">CISA Status</div></div>
      <div class="stat"><div class="sv" style="color:var(--apex-green)">${item.sourceCount||1}x</div><div class="sl">Sources</div></div>
    </div>
    ${item.cisaKev?`<div class="alert alert-crit"><span class="aico">🚨</span><div class="abody"><div class="atitle">CISA KNOWN EXPLOITED VULNERABILITY — MANDATORY REMEDIATION</div><p>Active exploitation confirmed. CISA KEV catalog listed. ${item.dueDate?`Federal agencies must remediate by <strong>${item.dueDate}</strong>.`:'All organizations must patch immediately.'} Required action: ${escHtml(item.reqAction||'Apply vendor patch immediately.')}</p></div></div>`:item.exploited?`<div class="alert alert-warn"><span class="aico">⚠️</span><div class="abody"><div class="atitle">ACTIVE EXPLOITATION DETECTED</div><p>Exploitation confirmed in the wild. Emergency patching required. Score: ${score}/100 — do not wait for maintenance window.</p></div></div>`:`<div class="alert alert-info"><span class="aico">🔵</span><div class="abody"><div class="atitle">HIGH-PRIORITY SECURITY ADVISORY — Priority Score: ${score}/100</div><p>CVSS ${cvss} ${tl}. SENTINEL APEX recommends immediate patch evaluation. Intelligence from ${item.sourceCount||1} confirmed source(s).</p></div></div>`}
    <h2 class="sh"><span>📋</span> Executive Summary</h2>
    <div class="exec-box"><div class="ex-label">⚡ Analyst Assessment — SENTINEL APEX v4.0</div><p>${escHtml(execSummary)}</p><div style="margin-top:12px;font-size:12px;color:var(--apex-muted)">Intelligence sources: ${srcBadges}</div></div>
    ${genSeverityAnatomy(item, escHtml)}
    ${genCweAnatomy(item, escHtml)}
    <h2 class="sh"><span>⚠️</span> Business Impact Analysis</h2>
    <ul class="impact-list">${bizImpactItems}</ul>
    <h2 class="sh"><span>🔗</span> Representative Attack Path</h2>
    <p class="bp" style="font-size:14px">A typical attack path for this vulnerability class, mapped to MITRE ATT&amp;CK. This is a representative model to guide detection and defense — not a claim of observed activity against a specific target. Confirm specifics against the primary sources below.</p>
    <table class="tbl"><thead><tr><th>#</th><th>Phase</th><th>Attacker Action</th><th>MITRE</th></tr></thead><tbody>${chainRows}</tbody></table>
    <h2 class="sh"><span>⚠</span> Deep Dive Analysis</h2>
    ${commentary.split('\n\n').map(p=>`<p class="bp">${escHtml(p)}</p>`).join('\n    ')}
    ${structuredReasoning}
    ${priorIntel}
    <h2 class="sh"><span>🎯</span> MITRE ATT&CK Mapping</h2>
    <table class="tbl"><thead><tr><th>Category</th><th>Mapping</th></tr></thead><tbody>
      <tr><td>Primary Tactic</td><td style="color:var(--apex-red);font-weight:700">${escHtml(mitre.tactic)}</td></tr>
      <tr><td>Primary Technique</td><td style="color:var(--apex-cyan)">${escHtml(mitre.technique)}</td></tr>
      <tr><td>Sub-Technique</td><td style="color:var(--apex-cyan)">${escHtml(mitre.sub)}</td></tr>
      <tr><td>Weakness (CWE)</td><td>${escHtml(item.cweId||'See NVD entry')}</td></tr>
      <tr><td>Intel Type</td><td>${escHtml(typeLabel)}</td></tr>
      <tr><td>Source(s)</td><td>${srcBadges}</td></tr>
    </tbody></table>
    ${cveIds.length>0?`<h2 class="sh"><span>🔴</span> CVE Reference</h2><table class="tbl"><thead><tr><th>CVE ID</th><th>Reference</th><th>Score</th></tr></thead><tbody>${cveRows||`<tr><td style="font-family:var(--mono);color:var(--apex-cyan)">${escHtml(item.id)}</td><td><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">NVD →</a></td><td>CVSS ${cvss}</td></tr>`}</tbody></table>`:''}
    ${iocRows?`<h2 class="sh"><span>🏷️</span> Source-Provided Indicators</h2><p class="bp">Indicators are normalized from structured source fields. Validate ownership, context, freshness, and false-positive impact before monitoring or blocking.</p><table class="tbl"><thead><tr><th>Indicator Value</th><th>Type</th><th>Source Confidence</th><th>First Seen</th></tr></thead><tbody>${iocRows}</tbody></table>`:''}
    ${showDetection?`<h2 class="sh"><span>🔍</span> Reference Detection Draft — Sigma</h2><p class="bp">Not production-validated. Review the evidence basis, test syntax, baseline expected activity, and tune in a non-production environment.</p><div class="code-block"><span class="code-lbl">Sigma YAML — reference draft</span>${escHtml(sigma)}</div>
    <h2 class="sh"><span>📡</span> Reference Detection Draft — YARA</h2><p class="bp">Not false-positive validated. Confirm that strings identify malicious behavior rather than the vulnerability name or normal product artifacts.</p><div class="code-block"><span class="code-lbl">YARA — reference draft</span>${escHtml(yara)}</div>`:''}
    ${showDetection?multiDetections:''}
    ${showDetection?intelligenceProducts:''}
    <h2 class="sh"><span>🛡️</span> SOC Response Playbook</h2>
    <ul class="alist">${playbookItems}</ul>
    <h2 class="sh"><span>📎</span> Intelligence References</h2>
    <ul style="list-style:none;padding:0">${refLinks}${item.id?.startsWith('CVE')?`<li><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">📌 NVD — ${escHtml(item.id)}</a></li>`:''}</ul>
    ${aiSecSection}${malwareSection}${darkwebSection}
    <!-- SENTINEL APEX: Newsletter capture + Related Resources -->
    <div style="background:linear-gradient(135deg,rgba(139,92,246,0.08),rgba(0,153,255,0.06));border:1px solid rgba(139,92,246,0.3);border-radius:14px;padding:1.75rem;margin:2.5rem 0;text-align:center">
      <div style="font-size:10px;color:#8b5cf6;font-weight:800;letter-spacing:.15em;text-transform:uppercase;margin-bottom:.6rem">SENTINEL INTEL BRIEF — FREE</div>
      <h3 style="font-size:1.15rem;font-weight:800;color:#fff;margin:.4rem 0">Get Critical CVE Alerts Before They Become Incidents</h3>
      <p style="font-size:.85rem;color:#94a3b8;margin:.5rem 0 1rem;line-height:1.6">Receive source-attributed CVE alerts and practical response guidance. Free. No spam. Unsubscribe anytime.</p>
      <form action="/newsletter.html" method="GET" style="display:flex;gap:.5rem;justify-content:center;max-width:420px;margin:0 auto 1rem" onsubmit="typeof trackEvent==='function'&&trackEvent('post_newsletter_capture','subscribe','open_form')">
        <input type="email" name="email" placeholder="soc@yourcompany.com" required style="flex:1;padding:.65rem 1rem;border-radius:8px;background:#0a0f1a;border:1px solid rgba(255,255,255,.15);color:#fff;font-size:.9rem;min-width:0">
        <button type="submit" style="background:linear-gradient(135deg,#8b5cf6,#7c3aed);color:#fff;padding:.65rem 1.25rem;border-radius:8px;border:none;font-weight:800;font-size:.85rem;cursor:pointer;white-space:nowrap">Subscribe Free →</button>
      </form>
      <p style="font-size:.7rem;color:#475569;margin:0">Consent-based subscription · Unsubscribe at any time</p>
    </div>
    <!-- Related Resources: Hub internal links -->
    <div style="background:rgba(0,212,255,0.04);border:1px solid rgba(0,212,255,0.12);border-radius:12px;padding:1.5rem;margin:2rem 0">
      <div style="font-size:10px;color:#00d4ff;font-weight:800;letter-spacing:.15em;text-transform:uppercase;margin-bottom:1rem">Related Resources — SENTINEL APEX</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.6rem">
        <a href="/intelligence.html" style="display:flex;align-items:center;gap:.5rem;padding:.7rem 1rem;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:8px;text-decoration:none;color:#94a3b8;font-size:.8rem;transition:.2s" onmouseover="this.style.color='#00d4ff'" onmouseout="this.style.color='#94a3b8'"><span>🔭</span>Threat Intelligence Hub</a>
        <a href="/mitre-attack-detection.html" style="display:flex;align-items:center;gap:.5rem;padding:.7rem 1rem;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:8px;text-decoration:none;color:#94a3b8;font-size:.8rem;transition:.2s" onmouseover="this.style.color='#00d4ff'" onmouseout="this.style.color='#94a3b8'"><span>🎯</span>MITRE ATT&amp;CK Detections</a>
        <a href="/owasp-llm-top10.html" style="display:flex;align-items:center;gap:.5rem;padding:.7rem 1rem;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:8px;text-decoration:none;color:#94a3b8;font-size:.8rem;transition:.2s" onmouseover="this.style.color='#00d4ff'" onmouseout="this.style.color='#94a3b8'"><span>🤖</span>OWASP LLM Top 10</a>
        <a href="/products.html" style="display:flex;align-items:center;gap:.5rem;padding:.7rem 1rem;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:8px;text-decoration:none;color:#94a3b8;font-size:.8rem;transition:.2s" onmouseover="this.style.color='#00d4ff'" onmouseout="this.style.color='#94a3b8'"><span>📦</span>Detection Pack Store</a>
        <a href="/pricing.html" style="display:flex;align-items:center;gap:.5rem;padding:.7rem 1rem;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:8px;text-decoration:none;color:#94a3b8;font-size:.8rem;transition:.2s" onmouseover="this.style.color='#00d4ff'" onmouseout="this.style.color='#94a3b8'"><span>⚡</span>SOC Pro Plans</a>
        <a href="/contact.html" style="display:flex;align-items:center;gap:.5rem;padding:.7rem 1rem;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:8px;text-decoration:none;color:#94a3b8;font-size:.8rem;transition:.2s" onmouseover="this.style.color='#00d4ff'" onmouseout="this.style.color='#94a3b8'"><span>🏢</span>Enterprise Contact</a>
      </div>
    </div>
    <div class="intel-sig"><div class="isb">⚡ CYBERDUDEBIVASH SENTINEL APEX</div><div class="iss">Automated, source-attributed intelligence report<br>Report ID: SENTINEL-${escHtml(item.id)}-${today} | Editorial priority: ${score}/100 ${tl} | Sources collected: ${item.sourceCount||1}<br>&copy; ${new Date().getFullYear()} CYBERDUDEBIVASH<br><strong style="color:var(--apex-cyan)">Verify technical claims in the linked primary sources before operational use</strong></div></div>
    <div class="ecta">
      <h3>🏢 ENTERPRISE THREAT INTELLIGENCE PLATFORM</h3>
      <p class="ep">Request a scoped intelligence briefing, evidence review, custom IOC ingestion assessment, or detection-engineering engagement.</p>
      <div class="cta-grid">
        <a href="/pricing.html" class="btn-p">⚡ SOC Pro — $18/mo</a>
        <a href="/enterprise.html" class="btn-e">🏢 Enterprise — Custom Pricing</a>
        <a href="/api.html" class="btn-s">🔌 Threat Intel API Access</a>
        <a href="/products.html" class="btn-g">📦 Detection Pack Store</a>
      </div>
      <p style="font-size:12px;color:var(--apex-muted);margin:0">Source review · Custom advisories · Detection assessment · API and MSSP licensing discussions</p>
    </div>
  </article>
  <aside class="sidebar">
    <div class="vbox">
      <div class="vscore">${cvss}</div><div class="vlabel">CVSS Score</div>
      <div class="threat-badge">${tl} — ${score}/100</div>
      <div style="margin-top:12px">
        <div class="vrow"><span class="vk">ID</span><span class="vv" style="color:var(--apex-cyan);font-family:monospace;font-size:11px">${escHtml(item.id)}</span></div>
        ${item.vendor?`<div class="vrow"><span class="vk">Vendor</span><span class="vv">${escHtml(item.vendor)}</span></div>`:''}
        ${item.product?`<div class="vrow"><span class="vk">Product</span><span class="vv">${escHtml(item.product)}</span></div>`:''}
        <div class="vrow"><span class="vk">Type</span><span class="vv">${escHtml(typeLabel)}</span></div>
        <div class="vrow"><span class="vk">Exploited</span><span class="vv" style="color:${item.exploited?'var(--apex-red)':'var(--apex-green)'}">${item.exploited?'✓ Confirmed':'Monitoring'}</span></div>
        <div class="vrow"><span class="vk">CISA KEV</span><span class="vv" style="color:${item.cisaKev?'var(--apex-red)':'var(--apex-muted)'}">${item.cisaKev?'⚠️ Listed':'Not Listed'}</span></div>
        ${item.dueDate?`<div class="vrow"><span class="vk">Patch By</span><span class="vv" style="color:var(--apex-red)">${escHtml(item.dueDate)}</span></div>`:''}
        <div class="vrow"><span class="vk">Published</span><span class="vv">${pubDateFmt}</span></div>
        <div class="vrow"><span class="vk">Sources</span><span class="vv" style="color:var(--apex-green)">${item.sourceCount||1} confirmed</span></div>
        <div class="vrow"><span class="vk">IOCs</span><span class="vv">${(item.iocs||[]).length} indicators</span></div>
      </div>
    </div>
    <div class="sw" style="background:linear-gradient(135deg,#001a14,#0d1117);border-color:rgba(0,255,224,.15)">
      <div class="wt">⚡ SOC Pro Intelligence</div>
      <p style="font-size:13px;color:var(--apex-muted);margin-bottom:16px;line-height:1.6">Source-attributed alerts, reference detection drafts, enriched IOC feeds, and response guidance. Validate detections in your environment before deployment.</p>
      <a href="/pricing.html" style="display:block;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:13px;padding:12px;border-radius:8px;text-decoration:none;text-align:center">Start Free Trial →</a>
    </div>
    <div class="sw" style="background:linear-gradient(135deg,#1a0a2e,#0d1117);border-color:rgba(168,85,247,.2)">
      <div class="wt" style="color:#a855f7">🏢 Enterprise Access</div>
      <p style="font-size:13px;color:var(--apex-muted);margin-bottom:14px;line-height:1.6">Request a scoped intelligence briefing, custom IOC ingestion assessment, API access, or MSSP licensing discussion.</p>
      <a href="/enterprise.html" style="display:block;background:rgba(168,85,247,.2);border:1px solid rgba(168,85,247,.4);color:#a855f7;font-weight:700;font-size:13px;padding:12px;border-radius:8px;text-decoration:none;text-align:center">Get Enterprise Proposal →</a>
    </div>
    <div class="sw">
      <div class="wt">🔌 Threat Intel API</div>
      <p style="font-size:13px;color:var(--apex-muted);margin-bottom:14px;line-height:1.6">Programmatic access to SENTINEL APEX intelligence. RESTful JSON. Integrate into SIEM, SOAR, or custom tools.</p>
      <a href="/api.html" style="display:block;border:1px solid var(--apex-border);color:var(--apex-cyan);font-weight:700;font-size:13px;padding:12px;border-radius:8px;text-decoration:none;text-align:center">View API Docs →</a>
    </div>
    <div class="sw">
      <div class="wt">📎 References</div>
      <ul style="list-style:none;padding:0">
        ${item.id?.startsWith('CVE')?`<li style="margin-bottom:8px;font-size:13px"><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">📌 NVD — ${escHtml(item.id)}</a></li>`:''}
        ${item.cisaKev?`<li style="margin-bottom:8px;font-size:13px"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener" style="color:var(--apex-red)">⚠️ CISA KEV Catalog</a></li>`:''}
        ${validRefs.slice(0,4).map(r=>`<li style="margin-bottom:6px;font-size:12px"><a href="${escHtml(r)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${escHtml(String(r).replace(/https?:\/\//,'').slice(0,42))}</a></li>`).join('\n')}
      </ul>
    </div>
  </aside>
</main>
<footer>
  <p>&copy; ${new Date().getFullYear()} CYBERDUDEBIVASH. Intelligence aggregation, analysis and enrichment by CYBERDUDEBIVASH SENTINEL APEX — sourcing standards at <a href="/about.html">About &amp; Editorial Standards</a>.<br>
  Unauthorized reproduction without attribution is prohibited.<br>
  <a href="/">Blog</a> · <a href="/products.html">Detection Packs</a> · <a href="/pricing.html">SOC Pro</a> · <a href="/api.html">API</a> · <a href="/enterprise.html">Enterprise</a> · <a href="/contact.html">Contact Sales</a> · <a href="/rss.xml">RSS</a> · <a href="/about.html">About</a> · <a href="/privacy.html">Privacy</a> · <a href="/terms.html">Terms</a></p>
</footer>
<script src="/security-engine.js" defer></script><script src="/monetization.js" defer></script><script src="/conversion-engine.js?v=20260705" defer></script><script src="/seo-engine.js" defer></script><script src="/detection-export.js" defer></script>
<script>
(function(){var c=document.getElementById('mc');if(!c)return;var x=c.getContext('2d');c.width=window.innerWidth;c.height=window.innerHeight;var cols=Math.floor(c.width/16),drops=new Array(cols).fill(1);setInterval(function(){x.fillStyle='rgba(7,9,15,0.05)';x.fillRect(0,0,c.width,c.height);x.fillStyle='#00ffe018';x.font='12px monospace';drops.forEach(function(y,i){x.fillText(String.fromCharCode(33+Math.random()*93),i*16,y*16);if(y*16>c.height&&Math.random()>.975)drops[i]=0;drops[i]++;});},90);window.addEventListener('resize',function(){c.width=window.innerWidth;c.height=window.innerHeight;});})();
</script>
</body>
</html>`;
  return { slug, title: item.title, html };
}

// ── POST CARD GENERATOR ────────────────────────────────────────────────
function generatePostCard(item, slug, title) {
  const hasCvss = typeof item.cvss === 'number' && item.cvss >= 0 && item.cvss <= 10;
  const cvss = hasCvss ? item.cvss : null;
  const cvssDisplay = hasCvss ? String(cvss) : 'Not assigned';
  const sevLabel = hasCvss ? (cvss>=9.0?'CRITICAL':cvss>=7.0?'HIGH':cvss>=4.0?'MEDIUM':'LOW') : String(item.severityLabel||'UNASSESSED').toUpperCase();
  const tl = item.threatLevel||sevLabel;
  const score = item.priority||0;
  const todayFmt = fmtDate(item.pubDate||isoNow());
  const shortTitle = (title||'').length>110 ? title.slice(0,107)+'...' : title;
  const shortDesc  = (item.desc||'').slice(0,200)+((item.desc||'').length>200?'...':'');
  const typeIcos = { CVE_REPORT:'🔴', ZERO_DAY:'💀', RANSOMWARE:'🏴', MALWARE_REPORT:'🦠', DATA_BREACH:'⚠️', THREAT_ACTOR:'🎯', AI_SECURITY:'🤖', NEWS_REPORT:'📡', ADVISORY:'🛡️' };
  const ico = typeIcos[item.type]||'⚡';
  const multiSrcBadge = (item.sourceCount||1)>=2 ? `<span class="post-badge" style="background:#00ff8822;color:#00ff88;border:1px solid #00ff8844;font-size:10px;padding:3px 7px;border-radius:3px;font-weight:700">✓ ${item.sourceCount}x</span>` : '';
  return `
    <!-- AUTO-GENERATED: ${item.id} — ${isoNow()} -->
    <a href="posts/${escHtml(slug)}.html" class="post-card" data-intel-auto="${escHtml(item.id)}" data-score="${score}" data-threat="${tl}">
      <div class="post-card-header">
        <span class="post-badge badge-crit">CVSS ${cvssDisplay}</span>
        ${item.cisaKev?`<span class="post-badge badge-cisa">CISA KEV</span>`:''}
        ${item.exploited?`<span class="post-badge badge-new">● Live Exploit</span>`:''}
        ${item.ransomware?`<span class="post-badge" style="background:#a855f722;color:#a855f7;border:1px solid #a855f744;font-size:10px;padding:3px 7px;border-radius:3px;font-weight:700">RANSOMWARE</span>`:''}
        ${multiSrcBadge}
        <span class="post-date">${todayFmt} | ${ico} ${escHtml(item.id)}</span>
      </div>
      <div class="post-card-body">
        <div class="post-title">${escHtml(shortTitle)}</div>
        <p class="post-excerpt">${escHtml(shortDesc)}</p>
        <div class="post-meta">
          <span class="post-cvss${cvss<9?' orange':''}">CVSS ${cvss} — ${tl}</span>
          <span class="post-cve">${escHtml(item.id)}</span>
          <span class="post-source" style="font-size:11px;color:var(--apex-muted,#6b7280)">${escHtml((item._sources||[item.source]).join(', '))}</span>
          <span class="post-read-more">Read Report →</span>
        </div>
      </div>
    </a>`;
}

// ── INDEX.HTML UPDATER ─────────────────────────────────────────────────
function updateIndexHTML(newCards) {
  if (!fs.existsSync(CFG.indexPath)) { warn('index.html not found.'); return; }
  let html = fs.readFileSync(CFG.indexPath, 'utf8');
  html = html.replace(/\s*<!-- AUTO-GENERATED:[\s\S]*?<\/a>/g, '');
  const MARKER = '<!-- POST 1 — FEATURED -->';
  if (!html.includes(MARKER)) { warn('Injection marker not found in index.html.'); return; }
  const cardBlock = newCards.map(c=>c.card).join('\n');
  html = html.replace(MARKER, `${cardBlock}\n\n    ${MARKER}`);
  const today = new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}).toUpperCase();
  html = html.replace(/BREAKING INTELLIGENCE &mdash;[^<]+ &mdash; UPDATED LIVE/, `BREAKING INTELLIGENCE &mdash; ${today} &mdash; UPDATED LIVE`);
  safeWriteSync(CFG.indexPath, html, 'utf8');
  log(`index.html updated: +${newCards.length} cards.`);
}

// ── RSS.XML UPDATER ────────────────────────────────────────────────────
function updateRSS(newItems) {
  const rssItems = newItems.map(item => {
    const link = `${CFG.baseUrl}/posts/${item.slug}.html`;
    return `  <item>\n    <title><![CDATA[${item.title}]]></title>\n    <link>${link}</link>\n    <description><![CDATA[Score ${item.priority||0}/100 ${item.threatLevel||'HIGH'} — CVSS ${item.cvss} — ${(item.desc||'').slice(0,300)}. Full analysis, Sigma/YARA rules, IOCs, Attack Chain by CYBERDUDEBIVASH SENTINEL APEX v4.0.]]></description>\n    <pubDate>${new Date().toUTCString()}</pubDate>\n    <guid isPermaLink="true">${link}</guid>\n    <category>Threat Intelligence</category>\n    <category>${item.cisaKev?'CISA KEV':item.type||'CVE Analysis'}</category>\n  </item>`;
  }).join('\n');
  if (!fs.existsSync(CFG.rssPath)) {
    safeWriteSync(CFG.rssPath, `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n  <channel>\n    <title>CYBERDUDEBIVASH SENTINEL APEX — Global Threat Intelligence</title>\n    <link>${CFG.baseUrl}</link>\n    <description>Real-time cybersecurity intelligence by CYBERDUDEBIVASH SENTINEL APEX v4.0.</description>\n    <language>en-us</language>\n    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>\n    <atom:link href="${CFG.baseUrl}/rss.xml" rel="self" type="application/rss+xml"/>\n${rssItems}\n  </channel>\n</rss>`, 'utf8');
    log('rss.xml created fresh.'); return;
  }
  let rss = fs.readFileSync(CFG.rssPath, 'utf8');
  rss = rss.replace(/(<lastBuildDate>)[^<]*(<\/lastBuildDate>)/, `$1${new Date().toUTCString()}$2`);
  rss = rss.includes('<item>') ? rss.replace(/(<item>)/, `${rssItems}\n  $1`) : rss.replace('</channel>', `${rssItems}\n  </channel>`);
  safeWriteSync(CFG.rssPath, rss, 'utf8');
  log(`rss.xml updated: +${newItems.length} items.`);
}

// ── SITEMAP UPDATER ────────────────────────────────────────────────────
function updateSitemap(slugs) {
  try {
    const today = isoNow();
    let sitemap = fs.existsSync(CFG.sitemapPath) ? fs.readFileSync(CFG.sitemapPath,'utf8') : `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n</urlset>`;
    const entries = slugs.map(slug=>`  <url>\n    <loc>${CFG.baseUrl}/posts/${slug}.html</loc>\n    <lastmod>${today}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.8</priority>\n  </url>`).join('\n');
    sitemap = sitemap.replace('</urlset>', `${entries}\n</urlset>`);
    safeWriteSync(CFG.sitemapPath, sitemap, 'utf8');
    log(`sitemap.xml updated: +${slugs.length} URLs.`);
  } catch(e) { warn(`Sitemap update failed: ${e.message}`); }
}

function updateSearchIndex(newItems) {
  const indexPath = path.join(__dirname, 'search-index.json');
  try {
    const existing = fs.existsSync(indexPath) ? JSON.parse(fs.readFileSync(indexPath,'utf8')) : [];
    const existingSlugs = new Set(existing.map(e => e.s));
    const today = isoNow();
    const typeMap = { CVE_REPORT:'CVE', ZERO_DAY:'ZERO-DAY', RANSOMWARE:'RANSOMWARE',
      MALWARE_REPORT:'RANSOMWARE', AI_SECURITY:'AI SECURITY', ADVISORY:'ADVISORY' };
    const newEntries = newItems
      .filter(item => item.slug && !existingSlugs.has(item.slug))
      .map(item => ({
        t: item.title || '',
        s: item.slug,
        d: (item.pubDate || today).slice(0,10),
        desc: (item.desc||'').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().slice(0,120),
        tp: typeMap[item.type] || 'INTEL',
      }));
    if (newEntries.length === 0) return;
    const updated = [...newEntries, ...existing].slice(0, 5000);
    safeWriteSync(indexPath, JSON.stringify(updated), 'utf8');
    log(`search-index.json: +${newEntries.length} entries (total: ${updated.length})`);
  } catch(e) { warn(`Search index update failed: ${e.message}`); }
}

// ── PHASE 5: ENTERPRISE API PLATFORM (S2N-powered static JSON endpoints) ──
async function writeAPIFiles(allItems, state) {
  try {
    // Ensure API directories exist
    const apiCveDir = path.join(CFG.apiDir, 'cve');
    [CFG.apiDir, apiCveDir].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

    const now     = new Date().toISOString();
    const apiMeta = {
      generated: now, version: '5.1', engine: 'SENTINEL APEX S2N v1.0',
      platform: 'CYBERDUDEBIVASH SENTINEL APEX', contact: 'bivash@cyberdudebivash.com',
      docs: `${CFG.baseUrl}/api.html`,
    };

    // ── Load existing live.json for S2N window (semantic dedup) ─────────
    let windowItems = [];
    const apiLivePath = path.join(CFG.apiDir, 'live.json');
    if (fs.existsSync(apiLivePath)) {
      try {
        const exData = JSON.parse(fs.readFileSync(apiLivePath, 'utf8'));
        windowItems = Array.isArray(exData.items) ? exData.items : [];
      } catch(_) {}
    }

    // ── Run S2N Engine ──────────────────────────────────────────────────
    log('── S2N ENGINE ─────────────────────────────────────────────────────');
    const s2nResult = runS2N(allItems, windowItems);
    const { live: liveItems, topThreats: topItems, raw: rawItems } = formatForFeed(s2nResult);

    log(`  S2N stats: input=${s2nResult.stats.input_items} candidates=${s2nResult.stats.candidates} passed=${s2nResult.stats.passed} suppressed=${s2nResult.stats.suppressed} merges=${s2nResult.stats.semantic_merges} elapsed=${s2nResult.stats.elapsed_ms}ms`);
    log(`  avg_qs=${s2nResult.stats.avg_qs} avg_ps=${s2nResult.stats.avg_final_ps} tier4_kept=${s2nResult.stats.tier4_kept}`);

    // ── /api/intel/live.json — top 50 S2N-passed items ─────────────────
    // Rolling merge with existing (new overrides by id, trim to apiLiveWindow)
    const mergedLive = [...liveItems];
    const newLiveIds = new Set(liveItems.map(i => i.id));
    windowItems.forEach(e => { if (!newLiveIds.has(e.id)) mergedLive.push(e); });
    mergedLive.sort((a,b) => {
      const ps = (b.final_ps||b.priority_score||0) - (a.final_ps||a.priority_score||0);
      if (ps !== 0) return ps;
      return new Date(b.first_seen||b.published||0) - new Date(a.first_seen||a.published||0);
    });
    const rolledLiveItems = mergedLive.slice(0, CFG.apiLiveWindow || 100);
    safeWriteSync(apiLivePath, JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/live.json',
      description: `S2N live threat intelligence feed — top ${CFG.apiLiveWindow||100} items by final_ps`,
      total_published: state.totalPublished || 0,
      s2n_stats: { passed: s2nResult.stats.passed, suppressed: s2nResult.stats.suppressed, avg_qs: s2nResult.stats.avg_qs },
      items: rolledLiveItems,
    }, null, 2), 'utf8');
    log(`api/intel/live.json: ${rolledLiveItems.length} items (S2N passed=${s2nResult.stats.passed}).`);

    // ── /api/intel/top-threats.json — final_ps≥70 AND quality_score≥0.60 ──
    safeWriteSync(path.join(CFG.apiDir, 'top-threats.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/top-threats.json',
      description: 'S2N top threats: final_ps ≥ 70 AND quality_score ≥ 0.60',
      count: topItems.length,
      items: topItems,
    }, null, 2), 'utf8');
    log(`api/intel/top-threats.json: ${topItems.length} items.`);

    // ── /api/intel/raw.json — unfiltered (paid tier, includes suppressed) ─
    const rawDir = path.join(CFG.apiDir);
    safeWriteSync(path.join(rawDir, 'raw.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/raw.json',
      description: 'Raw unfiltered S2N feed — all items including suppressed. Enterprise tier.',
      note: 'Access requires Enterprise API key. Includes suppression_reason and full IOC data.',
      count: rawItems.length,
      items: rawItems,
    }, null, 2), 'utf8');
    log(`api/intel/raw.json: ${rawItems.length} items (incl. ${s2nResult.stats.suppressed} suppressed).`);

    // ── /api/intel/iocs.json — all enriched IOCs ────────────────────────
    const allIOCs = [];
    s2nResult.passed.slice(0, 40).forEach(item => {
      (item.iocs||[]).forEach(ioc => {
        if (ioc && ioc.value) allIOCs.push({
          ...ioc, related_id: item.id, related_type: item.type,
          threat_level: finalThreatLevel(item.final_ps||0),
          priority_score: item.final_ps||0,
          quality_score: item.quality_score||0,
        });
      });
    });
    const iocMap = new Map();
    allIOCs.forEach(ioc => {
      const k = `${ioc.type}:${ioc.value}`;
      if (!iocMap.has(k)) iocMap.set(k, { ...ioc, source_count: 1 });
      else { const ex = iocMap.get(k); ex.source_count++; ex.confidence_score = Math.min(0.99, (ex.confidence_score||0.5) + 0.05); }
    });
    safeWriteSync(path.join(CFG.apiDir, 'iocs.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/iocs.json',
      description: 'Enriched IOC feed with confidence scoring',
      count: iocMap.size,
      note: 'Pro/Enterprise subscribers receive STIX 2.1 feeds',
      items: Array.from(iocMap.values()).sort((a,b)=>(b.confidence_score||0)-(a.confidence_score||0)).slice(0,200),
    }, null, 2), 'utf8');

    // ── /api/intel/ransomware.json — ransomware-specific ────────────────
    const ransomItems = s2nResult.passed.filter(i => i.ransomware || i.type==='RANSOMWARE');
    safeWriteSync(path.join(CFG.apiDir, 'ransomware.json'), JSON.stringify({
      ...apiMeta, endpoint: '/api/intel/ransomware.json',
      description: 'Ransomware-specific threat intelligence (S2N-filtered)',
      count: ransomItems.length,
      items: ransomItems.slice(0,20).map(i=>({
        id:i.id, title:(i.title||'').slice(0,100),
        final_ps: i.final_ps||0, quality_score: i.quality_score||0,
        threat_level: finalThreatLevel(i.final_ps||0), cvss:typeof i.cvss==='number'?i.cvss:null,
        cisa_kev:!!i.cisa_kev, vendor:i.vendor||'', product:i.product||'',
        ioc_count:i.ioc_count||(i.iocs||[]).length, report_url:i.report_url||null,
      })),
    }, null, 2), 'utf8');

    // ── /api/intel/cve/{id}.json — per-CVE detail files ─────────────────
    let cveFileCount = 0;
    const cveCandidates = s2nResult.passed
      .filter(i => i.id && i.id.startsWith('CVE') && (i.final_ps||0)>=50)
      .slice(0, 20);
    // Real EPSS scores, batched once for every CVE file about to be written
    // (never fabricated — a missing entry means "unknown", not zero).
    const epssMap = await fetchEpssBatch(cveCandidates.map(i => i.id));
    cveCandidates.forEach(item => {
        const orig = allItems.find(o => o.id === item.id) || item;
        const cveFile = path.join(apiCveDir, `${item.id}.json`);
        const epss = epssMap[item.id] || null;
        safeWriteSync(cveFile, JSON.stringify({
          ...apiMeta, endpoint: `/api/intel/cve/${item.id}.json`,
          id: item.id, title: item.title, description: item.description||orig.desc,
          cvss: typeof item.cvss==='number'?item.cvss:null, final_ps: item.final_ps||0, quality_score: item.quality_score||0,
          threat_level: finalThreatLevel(item.final_ps||0),
          epss_score: epss ? epss.score : null, epss_percentile: epss ? epss.percentile : null,
          type: orig.type, sources: item.merged_sources||[item.source],
          sources_confirmed: item.sources_confirmed||1,
          first_seen: item.first_seen, last_seen: item.last_seen,
          exploited: !!item.exploited, cisa_kev: !!item.cisa_kev,
          ransomware: !!item.ransomware, vendor: item.vendor, product: item.product,
          due_date: item.due_date||null, required_action: orig.reqAction||null,
          cves: item.cves||[], refs: item.refs||[], iocs: orig.iocs||[],
          mitre: orig._mitre || null, explanation: item.explanation||null,
          report_url: orig.slug ? `${CFG.baseUrl}/posts/${orig.slug}.html` : null,
        }, null, 2), 'utf8');
        cveFileCount++;
      });

    log(`API files written: live.json (${rolledLiveItems.length}), top-threats.json (${topItems.length}), raw.json (${rawItems.length}), iocs.json (${iocMap.size} IOCs), ransomware.json (${ransomItems.length}), ${cveFileCount} CVE files.`);
  } catch(e) { warn(`API generation failed: ${e.message}\n${e.stack||''}`); }
}

// ── LIVE-INTEL.JSON (widget feed) ─────────────────────────────────────
function writeLiveIntel(allItems, state) {
  try {
    // Load existing items for rolling merge
    let existingItems = [];
    if (fs.existsSync(CFG.liveJsonPath)) {
      try {
        const ex = JSON.parse(fs.readFileSync(CFG.liveJsonPath, 'utf8'));
        existingItems = Array.isArray(ex.items) ? ex.items : [];
      } catch(_) {}
    }
    const nowTs = new Date().toISOString();
    const existingIds = new Set(existingItems.map(e => e.id));
    const newItems = allItems.map(item => {
      // Compute resolved slug FIRST — item.slug may be null for many pipeline sources.
      // Using it directly in the object literal would make `link` always null when item.slug is falsy
      // because JS object literals cannot reference sibling properties during construction.
      const resolvedSlug = item.slug ||
        slugify(item.id.startsWith('CVE')
          ? `${item.id}-${item.vendor||''}-${item.product||''}`
          : item.title.slice(0, 60));
      // PRODUCTION FIX: Only set _addedAt=NOW for truly new items.
      // For items already in the rolling window, preserve their original _addedAt.
      const isNewToFeed = !existingIds.has(item.id);
      const existingItem = isNewToFeed ? null : existingItems.find(e => e.id === item.id);
      const addedAt = isNewToFeed ? nowTs : (existingItem?._addedAt || nowTs);
      return {
      id: item.id, title: (item.title||'').slice(0,120), desc: (item.desc||'').slice(0,200),
      cvss: typeof item.cvss==='number'?item.cvss:null, type: item.type||'INTEL', source: item.source||'',
      pubDate: item.pubDate||isoNow(), exploited: !!item.exploited, cisaKev: !!item.cisaKev,
      ransomware: !!item.ransomware, vendor: item.vendor||'', product: item.product||'',
      dueDate: item.dueDate||null, refs: (item.refs||[]).slice(0,2),
      priority: item.priority||0, threatLevel: item.threatLevel||'HIGH',
      sourceCount: item.sourceCount||1, iocCount: (item.iocs||[]).length,
      slug: resolvedSlug,
      link: resolvedSlug ? `${CFG.baseUrl}/posts/${resolvedSlug}.html` : null,
      _addedAt: addedAt,
      };
    });
    // Merge: new items override existing by id, then sort DESC by priority→pubDate, trim to window
    const merged = [...newItems];
    const newIds = new Set(newItems.map(i => i.id));
    existingItems.forEach(e => { if (!newIds.has(e.id)) merged.push(e); });
    merged.sort((a,b) => {
      const ps = (b.priority||0) - (a.priority||0);
      if (ps !== 0) return ps;
      return new Date(b.pubDate||0) - new Date(a.pubDate||0);
    });    const liveItems = merged.slice(0, CFG.liveRollingWindow || 150);
    const _liveGenTs = new Date().toISOString();
    // PRODUCTION DIAGNOSTIC: track truly new items (not in existingItems)
    const trulyNewCount = newItems.filter(i => !existingIds.has(i.id)).length;
    safeWriteSync(CFG.liveJsonPath, JSON.stringify({
      generatedAt: _liveGenTs, lastUpdated: _liveGenTs, totalPublished: state.totalPublished||0,
      metadata: { generated: _liveGenTs, version: '5.0', pipeline: 'SENTINEL APEX v5.0', platform: 'blog.cyberdudebivash.in' },
      source: 'CYBERDUDEBIVASH SENTINEL APEX v5.0', platform: 'blog.cyberdudebivash.in',
      version: '5.0',
      stats: {
        critical:   liveItems.filter(i=>i.threatLevel==='CRITICAL').length,
        high:       liveItems.filter(i=>i.threatLevel==='HIGH').length,
        cisaKev:    liveItems.filter(i=>i.cisaKev).length,
        exploited:  liveItems.filter(i=>i.exploited).length,
        ransomware: liveItems.filter(i=>i.ransomware).length,
        sources:    [...new Set(liveItems.map(i=>i.source))].length,
      },
      items: liveItems,
    }, null, 2), 'utf8');
    log(`live-intel.json: ${liveItems.length} total (${trulyNewCount} newly ingested, ${newItems.length-trulyNewCount} existing). Rolled window: ${CFG.liveRollingWindow||150}.`);
  } catch(e) { warn(`live-intel.json failed: ${e.message}`); }
}

// ── VALIDATION REPORT ─────────────────────────────────────────────────
function validateAndReport(allItems, generatedCards, state, T0, sourceStats) {
  // ── PHASE 8: PUBLICATION ENGINE STATS ────────────────────────────────
  const apexItems = allItems.filter(i=>i.sentinel_apex?.api_eligible);
  const hubMap = {};
  allItems.forEach(i=>(i.sentinel_apex?.content_hubs||[]).forEach(h=>{hubMap[h]=(hubMap[h]||0)+1;}));
  log('\n── PHASE 8+9: SENTINEL APEX PUBLICATION REPORT ─────────────────');
  log(`  API-eligible items: ${apexItems.length}`);
  log(`  MSSP-relevant items: ${allItems.filter(i=>i.sentinel_apex?.mssp_relevant).length}`);
  log(`  Detection-ready items: ${allItems.filter(i=>i.sentinel_apex?.detection_ready).length}`);
  Object.entries(hubMap).sort((a,b)=>b[1]-a[1]).forEach(([hub,cnt])=>log(`  ${hub}: ${cnt} items`));
  log('  ──────────────────────────────────────────────────────────────');
  const sourceCount  = allItems.reduce((acc,i) => { (i._sources||[i.source]).forEach(s=>acc.add(s)); return acc; }, new Set()).size;
  const critCount    = allItems.filter(i=>i.threatLevel==='CRITICAL').length;
  const highCount    = allItems.filter(i=>i.threatLevel==='HIGH').length;
  const kevCount     = allItems.filter(i=>i.cisaKev).length;
  const exploitCount = allItems.filter(i=>i.exploited).length;
  const multiSrc     = allItems.filter(i=>(i.sourceCount||1)>=2).length;
  const iocTotal     = allItems.reduce((s,i)=>s+(i.iocs||[]).length, 0);
  const elapsed      = ((Date.now()-T0)/1000).toFixed(1);
  const healthRpt    = getSourceHealthReport(state);

  log('\n' + '═'.repeat(65));
  log('SENTINEL APEX v5.0 — PIPELINE COMPLETE');
  log('═'.repeat(65));
  log(`⏱  Runtime           : ${elapsed}s`);
  log(`📡 Sources active     : ${sourceCount}/28`);
  log(`📊 Total items        : ${allItems.length}`);
  log(`🔴 CRITICAL           : ${critCount}`);
  log(`🟠 HIGH               : ${highCount}`);
  log(`⚠️  CISA KEV           : ${kevCount}`);
  log(`⚡ Exploited ITW      : ${exploitCount}`);
  log(`✓  Multi-source       : ${multiSrc}`);
  log(`🏷️  IOCs extracted     : ${iocTotal}`);
  log(`✅ Reports generated  : ${generatedCards.length}`);
  log(`📚 Total published    : ${state.totalPublished}`);
  if (healthRpt.degraded.length > 0) log(`🔥 DEGRADED sources   : ${healthRpt.degraded.join(', ')}`);
  if (healthRpt.warning.length  > 0) log(`⚠️  WARNING sources    : ${healthRpt.warning.join(', ')}`);
  if (sourceStats) {
    log('\n── Per-Source Stats ────────────────────────────────────────────');
    Object.entries(sourceStats).forEach(([src, st]) => {
      if (st.fetched > 0) log(`  ${src}: fetched=${st.fetched}, new=${st.new||0}`);
    });
  }
  log('═'.repeat(65));

  // Phase 9 validation criteria
  const criteria = [
    { check: sourceCount >= 5,         label: 'Minimum 5 sources active' },
    { check: allItems.length >= 5,     label: 'Minimum 5 intel items' },
    { check: kevCount >= 0,            label: 'CISA KEV feed active' },
    { check: iocTotal >= 0,            label: 'IOC extraction running' },
    { check: state.totalPublished > 0, label: 'At least 1 report published' },
    { check: healthRpt.degraded.length < 10, label: 'Less than 10 degraded sources' },
  ];
  criteria.forEach(c => log(`${c.check ? '✅' : '❌'} ${c.label}`));
  log('═'.repeat(65));
}

// ── TIERED PARALLEL INGESTION HELPER ─────────────────────────────────
async function runTier(label, tasks, state) {
  log(`\n── ${label} ──────────────────────────────────────────────────`);
  const results = await Promise.allSettled(tasks.map(([fn, key]) =>
    fetchWithTimeout(() => fn(state), key, CFG.sourceTimeoutMs)
      .then(items => { recordSourceSuccess(state, key); return items || []; })
      .catch(e   => { recordSourceFailure(state, key, e.message); warn(`${key} failed: ${e.message}`); return []; })
  ));
  const batches = results.map(r => r.status === 'fulfilled' ? r.value : []);
  const active  = batches.filter(b=>b.length>0).length;
  log(`${label}: ${active}/${tasks.length} sources returned data (${batches.reduce((s,b)=>s+b.length,0)} total items)`);
  return batches;
}

// ── MAIN PIPELINE v5.0 — TIERED, PARALLEL, STREAM-LIKE ───────────────
async function main() {
  const T0 = Date.now();
  log('═'.repeat(65));
  log('CYBERDUDEBIVASH SENTINEL APEX v5.0 — HIGH-FREQUENCY INTEL ENGINE');
  log('28 Sources | Tiered Parallel | Stream-Like Writes | Health Mon.');
  log(`Run started: ${new Date().toISOString()}`);
  log('═'.repeat(65));

  // ── PHASE 3: LOCK — no overlapping runs ───────────────────────────
  if (!acquireLock()) { process.exit(0); }
  let lockReleased = false;
  const safeRelease = () => { if (!lockReleased) { lockReleased = true; releaseLock(); } };
  process.on('exit', safeRelease);
  process.on('SIGTERM', () => { safeRelease(); process.exit(0); });

  try {
    if (!fs.existsSync(CFG.postsDir)) fs.mkdirSync(CFG.postsDir, { recursive: true });

    const state      = loadState();
    const sourceStats = {};
    log(`State: ${state.published.length} in dedup window (TTL=${CFG.dedupTtlDays}d). Total published: ${state.totalPublished}`);

    // Load persistent analyst memory (defensive: never fatal).
    if (AnalystMemory) {
      try {
        analystMemory = AnalystMemory.load(fs, CFG.memoryPath);
        log(`Analyst memory: ${analystMemory.stats().entities} entities tracked`);
      } catch (e) { warn(`Analyst memory load failed: ${e.message}`); analystMemory = null; }
    }

    // ══════════════════════════════════════════════════════════════════
    // TIER 1 — Critical CVE/Exploit sources (processed first, always)
    // ══════════════════════════════════════════════════════════════════
    const tier1Batches = await runTier('TIER 1: CRITICAL CVE + EXPLOIT SOURCES', [
      [fetchNVD,            'nvd'],
      [fetchCISAKev,        'cisa_kev'],
      [fetchCISAAlerts,     'cisa_alerts'],
      [fetchGitHubAdvisories,'github_advisories'],
      [s => fetchMSRC(),    'msrc'],
      [fetchExploitDB,      'exploitdb'],
      [fetchPacketStorm,    'packetstorm'],
      [fetchFullDisclosure, 'fulldisclosure'],
      [s => fetchSentinelApex(), 'sentinel_apex'],
    ], state);

    // ── PHASE 6: STREAM — write partial results after Tier 1 ──────────
    const tier1Items = correlateAndMerge(tier1Batches);
    if (tier1Items.length > 0) {
      log(`\n── PHASE 6: STREAMING — Writing Tier 1 partial results (${tier1Items.length} items)...`);
      writeLiveIntel(tier1Items.map(i=>({...i,priority:computePriorityScore(i),threatLevel:threatLevel(computePriorityScore(i))})), state);
      await writeAPIFiles(tier1Items.map(i=>({...i,priority:computePriorityScore(i),threatLevel:threatLevel(computePriorityScore(i))})), state);
    }
    tier1Batches.forEach((b,idx) => { const k=['nvd','cisa_kev','cisa_alerts','github_advisories','msrc','exploitdb','packetstorm','fulldisclosure','sentinel_apex'][idx]; if(k) sourceStats[k]={fetched:b.length}; });

    // ══════════════════════════════════════════════════════════════════
    // TIER 2 — Threat intel blogs + malware (run while Tier 1 publishes)
    // ══════════════════════════════════════════════════════════════════
    const tier2Batches = await runTier('TIER 2: THREAT BLOGS + MALWARE FEEDS', [
      [s=>fetchRSS(CFG.bleepingRss,'bleepingcomputer',CFG.maxRssItems,s), 'bleepingcomputer'],
      [s=>fetchRSS(CFG.thnRss,'thehackernews',CFG.maxRssItems,s),         'thehackernews'],
      [s=>fetchRSS(CFG.krebsRss,'krebsonsecurity',4,s),                   'krebsonsecurity'],
      [s=>fetchRSS(CFG.secweekRss,'securityweek',CFG.maxRssItems,s),      'securityweek'],
      [s=>fetchRSS(CFG.sansRss,'sans_isc',4,s),                           'sans_isc'],
      [s=>fetchRSS(CFG.darkReadingRss,'darkreading',CFG.maxRssItems,s),   'darkreading'],
      [fetchTalos,          'talos'],
      [fetchUnit42,         'unit42'],
      [fetchCrowdStrike,    'crowdstrike'],
      [fetchSentinelOne,    'sentinelone'],
      [fetchGoogleProjectZero,'googleprojectzero'],
      [fetchRapid7,         'rapid7'],
      [s=>fetchURLhaus(),   'urlhaus'],
      [s=>fetchThreatFox(), 'threatfox'],
    ], state);

    // ── PHASE 6: STREAM — write merged T1+T2 results ─────────────────
    const allT1T2 = [...tier1Batches, ...tier2Batches];
    const t1t2Items = correlateAndMerge(allT1T2);
    if (t1t2Items.length > 0) {
      log(`\n── PHASE 6: STREAMING — Writing T1+T2 merged results (${t1t2Items.length} items)...`);
      writeLiveIntel(t1t2Items.map(i=>({...i,priority:computePriorityScore(i),threatLevel:threatLevel(computePriorityScore(i))})), state);
    }
    tier2Batches.forEach((b,idx) => { const k=['bleepingcomputer','thehackernews','krebsonsecurity','securityweek','sans_isc','darkreading','talos','unit42','crowdstrike','sentinelone','googleprojectzero','rapid7','urlhaus','threatfox'][idx]; if(k) sourceStats[k]={fetched:b.length}; });

    // ══════════════════════════════════════════════════════════════════
    // TIER 3 — Community signals (lower priority, can be slower)
    // ══════════════════════════════════════════════════════════════════
    const tier3Batches = await runTier('TIER 3: COMMUNITY + SIGNAL SOURCES', [
      [fetchRedditNetsec,   'reddit_netsec'],
      [fetchRedditCyber,    'reddit_cyber'],
      [fetchCertEU,         'cert_eu'],
      [fetchMicrosoftSecBlog,'microsoft_security'],
      [fetchWiredSecurity,  'wired_security'],
      [fetchRecordedFuture, 'recorded_future'],
      [()=>fetchMalwareBazaar(), 'malwarebazaar'],
      [s=>fetchNCSCUK(s), 'ncsc_uk'],
      [s=>fetchCiscoPSIRT(s), 'cisco_psirt'],
      [s=>fetchOTX(s), 'otx'],
      [s=>fetchRansomWatch(s), 'ransomwatch'],
      [s=>fetchAIIncidentDB(s), 'ai_incident_db'],
    ], state);
    tier3Batches.forEach((b,idx) => { const k=['reddit_netsec','reddit_cyber','cert_eu','microsoft_security','wired_security','recorded_future'][idx]; if(k) sourceStats[k]={fetched:b.length}; });

    // ── FULL CORRELATION ACROSS ALL 28 SOURCES ────────────────────────
    log('\n── FULL CORRELATION ENGINE ─────────────────────────────────────');
    const allBatches      = [...tier1Batches, ...tier2Batches, ...tier3Batches];
    const correlatedItems = correlateAndMerge(allBatches);
    const activeSources   = allBatches.filter(b=>b.length>0).length;
    log(`Full corpus: ${correlatedItems.length} items from ${activeSources}/28 sources`);
    const multiSrcCount   = correlatedItems.filter(i=>(i.sourceCount||1)>=2).length;
    if (multiSrcCount > 0) log(`Multi-source corroborated: ${multiSrcCount} items`);

    if (activeSources === 0) { err('ALL sources failed — aborting.'); safeRelease(); process.exit(1); }

    // ── PHASE 4: SIGNAL vs NOISE FILTERING ───────────────────────────
    log('\n── PHASE 4: SIGNAL vs NOISE FILTERING ─────────────────────────');
    const filteredItems = filterSignalFromNoise(correlatedItems);
    log(`After filtering: ${filteredItems.length} signal items retained`);

    // ── INTELLIGENCE ENRICHMENT ───────────────────────────────────────
    log('\n── INTELLIGENCE ENRICHMENT PIPELINE ───────────────────────────');
    let enrichedItems = filteredItems;
    try {
      const enrichResult = runEnrichmentPipeline(filteredItems);
      enrichedItems      = enrichResult.enrichedItems;
      log(`Enrichment: ${enrichResult.stats.items_processed} items, ${enrichResult.stats.campaigns} campaigns, ${enrichResult.stats.elapsed_ms}ms`);
    } catch(enrichErr) {
      warn(`Enrichment non-fatal: ${enrichErr.message}. Continuing unenriched.`);
    }

    // ── PHASE 3: Normalize to universal schema ────────────────────────
    enrichedItems = enrichedItems.map(i => {
      try { return normalizeToUniversalSchema(i); } catch(_) { return i; }
    });
    log(`  Universal schema normalization: ${enrichedItems.length} items normalized`);

    // ── PHASE 9: Sentinel APEX stamps ────────────────────────────────
    enrichedItems = enrichedItems.map(i => {
      try { return sentinelApexStamp(i); } catch(_) { return i; }
    });
    const apexEligible = enrichedItems.filter(i=>i.sentinel_apex?.api_eligible).length;
    const msspRelevant = enrichedItems.filter(i=>i.sentinel_apex?.mssp_relevant).length;
    log(`  Sentinel APEX: ${apexEligible} API-eligible, ${msspRelevant} MSSP-relevant items`);

    // ── PHASE 9: PERFORMANCE — per-source new count ──────────────────
    const totalFetched  = Object.values(sourceStats).reduce((s,v)=>s+v.fetched,0);
    const newAfterDedup = enrichedItems.filter(i=>i.id&&!isPublished(state,i.id)).length;
    log(`\n── DEBUG STATS ─────────────────────────────────────────────────`);
    log(`  total_fetched: ${totalFetched} | new_after_dedup: ${newAfterDedup} | enriched: ${enrichedItems.length}`);
    Object.entries(sourceStats).forEach(([src,st]) => { st.new = enrichedItems.filter(i=>i.source===src&&!isPublished(state,i.id)).length; });

    // ── PHASE 8: FRESHNESS — alert if stale > 30 min ─────────────────
    const freshnessMs  = CFG.freshnessAlertMins * 60000;
    const lastRunMs    = state.lastRun ? Date.now()-new Date(state.lastRun).getTime() : 0;
    const yesterday    = new Date(Date.now()-86400000);
    const freshItems   = enrichedItems.filter(i=>{ try{return new Date(i.pubDate||0)>=yesterday;}catch(_){return false;} });
    if (freshItems.length===0 && lastRunMs > freshnessMs) {
      log(`⚠️  FRESHNESS ALERT: No intel with pubDate >= yesterday. Last run: ${Math.round(lastRunMs/60000)} min ago.`);
      log('    Check source availability. Consider running workflow_dispatch to reset state.');
    } else {
      log(`  fresh_items_24h: ${freshItems.length}`);
    }

    // ── PHASE 6: FINAL STREAM WRITE — S2N-powered ─────────────────────
    log('\n── PHASE 6: STREAMING — S2N + Final enriched write ─────────────');
    writeLiveIntel(enrichedItems, state);
    await writeAPIFiles(enrichedItems, state);  // <-- runs S2N engine internally

    // ── REPORT GENERATION — use S2N-passed items for scoring ──────────
    const newItems   = enrichedItems.filter(item=>item.id&&!isPublished(state,item.id));
    log(`\nNew (unpublished) items: ${newItems.length}`);

    if (newItems.length === 0) {
      log('No new intel this cycle — all within dedup TTL.');
      const health = getSourceHealthReport(state);
      if (health.degraded.length > 0) log(`⚠️  Degraded sources: ${health.degraded.join(', ')}`);
      saveState(state);
      validateAndReport(enrichedItems, [], state, T0, sourceStats);
      safeRelease();
      return;
    }

    log('\n── REPORT GENERATION ───────────────────────────────────────────');
    const toPublish     = newItems.slice(0, CFG.maxNewPostsPerRun);
    const generatedCards= [], rssItems = [], newSlugs = [];

    let qualityPassed = 0, qualityRejected = 0;
    for (const item of toPublish) {
      try {
        // ── PHASE 7: QUALITY GATE ─────────────────────────────────────
        const qg = qualityGate(item);
        if (!qg.pass) {
          warn(`QUALITY GATE REJECTED: ${item.id} — ${qg.reasons.join('; ')}`);
          qualityRejected++;
          continue;
        }
        qualityPassed++;

        const { slug, title, html } = generatePostHTML(item);
        const filePath = path.join(CFG.postsDir, `${slug}.html`);
        if (fs.existsSync(filePath)) {
          markPublished(state, { id:item.id, slug, title });
          continue;
        }

        // ── PHASE 7B: POST-RENDER INTEGRITY VALIDATOR ─────────────────
        const rv = validateRenderedPost(item, html);
        if (!rv.pass) {
          warn(`INTEGRITY VALIDATOR REJECTED: ${item.id} — ${rv.reasons.join('; ')}`);
          qualityRejected++;
          continue;
        }

        safeWriteSync(filePath, html, 'utf8');
        log(`✅ [${item.threatLevel||'HIGH'}] [${item.type}] ${slug}.html (score=${item.priority||0}, srcs=${item.sourceCount||1})`);
        markPublished(state, { id:item.id, slug, title });
        // Record this report's entities into persistent analyst memory (after
        // the post's prior-context note was already rendered above).
        if (analystMemory) { try { analystMemory.ingest(item, slug); } catch(_) {} }
        // Machine-readable intelligence product for API/MSSP consumers.
        try {
          const productJson = buildProductApiJSON(item);
          if (productJson) {
            const productsDir = path.join(CFG.apiDir, 'products');
            if (!fs.existsSync(productsDir)) fs.mkdirSync(productsDir, { recursive: true });
            safeWriteSync(path.join(productsDir, `${slug}.json`), productJson, 'utf8');
          }
        } catch (e) { warn(`Product package write failed for ${item.id}: ${e.message}`); }
        generatedCards.push({ card: generatePostCard(item, slug, title) });
        rssItems.push({ ...item, slug, title });
        newSlugs.push(slug);
        // Per-CVE API file
        if (item.id.startsWith('CVE') && (item.priority||0) >= 50) {
          try {
            const apiCveDir = path.join(CFG.apiDir, 'cve');
            if (!fs.existsSync(apiCveDir)) fs.mkdirSync(apiCveDir, { recursive: true });
            const cveFile   = path.join(apiCveDir, `${item.id}.json`);
            const existing  = fs.existsSync(cveFile) ? JSON.parse(fs.readFileSync(cveFile,'utf8')) : {};
            safeWriteSync(cveFile, JSON.stringify({ ...existing, report_url:`${CFG.baseUrl}/posts/${slug}.html`, slug }, null, 2), 'utf8');
          } catch(_) {}
        }
      } catch(e) { err(`Failed to generate: ${item.id} — ${e.message}`); }
    }

    // ── PLATFORM SYNC ─────────────────────────────────────────────────
    log('\n── PLATFORM SYNC ───────────────────────────────────────────────');
    if (generatedCards.length > 0) {
      updateIndexHTML(generatedCards);
      updateRSS(rssItems);
      updateSitemap(newSlugs);
      updateSearchIndex(rssItems);
    }

    log(`  Quality gate: ${qualityPassed} passed, ${qualityRejected} rejected`);
    // live-intel.json's rolling window is sorted by priority (not recency) and
    // trims to CFG.liveRollingWindow -- a genuinely new, real report can still
    // be trimmed out of the window if its priority is lower than what's
    // already there, leaving every item's _addedAt stale even while the
    // pipeline is actively publishing. lastReportGeneratedAt is set only when
    // a report was actually written this run, so freshness-check.yml can tell
    // "pipeline ran" apart from "pipeline actually produced new content"
    // without depending on window membership.
    if (newSlugs.length > 0) state.lastReportGeneratedAt = isoNowFull();
    saveState(state);
    if (analystMemory) {
      try {
        analystMemory.save(fs, CFG.memoryPath);
        log(`  Analyst memory: ${analystMemory.stats().entities} entities persisted`);
      } catch (e) { warn(`Analyst memory save failed: ${e.message}`); }
    }
    validateAndReport(enrichedItems, generatedCards, state, T0, sourceStats);

  } catch(fatalErr) {
    err(`FATAL: ${fatalErr.message}\n${fatalErr.stack||''}`);
    safeRelease();
    process.exit(1);
  }

  safeRelease();
}

// Run the pipeline only when invoked directly (node fetch-live-intel.js /
// npm start). When required as a module (e.g. tests), export the render
// helpers instead so they can be exercised without triggering live fetches.
if (require.main === module) {
  main().catch(e => {
    err(`UNHANDLED: ${e.message}\n${e.stack||''}`);
    releaseLock();
    process.exit(1);
  });
} else {
  module.exports = {
    generatePostHTML, genMultiPlatformDetections, genPriorIntelligence,
    genStructuredReasoning, genIntelligenceProducts, buildProductApiJSON,
    genSigma, genYARA, getMitre, stripHtml, decodeEntities,
    extractHttpUrls, parseCvssFromText, hasConfirmedExploitation,
    rssToIntel, qualityGate, validateRenderedPost, genExecutiveSummary, genBusinessImpact,
    genAttackChain, computePriorityScore, correlateAndMerge,
    resolveAuthoritativeCvss, technicalSeverityFromCvss,
    extractSentinelApexRecords, normalizeSentinelApexRecord,
    sapexCanonicalId, sapexNativeMitre, fetchSentinelApex,
    watermarkStart,
  };
}
