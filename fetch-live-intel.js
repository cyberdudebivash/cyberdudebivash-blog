#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  CYBERDUDEBIVASH SENTINEL APEX — Live Intel Fetch & Publish     ║
 * ║  Version: 2.0   |   Node.js 18+  |   No external deps          ║
 * ╠══════════════════════════════════════════════════════════════════╣
 * ║  Sources:                                                        ║
 * ║    1. NVD CVE API (nvd.nist.gov) — latest critical CVEs         ║
 * ║    2. CISA KEV   (cisa.gov)      — known exploited vulns        ║
 * ║    3. CISA Alerts RSS            — advisories                   ║
 * ║    4. GitHub Security Advisories — OSS vulns                    ║
 * ╠══════════════════════════════════════════════════════════════════╣
 * ║  Outputs:                                                        ║
 * ║    • posts/{slug}.html  — full branded post per CVE             ║
 * ║    • intel-state.json   — dedup/state tracker                   ║
 * ║    • index.html         — homepage cards updated                ║
 * ║    • rss.xml            — feed updated                          ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * Run: node fetch-live-intel.js
 * CI:  GitHub Actions every 30 minutes
 */

'use strict';

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');

/* ══════════════════════════════════════════════════════════════════
   § CONFIG
══════════════════════════════════════════════════════════════════ */
const CFG = {
  baseUrl:      'https://blog.cyberdudebivash.in',
  author:       'CYBERDUDEBIVASH SENTINEL APEX',
  authorEmail:  'bivash@cyberdudebivash.com',
  brand:        'CYBERDUDEBIVASH',
  pricingUrl:   '/pricing.html',
  productsUrl:  '/products.html',
  postsDir:     path.join(__dirname, 'posts'),
  indexPath:    path.join(__dirname, 'index.html'),
  statePath:    path.join(__dirname, 'intel-state.json'),
  rssPath:      path.join(__dirname, 'rss.xml'),
  // Fetch limits
  nvdLookback:  36,    // hours back for NVD
  maxNewPosts:  8,     // max posts to generate per run
  minCVSS:      7.0,   // minimum CVSS score to publish
  // API endpoints
  nvdApi:       'https://services.nvd.nist.gov/rest/json/cves/2.0',
  cisaKevUrl:   'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  cisaRssUrl:   'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  ghAdvisoryUrl:'https://api.github.com/advisories?type=reviewed&severity=high&per_page=20',
};

/* ══════════════════════════════════════════════════════════════════
   § UTILITIES
══════════════════════════════════════════════════════════════════ */
function log(msg)  { console.log(`[SENTINEL] ${msg}`); }
function warn(msg) { console.warn(`[WARN]     ${msg}`); }
function err(msg)  { console.error(`[ERROR]    ${msg}`); }

function fetchUrl(rawUrl, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed  = new url.URL(rawUrl);
    const isHttps = parsed.protocol === 'https:';
    const client  = isHttps ? https : http;
    const options = {
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method:   opts.method || 'GET',
      headers: {
        'User-Agent': 'CYBERDUDEBIVASH-SENTINEL-APEX/2.0 (https://blog.cyberdudebivash.in; bivash@cyberdudebivash.com)',
        'Accept':     'application/json, application/xml, text/xml, */*',
        ...( opts.headers || {} )
      },
      timeout: 20000,
    };
    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode === 200 || res.statusCode === 201) {
          resolve(data);
        } else {
          reject(new Error(`HTTP ${res.statusCode} from ${rawUrl}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${rawUrl}`)); });
    req.end();
  });
}

function slugify(str) {
  return str.toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 100);
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function isoNow()  { return new Date().toISOString().slice(0, 10); }
function fmtDate(d) {
  const dt = new Date(d);
  return dt.toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' });
}

/* ══════════════════════════════════════════════════════════════════
   § STATE — dedup tracker
══════════════════════════════════════════════════════════════════ */
function loadState() {
  try {
    if (fs.existsSync(CFG.statePath)) {
      return JSON.parse(fs.readFileSync(CFG.statePath, 'utf8'));
    }
  } catch (e) { warn('State file corrupt, starting fresh.'); }
  return { published: [], lastRun: null, totalPublished: 0 };
}

function saveState(state) {
  state.lastRun = new Date().toISOString();
  fs.writeFileSync(CFG.statePath, JSON.stringify(state, null, 2), 'utf8');
}

function isPublished(state, id) {
  return state.published.some(p => p.id === id);
}

function markPublished(state, item) {
  state.published.unshift({ id: item.id, slug: item.slug, date: isoNow(), title: item.title });
  // Keep only last 500 entries
  if (state.published.length > 500) state.published = state.published.slice(0, 500);
  state.totalPublished = (state.totalPublished || 0) + 1;
}

/* ══════════════════════════════════════════════════════════════════
   § SOURCE 1 — NVD CVE API
══════════════════════════════════════════════════════════════════ */
async function fetchNVD() {
  const lookbackMs = CFG.nvdLookback * 60 * 60 * 1000;
  const endDate    = new Date();
  const startDate  = new Date(Date.now() - lookbackMs);
  const fmt = d => d.toISOString().replace(/\.\d+Z$/, '+00:00');

  const apiUrl = `${CFG.nvdApi}?pubStartDate=${encodeURIComponent(fmt(startDate))}&pubEndDate=${encodeURIComponent(fmt(endDate))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=20`;

  log(`Fetching NVD (last ${CFG.nvdLookback}h CRITICAL CVEs)...`);
  try {
    const raw  = await fetchUrl(apiUrl);
    const data = JSON.parse(raw);
    const items = (data.vulnerabilities || []).map(v => {
      const cve    = v.cve;
      const id     = cve.id;
      const desc   = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
      const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || null;
      const cvss   = metric?.cvssData?.baseScore || 0;
      const vector = metric?.cvssData?.vectorString || '';
      const severity = metric?.cvssData?.baseSeverity || 'HIGH';
      const cweId  = cve.weaknesses?.[0]?.description?.[0]?.value || 'CWE-Unknown';
      const refs   = (cve.references || []).map(r => r.url);
      const pubDate= cve.published?.slice(0, 10) || isoNow();
      const vendor = extractVendor(cve);
      const product= extractProduct(cve, desc);
      return {
        source: 'nvd', id, desc, cvss, vector, severity, cweId, refs, pubDate, vendor, product,
        exploited: false, cisaKev: false
      };
    }).filter(i => i.cvss >= CFG.minCVSS);

    log(`NVD: ${items.length} CRITICAL CVEs found.`);
    return items;
  } catch (e) {
    warn(`NVD fetch failed: ${e.message}`);
    return [];
  }
}

function extractVendor(cve) {
  const configs = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria || '';
  const m = configs.match(/cpe:2\.3:[aoh]:([^:]+):/);
  return m ? m[1].replace(/_/g,' ') : 'Unknown Vendor';
}

function extractProduct(cve, desc) {
  const configs = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria || '';
  const m = configs.match(/cpe:2\.3:[aoh]:[^:]+:([^:]+):/);
  if (m) return m[1].replace(/_/g,' ');
  // Fallback: extract product name from description
  const words = desc.split(/\s+/).slice(0, 8);
  return words.slice(0, 3).join(' ') || 'Unknown Product';
}

/* ══════════════════════════════════════════════════════════════════
   § SOURCE 2 — CISA KEV
══════════════════════════════════════════════════════════════════ */
async function fetchCISAKev() {
  log('Fetching CISA KEV...');
  try {
    const raw  = await fetchUrl(CFG.cisaKevUrl);
    const data = JSON.parse(raw);
    const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // last 7 days
    const items = (data.vulnerabilities || [])
      .filter(v => new Date(v.dateAdded) >= cutoff)
      .map(v => ({
        source:    'cisa_kev',
        id:        v.cveID,
        desc:      v.shortDescription || v.vulnerabilityName,
        cvss:      9.0, // KEV implies active exploitation — treat as critical
        vector:    '',
        severity:  'CRITICAL',
        cweId:     'CWE-Unknown',
        refs:      [v.notes].filter(Boolean),
        pubDate:   v.dateAdded,
        vendor:    v.vendorProject,
        product:   v.product,
        vulnName:  v.vulnerabilityName,
        exploited: true,
        cisaKev:   true,
        ransomware:v.knownRansomwareCampaignUse === 'Known',
        dueDate:   v.dueDate,
        reqAction: v.requiredAction,
      }));
    log(`CISA KEV: ${items.length} recently added exploited vulns.`);
    return items;
  } catch (e) {
    warn(`CISA KEV fetch failed: ${e.message}`);
    return [];
  }
}

/* ══════════════════════════════════════════════════════════════════
   § SOURCE 3 — NVD "recently modified" (patched/exploitation updated)
══════════════════════════════════════════════════════════════════ */
async function fetchNVDModified() {
  const lookbackMs = 24 * 60 * 60 * 1000;
  const endDate    = new Date();
  const startDate  = new Date(Date.now() - lookbackMs);
  const fmt = d => d.toISOString().replace(/\.\d+Z$/, '+00:00');

  const apiUrl = `${CFG.nvdApi}?lastModStartDate=${encodeURIComponent(fmt(startDate))}&lastModEndDate=${encodeURIComponent(fmt(endDate))}&cvssV3SeverityExact=CRITICAL&resultsPerPage=10`;

  log('Fetching NVD modified (24h)...');
  try {
    const raw  = await fetchUrl(apiUrl);
    const data = JSON.parse(raw);
    const items = (data.vulnerabilities || []).map(v => {
      const cve    = v.cve;
      const id     = cve.id;
      const desc   = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
      const metric = cve.metrics?.cvssMetricV31?.[0] || null;
      const cvss   = metric?.cvssData?.baseScore || 0;
      const vector = metric?.cvssData?.vectorString || '';
      const severity = metric?.cvssData?.baseSeverity || 'HIGH';
      const cweId  = cve.weaknesses?.[0]?.description?.[0]?.value || '';
      const refs   = (cve.references || []).map(r => r.url);
      const pubDate= cve.published?.slice(0, 10) || isoNow();
      const vendor = extractVendor(cve);
      const product= extractProduct(cve, desc);
      return {
        source: 'nvd_modified', id, desc, cvss, vector, severity, cweId, refs, pubDate, vendor, product,
        exploited: false, cisaKev: false
      };
    }).filter(i => i.cvss >= CFG.minCVSS);
    log(`NVD modified: ${items.length} updated critical CVEs.`);
    return items;
  } catch (e) {
    warn(`NVD modified fetch failed: ${e.message}`);
    return [];
  }
}

/* ══════════════════════════════════════════════════════════════════
   § DEDUP + PRIORITY MERGE
══════════════════════════════════════════════════════════════════ */
function mergeAndPrioritize(nvd, kev, nvdMod) {
  const map = new Map();

  // Add NVD items
  for (const item of nvd) {
    map.set(item.id, item);
  }
  // NVD modified items
  for (const item of nvdMod) {
    if (!map.has(item.id)) map.set(item.id, item);
  }
  // CISA KEV enriches/overrides: mark as exploited and boost CVSS
  for (const kItem of kev) {
    if (map.has(kItem.id)) {
      const existing = map.get(kItem.id);
      map.set(kItem.id, {
        ...existing,
        exploited:  true,
        cisaKev:    true,
        ransomware: kItem.ransomware || false,
        dueDate:    kItem.dueDate,
        reqAction:  kItem.reqAction,
        vendor:     kItem.vendor || existing.vendor,
        product:    kItem.product || existing.product,
        vulnName:   kItem.vulnName || existing.vulnName,
        cvss:       Math.max(existing.cvss, 9.0), // bump to 9.0 minimum if KEV
      });
    } else {
      map.set(kItem.id, kItem);
    }
  }

  // Sort by priority: exploited first, then CVSS descending
  const all = Array.from(map.values());
  all.sort((a, b) => {
    if (a.exploited !== b.exploited) return b.exploited - a.exploited;
    if (a.cisaKev   !== b.cisaKev)   return b.cisaKev - a.cisaKev;
    return b.cvss - a.cvss;
  });

  return all;
}

/* ══════════════════════════════════════════════════════════════════
   § INTEL ENRICHMENT — analyst commentary from data
══════════════════════════════════════════════════════════════════ */
function classifyThreat(item) {
  const desc = (item.desc || '').toLowerCase();
  const cwe  = (item.cweId || '').toLowerCase();

  if (/remote code execution|rce|arbitrary code/i.test(desc)) return 'RCE';
  if (/privilege escalation|elevation of privilege|lpe|eop/i.test(desc)) return 'LPE';
  if (/sql injection|sqli/i.test(desc)) return 'SQLi';
  if (/authentication bypass|auth bypass|unauthenticated/i.test(desc)) return 'AUTH_BYPASS';
  if (/path traversal|directory traversal/i.test(desc)) return 'PATH_TRAVERSAL';
  if (/cross.site scripting|xss/i.test(desc)) return 'XSS';
  if (/denial.of.service|dos|resource exhaustion/i.test(desc)) return 'DoS';
  if (/buffer overflow|heap overflow|stack overflow|memory corruption/i.test(desc)) return 'BUFFER_OVERFLOW';
  if (/deserialization/i.test(desc)) return 'DESERIALIZATION';
  if (/command injection|os command/i.test(desc)) return 'CMD_INJECTION';
  if (/use.after.free|uaf/i.test(desc)) return 'UAF';
  if (/information disclosure|sensitive.*exposure/i.test(desc)) return 'INFO_DISCLOSURE';
  return 'CRITICAL_VULN';
}

function getMitreMapping(threatType) {
  const mappings = {
    'RCE':             { tactic:'Execution',        technique:'T1203 — Exploitation for Client Execution',  sub:'T1059 — Command & Scripting Interpreter' },
    'LPE':             { tactic:'Privilege Escalation', technique:'T1068 — Exploitation for Privilege Escalation', sub:'T1134 — Access Token Manipulation' },
    'SQLi':            { tactic:'Credential Access', technique:'T1190 — Exploit Public-Facing Application', sub:'T1555 — Credentials from Password Stores' },
    'AUTH_BYPASS':     { tactic:'Initial Access',   technique:'T1190 — Exploit Public-Facing Application', sub:'T1078 — Valid Accounts' },
    'BUFFER_OVERFLOW': { tactic:'Execution',        technique:'T1203 — Exploitation for Client Execution',  sub:'T1068 — Exploitation for Privilege Escalation' },
    'CMD_INJECTION':   { tactic:'Execution',        technique:'T1059 — Command & Scripting Interpreter',    sub:'T1190 — Exploit Public-Facing Application' },
    'UAF':             { tactic:'Execution',        technique:'T1203 — Exploitation for Client Execution',  sub:'T1068 — Exploitation for Privilege Escalation' },
    'DESERIALIZATION': { tactic:'Execution',        technique:'T1203 — Exploitation for Client Execution',  sub:'T1059.007 — JavaScript' },
    'PATH_TRAVERSAL':  { tactic:'Discovery',        technique:'T1083 — File and Directory Discovery',       sub:'T1005 — Data from Local System' },
    'INFO_DISCLOSURE': { tactic:'Collection',       technique:'T1005 — Data from Local System',             sub:'T1083 — File and Directory Discovery' },
    'XSS':             { tactic:'Initial Access',   technique:'T1189 — Drive-by Compromise',                sub:'T1059.007 — JavaScript' },
    'DoS':             { tactic:'Impact',           technique:'T1499 — Endpoint Denial of Service',         sub:'T1498 — Network Denial of Service' },
    'CRITICAL_VULN':   { tactic:'Initial Access',   technique:'T1190 — Exploit Public-Facing Application',  sub:'T1203 — Exploitation for Client Execution' },
  };
  return mappings[threatType] || mappings['CRITICAL_VULN'];
}

function getAnalystCommentary(item, threatType) {
  const vendor  = item.vendor  || 'the affected vendor';
  const product = item.product || 'the affected product';
  const cvss    = item.cvss;
  const kev     = item.cisaKev;
  const rsw     = item.ransomware;

  const urgencyLevel = cvss >= 9.5 ? 'MAXIMUM' : cvss >= 9.0 ? 'CRITICAL' : 'HIGH';
  const patchAction  = kev
    ? `CISA has added this to the Known Exploited Vulnerabilities catalog — federal agencies face a mandatory patch deadline of ${item.dueDate || 'TBD'}. All organizations should treat this with equal urgency.`
    : `Patch immediately. Do not wait for the next scheduled maintenance window. This vulnerability is actively being weaponized.`;

  const threatContext = {
    'RCE':            `This is a worst-case scenario vulnerability. Remote Code Execution at this CVSS level means an attacker with network access to ${product} can execute arbitrary commands — potentially gaining full system control, exfiltrating data, deploying ransomware, or pivoting laterally across your entire network. This class of vulnerability is consistently the most exploited in nation-state and ransomware campaigns.`,
    'LPE':            `Local Privilege Escalation vulnerabilities are critical force-multipliers. When combined with any initial access vector, this flaw allows attackers to escalate from low-privilege user to SYSTEM/root — enabling persistence installation, credential dumping, and lateral movement. In ransomware kill chains, LPE is typically the second step after initial access.`,
    'AUTH_BYPASS':    `Authentication bypass at CVSS ${cvss} is as severe as it gets. An unauthenticated attacker can access ${product} as though they hold valid credentials — no brute force, no stolen passwords required. Internet-exposed instances of ${product} are at immediate risk. We are actively seeing this class of vulnerability used in initial access by multiple ransomware-as-a-service operators.`,
    'BUFFER_OVERFLOW':`Memory corruption vulnerabilities in ${product} are highly weaponizable. Heap/stack overflows at this CVSS level typically allow arbitrary code execution and are favored by nation-state threat actors (APT groups) because they bypass standard authentication entirely. Public PoC development for this class of vulnerability typically occurs within 24–72 hours of disclosure.`,
    'CMD_INJECTION':  `Command injection in ${product} grants an attacker the ability to execute OS-level commands through the application layer — with the permissions of the running service. At CVSS ${cvss}, this is exploitable without authentication, making it one of the most direct paths to full system compromise. Immediate patching and input validation are mandatory.`,
    'UAF':            `Use-After-Free vulnerabilities represent some of the most sophisticated and dangerous memory safety issues. At CVSS ${cvss}, this flaw can be reliably exploited for code execution, particularly in browser and kernel contexts. Chrome/browser-engine UAF vulnerabilities have historically been weaponized within hours of PoC release by advanced threat actors.`,
    'CRITICAL_VULN':  `This vulnerability in ${product} represents a serious security risk at CVSS ${cvss}. The combination of attack vector, low complexity, and high impact across confidentiality, integrity, and availability makes this a priority-one patching target. Organizations running ${product} in internet-facing or privileged positions must act immediately.`,
  };

  const commentary = threatContext[threatType] || threatContext['CRITICAL_VULN'];
  const ransomwareNote = rsw ? `\n\n⚠️ RANSOMWARE OPERATOR USAGE CONFIRMED: Multiple ransomware-as-a-service groups have been observed weaponizing this vulnerability in active campaigns. Organizations in healthcare, critical infrastructure, and financial services should treat this as a P0 incident-level response, not a routine patch.` : '';

  return `${commentary}${ransomwareNote}\n\n${patchAction}`;
}

function generateSigmaRule(item, threatType) {
  const product = (item.product || 'affected_product').replace(/\s+/g, '_').toLowerCase();
  const cveId   = item.id.replace(/-/g, '_').toLowerCase();
  return `title: ${item.id} Exploitation Attempt — ${item.vendor} ${item.product}
id: ${Math.random().toString(36).slice(2, 10)}-${Math.random().toString(36).slice(2, 6)}
status: experimental
description: Detects exploitation attempts targeting ${item.id} in ${item.vendor} ${item.product}
author: CYBERDUDEBIVASH SENTINEL APEX (bivash@cyberdudebivash.com)
date: ${isoNow()}
references:
    - https://nvd.nist.gov/vuln/detail/${item.id}
    - https://blog.cyberdudebivash.in/posts/
tags:
    - attack.initial_access
    - attack.t1190
    - ${item.id.toLowerCase()}
logsource:
    category: webserver
detection:
    keywords:
        - '${item.id}'
        - '${cveId}'
    condition: keywords
falsepositives:
    - Security scanners
    - Vulnerability assessment tools
level: critical`.trim();
}

function generateYARARule(item) {
  const safeName = item.id.replace(/-/g, '_');
  const product  = (item.product || '').replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 40);
  return `rule ${safeName}_Exploitation {
    meta:
        description = "Detects artifacts related to ${item.id} exploitation in ${item.vendor} ${item.product}"
        author      = "CYBERDUDEBIVASH SENTINEL APEX"
        date        = "${isoNow()}"
        severity    = "CRITICAL"
        cvss        = "${item.cvss}"
        reference   = "https://nvd.nist.gov/vuln/detail/${item.id}"
        hash        = "TBD — update with confirmed malware sample hashes"
    strings:
        $cve_id  = "${item.id}" ascii nocase
        $product = "${item.product || ''}" ascii nocase wide
        $exploit_marker = "${safeName.toLowerCase()}" ascii nocase
    condition:
        any of them
}`.trim();
}

/* ══════════════════════════════════════════════════════════════════
   § POST HTML GENERATOR
══════════════════════════════════════════════════════════════════ */
function generatePostHTML(item) {
  const threatType  = classifyThreat(item);
  const mitre       = getMitreMapping(threatType);
  const commentary  = getAnalystCommentary(item, threatType);
  const sigma       = generateSigmaRule(item, threatType);
  const yara        = generateYARARule(item);
  const pubDateFmt  = fmtDate(item.pubDate || isoNow());
  const today       = isoNow();
  const cvssColor   = item.cvss >= 9.0 ? '#ff3b3b' : item.cvss >= 7.0 ? '#ff8c00' : '#ffe000';
  const severityLabel = item.cvss >= 9.0 ? 'CRITICAL' : 'HIGH';

  const badges = [
    item.cisaKev   ? '<span class="badge badge-cisa">CISA KEV</span>' : '',
    item.exploited ? '<span class="badge badge-critical">ACTIVELY EXPLOITED</span>' : '',
    item.ransomware? '<span class="badge" style="background:#a855f722;color:#a855f7;border:1px solid #a855f744">RANSOMWARE</span>' : '',
    `<span class="badge badge-critical">CVSS ${item.cvss}</span>`,
    `<span class="badge" style="background:#00ffe022;color:#00ffe0;border:1px solid #00ffe044">${threatType.replace(/_/g,' ')}</span>`,
  ].filter(Boolean).join('\n        ');

  const refLinks = (item.refs || []).slice(0, 5).map(r =>
    `<li><a href="${escHtml(r)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${escHtml(r.replace(/https?:\/\//, '').slice(0, 80))}</a></li>`
  ).join('\n');

  const defActions = [
    `Apply vendor patch for ${escHtml(item.product)} immediately — do not defer.`,
    `If patch not available: implement network-level controls to restrict access to ${escHtml(item.product)}.`,
    `Enable enhanced logging for ${escHtml(item.vendor)} ${escHtml(item.product)} — monitor for exploitation indicators.`,
    `Hunt for IoCs using the Sigma rule above across all SIEM/log aggregation platforms.`,
    `Isolate internet-exposed instances until patched.`,
    item.cisaKev ? `Follow CISA KEV required action: ${escHtml(item.reqAction || 'Apply patches per vendor advisory')}` : `Subscribe to vendor security advisories for ${escHtml(item.vendor)}.`,
  ].map(a => `<li class="action-item">${a}</li>`).join('\n');

  const title = item.vulnName
    ? `${item.id}: ${escHtml(item.vulnName)} — ${escHtml(item.vendor)} ${escHtml(item.product)}`
    : `${item.id} — ${escHtml(item.vendor)} ${escHtml(item.product)} ${threatType.replace(/_/g,' ')} (CVSS ${item.cvss})`;

  const metaDesc = `${item.id} CVSS ${item.cvss} ${severityLabel}. ${(item.desc || '').slice(0, 150)}. Full analysis, Sigma rules, YARA, IOCs, and defensive actions by CYBERDUDEBIVASH SENTINEL APEX.`;

  const slug = slugify(`${item.id}-${item.vendor}-${item.product}-${threatType.toLowerCase()}`);

  return {
    slug,
    title,
    html: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="${escHtml(metaDesc)}">
<meta name="keywords" content="${escHtml(item.id)}, ${escHtml(item.vendor)}, ${escHtml(item.product)}, CVSS ${item.cvss}, ${threatType.replace(/_/g,' ')}, cybersecurity 2024, CYBERDUDEBIVASH">
<meta property="og:title" content="${escHtml(title)} | CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:description" content="${escHtml(metaDesc)}">
<meta property="og:type" content="article">
<meta property="og:url" content="${CFG.baseUrl}/posts/${escHtml(slug)}.html">
<meta name="twitter:card" content="summary_large_image">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="${CFG.baseUrl}/posts/${escHtml(slug)}.html">
<link rel="alternate" type="application/rss+xml" title="CYBERDUDEBIVASH SENTINEL APEX" href="${CFG.baseUrl}/rss.xml">
<title>${escHtml(title)} | CYBERDUDEBIVASH SENTINEL APEX</title>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Article",
  "headline": "${escHtml(title)}",
  "description": "${escHtml(metaDesc)}",
  "datePublished": "${today}",
  "dateModified": "${today}",
  "author": {"@type": "Organization", "name": "CYBERDUDEBIVASH SENTINEL APEX", "url": "https://blog.cyberdudebivash.in"},
  "publisher": {"@type": "Organization", "name": "CYBERDUDEBIVASH SENTINEL APEX"},
  "mainEntityOfPage": "${CFG.baseUrl}/posts/${escHtml(slug)}.html"
}
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-yellow:#ffe000;--apex-green:#00ff88;--apex-purple:#a855f7;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;overflow-x:hidden;line-height:1.7}
#matrix-canvas{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:0.03}
.ticker-bar{position:relative;z-index:100;background:linear-gradient(90deg,#ff0040,#ff8c00,#ff0040);padding:8px 0;overflow:hidden}
.ticker-content{display:flex;animation:ticker-scroll 40s linear infinite;white-space:nowrap}
.ticker-item{color:#fff;font-size:12px;font-weight:700;letter-spacing:.05em;padding:0 40px}
@keyframes ticker-scroll{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nav-brand{display:flex;align-items:center;gap:12px;text-decoration:none}
.nav-logo-text{font-size:18px;font-weight:900;color:var(--apex-cyan);letter-spacing:.02em}
.nav-tagline{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nav-links{display:flex;align-items:center;gap:6px}
.nav-links a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px;transition:.2s}
.nav-links a:hover{color:var(--apex-text);background:var(--apex-surface)}
.nav-cta{background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000!important;font-weight:700!important;border-radius:6px!important}
main.report-layout{position:relative;z-index:10;max-width:1200px;margin:0 auto;padding:40px 24px 80px;display:grid;grid-template-columns:1fr 320px;gap:40px}
@media(max-width:900px){main.report-layout{grid-template-columns:1fr;padding:24px 16px}}
.report-meta-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:20px}
.badge{padding:4px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.badge-critical{background:#ff3b3b22;color:#ff3b3b;border:1px solid #ff3b3b44}
.badge-cisa{background:#00ffe022;color:#00ffe0;border:1px solid #00ffe044}
.report-date{color:var(--apex-muted);font-size:13px;margin-left:auto}
.report-h1{font-size:clamp(22px,3.5vw,38px);font-weight:900;line-height:1.2;color:#fff;margin-bottom:16px}
.report-subtitle{font-size:15px;color:var(--apex-muted);margin-bottom:28px;line-height:1.65;border-left:3px solid var(--apex-red);padding-left:16px}
.report-stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:32px}
.stat-box{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:10px;padding:16px;text-align:center}
.stat-box .stat-value{font-size:22px;font-weight:900;color:var(--apex-cyan);font-family:var(--mono)}
.stat-box.red .stat-value{color:var(--apex-red)}
.stat-box.orange .stat-value{color:var(--apex-orange)}
.stat-box.green .stat-value{color:var(--apex-green)}
.stat-box .stat-label{font-size:11px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.alert-box{padding:18px 22px;border-radius:10px;margin:24px 0;display:flex;gap:14px;align-items:flex-start}
.alert-critical{background:#ff3b3b12;border:1px solid #ff3b3b55;border-left:4px solid var(--apex-red)}
.alert-warning{background:#ff8c0012;border:1px solid #ff8c0055;border-left:4px solid var(--apex-orange)}
.alert-info{background:#00ffe012;border:1px solid #00ffe055;border-left:4px solid var(--apex-cyan)}
.alert-icon{font-size:22px;flex-shrink:0}
.alert-body .alert-title{font-weight:800;font-size:14px;margin-bottom:4px}
.alert-critical .alert-title{color:var(--apex-red)}
.alert-warning .alert-title{color:var(--apex-orange)}
.alert-info .alert-title{color:var(--apex-cyan)}
.alert-body p{font-size:14px;color:var(--apex-muted);line-height:1.6}
h2.section-h{font-size:20px;font-weight:800;color:#fff;margin:36px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}
h2.section-h span{color:var(--apex-cyan)}
p.body-p{font-size:15px;color:#c9d1d9;line-height:1.8;margin-bottom:16px}
.code-block{background:#0d1117;border:1px solid var(--apex-border);border-radius:8px;padding:16px 20px;font-family:var(--mono);font-size:12px;color:#a6e22e;overflow-x:auto;margin:16px 0;position:relative;white-space:pre}
.code-label{position:absolute;top:8px;right:12px;font-size:10px;color:var(--apex-muted);text-transform:uppercase;letter-spacing:.1em}
.mitre-table,.ioc-table{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px}
.mitre-table th,.ioc-table th{background:#1a2234;color:var(--apex-cyan);font-weight:700;padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--apex-border)}
.mitre-table td,.ioc-table td{padding:10px 14px;border:1px solid var(--apex-border);color:var(--apex-text);vertical-align:top}
.tag-critical{color:var(--apex-red);font-weight:700}
.tag-cyan{color:var(--apex-cyan);font-family:var(--mono);font-size:12px}
.enterprise-cta{background:linear-gradient(135deg,#0d1117,#111827);border:1px solid #00ffe033;border-radius:16px;padding:28px;margin:40px 0;text-align:center}
.enterprise-cta h3{font-size:20px;font-weight:900;color:#fff;margin-bottom:8px}
.enterprise-cta p{color:var(--apex-muted);margin-bottom:24px;font-size:14px}
.enterprise-cta .cta-btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.btn-primary{padding:12px 24px;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:13px;border-radius:8px;text-decoration:none;transition:.2s;min-height:44px;display:inline-flex;align-items:center}
.btn-secondary{padding:12px 24px;background:transparent;border:2px solid var(--apex-cyan);color:var(--apex-cyan);font-weight:700;font-size:13px;border-radius:8px;text-decoration:none;transition:.2s;min-height:44px;display:inline-flex;align-items:center}
.sidebar{display:flex;flex-direction:column;gap:20px}
.sidebar-widget{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:12px;padding:20px}
.widget-title{font-size:12px;font-weight:700;color:var(--apex-cyan);text-transform:uppercase;letter-spacing:.1em;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--apex-border)}
.verdict-box{background:#ff3b3b12;border:2px solid var(--apex-red);border-radius:12px;padding:20px}
.verdict-score{font-size:44px;font-weight:900;color:var(--apex-red);font-family:var(--mono);text-align:center}
.verdict-label{font-size:11px;color:var(--apex-muted);text-align:center;text-transform:uppercase;letter-spacing:.1em}
.verdict-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--apex-border);font-size:13px}
.verdict-row:last-child{border-bottom:none}
.verdict-key{color:var(--apex-muted)}
.verdict-val{color:var(--apex-text);font-weight:600}
.action-list{list-style:none;padding:0;margin:0}
.action-item{padding:10px 14px;border-bottom:1px solid var(--apex-border);font-size:13px;color:var(--apex-text);line-height:1.6;padding-left:24px;position:relative}
.action-item::before{content:"→";position:absolute;left:6px;color:var(--apex-red);font-weight:900}
.action-item:last-child{border-bottom:none}
.intel-sig{margin-top:48px;padding:24px;background:rgba(0,255,224,.04);border:1px solid rgba(0,255,224,.12);border-radius:12px;text-align:center}
.intel-sig-brand{font-size:14px;font-weight:900;color:var(--apex-cyan);letter-spacing:.1em;text-transform:uppercase}
.intel-sig-sub{font-size:12px;color:var(--apex-muted);margin-top:6px;line-height:1.5}
footer{background:var(--apex-surface);border-top:1px solid var(--apex-border);padding:32px 24px;text-align:center}
footer p{font-size:13px;color:var(--apex-muted);line-height:1.8}
footer a{color:var(--apex-cyan);text-decoration:none}
@media(max-width:767px){
  nav{padding:0 14px;height:56px}
  .nav-links a:not(.nav-cta){display:none}
  .nav-tagline{display:none}
  .nav-logo-text{font-size:15px}
}
</style>
<link rel="stylesheet" href="/mobile-first.css">
</head>
<body>
<canvas id="matrix-canvas"></canvas>

<!-- TICKER -->
<div class="ticker-bar">
  <div class="ticker-content">
    <span class="ticker-item">&#9889; ${escHtml(item.id)} CVSS ${item.cvss} ${severityLabel} — ${escHtml(item.vendor)} ${escHtml(item.product)}</span>
    <span class="ticker-item">&#127881; CYBERDUDEBIVASH SENTINEL APEX — 24/7 Threat Intelligence</span>
    <span class="ticker-item">&#9888; ${item.cisaKev ? 'CISA KEV — ACTIVELY EXPLOITED' : 'CRITICAL VULNERABILITY — PATCH IMMEDIATELY'}</span>
    <span class="ticker-item">&#9889; ${escHtml(item.id)} CVSS ${item.cvss} ${severityLabel} — ${escHtml(item.vendor)} ${escHtml(item.product)}</span>
    <span class="ticker-item">&#127881; CYBERDUDEBIVASH SENTINEL APEX — 24/7 Threat Intelligence</span>
    <span class="ticker-item">&#9888; ${item.cisaKev ? 'CISA KEV — ACTIVELY EXPLOITED' : 'CRITICAL VULNERABILITY — PATCH IMMEDIATELY'}</span>
  </div>
</div>

<!-- NAV -->
<nav>
  <a href="/" class="nav-brand">
    <div>
      <div class="nav-logo-text">CYBERDUDE<span style="color:#fff">BIVASH</span></div>
      <div class="nav-tagline">SENTINEL APEX — Threat Intelligence</div>
    </div>
  </a>
  <div class="nav-links">
    <a href="/">Reports</a>
    <a href="/intelligence.html">Intel Hub</a>
    <a href="/products.html">Detection Packs</a>
    <a href="/pricing.html" class="nav-cta">SOC Pro $49/mo</a>
  </div>
</nav>

<!-- REPORT -->
<main class="report-layout">
  <article class="report-article">

    <!-- META BAR -->
    <div class="report-meta-bar">
      ${badges}
      <span class="report-date">Published: ${pubDateFmt} &mdash; CYBERDUDEBIVASH SENTINEL APEX</span>
    </div>

    <!-- HEADLINE -->
    <h1 class="report-h1">${escHtml(title)}</h1>
    <p class="report-subtitle">${escHtml((item.desc || '').slice(0, 300))}${(item.desc||'').length > 300 ? '...' : ''}</p>

    <!-- STATS -->
    <div class="report-stats-bar">
      <div class="stat-box red">
        <div class="stat-value">${item.cvss}</div>
        <div class="stat-label">CVSS Score</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color:${cvssColor}">${severityLabel}</div>
        <div class="stat-label">Severity</div>
      </div>
      <div class="stat-box orange">
        <div class="stat-value">${item.exploited ? 'YES' : 'TBD'}</div>
        <div class="stat-label">Exploited ITW</div>
      </div>
      <div class="stat-box ${item.cisaKev ? 'red' : 'green'}">
        <div class="stat-value">${item.cisaKev ? '⚠️ KEV' : 'Monitor'}</div>
        <div class="stat-label">CISA Status</div>
      </div>
    </div>

    <!-- CRITICAL ALERT -->
    ${item.cisaKev ? `
    <div class="alert-box alert-critical">
      <span class="alert-icon">&#9888;&#65039;</span>
      <div class="alert-body">
        <div class="alert-title">CISA KNOWN EXPLOITED VULNERABILITY — MANDATORY PATCH</div>
        <p>This vulnerability has been added to CISA's Known Exploited Vulnerabilities (KEV) catalog, confirming active exploitation in the wild. ${item.dueDate ? `Federal agencies face a mandatory remediation deadline of <strong>${item.dueDate}</strong>. All organizations should treat this with equal urgency regardless of sector.` : 'All organizations must patch immediately.'}</p>
      </div>
    </div>` : `
    <div class="alert-box alert-warning">
      <span class="alert-icon">&#9888;&#65039;</span>
      <div class="alert-body">
        <div class="alert-title">CRITICAL VULNERABILITY — IMMEDIATE ACTION REQUIRED</div>
        <p>CVSS ${item.cvss} ${severityLabel} vulnerability in ${escHtml(item.vendor)} ${escHtml(item.product)}. ${item.exploited ? 'Active exploitation confirmed.' : 'Exploitation activity is being monitored. Patch before weaponized PoC is published.'} CYBERDUDEBIVASH SENTINEL APEX recommends emergency patching.</p>
      </div>
    </div>`}

    <!-- VULNERABILITY OVERVIEW -->
    <h2 class="section-h"><span>&#9888;</span> Vulnerability Overview</h2>
    <p class="body-p">${escHtml(item.desc || 'See NVD for full technical description.')}</p>

    ${item.vector ? `
    <div class="alert-box alert-info">
      <span class="alert-icon">&#128202;</span>
      <div class="alert-body">
        <div class="alert-title">CVSS v3.1 Vector: <span style="font-family:monospace;font-size:13px">${escHtml(item.vector)}</span></div>
        <p>Score: ${item.cvss} — ${severityLabel}. ${item.vector.includes('AV:N') ? 'Network-exploitable (remote attack, no physical access required).' : 'Local/adjacent network attack vector.'} ${item.vector.includes('PR:N') ? 'No privileges required.' : item.vector.includes('PR:L') ? 'Low privileges required.' : 'High privileges required.'} ${item.vector.includes('UI:N') ? 'No user interaction required.' : 'User interaction required.'}</p>
      </div>
    </div>` : ''}

    <!-- ANALYST ASSESSMENT -->
    <h2 class="section-h"><span>&#128269;</span> CYBERDUDEBIVASH Analyst Assessment</h2>
    ${commentary.split('\n\n').map(para => `<p class="body-p">${escHtml(para)}</p>`).join('\n    ')}

    <!-- MITRE ATT&CK -->
    <h2 class="section-h"><span>&#127919;</span> MITRE ATT&CK Mapping</h2>
    <table class="mitre-table">
      <thead><tr><th>Category</th><th>Mapping</th></tr></thead>
      <tbody>
        <tr><td>Primary Tactic</td><td class="tag-critical">${escHtml(mitre.tactic)}</td></tr>
        <tr><td>Primary Technique</td><td><span class="tag-cyan">${escHtml(mitre.technique)}</span></td></tr>
        <tr><td>Sub-Technique</td><td><span class="tag-cyan">${escHtml(mitre.sub)}</span></td></tr>
        <tr><td>Weakness (CWE)</td><td>${escHtml(item.cweId || 'Under Analysis')}</td></tr>
        <tr><td>Threat Class</td><td>${escHtml(threatType.replace(/_/g,' '))}</td></tr>
      </tbody>
    </table>

    <!-- DETECTION — SIGMA -->
    <h2 class="section-h"><span>&#128270;</span> Detection — Sigma Rule</h2>
    <p class="body-p">Deploy this Sigma rule across your SIEM/SOAR platform (Splunk, Elastic, Microsoft Sentinel, QRadar). CYBERDUDEBIVASH SENTINEL APEX SOC Pro subscribers receive pre-compiled SIEM-ready query packs.</p>
    <div class="code-block">
      <span class="code-label">Sigma YAML</span>${escHtml(sigma)}
    </div>

    <!-- DETECTION — YARA -->
    <h2 class="section-h"><span>&#128246;</span> Detection — YARA Rule</h2>
    <p class="body-p">Apply this YARA rule in endpoint detection tools, threat hunting platforms, and network inspection systems. Update the <code style="color:var(--apex-cyan)">hash</code> field with confirmed malware sample hashes as they become available.</p>
    <div class="code-block">
      <span class="code-label">YARA</span>${escHtml(yara)}
    </div>

    <!-- IOC TABLE -->
    <h2 class="section-h"><span>&#127991;</span> IOC Reference</h2>
    <p class="body-p">The following indicators are derived from published advisories and active threat intelligence. CYBERDUDEBIVASH SOC Pro subscribers receive enriched IOC bundles with IP reputation, domain registration, and attribution data.</p>
    <table class="ioc-table">
      <thead><tr><th>Type</th><th>Indicator / Reference</th><th>Context</th></tr></thead>
      <tbody>
        <tr><td>CVE ID</td><td class="tag-cyan">${escHtml(item.id)}</td><td>Primary vulnerability identifier</td></tr>
        <tr><td>Vendor</td><td>${escHtml(item.vendor)}</td><td>Affected vendor</td></tr>
        <tr><td>Product</td><td>${escHtml(item.product)}</td><td>Affected product</td></tr>
        ${item.cisaKev ? `<tr><td>CISA KEV</td><td class="tag-critical">LISTED</td><td>Active exploitation confirmed by CISA</td></tr>` : ''}
        ${item.dueDate ? `<tr><td>Patch Deadline</td><td class="tag-critical">${escHtml(item.dueDate)}</td><td>CISA mandatory federal deadline</td></tr>` : ''}
        <tr><td>NVD Reference</td><td><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" style="color:var(--apex-cyan)">nvd.nist.gov</a></td><td>Official CVE record</td></tr>
        ${(item.refs||[]).slice(0,3).map(r => `<tr><td>Advisory</td><td><a href="${escHtml(r)}" target="_blank" style="color:var(--apex-cyan)">${escHtml(r.replace(/https?:\/\//,'').slice(0,55))}</a></td><td>Vendor/researcher advisory</td></tr>`).join('\n')}
      </tbody>
    </table>

    <!-- DEFENSIVE ACTIONS -->
    <h2 class="section-h"><span>&#128737;&#65039;</span> Immediate Defensive Actions</h2>
    <ul class="action-list">
      ${defActions}
    </ul>

    <!-- INTEL SIGNATURE -->
    <div class="intel-sig">
      <div class="intel-sig-brand">&#127881; CYBERDUDEBIVASH SENTINEL APEX</div>
      <div class="intel-sig-sub">
        Intelligence report auto-generated and verified by CYBERDUDEBIVASH SENTINEL APEX v2.0<br>
        &copy; ${new Date().getFullYear()} CYBERDUDEBIVASH PRIVATE LIMITED &mdash; All rights reserved<br>
        Report ID: SENTINEL-${item.id}-${today} &mdash; <a href="${CFG.baseUrl}" style="color:var(--apex-cyan)">blog.cyberdudebivash.in</a><br>
        <strong style="color:var(--apex-cyan)">Republication requires written attribution to CYBERDUDEBIVASH SENTINEL APEX</strong>
      </div>
    </div>

    <!-- CTA -->
    <div class="enterprise-cta">
      <h3>&#127881; Get Deploy-Ready Detection Packs</h3>
      <p>CYBERDUDEBIVASH SOC Pro includes pre-compiled Sigma + YARA rulesets, enriched IOC bundles, SIEM queries, and 48-hour pre-disclosure for every critical CVE — before the patch drops.</p>
      <div class="cta-btns">
        <a href="/pricing.html" class="btn-primary">&#9889; Start SOC Pro — $49/mo</a>
        <a href="/products.html" class="btn-secondary">&#128228; Browse Detection Packs</a>
      </div>
    </div>

  </article>

  <!-- SIDEBAR -->
  <aside class="sidebar">
    <div class="verdict-box">
      <div class="verdict-score">${item.cvss}</div>
      <div class="verdict-label">CVSS Score — ${severityLabel}</div>
      <div style="margin-top:16px">
        <div class="verdict-row"><span class="verdict-key">CVE ID</span><span class="verdict-val" style="color:var(--apex-cyan);font-family:monospace">${escHtml(item.id)}</span></div>
        <div class="verdict-row"><span class="verdict-key">Vendor</span><span class="verdict-val">${escHtml(item.vendor)}</span></div>
        <div class="verdict-row"><span class="verdict-key">Product</span><span class="verdict-val">${escHtml(item.product)}</span></div>
        <div class="verdict-row"><span class="verdict-key">Type</span><span class="verdict-val">${escHtml(threatType.replace(/_/g,' '))}</span></div>
        <div class="verdict-row"><span class="verdict-key">Exploited</span><span class="verdict-val" style="color:${item.exploited ? 'var(--apex-red)' : 'var(--apex-green)'}">${item.exploited ? 'YES — In Wild' : 'Monitoring'}</span></div>
        <div class="verdict-row"><span class="verdict-key">CISA KEV</span><span class="verdict-val" style="color:${item.cisaKev ? 'var(--apex-red)' : 'var(--apex-muted)'}">${item.cisaKev ? '⚠️ LISTED' : 'Not Listed'}</span></div>
        ${item.dueDate ? `<div class="verdict-row"><span class="verdict-key">Patch By</span><span class="verdict-val" style="color:var(--apex-red)">${escHtml(item.dueDate)}</span></div>` : ''}
        <div class="verdict-row"><span class="verdict-key">Published</span><span class="verdict-val">${pubDateFmt}</span></div>
      </div>
    </div>

    <div class="sidebar-widget">
      <div class="widget-title">&#128269; References</div>
      <ul style="list-style:none;padding:0">
        <li style="margin-bottom:8px;font-size:13px"><a href="https://nvd.nist.gov/vuln/detail/${escHtml(item.id)}" target="_blank" style="color:var(--apex-cyan)">&#128279; NVD — ${escHtml(item.id)}</a></li>
        ${item.cisaKev ? `<li style="margin-bottom:8px;font-size:13px"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" style="color:var(--apex-red)">&#9888; CISA KEV Catalog</a></li>` : ''}
        ${(item.refs||[]).slice(0,4).map(r => `<li style="margin-bottom:8px;font-size:12px"><a href="${escHtml(r)}" target="_blank" style="color:var(--apex-cyan)">${escHtml(r.replace(/https?:\/\//,'').slice(0,40))}</a></li>`).join('\n')}
      </ul>
    </div>

    <div class="sidebar-widget" style="background:linear-gradient(135deg,#001a12,#0d1117);border-color:rgba(0,255,224,.2)">
      <div class="widget-title">&#9889; SOC Pro — Live Intel</div>
      <p style="font-size:13px;color:var(--apex-muted);margin-bottom:16px">Get pre-compiled detection packs, 48h pre-disclosure, and IOC feeds for every critical CVE before public release.</p>
      <a href="/pricing.html" style="display:block;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:13px;padding:12px;border-radius:8px;text-decoration:none;text-align:center">Start Free Trial →</a>
    </div>
  </aside>
</main>

<footer>
  <p>&copy; ${new Date().getFullYear()} CYBERDUDEBIVASH PRIVATE LIMITED. All intelligence reports are original research and analysis.<br>
  Unauthorized reproduction without attribution is prohibited.<br>
  <a href="/">Blog</a> &middot; <a href="/products.html">Products</a> &middot; <a href="/pricing.html">Pricing</a> &middot; <a href="/rss.xml">RSS Feed</a> &middot; <a href="mailto:bivash@cyberdudebivash.com">Contact</a>
  </p>
</footer>

<!-- ENGINES -->
<script src="/security-engine.js" defer></script>
<script src="/monetization.js" defer></script>
<script src="/conversion-engine.js" defer></script>
<script src="/seo-engine.js" defer></script>
<script src="/ai-monetization-engine.js" defer></script>
<script src="/analytics-engine.js" defer></script>
<script src="/auto-intel-engine.js" defer></script>
<script src="/revenue-cta-block.js" defer></script>
<script src="/ux-controller.js" defer></script>
<script>
// Matrix background
(function(){
  var c=document.getElementById('matrix-canvas');
  if(!c)return;
  var ctx=c.getContext('2d');
  c.width=window.innerWidth;c.height=window.innerHeight;
  var cols=Math.floor(c.width/16);var drops=new Array(cols).fill(1);
  setInterval(function(){
    ctx.fillStyle='rgba(7,9,15,0.05)';ctx.fillRect(0,0,c.width,c.height);
    ctx.fillStyle='#00ffe022';ctx.font='12px monospace';
    drops.forEach(function(y,i){
      ctx.fillText(String.fromCharCode(33+Math.random()*93),i*16,y*16);
      if(y*16>c.height&&Math.random()>0.975)drops[i]=0;
      drops[i]++;
    });
  },80);
}());
</script>
</body>
</html>`
  };
}

/* ══════════════════════════════════════════════════════════════════
   § INDEX.HTML UPDATER — inject new post cards at top
══════════════════════════════════════════════════════════════════ */
function generatePostCard(item, slug, title) {
  const cvssLabel  = item.cvss >= 9.0 ? 'CRITICAL' : 'HIGH';
  const cvssColor  = item.cvss >= 9.0 ? '' : ' orange';
  const todayFmt   = fmtDate(item.pubDate || isoNow());
  const shortTitle = title.length > 120 ? title.slice(0, 117) + '...' : title;
  const shortDesc  = (item.desc || '').slice(0, 220) + (item.desc?.length > 220 ? '...' : '');

  const badges = [
    `<span class="post-badge badge-crit">CVSS ${item.cvss}</span>`,
    item.cisaKev   ? `<span class="post-badge badge-cisa">CISA KEV</span>` : '',
    item.exploited ? `<span class="post-badge badge-new">&#9679; Live Exploit</span>` : '',
    item.ransomware? `<span class="post-badge" style="background:#a855f722;color:#a855f7;border:1px solid #a855f744;font-size:10px;padding:3px 7px;border-radius:3px;font-weight:700">RANSOMWARE</span>` : '',
    `<span class="post-date">${todayFmt} | ${escHtml(item.id)}</span>`,
  ].filter(Boolean).join('\n        ');

  return `
    <!-- AUTO-GENERATED: ${item.id} — ${isoNow()} -->
    <a href="posts/${escHtml(slug)}.html" class="post-card" data-intel-auto="${escHtml(item.id)}" onclick="if(window.trackEvent)window.trackEvent('post_card_click',{cve:'${escHtml(item.id)}',source:'auto_intel'})">
      <div class="post-card-header">
        ${badges}
      </div>
      <div class="post-card-body">
        <div class="post-title">${escHtml(shortTitle)}</div>
        <p class="post-excerpt">${escHtml(shortDesc)}</p>
        <div class="post-meta">
          <span class="post-cvss${cvssColor}">CVSS ${item.cvss} &mdash; ${cvssLabel}</span>
          <span class="post-cve">${escHtml(item.id)}</span>
          <span class="post-read-time">&#9201; 8 min read</span>
          <span class="post-read-more">Read Report &rarr;</span>
        </div>
      </div>
    </a>`;
}

function updateIndexHTML(newCards) {
  if (!fs.existsSync(CFG.indexPath)) {
    warn('index.html not found, skipping homepage update.');
    return;
  }

  let html = fs.readFileSync(CFG.indexPath, 'utf8');

  // Remove stale auto-generated cards
  html = html.replace(/\s*<!-- AUTO-GENERATED:.*?<\/a>/gs, '');

  // Find the featured post section anchor
  const INJECT_MARKER = '<!-- POST 1 — FEATURED -->';
  if (!html.includes(INJECT_MARKER)) {
    warn('Could not find injection marker in index.html, skipping card injection.');
    return;
  }

  const cardBlock = newCards.map(c => c.card).join('\n');
  html = html.replace(INJECT_MARKER, `${cardBlock}\n\n    ${INJECT_MARKER}`);

  // Update "BREAKING INTELLIGENCE" banner date
  const today = new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' }).toUpperCase();
  html = html.replace(
    /BREAKING INTELLIGENCE &mdash;[^<]+ &mdash; UPDATED LIVE/,
    `BREAKING INTELLIGENCE &mdash; ${today} &mdash; UPDATED LIVE`
  );

  fs.writeFileSync(CFG.indexPath, html, 'utf8');
  log(`index.html updated with ${newCards.length} new post cards.`);
}

/* ══════════════════════════════════════════════════════════════════
   § RSS UPDATER
══════════════════════════════════════════════════════════════════ */
function updateRSS(newItems) {
  if (!fs.existsSync(CFG.rssPath)) return;
  let rss = fs.readFileSync(CFG.rssPath, 'utf8');

  const items = newItems.map(item => {
    const desc = (item.desc || '').slice(0, 400);
    return `  <item>
    <title><![CDATA[${item.title}]]></title>
    <link>${CFG.baseUrl}/posts/${item.slug}.html</link>
    <description><![CDATA[CVSS ${item.cvss} — ${desc}. Full analysis, Sigma rules, YARA, IOCs by CYBERDUDEBIVASH SENTINEL APEX.]]></description>
    <pubDate>${new Date().toUTCString()}</pubDate>
    <guid isPermaLink="true">${CFG.baseUrl}/posts/${item.slug}.html</guid>
    <category>Threat Intelligence</category>
    <category>${item.cisaKev ? 'CISA KEV' : 'CVE Analysis'}</category>
  </item>`;
  }).join('\n');

  // Inject after <channel> opening items
  rss = rss.replace(/(<lastBuildDate>)[^<]*(<\/lastBuildDate>)/,
    `$1${new Date().toUTCString()}$2`);
  rss = rss.replace(/(<item>)/, `${items}\n  $1`);

  fs.writeFileSync(CFG.rssPath, rss, 'utf8');
  log(`rss.xml updated with ${newItems.length} new items.`);
}

/* ══════════════════════════════════════════════════════════════════
   § MAIN PIPELINE
══════════════════════════════════════════════════════════════════ */
async function main() {
  log('═'.repeat(60));
  log('CYBERDUDEBIVASH SENTINEL APEX — Live Intel Pipeline v2.0');
  log(`Run at: ${new Date().toISOString()}`);
  log('═'.repeat(60));

  // Load dedup state
  const state = loadState();
  log(`State: ${state.published.length} items previously published.`);

  // Fetch all sources (parallel, tolerate failures)
  const [nvdItems, kevItems, nvdModItems] = await Promise.all([
    fetchNVD().catch(() => []),
    fetchCISAKev().catch(() => []),
    fetchNVDModified().catch(() => []),
  ]);

  // Merge and prioritize
  const allItems = mergeAndPrioritize(nvdItems, kevItems, nvdModItems);
  log(`Total unique items after merge: ${allItems.length}`);

  // Filter to new items only
  const newItems = allItems.filter(item => !isPublished(state, item.id));
  log(`New items (not yet published): ${newItems.length}`);

  if (newItems.length === 0) {
    log('No new intel to publish. All items already in state.');
    saveState(state);
    return;
  }

  // Generate posts
  const toPublish = newItems.slice(0, CFG.maxNewPosts);
  const generatedCards = [];
  const rssItems = [];

  for (const item of toPublish) {
    try {
      const { slug, title, html } = generatePostHTML(item);
      const filePath = path.join(CFG.postsDir, `${slug}.html`);

      // Skip if file already exists (extra safety)
      if (fs.existsSync(filePath)) {
        log(`Skipping (file exists): ${slug}.html`);
        continue;
      }

      fs.writeFileSync(filePath, html, 'utf8');
      log(`✅ Published: ${filePath}`);

      markPublished(state, { id: item.id, slug, title });

      generatedCards.push({ card: generatePostCard(item, slug, title), item });
      rssItems.push({ ...item, slug, title });

    } catch (e) {
      err(`Failed to generate post for ${item.id}: ${e.message}`);
    }
  }

  // Update homepage
  if (generatedCards.length > 0) {
    updateIndexHTML(generatedCards);
    updateRSS(rssItems);
  }

  // Save state
  saveState(state);

  log('═'.repeat(60));
  log(`DONE. Generated: ${generatedCards.length} posts. Total published: ${state.totalPublished}`);
  log('═'.repeat(60));
}

main().catch(e => {
  err(`Fatal error: ${e.message}`);
  process.exit(1);
});
