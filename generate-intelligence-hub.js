#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH® SENTINEL APEX — Intelligence Hub Generator
 *
 * Renders four public, no-auth intelligence surfaces entirely from data
 * the live ingestion pipeline (fetch-live-intel.js) already generates:
 *   /vendor/       — real vendor & open-source-ecosystem CVE aggregation
 *   /timeline/     — chronological feed of published intelligence
 *   /collections/  — curated topic groupings (Ransomware, AI Security, ...)
 *   /detections/live-feed.html — aggregated real per-article detection content
 *   /threat/       — index over the existing hand-authored threat-actor pages
 *
 * Every item on every page links back to an existing canonical page
 * (/cve/{id}.html or /posts/{slug}.html) — nothing here duplicates content,
 * and nothing here is fabricated. A collection/vendor with zero real
 * matches is simply omitted.
 *
 * Usage: node generate-intelligence-hub.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const {
  loadProducts, loadCves, loadCampaigns,
  buildVendorIndex, buildTimeline, buildCollections, buildDetectionLibrary,
  articlesMatching,
} = require('./api/_lib/intelligence-hub');
const { buildDynamicOgImageUrl } = require('./Sentinel-APEX/renderer/metadata-engine');

const ROOT = __dirname;
const BASE_URL = 'https://blog.cyberdudebivash.in';
const GA_ID = 'G-XTGLNMNNC7';
const BRAND = 'CYBERDUDEBIVASH SENTINEL APEX';
const GENERATED_ISO = new Date().toISOString();
const TODAY = GENERATED_ISO.slice(0, 10);

/* ═══════════════════════════════════════════════════════════════════
   SHARED HTML SHELL — design tokens match research/index.html so all
   generated hub pages look and feel like the rest of the site.
═══════════════════════════════════════════════════════════════════ */

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toISOString().slice(0, 10);
  } catch (_) {
    return '';
  }
}

function severityColor(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'CRITICAL') return '#ff3b5c';
  if (s === 'HIGH') return '#ff8c42';
  if (s === 'MEDIUM') return '#ffd23f';
  if (s === 'LOW') return '#22c55e';
  return '#6b7280';
}

function renderShell({ path: urlPath, title, description, eyebrow, h1, lede, bodyHtml, jsonLd, activeHref }) {
  const canonical = `${BASE_URL}${urlPath}`;
  // All 7 hub page types funnel through here, so this one call covers all
  // of them — previously every hub page shared the single static
  // og-image.png regardless of section (platform/social-preview-metadata-audit.md
  // root cause #4). `eyebrow` is already a clean per-section label
  // ("Vendor Intelligence", "Timeline", ...), reused as-is rather than
  // adding a new per-call-site parameter.
  const dynamicImage = buildDynamicOgImageUrl({ baseUrl: BASE_URL, title, type: eyebrow });
  const nav = [
    ['/', 'Reports'], ['/research', 'Research'], ['/detections', 'Detections'],
    ['/vendor/', 'Vendors'], ['/timeline/', 'Timeline'], ['/collections/', 'Collections'],
    ['/threat/', 'Threat Actors'], ['/intelligence.html', 'Intelligence'],
  ];
  const navHtml = nav.map(([href, label]) =>
    `<a href="${href}"${href === activeHref ? ' style="color:#fff"' : ''}>${esc(label)}</a>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<script async src="https://www.googletagmanager.com/gtag/js?id=${GA_ID}"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','${GA_ID}',{page_title:document.title,page_location:window.location.href});</script>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#00ffe0">
<meta name="description" content="${esc(description)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${canonical}">
<meta property="og:site_name" content="${BRAND}">
<meta property="og:image" content="${dynamicImage}">
<meta property="og:image:secure_url" content="${dynamicImage}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${esc(title)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(description)}">
<meta name="twitter:image" content="${dynamicImage}">
<meta name="twitter:image:alt" content="${esc(title)}">
<meta name="twitter:site" content="@cyberdudebivash">
<meta name="twitter:creator" content="@cyberdudebivash">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="${canonical}">
<title>${esc(title)}</title>
<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-bg:#07090f;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;line-height:1.7}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan)}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;gap:4px;flex-wrap:wrap}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px}.nlinks a:hover{color:var(--apex-text)}
main{max-width:900px;margin:0 auto;padding:44px 24px 80px}
.eyebrow{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--apex-cyan);background:#00ffe012;border:1px solid #00ffe033;border-radius:6px;padding:5px 12px;margin-bottom:16px}
h1{font-size:clamp(28px,4.6vw,42px);font-weight:900;color:#fff;margin-bottom:14px}
.lede{font-size:17px;color:#c9d1d9;margin-bottom:36px;max-width:70ch}
.rcard{display:block;background:var(--apex-card);border:1px solid var(--apex-border);border-radius:14px;padding:20px 24px;margin-bottom:14px;text-decoration:none;transition:border-color .2s}
.rcard:hover{border-color:#00ffe066}
.rk{font-size:12px;font-weight:700;color:var(--apex-cyan);font-family:var(--mono);letter-spacing:.04em}
.rcard h2{font-size:19px;font-weight:800;color:#fff;margin:8px 0 8px;line-height:1.3}
.rcard p{font-size:14px;color:#c9d1d9;margin-bottom:8px}
.rmore{font-size:13px;font-weight:700;color:var(--apex-cyan)}
.badge{display:inline-block;font-size:11px;font-weight:800;padding:3px 9px;border-radius:20px;margin-right:6px;font-family:var(--mono)}
.stat-row{display:flex;gap:18px;flex-wrap:wrap;margin:6px 0 10px}
.stat{font-size:12.5px;color:var(--apex-muted);font-family:var(--mono)}
.stat b{color:#fff}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.note{font-size:13.5px;color:var(--apex-muted);margin-top:28px;border-top:1px solid var(--apex-border);padding-top:20px}
.note a{color:var(--apex-cyan)}
.empty-state{color:var(--apex-muted);font-size:14px;padding:20px 0}
footer{border-top:1px solid var(--apex-border);padding:28px 24px;text-align:center;font-size:13px;color:var(--apex-muted);margin-top:40px}
footer a{color:var(--apex-cyan);text-decoration:none}
code.rule-preview{display:block;background:#050709;border:1px solid var(--apex-border);border-radius:8px;padding:10px 12px;font-family:var(--mono);font-size:12px;color:#9ae6b4;white-space:pre-wrap;word-break:break-word;margin-top:8px}
</style>
</head>
<body>
<nav>
  <a class="nbrand" href="/"><span class="nlogo">CYBERDUDEBIVASH</span><span class="ntag">Sentinel APEX</span></a>
  <div class="nlinks">${navHtml}</div>
</nav>
<main>
  <span class="eyebrow">${esc(eyebrow)}</span>
  <h1>${esc(h1)}</h1>
  <p class="lede">${lede}</p>
  ${bodyHtml}
</main>
<footer>
  &copy; 2026 CYBERDUDEBIVASH ECOSYSTEM · <a href="/about.html">About</a> · <a href="/privacy.html">Privacy</a> · <a href="/terms.html">Terms</a> · <a href="/contact.html">Contact</a>
</footer>
</body>
</html>
`;
}

/* ═══════════════════════════════════════════════════════════════════
   VENDOR / ECOSYSTEM INTELLIGENCE CENTERS
═══════════════════════════════════════════════════════════════════ */

function renderVendorIndex(vendors) {
  const cards = vendors.map((v) => `
      <a class="rcard" href="/vendor/${v.slug}.html">
        <span class="rk">${v.count} tracked CVE${v.count === 1 ? '' : 's'}</span>
        <h2>${esc(v.name)}</h2>
        <div class="stat-row">
          <span class="stat">KEV: <b>${v.kevCount}</b></span>
          <span class="stat">Exploited: <b>${v.exploitedCount}</b></span>
          <span class="stat">Critical (CVSS≥9): <b>${v.criticalCount}</b></span>
        </div>
        <span class="rmore">View vendor intelligence →</span>
      </a>`).join('\n');

  const body = vendors.length
    ? `<div class="grid" style="display:block">${cards}</div>`
    : `<p class="empty-state">No vendor-attributed CVEs currently meet our inclusion criteria. Check back as new intelligence is ingested.</p>`;

  return renderShell({
    path: '/vendor/',
    title: `Vendor & Ecosystem Intelligence Centers | ${BRAND}`,
    description: 'Real, vendor-attributed CVE intelligence — technology vendors and open-source package ecosystems (npm, PyPI, Go, Maven) tracked by CYBERDUDEBIVASH SENTINEL APEX.',
    eyebrow: 'Vendor Intelligence',
    h1: 'Vendor & Ecosystem Intelligence Centers',
    lede: `Real CVE intelligence grouped by the technology vendor or open-source package ecosystem it actually affects — never by news source. ${vendors.length} vendor${vendors.length === 1 ? '' : 's'}/ecosystems currently tracked.`,
    bodyHtml: body,
    activeHref: '/vendor/',
    jsonLd: {
      '@context': 'https://schema.org', '@type': 'CollectionPage',
      name: 'Vendor & Ecosystem Intelligence Centers', url: `${BASE_URL}/vendor/`, dateModified: TODAY,
    },
  });
}

function renderVendorDetail(vendor) {
  const rows = vendor.items
    .sort((a, b) => (b.cvss || 0) - (a.cvss || 0))
    .map((i) => `
      <a class="rcard" href="${i.url}">
        <span class="rk">${esc(i.id)}${i.cvss != null ? ` · CVSS ${i.cvss}` : ''}</span>
        <h2>${esc(i.title)}</h2>
        <div class="stat-row">
          ${i.cisaKev ? '<span class="badge" style="background:#ff3b5c22;color:#ff3b5c;border:1px solid #ff3b5c55">CISA KEV</span>' : ''}
          ${i.exploited ? '<span class="badge" style="background:#ff8c4222;color:#ff8c42;border:1px solid #ff8c4255">EXPLOITED</span>' : ''}
        </div>
        <span class="rmore">View CVE report →</span>
      </a>`).join('\n');

  return renderShell({
    path: `/vendor/${vendor.slug}.html`,
    title: `${vendor.name} CVE & Vulnerability Intelligence | ${BRAND}`,
    description: `${vendor.count} real tracked CVE(s) affecting ${vendor.name}, including CISA KEV status and exploitation activity — from CYBERDUDEBIVASH SENTINEL APEX.`,
    eyebrow: 'Vendor Intelligence',
    h1: `${vendor.name}`,
    lede: `${vendor.count} tracked CVE${vendor.count === 1 ? '' : 's'} · ${vendor.kevCount} in CISA KEV · ${vendor.exploitedCount} confirmed exploited in the wild.`,
    bodyHtml: rows,
    activeHref: '/vendor/',
    jsonLd: {
      '@context': 'https://schema.org', '@type': 'CollectionPage',
      name: `${vendor.name} CVE Intelligence`, url: `${BASE_URL}/vendor/${vendor.slug}.html`, dateModified: TODAY,
    },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   TIMELINE ENGINE
═══════════════════════════════════════════════════════════════════ */

function renderTimelineIndex(items) {
  const rows = items.map((i) => `
      <a class="rcard" href="${i.url}">
        <span class="rk">${formatDate(i.generated)}${i.severity ? ` · <span style="color:${severityColor(i.severity)}">${esc(i.severity)}</span>` : ''}</span>
        <h2>${esc(i.title)}</h2>
        <div class="stat-row">
          ${i.cves.slice(0, 3).map((c) => `<span class="stat">${esc(c)}</span>`).join('')}
          ${i.cisaKev ? '<span class="badge" style="background:#ff3b5c22;color:#ff3b5c;border:1px solid #ff3b5c55">CISA KEV</span>' : ''}
        </div>
      </a>`).join('\n');

  return renderShell({
    path: '/timeline/',
    title: `Threat Intelligence Timeline | ${BRAND}`,
    description: 'Real-time chronological feed of every threat intelligence report published by CYBERDUDEBIVASH SENTINEL APEX — CVEs, ransomware, APT activity, and AI security.',
    eyebrow: 'Timeline',
    h1: 'Intelligence Timeline',
    lede: `A real, chronological record of every report as it was published — ${items.length} most-recent entries. Refreshed automatically as new intelligence is ingested.`,
    bodyHtml: items.length ? rows : '<p class="empty-state">No timeline entries available yet.</p>',
    activeHref: '/timeline/',
    jsonLd: {
      '@context': 'https://schema.org', '@type': 'CollectionPage',
      name: 'CYBERDUDEBIVASH SENTINEL APEX Timeline', url: `${BASE_URL}/timeline/`, dateModified: TODAY,
    },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   INTELLIGENCE COLLECTIONS
═══════════════════════════════════════════════════════════════════ */

function renderCollectionsIndex(collections) {
  const cards = collections.map((c) => `
      <a class="rcard" href="/collections/${c.slug}.html">
        <span class="rk">${c.count} report${c.count === 1 ? '' : 's'}${c.activeCampaigns.length ? ` · ${c.activeCampaigns.length} active correlated campaign${c.activeCampaigns.length === 1 ? '' : 's'}` : ''}</span>
        <h2>${esc(c.name)}</h2>
        <p>${esc(c.description)}</p>
        <span class="rmore">Browse collection →</span>
      </a>`).join('\n');

  return renderShell({
    path: '/collections/',
    title: `Intelligence Collections | ${BRAND}`,
    description: 'Curated threat intelligence collections — Ransomware, AI Security, Supply Chain, Nation-State APT, CISA KEV, and Cloud/DevSecOps — from CYBERDUDEBIVASH SENTINEL APEX.',
    eyebrow: 'Collections',
    h1: 'Intelligence Collections',
    lede: 'Curated groupings of real, already-published intelligence by topic. A collection only appears here when it contains real matching reports — nothing is pre-populated or fabricated.',
    bodyHtml: collections.length ? cards : '<p class="empty-state">No collections currently have matching intelligence.</p>',
    activeHref: '/collections/',
    jsonLd: {
      '@context': 'https://schema.org', '@type': 'CollectionPage',
      name: 'CYBERDUDEBIVASH SENTINEL APEX Intelligence Collections', url: `${BASE_URL}/collections/`, dateModified: TODAY,
    },
  });
}

function renderCollectionDetail(c) {
  const campaignHtml = c.activeCampaigns.length ? `
    <div class="note" style="border:1px solid var(--apex-border);border-radius:12px;padding:16px 20px;margin-bottom:24px">
      <strong style="color:var(--apex-cyan)">⚡ ${c.activeCampaigns.length} Active Correlated Campaign${c.activeCampaigns.length === 1 ? '' : 's'}</strong>
      <p style="margin-top:6px">Detected by the SENTINEL APEX campaign clustering engine — items in this collection share overlapping IOCs, CVEs, or actor TTPs.</p>
    </div>` : '';

  const rows = c.items.map((i) => `
      <a class="rcard" href="${i.url}">
        <span class="rk">${formatDate(i.generated)}${i.severity ? ` · <span style="color:${severityColor(i.severity)}">${esc(i.severity)}</span>` : ''}</span>
        <h2>${esc(i.title)}</h2>
        ${i.cves.length ? `<div class="stat-row">${i.cves.slice(0, 4).map((cv) => `<span class="stat">${esc(cv)}</span>`).join('')}</div>` : ''}
      </a>`).join('\n');

  return renderShell({
    path: `/collections/${c.slug}.html`,
    title: `${c.name} | ${BRAND}`,
    description: `${c.description} ${c.count} real reports currently in this collection.`,
    eyebrow: 'Collections',
    h1: c.name,
    lede: c.description,
    bodyHtml: campaignHtml + rows,
    activeHref: '/collections/',
    jsonLd: {
      '@context': 'https://schema.org', '@type': 'CollectionPage',
      name: c.name, url: `${BASE_URL}/collections/${c.slug}.html`, dateModified: TODAY,
    },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   DETECTION ENGINEERING LIBRARY — LIVE FEED
═══════════════════════════════════════════════════════════════════ */

function renderDetectionsLiveFeed(items) {
  const rows = items.map((i) => {
    const engines = [];
    if (i.sigma.length) engines.push(`Sigma (${i.sigma.length})`);
    if (i.kql.length) engines.push(`KQL (${i.kql.length})`);
    if (i.splunk.length) engines.push(`Splunk (${i.splunk.length})`);
    if (i.osquery.length) engines.push(`osquery (${i.osquery.length})`);
    if (i.suricata.length) engines.push(`Suricata (${i.suricata.length})`);
    return `
      <a class="rcard" href="${i.url}">
        <span class="rk">${formatDate(i.generated)}${i.severity ? ` · <span style="color:${severityColor(i.severity)}">${esc(i.severity)}</span>` : ''}</span>
        <h2>${esc(i.title)}</h2>
        <div class="stat-row">
          ${engines.map((e) => `<span class="badge" style="background:#00ffe012;color:var(--apex-cyan);border:1px solid #00ffe033">${esc(e)}</span>`).join('')}
        </div>
        ${i.mitreAttack.length ? `<p style="font-size:12.5px;color:var(--apex-muted)">MITRE ATT&amp;CK: ${i.mitreAttack.slice(0, 6).map(esc).join(', ')}</p>` : ''}
        <span class="rmore">View full report + detection content →</span>
      </a>`;
  }).join('\n');

  const body = `
    <p class="note" style="border:none;padding-top:0;margin-top:0">
      This live feed aggregates real detection content (Sigma, KQL, Splunk, osquery, Suricata) generated
      alongside individual intelligence reports as they are published. For the 8 hand-curated flagship
      Sigma rules covering major CISA KEV vulnerabilities, see the <a href="/detections">Detection Engineering hub</a>.
    </p>
    ${items.length ? rows : '<p class="empty-state">No live detection content is currently available.</p>'}`;

  return renderShell({
    path: '/detections/live-feed.html',
    title: `Live Detection Engineering Feed | ${BRAND}`,
    description: 'Real Sigma, KQL, Splunk, osquery, and Suricata detection content, aggregated live from every CYBERDUDEBIVASH SENTINEL APEX intelligence report as it publishes.',
    eyebrow: 'Detection Engineering',
    h1: 'Live Detection Feed',
    lede: `${items.length} report${items.length === 1 ? '' : 's'} with real, generated multi-format detection content — refreshed automatically as new intelligence is ingested.`,
    bodyHtml: body,
    activeHref: '/detections',
    jsonLd: {
      '@context': 'https://schema.org', '@type': 'CollectionPage',
      name: 'CYBERDUDEBIVASH SENTINEL APEX Live Detection Feed', url: `${BASE_URL}/detections/live-feed.html`, dateModified: TODAY,
    },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   THREAT ACTOR INDEX — aggregates the existing hand-authored pages,
   never re-authors actor intelligence content itself (fabrication risk).
═══════════════════════════════════════════════════════════════════ */

const KNOWN_ACTOR_PAGES = [
  { slug: 'lockbit', name: 'LockBit', pattern: /lockbit/i },
  { slug: 'akira', name: 'Akira', pattern: /\bakira\b/i },
  { slug: 'qilin', name: 'Qilin', pattern: /\bqilin\b/i },
  { slug: 'volt-typhoon', name: 'Volt Typhoon', pattern: /volt typhoon/i },
  { slug: 'apt28', name: 'APT28', pattern: /apt ?28|fancy bear/i },
  { slug: 'lazarus', name: 'Lazarus Group', pattern: /lazarus/i },
];

function renderThreatIndex(products) {
  const cards = KNOWN_ACTOR_PAGES.map((actor) => {
    const recent = articlesMatching(products, actor.pattern, { limit: 3 });
    const recentHtml = recent.length
      ? `<div class="stat-row" style="flex-direction:column;gap:4px;align-items:flex-start">
          ${recent.map((r) => `<a href="${r.url}" style="font-size:12.5px;color:var(--apex-muted)">→ ${esc(r.title)} <span style="color:var(--apex-muted)">(${formatDate(r.generated)})</span></a>`).join('')}
        </div>`
      : '';
    return `
      <a class="rcard" href="/threat/${actor.slug}.html" style="text-decoration:none">
        <span class="rk">Threat Actor Profile</span>
        <h2>${esc(actor.name)}</h2>
        ${recentHtml}
        <span class="rmore">View full profile →</span>
      </a>`;
  }).join('\n');

  return renderShell({
    path: '/threat/',
    title: `Threat Actor Intelligence | ${BRAND}`,
    description: 'Threat actor profiles tracked by CYBERDUDEBIVASH SENTINEL APEX — ransomware groups and nation-state APT crews, cross-linked to real recent coverage.',
    eyebrow: 'Threat Actors',
    h1: 'Threat Actor Intelligence',
    lede: 'Profiles for ransomware groups and nation-state threat actors CYBERDUDEBIVASH SENTINEL APEX actively tracks, cross-linked to our most recent real coverage of each.',
    bodyHtml: cards,
    activeHref: '/threat/',
    jsonLd: {
      '@context': 'https://schema.org', '@type': 'CollectionPage',
      name: 'CYBERDUDEBIVASH SENTINEL APEX Threat Actor Intelligence', url: `${BASE_URL}/threat/`, dateModified: TODAY,
    },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   SITEMAP — idempotent append of new hub URLs only.
═══════════════════════════════════════════════════════════════════ */

function updateSitemap(urls) {
  const sitemapPath = path.join(ROOT, 'sitemap.xml');
  let xml;
  try {
    xml = fs.readFileSync(sitemapPath, 'utf8');
  } catch (_) {
    return; // sitemap.xml missing — leave to the pipeline that owns it
  }
  if (!xml.includes('</urlset>')) return;

  const missing = urls.filter((u) => !xml.includes(`<loc>${u}</loc>`));
  if (!missing.length) return;

  const entries = missing.map((loc) =>
    `  <url>\n    <loc>${loc}</loc>\n    <lastmod>${TODAY}</lastmod>\n    <changefreq>daily</changefreq>\n    <priority>0.7</priority>\n  </url>\n`).join('');
  xml = xml.replace('</urlset>', `${entries}</urlset>`);
  fs.writeFileSync(sitemapPath, xml, 'utf8');
  console.log(`✅ sitemap.xml: added ${missing.length} new hub URL(s)`);
}

/* ═══════════════════════════════════════════════════════════════════
   MAIN
═══════════════════════════════════════════════════════════════════ */

function writeFile(relPath, content) {
  const full = path.join(ROOT, relPath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, 'utf8');
}

function main() {
  console.log(`🛰 Intelligence Hub generation started — ${GENERATED_ISO}`);

  const products = loadProducts();
  const cves = loadCves();
  const campaigns = loadCampaigns();
  console.log(`   Loaded ${products.length} products, ${cves.length} CVEs, ${campaigns.length} campaigns`);

  /* ── Vendor / Ecosystem Intelligence Centers ─────────────────── */
  const vendors = buildVendorIndex(cves, { minItems: 1 });
  writeFile('api/intel/vendors.json', JSON.stringify({
    generated: GENERATED_ISO, platform: BRAND, count: vendors.length,
    vendors: vendors.map((v) => ({ slug: v.slug, name: v.name, count: v.count, kevCount: v.kevCount, exploitedCount: v.exploitedCount, criticalCount: v.criticalCount })),
  }, null, 2));
  for (const v of vendors) {
    writeFile(`api/intel/vendor/${v.slug}.json`, JSON.stringify({ generated: GENERATED_ISO, platform: BRAND, ...v }, null, 2));
    writeFile(`vendor/${v.slug}.html`, renderVendorDetail(v));
  }
  writeFile('vendor/index.html', renderVendorIndex(vendors));
  console.log(`   ✅ Vendor Intelligence Centers: ${vendors.length} vendor/ecosystem pages`);

  /* ── Timeline Engine ──────────────────────────────────────────── */
  const timeline = buildTimeline(products, { limit: 300 });
  writeFile('api/intel/timeline.json', JSON.stringify({ generated: GENERATED_ISO, platform: BRAND, count: timeline.length, items: timeline }, null, 2));
  writeFile('timeline/index.html', renderTimelineIndex(timeline));
  console.log(`   ✅ Timeline Engine: ${timeline.length} entries`);

  /* ── Intelligence Collections ─────────────────────────────────── */
  const collections = buildCollections(products, campaigns);
  writeFile('api/intel/collections.json', JSON.stringify({ generated: GENERATED_ISO, platform: BRAND, count: collections.length, collections }, null, 2));
  for (const c of collections) {
    writeFile(`collections/${c.slug}.html`, renderCollectionDetail(c));
  }
  writeFile('collections/index.html', renderCollectionsIndex(collections));
  console.log(`   ✅ Intelligence Collections: ${collections.length} populated collections`);

  /* ── Detection Engineering Library — live feed ───────────────── */
  const detectionLib = buildDetectionLibrary(products, { limit: 200 });
  writeFile('api/intel/detections-library.json', JSON.stringify({ generated: GENERATED_ISO, platform: BRAND, count: detectionLib.length, items: detectionLib }, null, 2));
  writeFile('detections/live-feed.html', renderDetectionsLiveFeed(detectionLib));
  console.log(`   ✅ Detection Library live feed: ${detectionLib.length} reports with real detection content`);

  /* ── Threat Actor Index ───────────────────────────────────────── */
  writeFile('threat/index.html', renderThreatIndex(products));
  console.log(`   ✅ Threat actor index: ${KNOWN_ACTOR_PAGES.length} profiles indexed`);

  /* ── Sitemap ──────────────────────────────────────────────────── */
  const hubUrls = [
    `${BASE_URL}/vendor/`, `${BASE_URL}/timeline/`, `${BASE_URL}/collections/`,
    `${BASE_URL}/detections/live-feed.html`, `${BASE_URL}/threat/`,
    ...vendors.map((v) => `${BASE_URL}/vendor/${v.slug}.html`),
    ...collections.map((c) => `${BASE_URL}/collections/${c.slug}.html`),
  ];
  updateSitemap(hubUrls);

  console.log('🛰 Intelligence Hub generation complete.');
}

if (require.main === module) {
  main();
}

module.exports = { main, renderShell };
