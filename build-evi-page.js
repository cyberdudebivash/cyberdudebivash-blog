#!/usr/bin/env node
/**
 * Renders /research/exploitation-velocity-index.html from the EVI dataset.
 * The page is generated from data/exploitation-velocity-index.json so
 * displayed numbers are always identical to the machine-readable data.
 */
const fs = require('fs');
const D = JSON.parse(fs.readFileSync('/home/user/cyberdudebivash-blog/data/exploitation-velocity-index.json', 'utf8'));
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const BASE = 'https://blog.cyberdudebivash.in';

const cs = D.catalogSummary;
const vel = D.velocity;
const maxM = Math.max(...vel.monthly.map(m => m.additions));
const bars = vel.monthly.map(m => {
  const h = Math.round((m.additions / maxM) * 100);
  return `<div class="bar" title="${m.month}: ${m.additions} additions"><div class="bar-fill" style="height:${h}%"></div><span class="bar-lbl">${m.month.slice(2)}</span></div>`;
}).join('');

const vendorRows = D.topVendorsByRepresentation.map((v, i) => `<tr>
  <td>${i + 1}</td>
  <td style="color:#fff;font-weight:600">${esc(v.vendor)}</td>
  <td style="text-align:right;font-family:var(--mono);color:var(--apex-cyan)">${v.kevEntries}</td>
  <td style="text-align:right">${v.shareOfCatalogPct}%</td>
  <td style="text-align:right;color:${v.ransomwareSharePct >= 20 ? 'var(--apex-red)' : 'var(--apex-text)'}">${v.ransomwareSharePct}%</td>
  <td style="text-align:right;font-family:var(--mono)">${v.medianRemediationWindowDays}d</td>
</tr>`).join('\n');

const urgencyRows = D.highestUrgencyVendors.vendors.map((v, i) => `<tr>
  <td>${i + 1}</td>
  <td style="color:#fff;font-weight:600">${esc(v.vendor)}</td>
  <td style="text-align:right;font-family:var(--mono);color:var(--apex-orange)">${v.medianRemediationWindowDays} days</td>
  <td style="text-align:right">${v.kevEntries}</td>
</tr>`).join('\n');

const cweRows = D.topWeaknessCategories.map(c => `<tr>
  <td style="font-family:var(--mono);color:var(--apex-cyan)"><a href="https://cwe.mitre.org/data/definitions/${esc(c.cwe.replace('CWE-', ''))}.html" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${esc(c.cwe)}</a></td>
  <td style="text-align:right;font-family:var(--mono)">${c.count}</td>
  <td style="text-align:right">${c.sharePct}%</td>
</tr>`).join('\n');

const recentRows = D.recentAdditions.slice(0, 10).map(v => `<tr>
  <td style="font-family:var(--mono)"><a href="${esc(v.nvd)}" target="_blank" rel="noopener" style="color:var(--apex-cyan)">${esc(v.cveID)}</a></td>
  <td>${esc(v.vendor)}</td>
  <td>${esc(v.dateAdded)}</td>
  <td style="text-align:right;font-family:var(--mono)">${v.remediationWindowDays}d</td>
  <td style="text-align:center">${v.ransomware ? '<span style="color:var(--apex-red)">●</span>' : '<span style="color:var(--apex-muted)">—</span>'}</td>
</tr>`).join('\n');

const updated = D.generatedAt.slice(0, 10);

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="dns-prefetch" href="https://www.googletagmanager.com">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XTGLNMNNC7"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-XTGLNMNNC7',{page_title:document.title,page_location:window.location.href});</script>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#00ffe0">
<meta name="description" content="The Exploitation Velocity Index — original, reproducible analysis of the CISA Known Exploited Vulnerabilities catalog: vendor exposure, ransomware association, catalog growth velocity, and CISA remediation-urgency windows. Updated ${updated}.">
<meta name="keywords" content="CISA KEV analysis, known exploited vulnerabilities, exploitation velocity, vendor vulnerability exposure, ransomware CVE, remediation deadline, threat intelligence data">
<meta property="og:title" content="Exploitation Velocity Index — CISA KEV Analysis | CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:description" content="Original reproducible analysis of the CISA KEV catalog: vendor exposure, ransomware association, catalog velocity, and remediation-urgency windows.">
<meta property="og:type" content="article">
<meta property="og:url" content="${BASE}/research/exploitation-velocity-index.html">
<meta property="og:site_name" content="CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:image" content="${BASE}/og-image.png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Exploitation Velocity Index — CISA KEV Analysis">
<meta name="twitter:description" content="Original reproducible analysis of the CISA KEV catalog. Updated ${updated}.">
<meta name="twitter:image" content="${BASE}/og-image.png">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="${BASE}/research/exploitation-velocity-index.html">
<title>Exploitation Velocity Index — CISA KEV Analysis | CYBERDUDEBIVASH SENTINEL APEX</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Dataset","name":"Exploitation Velocity Index (EVI)","description":"Reproducible aggregate statistics derived from the official CISA Known Exploited Vulnerabilities catalog: vendor representation, ransomware association, catalog growth velocity, and CISA remediation-urgency windows.","url":"${BASE}/research/exploitation-velocity-index.html","license":"https://creativecommons.org/licenses/by/4.0/","creator":{"@type":"Organization","name":"CYBERDUDEBIVASH SENTINEL APEX","url":"${BASE}"},"isBasedOn":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","dateModified":"${updated}","distribution":[{"@type":"DataDownload","encodingFormat":"application/json","contentUrl":"${BASE}/data/exploitation-velocity-index.json"}]}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-green:#00ff88;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;line-height:1.7}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan)}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;gap:4px;flex-wrap:wrap}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px}.nlinks a:hover{color:var(--apex-text)}
main{max-width:960px;margin:0 auto;padding:44px 24px 80px}
.crumb{font-size:12px;color:var(--apex-muted);margin-bottom:16px}.crumb a{color:var(--apex-cyan);text-decoration:none}
.eyebrow{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--apex-cyan);background:#00ffe012;border:1px solid #00ffe033;border-radius:6px;padding:5px 12px;margin-bottom:16px}
h1{font-size:clamp(26px,4.4vw,40px);font-weight:900;line-height:1.15;color:#fff;margin-bottom:14px}
.lede{font-size:17px;color:#c9d1d9;margin-bottom:10px;max-width:70ch}
.dateline{font-size:13px;color:var(--apex-muted);font-family:var(--mono);margin:18px 0 30px;padding-bottom:20px;border-bottom:1px solid var(--apex-border)}
.dateline a{color:var(--apex-cyan);text-decoration:none}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:28px 0 36px}
.kpi{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:12px;padding:18px 20px}
.kpi .v{font-size:30px;font-weight:900;color:var(--apex-cyan);font-family:var(--mono);line-height:1}
.kpi.red .v{color:var(--apex-red)}.kpi.orange .v{color:var(--apex-orange)}
.kpi .l{font-size:12px;color:var(--apex-muted);margin-top:8px;line-height:1.4}
h2{font-size:22px;font-weight:800;color:#fff;margin:44px 0 8px}
h2 .n{color:var(--apex-cyan);font-family:var(--mono);font-size:16px;margin-right:8px}
.sec-note{font-size:14px;color:var(--apex-muted);margin-bottom:18px;max-width:74ch}
.chart{display:flex;align-items:flex-end;gap:6px;height:180px;padding:16px;background:var(--apex-card);border:1px solid var(--apex-border);border-radius:12px;overflow-x:auto}
.bar{flex:1;min-width:26px;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;gap:6px}
.bar-fill{width:70%;background:linear-gradient(180deg,var(--apex-cyan),#0099ff);border-radius:3px 3px 0 0;min-height:2px}
.bar-lbl{font-size:9px;color:var(--apex-muted);font-family:var(--mono);white-space:nowrap}
table{width:100%;border-collapse:collapse;margin:8px 0 8px;font-size:13.5px}
th{background:#1a2234;color:var(--apex-cyan);font-weight:700;padding:10px 12px;text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;border:1px solid var(--apex-border)}
td{padding:9px 12px;border:1px solid var(--apex-border);color:var(--apex-text)}
.tbl-wrap{overflow-x:auto;border-radius:10px}
.method{background:var(--apex-card);border:1px solid var(--apex-border);border-left:4px solid var(--apex-green);border-radius:12px;padding:22px 26px;margin:24px 0}
.method h3{font-size:14px;font-weight:800;color:var(--apex-green);letter-spacing:.05em;text-transform:uppercase;margin-bottom:12px}
.method p,.method li{font-size:14px;color:#c9d1d9}.method ul{margin:8px 0 8px 20px}.method li{margin-bottom:6px}
.method code{font-family:var(--mono);font-size:12.5px;color:var(--apex-cyan);background:#0a0e18;padding:1px 6px;border-radius:4px}
.cta{background:linear-gradient(135deg,#0a1428,#111827);border:1px solid #00ffe022;border-radius:16px;padding:28px;margin:44px 0 0;text-align:center}
.cta h3{font-size:20px;font-weight:900;color:#fff;margin-bottom:8px}.cta p{color:var(--apex-muted);margin-bottom:18px;font-size:14px}
.cta-row{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.btn-p{padding:12px 22px;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:14px;border-radius:8px;text-decoration:none}
.btn-s{padding:12px 22px;background:transparent;border:2px solid var(--apex-cyan);color:var(--apex-cyan);font-weight:700;font-size:14px;border-radius:8px;text-decoration:none}
a{color:var(--apex-cyan)}
footer{border-top:1px solid var(--apex-border);padding:28px 24px;text-align:center;font-size:13px;color:var(--apex-muted);margin-top:40px}
footer a{color:var(--apex-cyan);text-decoration:none}
</style>
</head>
<body>
<nav>
  <a class="nbrand" href="/"><span class="nlogo">CYBERDUDEBIVASH</span><span class="ntag">Sentinel APEX</span></a>
  <div class="nlinks"><a href="/">Reports</a><a href="/research">Research</a><a href="/detections">Detections</a><a href="/intelligence.html">Intelligence</a><a href="/pricing.html">Pricing</a><a href="/enterprise.html">Enterprise</a></div>
</nav>
<main>
  <div class="crumb"><a href="/">Home</a> › <a href="/research">Research</a> › Exploitation Velocity Index</div>
  <span class="eyebrow">Original Research · Reproducible Data</span>
  <h1>The Exploitation Velocity Index</h1>
  <p class="lede">A reproducible read on <em>which vendors actually get exploited in the wild</em> — derived entirely from the official CISA Known Exploited Vulnerabilities catalog, not from vendor marketing or estimated severity.</p>
  <p class="dateline">Dataset: CISA KEV catalog <strong>v${esc(D.catalogVersion)}</strong> · ${cs.totalKevEntries} entries · updated ${updated} · <a href="${BASE}/data/exploitation-velocity-index.json">Download JSON</a> · <a href="#methodology">Methodology</a></p>

  <div class="kpis">
    <div class="kpi"><div class="v">${cs.totalKevEntries}</div><div class="l">confirmed in-the-wild exploited CVEs in the catalog</div></div>
    <div class="kpi red"><div class="v">${cs.ransomwareLinkedSharePct}%</div><div class="l">linked to a known ransomware campaign (${cs.ransomwareLinkedEntries} CVEs)</div></div>
    <div class="kpi orange"><div class="v">${cs.medianRemediationWindowDays}d</div><div class="l">median CISA remediation window (add → federal deadline)</div></div>
    <div class="kpi"><div class="v">${vel.trailing12MonthAdditions}</div><div class="l">new exploited CVEs confirmed in the trailing 12 months</div></div>
  </div>

  <h2><span class="n">01</span>Catalog growth velocity</h2>
  <p class="sec-note">${esc(vel.note)} The trailing 12 months added <strong>${vel.trailing12MonthAdditions}</strong> entries versus <strong>${vel.prior12MonthAdditions}</strong> in the prior 12 (${vel.yoyChangePct >= 0 ? '+' : ''}${vel.yoyChangePct}% year-over-year). Each bar is one calendar month.</p>
  <div class="chart">${bars}</div>

  <h2><span class="n">02</span>Which vendors dominate real-world exploitation</h2>
  <p class="sec-note">Ranked by share of the entire KEV catalog. This is the single most useful patch-prioritization signal most teams ignore: exploitation is heavily concentrated. <strong>${esc(D.topVendorsByRepresentation[0].vendor)}</strong> alone accounts for ${D.topVendorsByRepresentation[0].shareOfCatalogPct}% of every confirmed in-the-wild exploited vulnerability CISA tracks.</p>
  <div class="tbl-wrap"><table>
    <thead><tr><th>#</th><th>Vendor</th><th style="text-align:right">KEV entries</th><th style="text-align:right">Catalog share</th><th style="text-align:right">Ransomware share</th><th style="text-align:right">Median deadline</th></tr></thead>
    <tbody>${vendorRows}</tbody>
  </table></div>

  <h2><span class="n">03</span>Highest assessed urgency — tightest deadlines</h2>
  <p class="sec-note">${esc(D.highestUrgencyVendors.note)}</p>
  <div class="tbl-wrap"><table>
    <thead><tr><th>#</th><th>Vendor</th><th style="text-align:right">Median remediation window</th><th style="text-align:right">KEV entries</th></tr></thead>
    <tbody>${urgencyRows}</tbody>
  </table></div>

  <h2><span class="n">04</span>Dominant weakness categories</h2>
  <p class="sec-note">The CWE classes most represented across exploited CVEs — where detection and secure-development effort pays off most.</p>
  <div class="tbl-wrap"><table>
    <thead><tr><th>CWE</th><th style="text-align:right">Count</th><th style="text-align:right">Catalog share</th></tr></thead>
    <tbody>${cweRows}</tbody>
  </table></div>

  <h2><span class="n">05</span>Most recent additions</h2>
  <p class="sec-note">The 10 most recently confirmed in-the-wild exploited CVEs. Detection content for the highest-priority entries is published in our <a href="/detections">detection pack</a>.</p>
  <div class="tbl-wrap"><table>
    <thead><tr><th>CVE</th><th>Vendor</th><th>Added</th><th style="text-align:right">Window</th><th style="text-align:center">Ransomware</th></tr></thead>
    <tbody>${recentRows}</tbody>
  </table></div>

  <h2 id="methodology"><span class="n">06</span>Methodology &amp; reproducibility</h2>
  <div class="method">
    <h3>✓ How every number on this page is produced</h3>
    <p>The Exploitation Velocity Index is computed directly from the primary source — the official CISA KEV catalog JSON feed — with no estimation, weighting, or editorial adjustment:</p>
    <ul>
      <li><strong>Source:</strong> <a href="${esc(D.primarySource)}" target="_blank" rel="noopener"><code>known_exploited_vulnerabilities.json</code></a> (CISA, public domain), catalog version <code>${esc(D.catalogVersion)}</code>.</li>
      <li><strong>Catalog share</strong> = a vendor's KEV entry count ÷ total catalog entries.</li>
      <li><strong>Ransomware share</strong> = entries where CISA's <code>knownRansomwareCampaignUse</code> field equals <code>"Known"</code> ÷ that vendor's entries. CISA-confirmed only; no inference.</li>
      <li><strong>Remediation window</strong> = <code>dueDate − dateAdded</code> in days, straight from the record. A shorter median window is CISA signalling higher assessed urgency.</li>
      <li><strong>Velocity</strong> = count of entries grouped by <code>dateAdded</code> calendar month.</li>
    </ul>
    <p>What this index deliberately does <strong>not</strong> claim: KEV contains no disclosure-to-exploitation timing, so we publish no such metric. Every figure here is reproducible by re-running the same computation against the same public feed. The machine-readable output is published under CC BY 4.0: <a href="${BASE}/data/exploitation-velocity-index.json">exploitation-velocity-index.json</a>.</p>
  </div>

  <div class="cta">
    <h3>Turn this data into detections</h3>
    <p>The concentration this index reveals is only useful if you can act on it. Our detection pack ships traceable Sigma rules for the highest-priority KEV entries — every rule linked to its CVE, KEV date, and vendor advisory.</p>
    <div class="cta-row">
      <a class="btn-p" href="/detections">View Detection Pack →</a>
      <a class="btn-s" href="/research">More Research →</a>
    </div>
  </div>
</main>
<footer>
  &copy; 2026 CYBERDUDEBIVASH ECOSYSTEM · Derived from CISA KEV (public domain) under CC BY 4.0 · <a href="/about.html">About</a> · <a href="/privacy.html">Privacy</a> · <a href="/terms.html">Terms</a> · <a href="/contact.html">Contact</a>
</footer>
</body>
</html>`;

fs.writeFileSync('/home/user/cyberdudebivash-blog/research/exploitation-velocity-index.html', html);
console.log('EVI page written:', html.length, 'bytes');
