#!/usr/bin/env node
/**
 * Builds the named-analyst research stream:
 *   /research/index.html                                  (research hub)
 *   /research/kev-exploitation-concentration-2026.html    (flagship report)
 *   /research/exploitation-velocity-index.html            (built separately)
 *
 * The flagship report draws its figures from the EVI dataset so the analysis
 * and the data never disagree. Authored under a named analyst with Person
 * author schema (closes the author-schema SEO gap).
 */
const fs = require('fs');
const D = JSON.parse(fs.readFileSync('/home/user/cyberdudebivash-blog/data/exploitation-velocity-index.json', 'utf8'));
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const BASE = 'https://blog.cyberdudebivash.in';
const AUTHOR = 'Bivash';
const AUTHOR_FULL = 'Bivash — Founder &amp; Principal Analyst';
const PUBDATE = '2026-07-05';

const cs = D.catalogSummary;
const v = D.topVendorsByRepresentation;
const ms = v[0], cisco = v[1];
const top5Share = Math.round((v.slice(0, 5).reduce((a, x) => a + x.kevEntries, 0) / cs.totalKevEntries) * 1000) / 10;
const top10Share = Math.round((v.slice(0, 10).reduce((a, x) => a + x.kevEntries, 0) / cs.totalKevEntries) * 1000) / 10;
const tightest = D.highestUrgencyVendors.vendors[0];

// ---------- Flagship report ----------
const report = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XTGLNMNNC7"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-XTGLNMNNC7',{page_title:document.title,page_location:window.location.href});</script>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#00ffe0">
<meta name="description" content="Real-world exploitation is extremely concentrated: the top 5 vendors account for ${top5Share}% of every CVE CISA confirms exploited in the wild. An analyst argument for prioritizing patches by KEV representation and ransomware association over raw CVSS.">
<meta name="keywords" content="KEV analysis, patch prioritization, exploitation concentration, ransomware CVE, CVSS alternative, vulnerability management, threat intelligence research">
<meta property="og:title" content="Exploitation Is Concentrated: Why Patch Prioritization Should Follow KEV, Not CVSS | CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:description" content="The top 5 vendors account for ${top5Share}% of every CVE CISA confirms exploited in the wild. A data-driven case for KEV-led patch prioritization.">
<meta property="og:type" content="article">
<meta property="og:url" content="${BASE}/research/kev-exploitation-concentration-2026.html">
<meta property="og:site_name" content="CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:image" content="${BASE}/og-image.png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta property="article:published_time" content="${PUBDATE}">
<meta property="article:author" content="${AUTHOR}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Exploitation Is Concentrated: Prioritize Patches by KEV, Not CVSS">
<meta name="twitter:description" content="Top 5 vendors = ${top5Share}% of all confirmed in-the-wild exploitation. The analyst case for KEV-led prioritization.">
<meta name="twitter:image" content="${BASE}/og-image.png">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="${BASE}/research/kev-exploitation-concentration-2026.html">
<title>Exploitation Is Concentrated: Why Patch Prioritization Should Follow KEV, Not CVSS | CYBERDUDEBIVASH SENTINEL APEX</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"AnalysisNewsArticle","headline":"Exploitation Is Concentrated: Why Patch Prioritization Should Follow KEV, Not CVSS","description":"The top 5 vendors account for ${top5Share}% of every CVE CISA confirms exploited in the wild — a data-driven case for KEV-led patch prioritization.","image":"${BASE}/og-image.png","datePublished":"${PUBDATE}","dateModified":"${PUBDATE}","author":{"@type":"Person","name":"${AUTHOR}","jobTitle":"Founder & Principal Analyst","worksFor":{"@type":"Organization","name":"CYBERDUDEBIVASH SENTINEL APEX"},"url":"${BASE}/about.html"},"publisher":{"@type":"Organization","name":"CYBERDUDEBIVASH SENTINEL APEX","url":"${BASE}"},"citation":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","isBasedOn":"${BASE}/research/exploitation-velocity-index.html"}</script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{"@type":"ListItem","position":1,"name":"Home","item":"${BASE}/"},{"@type":"ListItem","position":2,"name":"Research","item":"${BASE}/research"},{"@type":"ListItem","position":3,"name":"Exploitation Is Concentrated","item":"${BASE}/research/kev-exploitation-concentration-2026.html"}]}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-green:#00ff88;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;line-height:1.75}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan)}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;gap:4px;flex-wrap:wrap}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px}.nlinks a:hover{color:var(--apex-text)}
main{max-width:760px;margin:0 auto;padding:44px 24px 80px}
.crumb{font-size:12px;color:var(--apex-muted);margin-bottom:16px}.crumb a{color:var(--apex-cyan);text-decoration:none}
.eyebrow{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--apex-cyan);background:#00ffe012;border:1px solid #00ffe033;border-radius:6px;padding:5px 12px;margin-bottom:18px}
h1{font-size:clamp(27px,4.6vw,40px);font-weight:900;line-height:1.14;color:#fff;margin-bottom:18px;letter-spacing:-.01em}
.byline{display:flex;align-items:center;gap:12px;padding:18px 0;margin-bottom:8px;border-top:1px solid var(--apex-border);border-bottom:1px solid var(--apex-border)}
.avatar{width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,#00ffe0,#0099ff);display:flex;align-items:center;justify-content:center;font-weight:900;color:#000;font-size:18px;flex-shrink:0}
.byline .bmeta{font-size:13px;color:var(--apex-muted)}.byline .bname{color:#fff;font-weight:700;font-size:14px}
.byline a{color:var(--apex-cyan);text-decoration:none}
.summary{background:var(--apex-card);border:1px solid var(--apex-border);border-left:4px solid var(--apex-cyan);border-radius:12px;padding:20px 24px;margin:28px 0}
.summary h2{font-size:12px;font-weight:800;color:var(--apex-cyan);letter-spacing:.12em;text-transform:uppercase;margin-bottom:10px}
.summary p{font-size:15px;color:#c9d1d9}
p.body{font-size:16.5px;color:#d5dce6;margin-bottom:20px}
h2.sh{font-size:23px;font-weight:800;color:#fff;margin:40px 0 14px;letter-spacing:-.01em}
.pull{font-size:20px;font-weight:700;color:#fff;line-height:1.4;border-left:4px solid var(--apex-cyan);padding:6px 0 6px 20px;margin:28px 0}
.stat-inline{color:var(--apex-cyan);font-weight:800;font-family:var(--mono)}
ul.body{margin:0 0 20px 22px}ul.body li{font-size:16px;color:#d5dce6;margin-bottom:10px}
.takeaway{background:linear-gradient(135deg,#0a1220,#111827);border:1px solid rgba(0,255,136,.2);border-radius:12px;padding:22px 26px;margin:30px 0}
.takeaway h3{font-size:13px;font-weight:800;color:var(--apex-green);letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px}
.takeaway ol{margin:0 0 0 20px}.takeaway li{font-size:15px;color:#d5dce6;margin-bottom:8px}
.sources{background:var(--apex-card);border:1px solid var(--apex-border);border-left:4px solid var(--apex-green);border-radius:12px;padding:20px 24px;margin:32px 0}
.sources h3{font-size:13px;font-weight:800;color:var(--apex-green);letter-spacing:.06em;text-transform:uppercase;margin-bottom:12px}
.sources li{font-size:14px;margin-bottom:7px;margin-left:18px}
a{color:var(--apex-cyan)}
.cta{background:linear-gradient(135deg,#0a1428,#111827);border:1px solid #00ffe022;border-radius:16px;padding:26px;margin:36px 0 0;text-align:center}
.cta h3{font-size:19px;font-weight:900;color:#fff;margin-bottom:8px}.cta p{color:var(--apex-muted);margin-bottom:18px;font-size:14px}
.cta-row{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.btn-p{padding:12px 22px;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:14px;border-radius:8px;text-decoration:none}
.btn-s{padding:12px 22px;background:transparent;border:2px solid var(--apex-cyan);color:var(--apex-cyan);font-weight:700;font-size:14px;border-radius:8px;text-decoration:none}
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
  <div class="crumb"><a href="/">Home</a> › <a href="/research">Research</a> › Exploitation Concentration</div>
  <span class="eyebrow">Original Analysis</span>
  <h1>Exploitation Is Concentrated: Why Patch Prioritization Should Follow KEV, Not CVSS</h1>
  <div class="byline">
    <div class="avatar">B</div>
    <div class="bmeta"><span class="bname">${AUTHOR_FULL}</span>, CYBERDUDEBIVASH SENTINEL APEX<br>Published ${PUBDATE} · Analysis · <a href="/about.html">Editorial standards</a></div>
  </div>

  <div class="summary">
    <h2>Executive summary</h2>
    <p>Across the entire CISA Known Exploited Vulnerabilities catalog (<span class="stat-inline">${cs.totalKevEntries}</span> CVEs confirmed exploited in the wild), real-world exploitation is dramatically concentrated. The top five vendors account for <span class="stat-inline">${top5Share}%</span> of every entry; the top ten for <span class="stat-inline">${top10Share}%</span>. A vulnerability-management program that ranks work by CVSS treats a rarely-touched flaw and a mass-exploited one as equals. Ranking by KEV presence, ransomware association, and CISA's assigned remediation window does not.</p>
  </div>

  <p class="body">Every security team faces the same arithmetic: far more CVEs are published than any team can patch immediately, so something has to decide the order. For most organizations that "something" is still CVSS base score. It is the wrong instrument for the job — not because the score is inaccurate, but because it measures the wrong thing. CVSS estimates <em>how bad exploitation would be</em>. It says nothing about <em>whether exploitation is actually happening</em>. The CISA KEV catalog answers exactly that question, and when you analyze it in aggregate, the signal is unusually clean.</p>

  <h2 class="sh">Finding 1 — A handful of vendors carry most of the risk</h2>
  <p class="body">${esc(ms.vendor)} alone accounts for <span class="stat-inline">${ms.shareOfCatalogPct}%</span> of the entire catalog — <span class="stat-inline">${ms.kevEntries}</span> distinct CVEs confirmed exploited in the wild. ${esc(cisco.vendor)}, the next-largest, sits at ${cisco.shareOfCatalogPct}%. This is not a knock on any vendor; large install bases attract attackers. It is a planning fact: your exposure to <em>confirmed</em> exploitation is dominated by a small set of technologies, and your patch cadence for those should be structurally faster than for everything else.</p>
  <div class="pull">If you can only guarantee a rapid-patch SLA for a handful of product families, the KEV catalog tells you precisely which handful.</div>

  <h2 class="sh">Finding 2 — One in five exploited CVEs is ransomware-linked</h2>
  <p class="body"><span class="stat-inline">${cs.ransomwareLinkedSharePct}%</span> of catalog entries (<span class="stat-inline">${cs.ransomwareLinkedEntries}</span> CVEs) are flagged by CISA as used in known ransomware campaigns. For ${esc(ms.vendor)}, that share is <span class="stat-inline">${ms.ransomwareSharePct}%</span>. Ransomware association is the single most actionable enrichment in the catalog, because it maps a vulnerability directly to the outcome executives care about most. A KEV entry with a ransomware flag is not a patch ticket — it is a business-continuity control, and should be routed and escalated as one.</p>

  <h2 class="sh">Finding 3 — CISA's remediation windows are a free urgency signal</h2>
  <p class="body">Each KEV entry carries a federal remediation deadline. The median window across the catalog is <span class="stat-inline">${cs.medianRemediationWindowDays} days</span>, but it is not uniform: CISA assigns tighter deadlines to the threats it assesses as most urgent. ${esc(tightest.vendor)} entries carry a median window of just <span class="stat-inline">${tightest.medianRemediationWindowDays} days</span>. Most teams never look at this field. It is, in effect, a government-funded triage label sitting unused in a public feed.</p>

  <div class="takeaway">
    <h3>What to do with this</h3>
    <ol>
      <li><strong>Add a KEV gate to your VM workflow.</strong> Any CVE present in the KEV catalog jumps the queue regardless of CVSS. This is now US federal baseline (BOD 22-01); adopt it whether or not you are required to.</li>
      <li><strong>Structurally accelerate your top KEV vendors.</strong> Build a faster patch lane for the product families that dominate the catalog for <em>your</em> stack — for most organizations that starts with ${esc(ms.vendor)}.</li>
      <li><strong>Escalate the ransomware flag.</strong> Route ransomware-linked KEV entries to business-continuity owners, not just the patch queue.</li>
      <li><strong>Inherit CISA's deadlines.</strong> Use the remediation window as your internal SLA. It is a defensible, externally-sourced urgency label.</li>
      <li><strong>Detect while you patch.</strong> Patching takes time; deploy detections for KEV entries in parallel. Our <a href="/detections">detection pack</a> ships traceable Sigma rules for the highest-priority entries in this dataset.</li>
    </ol>
  </div>

  <p class="body">None of this requires a threat-intelligence subscription or a proprietary risk score. It requires treating a free, authoritative, public dataset as the prioritization backbone it already is. The full figures behind this analysis — vendor rankings, ransomware shares, remediation windows, and monthly velocity — are published as the <a href="/research/exploitation-velocity-index.html">Exploitation Velocity Index</a>, updated from the catalog and downloadable as JSON so you can reproduce every number here.</p>

  <div class="sources">
    <h3>✓ Sources &amp; reproducibility</h3>
    <ul>
      <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA Known Exploited Vulnerabilities Catalog</a> — primary dataset (v${esc(D.catalogVersion)})</li>
      <li><a href="https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities" target="_blank" rel="noopener">CISA BOD 22-01</a> — the directive establishing KEV remediation deadlines</li>
      <li><a href="/research/exploitation-velocity-index.html">Exploitation Velocity Index</a> — the derived dataset and full methodology behind every figure</li>
      <li><a href="${BASE}/data/exploitation-velocity-index.json">exploitation-velocity-index.json</a> — machine-readable data (CC BY 4.0)</li>
    </ul>
  </div>

  <div class="cta">
    <h3>Operationalize it</h3>
    <p>Traceable Sigma detections for the highest-priority KEV entries — every rule linked to its CVE, KEV date, and vendor advisory.</p>
    <div class="cta-row">
      <a class="btn-p" href="/detections">Detection Pack →</a>
      <a class="btn-s" href="/enterprise.html">Enterprise Advisory →</a>
    </div>
  </div>
</main>
<footer>
  &copy; 2026 CYBERDUDEBIVASH ECOSYSTEM · Analysis by ${AUTHOR}, CYBERDUDEBIVASH SENTINEL APEX · <a href="/about.html">About</a> · <a href="/privacy.html">Privacy</a> · <a href="/terms.html">Terms</a> · <a href="/contact.html">Contact</a>
</footer>
</body>
</html>`;
fs.writeFileSync('/home/user/cyberdudebivash-blog/research/kev-exploitation-concentration-2026.html', report);

// ---------- Research hub ----------
const REPORTS = [
  { url: '/research/kev-exploitation-concentration-2026.html', kicker: 'Analysis', date: PUBDATE,
    title: 'Exploitation Is Concentrated: Why Patch Prioritization Should Follow KEV, Not CVSS',
    desc: `The top 5 vendors account for ${top5Share}% of every CVE CISA confirms exploited in the wild. A data-driven case for KEV-led prioritization.` },
  { url: '/research/exploitation-velocity-index.html', kicker: 'Dataset · Updated monthly', date: PUBDATE,
    title: 'The Exploitation Velocity Index',
    desc: `Reproducible analysis of the CISA KEV catalog: vendor exposure, ransomware association, catalog velocity, and remediation-urgency windows. ${cs.totalKevEntries} entries.` },
];
const cards = REPORTS.map(r => `      <a class="rcard" href="${r.url}">
        <span class="rk">${esc(r.kicker)} · ${esc(r.date)}</span>
        <h2>${esc(r.title)}</h2>
        <p>${esc(r.desc)}</p>
        <span class="rmore">Read →</span>
      </a>`).join('\n');

const hub = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XTGLNMNNC7"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-XTGLNMNNC7',{page_title:document.title,page_location:window.location.href});</script>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#00ffe0">
<meta name="description" content="Original cyber threat intelligence research from CYBERDUDEBIVASH SENTINEL APEX — named-analyst analysis and reproducible datasets built on primary sources (CISA KEV, NVD, vendor advisories).">
<meta property="og:title" content="Research | CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:description" content="Named-analyst analysis and reproducible datasets built on primary sources.">
<meta property="og:type" content="website">
<meta property="og:url" content="${BASE}/research">
<meta property="og:site_name" content="CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:image" content="${BASE}/og-image.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Research | CYBERDUDEBIVASH SENTINEL APEX">
<meta name="twitter:description" content="Named-analyst analysis and reproducible datasets built on primary sources.">
<meta name="twitter:image" content="${BASE}/og-image.png">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="${BASE}/research">
<title>Research | CYBERDUDEBIVASH SENTINEL APEX</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"CollectionPage","name":"CYBERDUDEBIVASH SENTINEL APEX Research","description":"Original named-analyst threat intelligence research and reproducible datasets.","url":"${BASE}/research","dateModified":"${PUBDATE}"}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-bg:#07090f;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;line-height:1.7}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan)}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;gap:4px;flex-wrap:wrap}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px}.nlinks a:hover{color:var(--apex-text)}
main{max-width:820px;margin:0 auto;padding:44px 24px 80px}
.eyebrow{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--apex-cyan);background:#00ffe012;border:1px solid #00ffe033;border-radius:6px;padding:5px 12px;margin-bottom:16px}
h1{font-size:clamp(28px,4.6vw,42px);font-weight:900;color:#fff;margin-bottom:14px}
.lede{font-size:17px;color:#c9d1d9;margin-bottom:36px;max-width:70ch}
.rcard{display:block;background:var(--apex-card);border:1px solid var(--apex-border);border-radius:14px;padding:24px 26px;margin-bottom:16px;text-decoration:none;transition:border-color .2s}
.rcard:hover{border-color:#00ffe066}
.rk{font-size:12px;font-weight:700;color:var(--apex-cyan);font-family:var(--mono);letter-spacing:.04em}
.rcard h2{font-size:21px;font-weight:800;color:#fff;margin:8px 0 10px;line-height:1.3}
.rcard p{font-size:15px;color:#c9d1d9;margin-bottom:12px}
.rmore{font-size:14px;font-weight:700;color:var(--apex-cyan)}
.note{font-size:13.5px;color:var(--apex-muted);margin-top:28px;border-top:1px solid var(--apex-border);padding-top:20px}
.note a{color:var(--apex-cyan)}
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
  <span class="eyebrow">Research</span>
  <h1>Original Research</h1>
  <p class="lede">Named-analyst analysis and reproducible datasets, built entirely on primary sources — the CISA KEV catalog, NVD, and vendor advisories. Every figure is traceable; every dataset is downloadable.</p>
${cards}
  <p class="note">Our research is held to the sourcing and corrections standards described in <a href="/about.html">About &amp; Editorial Standards</a>. Datasets are published under CC BY 4.0. To discuss enterprise research or advisory work, <a href="/enterprise.html">get in touch</a>.</p>
</main>
<footer>
  &copy; 2026 CYBERDUDEBIVASH ECOSYSTEM · <a href="/about.html">About</a> · <a href="/privacy.html">Privacy</a> · <a href="/terms.html">Terms</a> · <a href="/contact.html">Contact</a>
</footer>
</body>
</html>`;
fs.writeFileSync('/home/user/cyberdudebivash-blog/research/index.html', hub);
console.log('Research report + hub written. top5Share=' + top5Share + '% top10Share=' + top10Share + '%');
