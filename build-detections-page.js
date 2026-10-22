#!/usr/bin/env node
const fs = require('fs');
const M = JSON.parse(fs.readFileSync('/tmp/detections-manifest.json', 'utf8'));
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const BASE = 'https://blog.cyberdudebivash.in';
const updated = '2026-07-05';

const cards = M.map(d => `    <article class="rule">
      <div class="rule-head">
        <span class="lvl lvl-${d.level}">${d.level.toUpperCase()}</span>
        ${d.ransomware ? '<span class="rw">🏴 RANSOMWARE-LINKED</span>' : ''}
        <a class="cve" href="https://nvd.nist.gov/vuln/detail/${esc(d.cve)}" target="_blank" rel="noopener">${esc(d.cve)}</a>
      </div>
      <h3>${esc(d.title.replace(/ \(CVE-[0-9-]+\)$/, ''))}</h3>
      <p class="rd">${esc(d.desc)}</p>
      <div class="trace">
        <span><strong>Vendor:</strong> ${esc(d.vendor)} · ${esc(d.product)}</span>
        <span><strong>CISA KEV:</strong> added ${esc(d.kevAdded)} · due ${esc(d.kevDue)}</span>
        <span><strong>ATT&amp;CK:</strong> ${esc(d.tactic.filter(t => t.startsWith('attack.t1')).map(t => t.replace('attack.', '').toUpperCase()).join(', ') || '—')}</span>
      </div>
      <div class="rule-actions">
        <a class="dl" href="/detections/rules/${esc(d.fname)}" download>⬇ Download Sigma rule</a>
        <a class="src" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">Verify in KEV →</a>
      </div>
    </article>`).join('\n');

const critical = M.filter(d => d.level === 'critical').length;
const ransom = M.filter(d => d.ransomware).length;

const html = `<!DOCTYPE html>
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
<meta name="description" content="Traceable Sigma detection pack for actively-exploited CISA KEV vulnerabilities. Every rule links to its CVE, KEV catalog entry, and vendor advisory. Free, verifiable, SIEM-ready. Updated ${updated}.">
<meta name="keywords" content="Sigma rules, detection engineering, CISA KEV detection, SIEM rules, threat detection, SharePoint RCE detection, Ivanti detection, Splunk detection">
<meta property="og:title" content="Traceable Detection Pack — Sigma Rules for KEV CVEs | CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:description" content="Traceable Sigma detection rules for actively-exploited KEV vulnerabilities. Every rule linked to its CVE, KEV entry, and vendor advisory.">
<meta property="og:type" content="website">
<meta property="og:url" content="${BASE}/detections">
<meta property="og:site_name" content="CYBERDUDEBIVASH SENTINEL APEX">
<meta property="og:image" content="${BASE}/og-image.png">
<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Traceable Detection Pack — Sigma Rules for KEV CVEs">
<meta name="twitter:description" content="Every rule linked to its CVE, KEV entry, and vendor advisory. Free and verifiable.">
<meta name="twitter:image" content="${BASE}/og-image.png">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="${BASE}/detections">
<title>Traceable Detection Pack — Sigma Rules for KEV CVEs | CYBERDUDEBIVASH SENTINEL APEX</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"CollectionPage","name":"CYBERDUDEBIVASH SENTINEL APEX Detection Pack","description":"Traceable Sigma detection rules for actively-exploited CISA KEV vulnerabilities.","url":"${BASE}/detections","isPartOf":{"@type":"WebSite","name":"CYBERDUDEBIVASH SENTINEL APEX","url":"${BASE}"},"dateModified":"${updated}"}</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--apex-cyan:#00ffe0;--apex-red:#ff3b3b;--apex-orange:#ff8c00;--apex-green:#00ff88;--apex-purple:#a855f7;--apex-bg:#07090f;--apex-surface:#0d1117;--apex-card:#111827;--apex-border:#1f2937;--apex-text:#e2e8f0;--apex-muted:#6b7280;--apex-font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--apex-font);background:var(--apex-bg);color:var(--apex-text);min-height:100vh;line-height:1.7}
nav{position:sticky;top:0;z-index:9999;background:rgba(7,9,15,.97);backdrop-filter:blur(20px);border-bottom:1px solid var(--apex-border);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between}
.nbrand{display:flex;align-items:center;gap:10px;text-decoration:none}.nlogo{font-size:18px;font-weight:900;color:var(--apex-cyan)}.ntag{font-size:10px;color:var(--apex-muted);letter-spacing:.1em;text-transform:uppercase}
.nlinks{display:flex;gap:4px;flex-wrap:wrap}.nlinks a{color:var(--apex-muted);text-decoration:none;font-size:13px;font-weight:500;padding:6px 12px;border-radius:6px}.nlinks a:hover{color:var(--apex-text)}
main{max-width:1000px;margin:0 auto;padding:44px 24px 80px}
.crumb{font-size:12px;color:var(--apex-muted);margin-bottom:16px}.crumb a{color:var(--apex-cyan);text-decoration:none}
.eyebrow{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:var(--apex-green);background:#00ff8812;border:1px solid #00ff8833;border-radius:6px;padding:5px 12px;margin-bottom:16px}
h1{font-size:clamp(26px,4.4vw,40px);font-weight:900;line-height:1.15;color:#fff;margin-bottom:14px}
.lede{font-size:17px;color:#c9d1d9;margin-bottom:24px;max-width:74ch}
.stat-row{display:flex;gap:24px;flex-wrap:wrap;padding:18px 0 26px;margin-bottom:26px;border-bottom:1px solid var(--apex-border);font-size:13px;color:var(--apex-muted)}
.stat-row strong{color:var(--apex-cyan);font-family:var(--mono);font-size:18px;display:block}
.trust{background:var(--apex-card);border:1px solid var(--apex-border);border-left:4px solid var(--apex-green);border-radius:12px;padding:18px 22px;margin-bottom:30px;font-size:14px;color:#c9d1d9}
.trust strong{color:var(--apex-green)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.rule{background:var(--apex-card);border:1px solid var(--apex-border);border-radius:14px;padding:20px 22px;display:flex;flex-direction:column}
.rule-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.lvl{font-size:10px;font-weight:800;letter-spacing:.08em;padding:3px 9px;border-radius:5px}
.lvl-critical{background:#ff3b3b22;color:var(--apex-red);border:1px solid #ff3b3b55}
.lvl-high{background:#ff8c0022;color:var(--apex-orange);border:1px solid #ff8c0055}
.rw{font-size:10px;font-weight:800;color:var(--apex-purple);background:#a855f722;border:1px solid #a855f755;padding:3px 8px;border-radius:5px}
.cve{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--apex-cyan);text-decoration:none}
.rule h3{font-size:16px;font-weight:800;color:#fff;margin-bottom:8px;line-height:1.3}
.rd{font-size:13.5px;color:#c9d1d9;margin-bottom:14px;flex:1}
.trace{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--apex-muted);background:#0a0e18;border-radius:8px;padding:10px 12px;margin-bottom:14px}
.trace strong{color:var(--apex-text);font-weight:600}
.rule-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.dl{font-size:13px;font-weight:700;color:#000;background:linear-gradient(135deg,#00ffe0,#0099ff);padding:9px 14px;border-radius:8px;text-decoration:none}
.src{font-size:12px;color:var(--apex-muted);text-decoration:none}.src:hover{color:var(--apex-cyan)}
.cta{background:linear-gradient(135deg,#0a1428,#111827);border:1px solid #00ffe022;border-radius:16px;padding:28px;margin:40px 0 0;text-align:center}
.cta h3{font-size:20px;font-weight:900;color:#fff;margin-bottom:8px}.cta p{color:var(--apex-muted);margin-bottom:18px;font-size:14px}
.cta-row{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.btn-p{padding:12px 22px;background:linear-gradient(135deg,#00ffe0,#0099ff);color:#000;font-weight:800;font-size:14px;border-radius:8px;text-decoration:none}
.btn-s{padding:12px 22px;background:transparent;border:2px solid var(--apex-cyan);color:var(--apex-cyan);font-weight:700;font-size:14px;border-radius:8px;text-decoration:none}
a{color:var(--apex-cyan)}
footer{border-top:1px solid var(--apex-border);padding:28px 24px;text-align:center;font-size:13px;color:var(--apex-muted);margin-top:44px}
footer a{color:var(--apex-cyan);text-decoration:none}
</style>
</head>
<body>
<nav>
  <a class="nbrand" href="/"><span class="nlogo">CYBERDUDEBIVASH</span><span class="ntag">Sentinel APEX</span></a>
  <div class="nlinks"><a href="/">Reports</a><a href="/research">Research</a><a href="/detections">Detections</a><a href="/intelligence.html">Intelligence</a><a href="/pricing.html">Pricing</a><a href="/enterprise.html">Enterprise</a></div>
</nav>
<main>
  <div class="crumb"><a href="/">Home</a> › Detection Pack</div>
  <span class="eyebrow">Detection Engineering · Verifiable</span>
  <h1>Traceable Detection Pack</h1>
  <p class="lede">Production-ready Sigma rules for vulnerabilities that are <em>confirmed exploited in the wild</em> by CISA. Every rule is traceable: its CVE, its KEV catalog entry with the exact date, and its vendor advisory — no black-box "threat feed."</p>
  <div class="stat-row">
    <div><strong>${M.length}</strong> Sigma rules</div>
    <div><strong>${critical}</strong> critical severity</div>
    <div><strong>${ransom}</strong> ransomware-linked</div>
    <div><strong>100%</strong> KEV-confirmed CVEs</div>
  </div>
  <div class="trust">
    <strong>Why "traceable" matters:</strong> anyone can ship a rule that fires. These rules tell you <em>exactly</em> which authority confirmed the threat and when — paste any CVE below into the <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA KEV catalog</a> and the metadata matches. Rules are Sigma-format (SIEM-agnostic): convert to Splunk, Elastic, Sentinel, or QRadar with <a href="https://github.com/SigmaHQ/sigma-cli" target="_blank" rel="noopener">sigma-cli</a>. Detection logic targets exploitation behaviour; tune the source/CIDR filters to your environment before enabling.
  </div>
  <div class="grid">
${cards}
  </div>

  <div class="cta">
    <h3>The data behind these picks</h3>
    <p>These CVEs aren't chosen by hunch. See the Exploitation Velocity Index — our reproducible analysis of which vendors and weakness classes actually dominate real-world exploitation.</p>
    <div class="cta-row">
      <a class="btn-p" href="/research/exploitation-velocity-index.html">View the Index →</a>
      <a class="btn-s" href="/enterprise.html">Enterprise Detection Engineering →</a>
    </div>
  </div>
</main>
<footer>
  &copy; 2026 CYBERDUDEBIVASH ECOSYSTEM · Rules reference CISA KEV (public domain) &amp; NVD · <a href="/about.html">About</a> · <a href="/privacy.html">Privacy</a> · <a href="/terms.html">Terms</a> · <a href="/contact.html">Contact</a>
</footer>
</body>
</html>`;

fs.writeFileSync('/home/user/cyberdudebivash-blog/detections/index.html', html);
console.log('Detections page written:', html.length, 'bytes;', M.length, 'rules catalogued');
