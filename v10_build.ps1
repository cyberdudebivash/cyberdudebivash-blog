$repo = "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
Set-Location $repo
$log = "$repo\v10_build_log.txt"
"=== GOD LEVEL v10 BUILD START $(Get-Date) ===" | Out-File $log

# ── PHASE 1: UPDATE SITEMAP ───────────────────────────────────────────────────
$sitemapPath = "$repo\sitemap.xml"
$sitemap = Get-Content $sitemapPath -Raw -Encoding UTF8

$newEntries = @"

  <!-- Auto Intel Hub -->
  <url>
    <loc>https://blog.cyberdudebivash.in/intel/</loc>
    <lastmod>2026-04-22</lastmod>
    <changefreq>hourly</changefreq>
    <priority>0.95</priority>
  </url>

  <!-- Breaking Cyber News -->
  <url>
    <loc>https://blog.cyberdudebivash.in/breaking/</loc>
    <lastmod>2026-04-22</lastmod>
    <changefreq>hourly</changefreq>
    <priority>0.93</priority>
  </url>

  <!-- Malware Tracker -->
  <url>
    <loc>https://blog.cyberdudebivash.in/malware/</loc>
    <lastmod>2026-04-22</lastmod>
    <changefreq>hourly</changefreq>
    <priority>0.92</priority>
  </url>

  <!-- AI Security Hub -->
  <url>
    <loc>https://blog.cyberdudebivash.in/ai-security/</loc>
    <lastmod>2026-04-22</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.90</priority>
  </url>

"@

if ($sitemap -notmatch 'intel/</loc>') {
  $sitemap = $sitemap -replace '(</urlset>)', "$newEntries`$1"
  [System.IO.File]::WriteAllText($sitemapPath, $sitemap, [System.Text.Encoding]::UTF8)
  "SITEMAP: Updated with 4 new section pages" | Out-File $log -Append
} else {
  "SITEMAP: Already up to date" | Out-File $log -Append
}

# ── PHASE 2: INJECT auto-intel-engine.js INTO ALL KEY HTML PAGES ─────────────
$keyPages = Get-ChildItem -Path $repo -Filter "*.html" | Where-Object { $_.Name -notin @("admin-dashboard.html") }
$intelTag = '<script src="/auto-intel-engine.js"></script>'
$injected = 0

foreach ($f in $keyPages) {
  $c = Get-Content $f.FullName -Raw -Encoding UTF8
  if ($c -notmatch 'auto-intel-engine') {
    # Add before </body>
    $c = $c -replace '(</body>)', "$intelTag`n`$1"
    [System.IO.File]::WriteAllText($f.FullName, $c, [System.Text.Encoding]::UTF8)
    $injected++
  }
}
"PHASE 2: auto-intel-engine.js injected into $injected pages" | Out-File $log -Append

# ── PHASE 3: ADD SECTION NAV LINKS TO FOOTER OF KEY PAGES ────────────────────
$sectionLinks = '<a href="/intel/">Intel Hub</a> | <a href="/breaking/">Breaking</a> | <a href="/malware/">Malware</a> | <a href="/ai-security/">AI Security</a>'
$navPages = @("index.html", "archive.html", "products.html", "pricing.html", "enterprise.html", "leads.html", "api.html", "newsletter.html")

foreach ($page in $navPages) {
  $fp = "$repo\$page"
  if (-not (Test-Path $fp)) { continue }
  $c = Get-Content $fp -Raw -Encoding UTF8

  # Inject into existing nav if it has one but is missing the intel link
  if ($c -notmatch '/intel/') {
    # Try to add after existing nav links near </nav> or footer
    if ($c -match '</nav>') {
      $c = $c -replace '(</nav>)', "`$1`n<div class='section-nav-bar' style='background:#060a14;border-top:1px solid #1a2535;padding:6px 20px;font-size:.78em;display:flex;gap:16px;flex-wrap:wrap'>$sectionLinks</div>"
      [System.IO.File]::WriteAllText($fp, $c, [System.Text.Encoding]::UTF8)
      "  SECTION-NAV: $page" | Out-File $log -Append
    }
  }
}
"PHASE 3 COMPLETE" | Out-File $log -Append

# ── PHASE 4: GIT COMMIT & PUSH ────────────────────────────────────────────────
"PHASE 4: Starting git operations..." | Out-File $log -Append

if (Test-Path "$repo\.git\index.lock") {
  Remove-Item "$repo\.git\index.lock" -Force
}

git add auto-intel-engine.js sitemap.xml 2>&1 | Out-File $log -Append
git add intel/ breaking/ malware/ ai-security/ 2>&1 | Out-File $log -Append
git add index.html archive.html products.html pricing.html enterprise.html leads.html api.html newsletter.html 2>&1 | Out-File $log -Append

git status --short 2>&1 | Out-File $log -Append

$msg = "GOD LEVEL v10 -- Continuous Intelligence System: auto-intel-engine.js, /intel/ /breaking/ /malware/ /ai-security/ live feed sections, CISA KEV + RSS feed aggregator, freemium paywall, MITRE mapping, social distribution"
git commit -m $msg 2>&1 | Out-File $log -Append

"Starting push to GitHub..." | Out-File $log -Append
git push origin main 2>&1 | Out-File $log -Append

git log --oneline -3 2>&1 | Out-File $log -Append
"=== BUILD COMPLETE $(Get-Date) ===" | Out-File $log -Append
"V10_DONE" | Out-File $log -Append
