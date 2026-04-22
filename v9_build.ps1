$repo = "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
Set-Location $repo
$log = "$repo\v9_build_log.txt"
"=== GOD LEVEL v9 BUILD START $(Get-Date) ===" | Out-File $log

# ── PHASE 1: INJECT NEW ENGINES INTO ALL HTML PAGES ──────────────────────────
# security-engine.js goes FIRST (before closing head), rest go before </body>

$allHtml = Get-ChildItem -Path $repo -Recurse -Filter "*.html" |
  Where-Object { $_.Name -notin @("admin-dashboard.html","order-confirmation.html") }

$securityTag   = '<script src="/security-engine.js"></script>'
$analyticsTag  = '<script src="/analytics-engine.js" defer></script>'
$emailTag      = '<script src="/email-engine.js" defer></script>'
$paymentTag    = '<script src="/payment-engine.js" defer></script>'

$injected = 0
foreach ($f in $allHtml) {
  $content = Get-Content $f.FullName -Raw -Encoding UTF8
  $changed = $false

  # Inject security-engine before </head> if not present
  if ($content -notmatch 'security-engine\.js') {
    $content = $content -replace '(</head>)', "$securityTag`n`$1"
    $changed = $true
  }

  # Inject analytics/email/payment before </body> if not present
  if ($content -notmatch 'analytics-engine\.js') {
    $content = $content -replace '(</body>)', "$analyticsTag`n$emailTag`n$paymentTag`n`$1"
    $changed = $true
  }

  if ($changed) {
    [System.IO.File]::WriteAllText($f.FullName, $content, [System.Text.Encoding]::UTF8)
    "  INJECTED: $($f.Name)" | Out-File $log -Append
    $injected++
  }
}
"PHASE 1 COMPLETE: $injected files injected" | Out-File $log -Append

# ── PHASE 2: UPDATE SITEMAP WITH NEW PAGES ────────────────────────────────────
$sitemapPath = "$repo\sitemap.xml"
$sitemap = Get-Content $sitemapPath -Raw -Encoding UTF8

$newEntries = @"

  <!-- Newsletter Archive -->
  <url>
    <loc>https://blog.cyberdudebivash.in/newsletter.html</loc>
    <lastmod>2026-04-22</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.75</priority>
  </url>

  <!-- Order Confirmation -->
  <url>
    <loc>https://blog.cyberdudebivash.in/order-confirmation.html</loc>
    <lastmod>2026-04-22</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.40</priority>
  </url>

"@

if ($sitemap -notmatch 'newsletter\.html') {
  $sitemap = $sitemap -replace '(</urlset>)', "$newEntries`$1"
  [System.IO.File]::WriteAllText($sitemapPath, $sitemap, [System.Text.Encoding]::UTF8)
  "PHASE 2: sitemap.xml updated with newsletter + order-confirmation" | Out-File $log -Append
} else {
  "PHASE 2: sitemap already up-to-date" | Out-File $log -Append
}

# ── PHASE 3: ADD NEWSLETTER LINK TO NAV IN KEY PAGES ─────────────────────────
$keyPages = @("index.html","archive.html","pricing.html","products.html","enterprise.html","leads.html","api.html")
foreach ($page in $keyPages) {
  $fp = "$repo\$page"
  if (Test-Path $fp) {
    $c = Get-Content $fp -Raw -Encoding UTF8
    if ($c -notmatch 'newsletter\.html') {
      # Add newsletter to footer links area (near archive link)
      $c = $c -replace '(href="archive\.html">Archive<)', 'href="newsletter.html">Newsletter</a> | <a $1'
      [System.IO.File]::WriteAllText($fp, $c, [System.Text.Encoding]::UTF8)
      "  NAV-UPDATED: $page" | Out-File $log -Append
    }
  }
}
"PHASE 3 COMPLETE" | Out-File $log -Append

# ── PHASE 4: GIT COMMIT & PUSH ────────────────────────────────────────────────
"PHASE 4: Starting git operations..." | Out-File $log -Append

# Remove stale lock if exists
if (Test-Path "$repo\.git\index.lock") {
  Remove-Item "$repo\.git\index.lock" -Force
  "Removed stale index.lock" | Out-File $log -Append
}

# Stage all new + modified files
git add admin-dashboard.html analytics-engine.js email-engine.js newsletter.html order-confirmation.html payment-engine.js security-engine.js sitemap.xml index.html intelligence.html archive.html pricing.html products.html enterprise.html leads.html api.html 2>&1 | Out-File $log -Append

# Also stage CVE/threat/attack pages (engine injection)
git add cve/ threat/ attack/ posts/ 2>&1 | Out-File $log -Append

git status --short 2>&1 | Out-File $log -Append

$msg = "GOD LEVEL v9 -- Final production: analytics+security+email+payment engines, admin dashboard, order flow, newsletter archive, engine injection all pages"
git commit -m $msg 2>&1 | Out-File $log -Append

"Starting push..." | Out-File $log -Append
git push origin main 2>&1 | Out-File $log -Append

git log --oneline -3 2>&1 | Out-File $log -Append
"=== BUILD COMPLETE $(Get-Date) ===" | Out-File $log -Append
"V9_DONE" | Out-File $log -Append
