Set-Location 'C:\Users\Administrator\Desktop\cyberdudebivash-blog'

git add .

$msg = @"
GOD LEVEL v11 — Alert Fix + Brand Rebuild + Live Threat Intel

FIX: section-nav-bar moved outside header-inner in 3 HTML files — eliminates header overlap
FIX: #cx-return-banner repositioned top:64px — no longer hides hero content
FIX: ticker item text color changed from muted gray to high-contrast #e2e8f0
FIX: all notification z-indexes corrected (toasts: 20000, overlays: 19000, banner: 18000)
NEW: apex-v11.css global stylesheet injected into all 52 HTML pages
NEW: LIVE CRITICAL THREAT ALERT BAR between header and hero — auto-updates from CISA KEV
NEW: Daily threat digest inline in hero section — top CVEs/zerodays/ransomware always visible
NEW: apex-live-threat-updater.js — fetches CISA KEV feed live, refreshes every 30 min
BRAND: SENTINEL APEX → CYBERDUDEBIVASH SENTINEL APEX across 53 files (HTML + JS)
BRAND: Hero label, terminal, footer, sidebar, pricing, badges all updated
MONETIZE: All forms high-visibility — input fields styled for maximum conversion
"@

git commit -m $msg

git push origin main
