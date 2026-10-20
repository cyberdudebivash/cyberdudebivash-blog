'use strict';

/**
 * Enterprise CTI reader v14 — presentation and navigation only.
 * Reuses the existing v12 SOC cover, v13 reading rules and canonical HTML.
 * No remote fonts, external dependencies, analytics, data enrichment,
 * security-gate changes, new executive claims or certification shortcuts.
 */
const STYLE_ID = 'cdb-cti-enterprise-reader-v14-css';
const RULES = [
  /* Strong but restrained commercial editorial hierarchy. */
  '.cdb-cti-reader{--cdb-v14-paper:#101e2d;--cdb-v14-raised:#13273a;--cdb-v14-border:#42617c;--cdb-v14-ink:#f0f6fc;--cdb-v14-muted:#c3d5e6;--cdb-v14-accent:#84e3ee;--cdb-v14-gold:#e5c88a;max-width:100%;min-width:0}',
  '.cdb-cti-reader :where(.rh1,h1){font-size:clamp(27px,3.5vw,43px)!important;line-height:1.17!important;font-weight:800!important;letter-spacing:-.028em!important;color:#f7fcff!important;text-wrap:balance}',
  '.cdb-cti-reader :where(.rsubtitle,.exec-box p,.bp,.card p){max-width:78ch;line-height:1.82!important;letter-spacing:.002em!important}',
  '.cdb-cti-reader .cdb-soc12{box-shadow:0 14px 48px rgba(1,9,17,.22)!important;border-color:#496a83!important}',
  '.cdb-cti-reader .cdb-soc12-head h2{font-size:clamp(25px,3.1vw,37px)!important;line-height:1.18!important}',
  '.cdb-cti-reader .cdb-soc12-grid>div{padding:14px!important}',
  '.cdb-cti-reader .cdb-soc12-grid small{color:#c3d4e5!important;font-size:11px!important}',
  '.cdb-cti-reader .cdb-soc12-grid strong{font-size:13px!important;font-variant-numeric:tabular-nums}',
  '.cdb-cti-reader .cdb-soc12-handoff p{font-size:13px!important;color:#d8e6f1!important}',
  '.cdb-cti-reader .cdb-soc12-caveat{font-size:12px!important;color:#dbe8f1!important}',
  /* Reader guide — browser-native details; keyboard and no-JS friendly. */
  '.cdb-cti-reader .cdb-v14-guide{margin:19px 0 26px;background:linear-gradient(125deg,#122b3b,#0b1d2c 65%);border:1px solid var(--cdb-v14-border);border-radius:13px;padding:16px 19px;color:var(--cdb-v14-ink);box-shadow:0 12px 30px rgba(0,0,0,.13)}',
  '.cdb-cti-reader .cdb-v14-guide-top{display:flex;gap:12px;flex-wrap:wrap;align-items:center;justify-content:space-between}',
  '.cdb-cti-reader .cdb-v14-overline{font-size:11px;line-height:1.5;font-weight:800;letter-spacing:.12em;color:var(--cdb-v14-accent);text-transform:uppercase}',
  '.cdb-cti-reader .cdb-v14-status{display:inline-flex;align-items:center;padding:5px 10px;border:1px solid #55738b;border-radius:999px;font:700 11px/1.4 system-ui,sans-serif;color:#e7f2fb}',
  '.cdb-cti-reader .cdb-v14-shortcuts{display:flex;gap:9px;flex-wrap:wrap;margin-top:13px}',
  '.cdb-cti-reader .cdb-v14-shortcuts a{display:inline-flex;min-height:44px;align-items:center;justify-content:center;padding:9px 13px;border:1px solid #547993;border-radius:8px;color:#a5e9f6;font-size:13px;font-weight:750;text-decoration:none;line-height:1.3}',
  '.cdb-cti-reader .cdb-v14-shortcuts a:hover{background:#224258;text-decoration:underline;text-underline-offset:3px}',
  '.cdb-cti-reader .cdb-v14-guide details{margin-top:13px;padding-top:13px;border-top:1px solid #36546b}',
  '.cdb-cti-reader .cdb-v14-guide summary{cursor:pointer;color:#dfedf8;font-size:13px;font-weight:750;line-height:1.7;padding:3px 0}',
  '.cdb-cti-reader .cdb-v14-guide details p{margin:9px 0 1px!important;color:#c9dceb!important;font-size:13px!important;line-height:1.75!important;max-width:85ch}',
  /* Dense analytics without tiny, low-contrast metadata or unsafe width. */
  '.cdb-cti-reader :where(.stats-bar,.stat-grid){gap:12px!important;min-width:0}',
  '.cdb-cti-reader :where(.stat,.stat-box){background:#132539!important;border:1px solid #385872!important;border-radius:10px!important;min-width:0;box-shadow:0 8px 18px rgba(0,0,0,.09)}',
  '.cdb-cti-reader :where(.stat .sl,.stat-lbl){color:#d0dfec!important;font-size:11px!important;line-height:1.5!important;letter-spacing:.06em!important}',
  '.cdb-cti-reader :where(.stat .sv,.stat-val){font-size:clamp(19px,2vw,25px)!important;line-height:1.25!important;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}',
  '.cdb-cti-reader :where(.badge,.meta-bar){line-height:1.55}',
  '.cdb-cti-reader :where(.rep-date,.vk,.wt){color:#bdd0e1!important}',
  '.cdb-cti-reader :where(.card,.exec-box,.vbox,.sw){border-color:#3d5c75!important;border-radius:11px;min-width:0}',
  '.cdb-cti-reader :where(.exec-box,.card,.cta-box){padding:clamp(16px,2vw,25px)!important}',
  '.cdb-cti-reader .sh{font-size:clamp(22px,2.3vw,28px)!important;line-height:1.33!important;color:#f2f8fe!important;border-bottom:1px solid #476279!important;padding-bottom:13px!important;margin-top:43px!important;margin-bottom:20px!important;scroll-margin-top:90px}',
  '.cdb-cti-reader .sh::before{content:"";display:inline-block;width:4px;height:20px;margin-right:12px;vertical-align:-3px;background:#88e4ed;border-radius:2px}',
  '.cdb-cti-reader :where(.exec-box,.card,.alert){overflow-wrap:break-word}',
  /* Don't clip wide IOC/ATT&CK tables; preserve their scroll affordance. */
  '.cdb-cti-reader :where(.tbl,table){border-collapse:separate!important;border-spacing:0!important;border:1px solid #405e76;border-radius:8px;max-width:100%;min-width:0}',
  '.cdb-cti-reader :where(th,td){border-bottom:1px solid #324c64!important;line-height:1.65!important}',
  '.cdb-cti-reader :where(th){font-size:12px!important;letter-spacing:.04em!important;color:#e0f7ff!important;background:#21394e!important;text-align:left!important}',
  '.cdb-cti-reader :where(td){color:#e3eff9!important;font-size:13px!important}',
  '.cdb-cti-reader :where(tbody tr:nth-child(even)){background:rgba(111,151,180,.07)}',
  '.cdb-cti-reader :where(pre,.code-block){font-size:13px!important;line-height:1.72!important;border-color:#456079!important;background:#0d1925!important;color:#dceefe!important;white-space:pre;overflow-x:auto!important}',
  '.cdb-cti-reader :where(a){text-underline-offset:3px}',
  '.cdb-cti-reader :where(a,summary,button,input,select):focus-visible{outline:3px solid #ffd57e!important;outline-offset:4px!important}',
  /* Keep the actual article readable even on narrow devices. */
  '@media(max-width:760px){.cdb-cti-reader .cdb-v14-guide{padding:14px}.cdb-cti-reader .cdb-v14-shortcuts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.cdb-cti-reader .cdb-v14-shortcuts a{text-align:center;overflow-wrap:anywhere}.cdb-cti-reader .stats-bar{grid-template-columns:repeat(2,minmax(0,1fr))!important}.cdb-cti-reader :where(.tbl,table){display:block;overflow-x:auto!important;overscroll-behavior-x:contain;scrollbar-width:thin}.cdb-cti-reader :where(.tbl th,.tbl td,table th,table td){min-width:110px}.cdb-cti-reader :where(.card,.exec-box){padding:17px!important}}',
  '@media(max-width:380px){.cdb-cti-reader .cdb-v14-shortcuts{grid-template-columns:1fr}.cdb-cti-reader .cdb-soc12-grid{grid-template-columns:1fr!important}.cdb-cti-reader .stats-bar{grid-template-columns:1fr 1fr!important}}',
  '@media(prefers-reduced-motion:reduce){.cdb-cti-reader *,body .ticker-inner{scroll-behavior:auto!important;animation:none!important;transition:none!important}}',
  /* Accessible, procurement-friendly export: light ink, no truncated code. */
  '@page{size:A4;margin:15mm 13mm}',
  '@media print{html,body{background:#fff!important;color:#111!important}body::before,body #mc,body .ticker,body nav,body footer,.cdb-cti-reader .cdb-v14-guide,.cdb-cti-reader .sidebar,.cdb-cti-reader .cta-box,.cdb-cti-reader .ecta{display:none!important}main{display:block!important;max-width:none!important;margin:0!important;padding:0!important}.cdb-cti-reader,.cdb-cti-reader :where(.exec-box,.card,.stat,.stat-box,.vbox,.sw,.alert){color:#111!important;background:#fff!important;box-shadow:none!important;border-color:#aab4bd!important}.cdb-cti-reader :where(h1,h2,h3,p,small,span,strong,div,li,td,th){color:#111!important;text-shadow:none!important}.cdb-cti-reader :where(h1,h2,h3,.sh){break-after:avoid-page!important}.cdb-cti-reader :where(.card,.exec-box,.stat,.stat-box,.alert){break-inside:avoid-page}.cdb-cti-reader :where(.tbl,table){display:table!important;overflow:visible!important;width:100%;table-layout:fixed;border-color:#aab4bd!important}.cdb-cti-reader :where(.tbl th,.tbl td,table th,table td){background:#fff!important;color:#111!important;border-color:#c1cad2!important;min-width:0!important;overflow-wrap:anywhere!important}.cdb-cti-reader :where(pre,.code-block){white-space:pre-wrap!important;overflow:visible!important;max-height:none!important;color:#111!important;background:#f5f7fa!important}.cdb-cti-reader a{color:#143e63!important;text-decoration:underline!important}.cdb-cti-reader .cdb-soc12{break-inside:auto!important}.cdb-cti-reader .cdb-soc12-grid{background:#fff!important}}'
].join('\n');
const CSS = '<style id="' + STYLE_ID + '">\n' + RULES + '\n</style>';

/**
 * Native HTML details gives keyboard-accessible reading guidance with no JS.
 * Anchors are included only for sections known to be present in that renderer.
 */
function renderReaderGuide({ surface = 'post', hasSources = true } = {}) {
  if (surface !== 'post' && surface !== 'cve') throw new RangeError('Unsupported report surface');
  const links = [
    ['Executive', '#cdb-static-executive'],
    ['Technical', '#cdb-static-technical'],
    ...(hasSources ? [['Evidence & sources', '#cdb-static-references']] : []),
    ...(surface === 'post' ? [['SOC response', '#cdb-static-response']] : []),
  ];
  const nav = links.map(([label, href]) =>
    '<a href="' + href + '">' + label + '</a>').join('');
  return '<section class="cdb-v14-guide" aria-label="Intelligence report reading guide" data-cdb-reader-v14="true">' +
    '<div class="cdb-v14-guide-top"><span class="cdb-v14-overline">SENTINEL APEX / Enterprise Reader</span>' +
    '<span class="cdb-v14-status">Source-based brief · exposure not assessed</span></div>' +
    '<nav class="cdb-v14-shortcuts" aria-label="Report section shortcuts">' + nav + '</nav>' +
    '<details><summary>How to read this intelligence report</summary>' +
    '<p><strong>Source facts</strong> come from cited records. <strong>Analyst guidance</strong> describes suggested checks, not actions already performed. ' +
    '<strong>Customer exposure remains unverified</strong> until your own asset inventory and security telemetry are reviewed. ' +
    'Use your browser’s Print / Save as PDF function to retain the report for an internal evidence review; preserve its references and caveats.</p>' +
    '</details></section>';
}
module.exports = { STYLE_ID, CSS, renderReaderGuide };
