'use strict';
/**
 * v13 enterprise readability / accessible CTI evidence presentation.
 * Additive static stylesheet for /posts and /cve. No new source facts,
 * telemetry, billing controls, JavaScript dependencies or network calls.
 */
const STYLE_ID = 'cdb-cti-reader-v13-css';
const RULES = [
  '.cdb-cti-reader{--cdb-read-text:#e7f1fa;--cdb-read-secondary:#b8cee1;--cdb-read-link:#87ddff;--cdb-read-line:#39546b;--cdb-read-surface:#0b1b2a;min-width:0;overflow-wrap:break-word;text-rendering:optimizeLegibility}',
  '.cdb-cti-reader :where(a,button,input,summary):focus-visible{outline:3px solid #ffdb79!important;outline-offset:3px!important;border-radius:3px}',
  '.cdb-cti-reader :where(.bp,.body,.rsubtitle,.exec-box p,.action-item,.impact-item,.card p){font-size:clamp(15px,1.2vw,17px)!important;line-height:1.82!important;color:var(--cdb-read-text)!important;letter-spacing:normal!important}',
  '.cdb-cti-reader .bp{max-width:78ch;margin-bottom:18px!important}',
  '.cdb-cti-reader .sh{font-size:clamp(20px,2.25vw,27px)!important;line-height:1.35!important;letter-spacing:-.015em!important;scroll-margin-top:110px!important;margin-top:38px!important;margin-bottom:15px!important;overflow-wrap:anywhere}',
  '.cdb-cti-reader :where(.rh1,h1){text-wrap:balance;overflow-wrap:anywhere;letter-spacing:-.025em}',
  '.cdb-cti-reader :where(.tbl,table){font-size:14px!important;line-height:1.6!important;font-variant-numeric:tabular-nums}',
  '.cdb-cti-reader :where(.tbl th,.tbl td,table th,table td){padding:12px 14px!important;vertical-align:top;overflow-wrap:anywhere}',
  '.cdb-cti-reader :where(.tbl,table){max-width:100%}',
  '.cdb-cti-reader :where(pre,.code-block){overflow-x:auto!important;max-width:100%!important;font-size:13px!important;line-height:1.62!important;scrollbar-width:thin;tab-size:2}',
  '.cdb-cti-reader :where(code,.vscore,.stat-val){font-variant-numeric:tabular-nums;overflow-wrap:anywhere}',
  '.cdb-cti-reader :where(.btn,.btn-p,.btn-s,.btn-e,.btn-g,.pro-btn){min-height:44px;line-height:1.45;text-decoration:none}',
  '.cdb-cti-reader :where(.btn,.btn-p,.btn-s,.btn-e,.btn-g,.pro-btn):hover{text-decoration:underline;text-underline-offset:3px}',
  '.cdb-cti-reader .cdb-soc12{line-height:1.75!important}',
  '.cdb-cti-reader .cdb-soc12-over{font-size:11px!important;line-height:1.5!important}',
  '.cdb-cti-reader .cdb-soc12-head h2{font-size:clamp(23px,3vw,35px)!important;line-height:1.25!important;text-wrap:balance}',
  '.cdb-cti-reader .cdb-soc12-head p{font-size:15px!important;line-height:1.75!important}',
  '.cdb-cti-reader .cdb-soc12-grid small{font-size:11px!important;line-height:1.45!important;letter-spacing:.035em!important;color:#b4cee1!important}',
  '.cdb-cti-reader .cdb-soc12-grid strong{font-size:13px!important;line-height:1.55!important}',
  '.cdb-cti-reader .cdb-soc12-nav{gap:8px!important;margin:19px 0!important}',
  '.cdb-cti-reader .cdb-soc12-nav a{font-size:13px!important;display:inline-flex;align-items:center;justify-content:center;min-height:44px!important;line-height:1.3!important}',
  '.cdb-cti-reader .cdb-soc12-focus small{font-size:11px!important}',
  '.cdb-cti-reader .cdb-soc12-focus p{font-size:14px!important;line-height:1.75!important}',
  '.cdb-cti-reader .cdb-soc12-handoff h3{font-size:13px!important}',
  '.cdb-cti-reader .cdb-soc12-handoff b{font-size:12px!important}',
  '.cdb-cti-reader .cdb-soc12-handoff p{font-size:13px!important;line-height:1.75!important}',
  '.cdb-cti-reader .cdb-soc12-caveat{font-size:12px!important;line-height:1.75!important;color:#d2e2ef!important}',
  '.cdb-cti-reader .cta-box{text-align:left}',
  '.cdb-cti-reader .cta-box p{font-size:14px!important;line-height:1.7!important;color:#c2d6e7!important}',
  '@media(max-width:760px){.cdb-cti-reader{padding-inline:clamp(12px,3vw,20px)!important}.cdb-cti-reader .cdb-soc12{padding:16px!important}.cdb-cti-reader .cdb-soc12-head{gap:13px!important}.cdb-cti-reader .cdb-soc12-nav{display:flex;flex-wrap:nowrap;overflow-x:auto;overscroll-behavior-x:contain;scrollbar-width:thin;padding-bottom:8px}.cdb-cti-reader .cdb-soc12-nav a{flex:0 0 auto}.cdb-cti-reader :where(.tbl,table){display:block;overflow-x:auto;overscroll-behavior-x:contain}.cdb-cti-reader :where(.tbl th,.tbl td,table th,table td){min-width:105px}}',
  '@media(max-width:420px){.cdb-cti-reader .cdb-soc12-over{gap:6px}.cdb-cti-reader .cdb-soc12-grid strong{font-size:12.5px!important}.cdb-cti-reader :where(.btn,.btn-p,.btn-s,.btn-e,.btn-g){width:100%;justify-content:center}}',
  '@media(prefers-reduced-motion:reduce){.cdb-cti-reader *{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}',
  '@media print{.cdb-cti-reader{color:#111!important;background:#fff!important;box-shadow:none!important}.cdb-cti-reader :where(.bp,.body,.rsubtitle,.exec-box p,.card p,.action-item){color:#111!important}.cdb-cti-reader :where(.cdb-soc12,.card,.exec-box,.cta-box){break-inside:avoid;box-shadow:none!important}.cdb-cti-reader :where(a){color:#153c63!important;text-decoration:underline!important}.cdb-cti-reader .cdb-soc12-nav,.cdb-cti-reader .pro-overlay{display:none!important}}'
].join('\n');
const CSS = '<style id="' + STYLE_ID + '">\n' + RULES + '\n</style>';
module.exports = { STYLE_ID, CSS };
