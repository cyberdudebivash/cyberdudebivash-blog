'use strict';

/**
 * CYBERDUDEBIVASH ECOSYSTEM® — clearly labelled owned-platform promotion.
 * Editorial firebreak: never inserts recommendations inside threat findings,
 * and never asserts product readiness, current pricing, client outcomes, or
 * completed operational assessments. No network, JS on the public page,
 * tracking pixels, third-party dependencies or runtime state mutations.
 *
 * Source: operator-supplied public ecosystem catalog (2026-10-21).
 */
const STYLE_ID = 'cdb-ecosystem-showcase-v1-css';
const OFFERINGS = Object.freeze({
  intel: {
    name: 'SENTINEL APEX™ Threat Intelligence',
    category: 'Threat intelligence platform',
    description: 'Explore source-linked advisories, IOC context and structured-intelligence options for security operations.',
    url: 'https://intel.cyberdudebivash.com/'
  },
  ai: {
    name: 'SENTINEL APEX™ AI Security Hub',
    category: 'AI application and agent security',
    description: 'Discover AI security assessment, agent/MCP review and governance engagement options.',
    url: 'https://www.cyberdudebivash.in/'
  },
  services: {
    name: 'Enterprise Security Services',
    category: 'Professional security engagements',
    description: 'Request a scoped discussion about authorized security testing, response readiness and detection engineering.',
    url: 'https://www.cyberdudebivash.com/services'
  },
  tools: {
    name: 'ThreatCore™ Security Tools',
    category: 'Defensive tools and resources',
    description: 'Explore security utilities, SOC toolkits, self-hosted resources and available licensing information.',
    url: 'https://tools.cyberdudebivash.com/'
  },
  academy: {
    name: 'SENTINEL APEX™ Academy',
    category: 'Security education',
    description: 'Browse practical cybersecurity, SOC, threat intelligence and AI security learning resources.',
    url: 'https://academy.cyberdudebivash.com/'
  },
  labs: {
    name: 'SENTINEL APEX™ Labs & Store',
    category: 'Technical labs and product catalog',
    description: 'Discover applied labs, evaluation resources and listed security engineering products.',
    url: 'https://labs.cyberdudebivash.in/'
  },
  research: {
    name: 'Research Blog & Intel Factory',
    category: 'Open security research',
    description: 'Read threat research, vulnerability intelligence and defender-oriented technical briefings.',
    url: 'https://blog.cyberdudebivash.in/'
  },
  trustx: {
    name: 'TRUSTX™ Identity Security',
    category: 'Private preview',
    description: 'Learn about the identity threat-detection and privileged-access research preview.',
    url: 'https://trustx.cyberdudebivash.com/'
  },
  swarms: {
    name: 'SENTINEL APEX™ Agent Swarms',
    category: 'Availability on enquiry',
    description: 'Explore AI-assisted security analysis and investigation concepts subject to access review.',
    url: 'https://intel.cyberdudebivash.com/swarm'
  }
});

const CHANNELS = Object.freeze({
  AI_SECURITY: ['ai', 'services', 'labs'],
  RANSOMWARE: ['intel', 'services', 'tools'],
  DATA_BREACH: ['services', 'intel', 'trustx'],
  DARK_WEB: ['services', 'intel', 'trustx'],
  THREAT_ACTOR: ['intel', 'services', 'tools'],
  CVE_REPORT: ['intel', 'tools', 'services'],
  ZERO_DAY: ['intel', 'services', 'tools'],
  MALWARE_REPORT: ['intel', 'tools', 'services'],
  ADVISORY: ['intel', 'services', 'academy'],
  NEWS_REPORT: ['intel', 'academy', 'research']
});
const BACKUP = ['intel','services','tools'];
const safe = value => String(value ?? '').replace(/&/g, '&amp;')
  .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

function recommendationsFor(type) {
  const key = String(type || '').toUpperCase();
  return [...(CHANNELS[key] || BACKUP)];
}

function renderEcosystemShowcase({ type = 'ADVISORY' } = {}) {
  const picks = recommendationsFor(type);
  const card = key => {
    const offering = OFFERINGS[key];
    return '<article class="cdb-eco-card">' +
      '<span class="cdb-eco-category">' + safe(offering.category) + '</span>' +
      '<h3>' + safe(offering.name) + '</h3>' +
      '<p>' + safe(offering.description) + '</p>' +
      '<a href="' + safe(offering.url) + '" target="_blank" rel="noopener noreferrer">' +
      'Explore official offering <span aria-hidden="true">↗</span></a></article>';
  };
  const catalogLinks = Object.values(OFFERINGS).map(offering =>
    '<li><a href="' + safe(offering.url) + '" target="_blank" rel="noopener noreferrer">' +
    safe(offering.name) + '</a><span>' + safe(offering.category) + '</span></li>').join('');
  return '<section id="cdb-ecosystem-services" class="cdb-eco-showcase" ' +
    'data-cdb-ecosystem-promotion="v1" data-cdb-ecosystem-static-v1="true" aria-label="CYBERDUDEBIVASH ecosystem promotional offers">' +
    '<header class="cdb-eco-head">' +
    '<span class="cdb-eco-overline">ECOSYSTEM PROMOTION · OWNED PLATFORMS &amp; SERVICES</span>' +
    '<h2>Extend your defense with CYBERDUDEBIVASH® ECOSYSTEM</h2>' +
    '<p>Explore connected cybersecurity platforms, specialist engagements, tools, labs and learning resources. ' +
    'Choose a relevant next step for your organization.</p></header>' +
    '<div class="cdb-eco-cards">' + picks.map(card).join('') + '</div>' +
    '<div class="cdb-eco-actions">' +
    '<a class="cdb-eco-primary" href="https://www.cyberdudebivash.com/ecosystem" ' +
    'target="_blank" rel="noopener noreferrer">Explore the complete ecosystem ↗</a>' +
    '<a class="cdb-eco-secondary" href="mailto:contact@cyberdudebivash.in?subject=Enterprise%20Security%20Enquiry">' +
    'Request an enterprise consultation</a></div>' +
    '<details class="cdb-eco-directory"><summary>Browse all public platform listings</summary>' +
    '<ul>' + catalogLinks + '</ul></details>' +
    '<p class="cdb-eco-disclosure"><strong>Commercial disclosure:</strong> This section promotes ' +
    'CYBERDUDEBIVASH-owned offerings and is separate from the intelligence assessment above. ' +
    'Availability, checkout, licensing, service scope and prices require confirmation on the linked ' +
    'official page or in a written proposal. Private previews are not generally available products. ' +
    'Security assessments require written authorization. A paid offering does not increase the ' +
    'confidence of threat intelligence findings.</p>' +
    '</section>';
}

const RULES = [
  '.cdb-eco-showcase{--eco-ink:#e8f4fe;--eco-muted:#c9ddec;--eco-link:#96e6f4;--eco-outline:#50768f;position:relative;clear:both;margin:46px 0 30px;padding:clamp(20px,3vw,34px);border-radius:18px;border:1px solid #47687f;background:linear-gradient(132deg,#122c3e 0%,#0c2133 62%,#11263b 100%);color:var(--eco-ink);font:400 15px/1.65 system-ui,sans-serif;box-shadow:0 18px 38px rgba(0,0,0,.15);text-align:left;min-width:0}',
  '.cdb-eco-showcase *{box-sizing:border-box}',
  '.cdb-eco-overline{display:block;font:800 11px/1.6 system-ui,sans-serif;letter-spacing:.11em;color:#a8eafa;text-transform:uppercase}',
  '.cdb-eco-head h2{font-size:clamp(22px,2.45vw,32px)!important;line-height:1.2!important;font-weight:800!important;color:#fff!important;max-width:34ch;margin:11px 0!important}',
  '.cdb-eco-head p{max-width:68ch;color:#d5e5f3;font-size:15px;line-height:1.75;margin:0 0 22px}',
  '.cdb-eco-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px}',
  '.cdb-eco-card{display:flex;flex-direction:column;gap:10px;padding:20px 18px;border-radius:12px;border:1px solid #46647e;background:#162f43;min-width:0}',
  '.cdb-eco-category{color:#c1e6ec;font-size:11px;letter-spacing:.07em;text-transform:uppercase;font-weight:800}',
  '.cdb-eco-card h3{font-size:18px!important;line-height:1.32!important;color:#fff!important;margin:0!important}',
  '.cdb-eco-card p{flex:1;color:#d0e0eb!important;font-size:13px!important;line-height:1.7!important;margin:0!important}',
  '.cdb-eco-showcase a{color:var(--eco-link);text-underline-offset:3px;overflow-wrap:anywhere}',
  '.cdb-eco-card a{display:inline-flex;align-items:center;margin-top:5px;min-height:44px;font-size:13px;font-weight:800;text-decoration:underline}',
  '.cdb-eco-actions{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0 5px}',
  '.cdb-eco-actions a{min-height:44px;display:inline-flex;align-items:center;justify-content:center;border-radius:8px;padding:10px 15px;font-size:14px;font-weight:800;text-align:center;text-decoration:none}',
  '.cdb-eco-actions .cdb-eco-primary{background:#a1edeb;color:#092331!important}',
  '.cdb-eco-actions .cdb-eco-secondary{border:1px solid #7097b4;color:#e1f2fa}',
  '.cdb-eco-directory{margin:20px 0 0;border-top:1px solid #3f617a;padding-top:15px}',
  '.cdb-eco-directory summary{cursor:pointer;min-height:44px;font-size:14px;font-weight:800;color:#e2f5fe;display:flex;align-items:center}',
  '.cdb-eco-directory ul{list-style:none;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 18px;padding:8px 0;margin:0}',
  '.cdb-eco-directory li{display:flex;flex-direction:column;gap:2px;overflow-wrap:anywhere}',
  '.cdb-eco-directory li a{font-size:13px;font-weight:700}',
  '.cdb-eco-directory li span{font-size:11px;color:#bcd5e5}',
  '.cdb-eco-disclosure{margin:20px 0 0!important;padding:13px 0 0;border-top:1px solid #3f617a;color:#cbddea!important;font-size:12px!important;line-height:1.7!important}',
  '.cdb-eco-showcase :where(a,summary):focus-visible{outline:3px solid #ffd580!important;outline-offset:4px!important}',
  '@media(max-width:940px){.cdb-eco-cards{grid-template-columns:1fr 1fr}.cdb-eco-card:last-child{grid-column:span 2}}',
  '@media(max-width:600px){.cdb-eco-showcase{padding:18px;margin:28px 0}.cdb-eco-cards,.cdb-eco-directory ul{grid-template-columns:1fr}.cdb-eco-card:last-child{grid-column:auto}.cdb-eco-actions a{width:100%}}',
  '@media(prefers-reduced-motion:reduce){.cdb-eco-showcase *{animation:none!important;transition:none!important}}',
  '@media print{.cdb-eco-showcase{background:#fff!important;color:#111!important;box-shadow:none!important;border:1px solid #8899a6!important;break-inside:avoid-page}.cdb-eco-head h2,.cdb-eco-card h3,.cdb-eco-showcase :where(p,span,summary){color:#111!important}.cdb-eco-card{background:#fff!important;border:1px solid #bdc8cf!important;break-inside:avoid-page}.cdb-eco-showcase a{color:#153e5c!important;text-decoration:underline!important}.cdb-eco-directory{display:none!important}.cdb-eco-actions .cdb-eco-primary{background:#fff!important;border:1px solid #999!important}}'
].join('\n');
const CSS = '<style id="' + STYLE_ID + '">\n' + RULES + '\n</style>';
module.exports={STYLE_ID,CSS,OFFERINGS,recommendationsFor,renderEcosystemShowcase};
