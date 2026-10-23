'use strict';

/**
 * Build-time UI-only SOC brand. Do not rewrite archive evidence, canonical
 * URLs, legal records, payment code, scripts or security assurances.
 * The legacy hostname remains a routing identifier until DNS cutover.
 */
const STYLESHEET='/soc-platform-ui.css?v=20261022-soc1';
const PLATFORM='SENTINEL APEX SOC';
const SHELL=[
'<div class="soc-unified-shell" data-soc-platform-shell="v1" aria-label="SENTINEL APEX SOC platform navigation">',
' <div class="soc-unified-shell__inner">',
'  <a class="soc-unified-shell__identity" href="/soc.html" aria-label="SENTINEL APEX SOC platform overview">',
'   <span class="soc-unified-shell__mark" aria-hidden="true">S<span>•</span></span>',
'   <span class="soc-unified-shell__name"><strong>SENTINEL APEX <em>SOC</em></strong><small>HYBRID SECURITY OPERATIONS + THREAT INTELLIGENCE</small></span>',
'  </a>',
'  <nav class="soc-unified-shell__nav" aria-label="SOC operational modules">',
'   <a href="/soc.html#soc-intelligence-desk">SOC Intelligence Desk</a><a href="/intel/">Threat Intelligence</a>',
'   <a href="/hunts.html">Threat Hunting</a><a href="/detections/">Detections</a>',
'   <a href="/customer-incident-response.html">Incident Readiness</a>',
'   <a href="/customer-assurance.html">Assurance</a>',
'   <a href="/service-status.html">Service Evidence</a>',
'  </nav>',
'  <a class="soc-unified-shell__action" href="/enterprise-onboarding.html">Request SOC Assessment <span aria-hidden="true">↗</span></a>',
' </div>',
'</div>'
].join('\n');
const UI_MAP=[
  [/\bResearch Blog\s*\/\s*Intel Factory\b/gi,'Hybrid SOC + CTI Platform'],
  [/\bResearch Blog and Intel Factory\b/gi,'SOC and CTI Operations'],
  [/\bSENTINEL APEX Research Blog\b/gi,'SENTINEL APEX SOC'],
  [/\bIntelligence Blog\b/gi,'SOC Intelligence Platform'],
  [/\bResearch Blog\b/gi,'SOC Threat Intelligence'],
  [/\bThis Blog\b/gi,'SENTINEL APEX SOC'],
  [/\bCybersecurity Blog\b/gi,'Cybersecurity Operations'],
  [/\bBlog Newsletter\b/gi,'SOC Threat Intelligence Briefing'],
  [/\bNew Blog Newsletter Subscriber\b/gi,'New SOC Intelligence Subscriber'],
  [/\bBlog Newsletter Subscription\b/gi,'SOC Intelligence Subscription'],
  [/\bIntel Factory\b/gi,'CTI Operations'],
];
function renameUi(text){return UI_MAP.reduce((s,[re,next])=>s.replace(re,next),String(text));}
function renameMetadata(html){
  let out=html.replace(/(<title\b[^>]*>)([\s\S]*?)(<\/title>)/gi,
    (_,a,v,z)=>a+renameUi(v)+z);
  return out.replace(/<meta\b[^>]*>/gi,tag=>{
    if(!/\b(?:name|property)\s*=\s*["'](?:description|keywords|application-name|og:(?:title|description|site_name|image:alt)|twitter:(?:title|description|image:alt))["']/i.test(tag))return tag;
    return tag.replace(/(\bcontent\s*=\s*)(["'])([\s\S]*?)\2/i,
      (m,pre,q,v)=>pre+q+renameUi(v)+q);
  });
}
/**
 * Update visible labels in navigation, headings, branding and footer only.
 * Historical research articles, citations, JSON-LD and code stay intact.
 */
function renameUiMarkup(html){
  const stack=[];let raw=null;
  const tokens=html.match(/<!--[\s\S]*?-->|<![^>]*>|<\/?[A-Za-z][^>"']*(?:(?:"[^"]*"|'[^']*')[^>"']*)*>|[^<]+|</g)||[];
  return tokens.map(token=>{
    if(raw){
      if(new RegExp('^</'+raw+'\\s*>$','i').test(token))raw=null;
      return token;
    }
    if(token.startsWith('<!--')||token.startsWith('<!'))return token;
    if(token.startsWith('<')){
      const m=token.match(/^<(\/)?([\w:-]+)/);if(!m)return token;
      const name=m[2].toLowerCase();
      if(m[1]){const i=stack.map(x=>x.name).lastIndexOf(name);if(i>=0)stack.splice(i);return token;}
      if(['script','style','pre','code','textarea','svg'].includes(name)){raw=name;return token;}
      const controlled=stack.some(x=>x.ui)||['nav','header','footer','button','title','h1','h2','h3'].includes(name);
      const child=controlled||/class=["'][^"']*(?:nav|brand|masthead|logo|hero|footer|platform)[^"']*["']/i.test(token);
      if(!['meta','link','input','img','hr','br','source','path'].includes(name)&&!/\/>$/.test(token))stack.push({name,ui:child});
      return token.replace(/(\s(?:title|alt|aria-label)\s*=\s*)(["'])(.*?)\2/gi,
        (all,pre,q,v)=>pre+q+renameUi(v)+q);
    }
    if(stack.some(x=>x.ui)&&token.trim().length<=600)return renameUi(token);
    if(token.trim().length<=80&&/^(?:Blog|Research Blog|Intel Factory|This Blog|Intelligence Blog)$/i.test(token.trim()))return renameUi(token);
    return token;
  }).join('');
}
function injectSocPresentation(html){
  let out=String(html);
  if(!/<html\b/i.test(out)||!/<body\b/i.test(out)||!/<\/body>/i.test(out))
    throw Error('SOC presentation requires full HTML');
  out=renameUiMarkup(renameMetadata(out));
  if(!out.includes(STYLESHEET))out=out.replace(/<\/head\s*>/i,
    '<link rel="stylesheet" href="'+STYLESHEET+'">\n</head>');
  if(!out.includes('data-soc-platform-shell="v1"'))out=out.replace(/<body\b[^>]*>/i,
    tag=>tag+'\n'+SHELL);
  return out;
}
module.exports={injectSocPresentation,renameUi,renameMetadata,renameUiMarkup,STYLESHEET,SHELL,PLATFORM};
