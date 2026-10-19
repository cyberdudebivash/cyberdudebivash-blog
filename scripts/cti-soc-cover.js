'use strict';
/** Static publisher SOC/CTI assurance-style dossier cover. Presentation only. */
const FOCUS = Object.freeze({
  AI_SECURITY:['AI / agent trust boundaries','Inventory connected models, delegated permissions, tools, and relevant agent logs.'],
  CVE_REPORT:['Vulnerability exposure','Match affected versions and vendor remediation to authoritative enterprise inventory.'],
  ZERO_DAY:['Reported exploitation and attack surface','Verify primary evidence and customer applicability before escalation.'],
  RANSOMWARE:['Ransomware claim and incident scope','Separate actor claims from internally observed compromise, exfiltration or encryption.'],
  MALWARE_REPORT:['Malware behavior and observables','Validate source-backed artifacts before running detection or containment rules.'],
  DATA_BREACH:['Third-party data and identity impact','Establish vendor, customer and identity dependencies before inferring exposure.'],
});
const STEPS=[
  ['SOURCE REVIEW','Review primary record, affected technology, publication date, confidence and evidence gaps.'],
  ['EXPOSURE VALIDATION','Check inventory, product versions, reachable surfaces, privileges and ownership.'],
  ['DETECTION READINESS','Identify supported telemetry and test sourced detections before operational use.'],
  ['RESPONSE DECISION','Document owner and evidence; escalate only after local indicators justify incident response.'],
];
const clean=(v,n=160)=>String(v==null?'':v).replace(/\s+/g,' ').trim().slice(0,n);
const esc=v=>clean(v,500).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
function sourceLink(refs){
  for(const ref of Array.isArray(refs)?refs:[]){
    try{const u=new URL(String(ref));if(!['http:','https:'].includes(u.protocol)||!u.hostname||u.username||u.password)continue;
      return '<a href="'+esc(u.href)+'" target="_blank" rel="noopener noreferrer">Open cited source ↗</a>';
    }catch(_){}
  }
  return 'No actionable source URL supplied.';
}
function cvssState(item){
  const s=typeof item.cvss==='number'&&Number.isFinite(item.cvss)&&item.cvss>=0&&item.cvss<=10?item.cvss:null;
  return s===null?['Not assigned','UNASSESSED']:[String(s),s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW'];
}
function renderSocCtiCover(item, options={}){
  if(!item)return '';
  const type=clean(item.type||'NEWS_REPORT',64).toUpperCase();
  const [score,severity]=cvssState(item),[focus,focusDetail]=FOCUS[type]||['Evidence and enterprise relevance','Determine applicability through source evidence and local telemetry.'];
  const ref=clean(item.id||'NOT ASSIGNED',100),date=clean(item.pubDate||'Not provided',50);
  const count=Number.isInteger(item.sourceCount)&&item.sourceCount>=0?item.sourceCount:Array.isArray(item._sources)?item._sources.length:0;
  const exploit=item.cisaKev===true?'CISA KEV listed; verify record':item.exploited===true?'Exploitation reported; check sources':'Not established by this source record';
  const priority=item.priority==null?'Not assigned':clean(item.priority,5)+'/100';
  const vector=clean(item.vector||'',50),scoreVersion=vector.startsWith('CVSS:4.0')?'CVSS 4.0':vector.startsWith('CVSS:3.')?'CVSS v3.x':'CVSS version not provided';
  const nav=[['Executive','#cdb-static-executive'],['Technical','#cdb-static-technical'],
    ['Sources','#cdb-static-references'],['Response','#cdb-static-response'],['Ecosystem','#cdb-ecosystem-services']];
  if(options.verifiedDetectionEvidence)nav.splice(3,0,['Detection','#cdb-static-detection']);
  const navHtml=nav.map(([n,h])=>'<a href="'+h+'">'+esc(n)+'</a>').join('');
  const stepHtml=STEPS.map(([n,d],i)=>'<div><b>0'+(i+1)+' / '+esc(n)+'</b><p>'+esc(d)+'</p></div>').join('');
  const cell=(name,value,note='')=>'<div><small>'+esc(name)+'</small><strong>'+esc(value)+'</strong>'+(note?'<small>'+esc(note)+'</small>':'')+'</div>';
  return '<section class="cdb-soc12" data-cdb-soc-cti-v12="true" aria-label="SOC and CTI intelligence dossier">'+
    '<div class="cdb-soc12-over"><span>SENTINEL APEX™ / CYBERDUDEBIVASH® ECOSYSTEM</span><span>ENTERPRISE CTI / PUBLIC BRIEF</span></div>'+
    '<div class="cdb-soc12-head"><div><small>SOC ANALYST DECISION RECORD / '+esc(type)+'</small><h2>'+esc(clean(item.title||'Intelligence report',260))+
    '</h2><p>Source-traceable intelligence with accountable validation and clear uncertainty boundaries.</p></div>'+
    '<aside><b>PUBLIC INTELLIGENCE</b><span>Customer exposure: NOT ASSESSED</span><span>Incident determination: NOT MADE</span></aside></div>'+
    '<div class="cdb-soc12-grid">'+cell('REPORT ID',ref)+cell('CVSS TECHNICAL SEVERITY',score+' · '+severity,scoreVersion)+
    cell('EXPLOITATION ASSESSMENT',exploit)+cell('SOURCE RECORDS',count+' collected; not corroboration')+
    cell('SOURCE PUBLICATION DATE',date)+cell('EDITORIAL PRIORITY',priority+' · '+clean(item.threatLevel||'UNASSESSED'))+'</div>'+
    '<nav aria-label="Jump to dossier sections" class="cdb-soc12-nav">'+navHtml+'</nav>'+
    '<div class="cdb-soc12-focus"><div><small>ANALYST FOCUS</small><h3>'+esc(focus)+'</h3><p>'+esc(focusDetail)+'</p></div>'+
    '<div><small>PROVENANCE ENTRY</small><p>'+sourceLink(item.refs)+'</p><p>Source facts are separate from customer telemetry and commercial content.</p></div></div>'+
    '<div class="cdb-soc12-handoff"><h3>SOC HANDOFF / DECISION GATES</h3><div>'+stepHtml+'</div></div>'+
    '<p class="cdb-soc12-caveat"><b>Assurance boundary:</b> This is an operational CTI brief, not an AICPA SOC 2 Type I/II attestation, audit opinion, completed control test or evidence of customer compromise. All response actions require source and local-telemetry verification.</p>'+
    '</section>';
}
const CSS='<style id="cdb-soc-cti-v12-css">'+
'.cdb-soc12{margin:0 0 34px;padding:clamp(16px,2.7vw,28px);background:radial-gradient(ellipse at top right,rgba(34,163,207,.13),transparent 60%),linear-gradient(135deg,#081625,#0b1d2d);border:1px solid #2e5069;border-radius:17px;color:#dbeafe;font:400 13px/1.65 system-ui,sans-serif;box-shadow:0 18px 56px rgba(0,0,0,.2)}'+
'.cdb-soc12 *{box-sizing:border-box}.cdb-soc12-over{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;color:#80ddfa;font:800 10px/1.5 monospace;letter-spacing:.08em}.cdb-soc12-head{display:grid;grid-template-columns:minmax(0,1fr) 220px;gap:20px;margin:25px 0}.cdb-soc12-head small{color:#81daf4;letter-spacing:.1em;font-weight:800}.cdb-soc12-head h2{color:#fff;font-size:clamp(21px,3vw,30px);line-height:1.3;margin:8px 0;overflow-wrap:anywhere}.cdb-soc12-head p{color:#c1d6e9;margin:8px 0}.cdb-soc12-head aside{background:rgba(26,58,83,.7);border:1px solid #355c78;border-radius:10px;padding:13px}.cdb-soc12-head aside b{font-size:10px;display:block;color:#9be7fc}.cdb-soc12-head aside span{display:block;margin-top:9px;font-size:11px}'+
'.cdb-soc12-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:#26455d;border:1px solid #26455d;border-radius:11px;overflow:hidden}.cdb-soc12-grid>div{background:#0b2031;padding:12px;min-width:0}.cdb-soc12-grid small{display:block;font-size:9px;font-weight:800;letter-spacing:.08em;color:#8fabc0}.cdb-soc12-grid strong{display:block;color:#f4fcff;font:750 12px/1.5 monospace;margin:5px 0;overflow-wrap:anywhere}'+
'.cdb-soc12-nav{display:flex;flex-wrap:wrap;gap:8px;margin:17px 0}.cdb-soc12-nav a{border:1px solid #345e78;border-radius:7px;padding:7px 12px;color:#96dfff;text-decoration:none;font-size:11px;font-weight:800;min-height:34px}.cdb-soc12-nav a:focus-visible,.cdb-soc12-nav a:hover{background:#18394f;outline-offset:2px}.cdb-soc12-focus{display:grid;grid-template-columns:1.3fr 1fr;gap:10px}.cdb-soc12-focus>div{border:1px solid #27465d;background:#081b2b;border-radius:10px;padding:14px}.cdb-soc12-focus small{color:#94e6fa;font-weight:800;font-size:10px;letter-spacing:.08em}.cdb-soc12-focus h3{color:#fff;margin:8px 0;font-size:17px}.cdb-soc12-focus p{color:#d3e7f4;font-size:12px;margin:7px 0}.cdb-soc12-focus a{color:#8be4ff;overflow-wrap:anywhere}'+
'.cdb-soc12-handoff{margin-top:17px}.cdb-soc12-handoff h3{font-size:11px;letter-spacing:.09em;color:#8de1f4;margin:0 0 10px}.cdb-soc12-handoff>div{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.cdb-soc12-handoff>div>div{background:#0b1b2b;border:1px solid #27455d;border-radius:9px;padding:11px}.cdb-soc12-handoff b{color:#fff;font-size:10px}.cdb-soc12-handoff p{color:#b9d0e2;font-size:11px;margin:8px 0 0;line-height:1.55}.cdb-soc12-caveat{margin:17px 0 0;padding:11px;border-left:3px solid #8aaec8;background:rgba(138,174,200,.08);font-size:11px;color:#c5d4e2}'+
'@media(max-width:900px){.cdb-soc12-handoff>div{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:720px){.cdb-soc12-head,.cdb-soc12-focus{grid-template-columns:1fr}.cdb-soc12-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:420px){.cdb-soc12-grid,.cdb-soc12-handoff>div{grid-template-columns:1fr}}@media print{.cdb-soc12{background:#fff!important;color:#111!important;box-shadow:none}.cdb-soc12 *{color:#111!important}}'+
'</style>';
module.exports={renderSocCtiCover,CSS};
