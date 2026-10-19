'use strict';
/**
 * SENTINEL APEX Historical CTI Archive v14.
 *
 * Zero-network, read-only inventory + optional presentation-only staging.
 * Old findings are preserved byte-for-byte within their article sections.
 * This does not attest SOC 2, certify sources, or invent detection artifacts.
 *
 * CLI (NO SOURCE WRITES):
 *   node scripts/cti-archive-v14.js
 *   node scripts/cti-archive-v14.js --manifest /tmp/cti-archive-v14.json
 *
 * The published build consumes decorateLegacyPost() on the COPY only.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ARCHIVE_MARKER = 'data-cdb-archive-v14="presentation-only"';
const STYLE_REF = '/cti-archive-reader.css?v=14';
const NOTICE = '<section class="cdb-archive-notice" role="note" '+ARCHIVE_MARKER+' aria-label="Historical intelligence provenance and operational limitations">'+
  '<strong>SENTINEL APEX™ / Historical intelligence record</strong>'+
  '<p>Archived source-attributed reporting is preserved for research and investigation. This page has not been independently revalidated against current vendor, CISA or enterprise telemetry. '+
  'CVSS technical severity and editorial triage priority are different measures. Previously published IOC, exploitation, ATT&amp;CK and detection-rule statements require verification against cited primary sources and your own logs before operational use. '+
  'This is not an audited SOC 2 attestation or evidence of customer compromise.</p></section>';

function isPost(rel){return /^posts\/[^/]+\.html$/i.test(String(rel).replace(/\\/g,'/'));}
function isCve(rel){return /^cve\/CVE-\d{4}-\d+\.html$/i.test(String(rel).replace(/\\/g,'/'));}
function digest(data){return crypto.createHash('sha256').update(data).digest('hex');}

/**
 * Legacy sidebar used an editorial priority band as if it described a CVSS
 * base score. Render BOTH labels separately, deriving a band solely from the
 * numeric score already shown on this page. This does not verify that the
 * historical score itself is authoritative.
 */
function normalizeArchiveSidebar(html) {
  const match=String(html).match(/<div class="vscore">\s*(\d+(?:\.\d+)?)\s*<\/div>/i);
  if(!match)return String(html);
  const score=Number(match[1]);
  if(!Number.isFinite(score)||score<0||score>10)return String(html);
  const band=score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':score>0?'LOW':'NONE';
  let out=String(html);
  out=out.replace(/(<div class="threat-badge">)(CRITICAL|HIGH|MEDIUM|LOW)\s*[—-]\s*(\d{1,3})\/100(<\/div>)/i,
    (_,begin,priorityBand,priority,end)=>begin+'Displayed CVSS '+match[1]+' ('+band+') · Editorial priority '+priority+'/100 ('+priorityBand+')'+end);
  // Source-count is an ingestion count. It does not establish corroboration.
  out=out.replace(/(<span class="vk">Sources<\/span><span class="vv"[^>]*>)(\d+)\s+confirmed(<\/span>)/i,
    (_,begin,count,end)=>begin+count+' collected'+end);
  return out;
}

function decorateLegacyPost(html, relativePath) {
  const raw = String(html || '');
  if(!isPost(relativePath) || !raw || raw.includes(ARCHIVE_MARKER) ||
     raw.includes('data-cdb-soc-cti-v12="true"') ||
     raw.includes('class="cdb-cti-reader"')) return raw;
  // Only change the familiar published report shell, never arbitrary pages.
  if(!/<article(?:\s[^>]*)?>/i.test(raw) || !/\bclass=["'][^"']*\bmeta-bar\b/i.test(raw) ||
     !/<head(?:\s[^>]*)?>/i.test(raw) || !/<\/head>/i.test(raw) ||
     !/<\/body>/i.test(raw)) return raw;

  let output = normalizeArchiveSidebar(raw);
  if(!output.includes('cti-archive-reader.css')) {
    output = output.replace(/<\/head>/i,
      '<link rel="stylesheet" href="'+STYLE_REF+'">\n</head>');
  }
  // Constrain the old typography to one article instead of changing site chrome.
  output = output.replace(/<article(?<attrs>\s[^>]*)?>/i, (match, attrs='') => {
    const orig = String(attrs || '');
    const cls = orig.match(/\bclass\s*=\s*(["'])(.*?)\1/i);
    const patched = cls
      ? orig.replace(cls[0], 'class='+cls[1]+cls[2]+' cdb-cti-archive-v14'+cls[1])
      : orig+' class="cdb-cti-archive-v14"';
    return '<article'+patched+'>\n'+NOTICE;
  });
  return output;
}

function findSourceForCve(root, relativePath) {
  if(!isCve(relativePath)) return { status:'not_cve' };
  const id = path.basename(relativePath,'.html').toUpperCase();
  const source = path.join(root,'api','intel','cve',id+'.json');
  if(!fs.existsSync(source)) return { status:'source_unavailable', id };
  try {
    const buf = fs.readFileSync(source);
    if(buf.length > 1024*1024) return {status:'source_too_large',id};
    const record = JSON.parse(buf.toString('utf8'));
    if(!record || typeof record !== 'object' || Array.isArray(record))
      return {status:'source_invalid',id};
    if(record.id && String(record.id).toUpperCase()!==id)
      return {status:'identity_conflict',id};
    // Some old raw feeds have only a CVE ID and placeholder description. Do not
    // erase a useful historical page just to show a modern-looking blank.
    if(typeof record.title !== 'string' || record.title.trim().length<8 ||
       typeof record.description !== 'string' || record.description.trim().length<25)
      return {status:'source_insufficient',id};
    return {status:'source_eligible',id,source,source_sha256:digest(buf)};
  } catch (_) {return {status:'source_invalid',id};}
}

function* walkHtml(root,subdir){
  const dir = path.join(root,subdir);
  if(!fs.existsSync(dir)) return;
  for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
    if(entry.isSymbolicLink()) continue;
    const rel = subdir+'/'+entry.name;
    if(entry.isDirectory()) yield* walkHtml(root,rel);
    else if(entry.isFile() && /\.html$/i.test(entry.name)) yield rel;
  }
}

function inspectArchive(root){
  const files=[],totals={posts:0,cve:0,post_presentation_candidates:0,cve_source_eligible:0,already_modern:0,exceptions:0};
  const resolution=path.resolve(root);
  for(const dir of ['posts','cve']){
    for(const rel of walkHtml(resolution,dir)){
      const full=path.join(resolution,rel);
      const bytes=fs.readFileSync(full);
      const html=bytes.toString('utf8');
      const type=dir==='posts'?'post':'cve';
      totals[dir]++;
      const prior=digest(bytes);
      const modern=html.includes('data-cdb-soc-cti-v12="true"');
      const entry={path:rel,kind:type,original_sha256:prior,original_bytes:bytes.length};
      if(type==='post'){
        const changed=decorateLegacyPost(html,rel);
        entry.state=modern?'already_modern':changed===html?'unchanged_no_known_shell':'presentation_candidate';
        entry.staged_sha256=digest(changed);
        entry.staged_bytes=Buffer.byteLength(changed);
        if(changed!==html)totals.post_presentation_candidates++;
      }else{
        const source=findSourceForCve(resolution,rel);
        entry.state=modern?'already_modern':source.status;
        entry.source_sha256=source.source_sha256||null;
        if(source.status==='source_eligible'&&!modern){
          totals.cve_source_eligible++;
          // Produce the exact build-stage public-byte hash using the same
          // canonical renderer and customer-experience layer. Only read files.
          try {
            const pub=require('./build-cloudflare-assets');
            const rendered=pub.renderCvePageFromJson(source.id,source.source,rel);
            const staged=pub.injectCustomerExperience(pub.validatePublicHtmlStructure(
              pub.neutralizeLegacyCommercialCopy(rendered),rel));
            entry.staged_sha256=digest(staged);
            entry.staged_bytes=Buffer.byteLength(staged);
          } catch (error) {
            entry.state='render_failed';
            entry.render_error=String(error.message||'error').slice(0,160);
            totals.cve_source_eligible--;
          }
        }
      }
      if(modern)totals.already_modern++;
      if(entry.state!=='already_modern'&&entry.state!=='presentation_candidate'&&entry.state!=='source_eligible')totals.exceptions++;
      files.push(entry);
    }
  }
  // Explicitly no timestamps: two runs over unchanged bytes have the same hash.
  return {
    schema:'SENTINEL-APEX-CTI-ARCHIVE-V14',
    mode:'READ_ONLY_SOURCE_AUDIT',
    source_root:resolution,
    totals,
    files,
  };
}

function cli(argv=process.argv.slice(2)){
  const root=path.resolve(__dirname,'..');
  let output=null;
  if(argv.length){
    if(argv.length!==2 || argv[0]!=='--manifest' || !argv[1]) throw Error('Usage: node scripts/cti-archive-v14.js [--manifest PATH]');
    output=path.resolve(argv[1]);
    // Never overwrite public source or build output with an audit.
    if(output===root || output.startsWith(root+path.sep) ||
       output===path.dirname(root) || output.endsWith('.html'))
       throw Error('Audit manifest must be outside repository and must not overwrite HTML');
    if(fs.existsSync(output)) throw Error('Refusing to overwrite existing audit evidence');
  }
  const report=inspectArchive(root);
  if(output){fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
  process.stdout.write(JSON.stringify({schema:report.schema,mode:report.mode,totals:report.totals,manifest_path:output})+'\n');
  return report;
}
if(require.main===module){try{cli();}catch(err){console.error('[CTI ARCHIVE] '+err.message);process.exitCode=1;}}
module.exports={ARCHIVE_MARKER,STYLE_REF,NOTICE,decorateLegacyPost,normalizeArchiveSidebar,findSourceForCve,inspectArchive,digest,cli};
