'use strict';

/**
 * Inspect final allowlisted Cloudflare HTML artifacts, not just source fixtures.
 * No remote HTTP, no user data and no artifact modification.
 */
const fs=require('node:fs');
const path=require('node:path');
const {STYLESHEET}=require('./soc-platform-presentation.cjs');

function audit(root){
  if(typeof root!=='string'||!fs.existsSync(root)||!fs.statSync(root).isDirectory())
    throw Error('Existing built public asset directory required');
  const failures=[];let checked=0;
  const walk=(dir)=>{
    for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
      const full=path.join(dir,entry.name);
      if(entry.isSymbolicLink())throw Error('Symlink in published assets rejected');
      if(entry.isDirectory()){walk(full);continue;}
      if(!entry.name.toLowerCase().endsWith('.html'))continue;
      const html=fs.readFileSync(full,'utf8');
      const rel=path.relative(root,full).split(path.sep).join('/');
      const count=(needle)=>html.split(needle).length-1;
      const checks=[
        [count('data-soc-platform-shell="v1"')===1,'SOC shell missing or duplicated'],
        [count(STYLESHEET)===1,'SOC stylesheet missing or duplicated'],
        [html.includes('href="/soc.html"'),'SOC overview link missing'],
        [html.includes('href="/enterprise-onboarding.html"'),'SOC enterprise CTA missing'],
        [!/<title>[^<]*(?:Research Blog|Intel Factory|Cybersecurity Blog|Intelligence Blog)[^<]*<\/title>/i.test(html),'Legacy product title'],
        [!/<(?:nav|header|footer)\b[^>]*>[^]*?\bResearch Blog\s*\/\s*Intel Factory\b/i.test(
          // Narrow: archived evidence and raw scripts may mention old product.
          html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'')
        ),'Legacy SOC platform identity'],
      ];
      const bad=checks.filter(x=>!x[0]).map(x=>x[1]);
      if(bad.length)failures.push({path:rel,reasons:bad});
      checked++;
    }
  };
  walk(root);
  if(checked<30)throw Error('Implausibly small public HTML artifact set');
  if(failures.length) {
    const detail=failures.slice(0,8).map(v=>v.path+': '+v.reasons.join('; ')).join('\n');
    throw Error('SOC published UI audit rejected '+failures.length+'/'+checked+' files:\n'+detail);
  }
  return Object.freeze({checked,passed:checked,product:'SENTINEL APEX SOC',verified:'built HTML only'});
}
if(require.main===module) {
  try {
    const root=process.argv[2]||path.join(__dirname,'..','dist-public');
    const report=audit(path.resolve(root));
    process.stdout.write('PASS SOC published all-pages presentation '+JSON.stringify(report)+'\n');
  } catch(err) {
    process.stderr.write('SOC P0 HTML presentation audit failed: '+String(err.message).slice(0,1200)+'\n');
    process.exitCode=1;
  }
}
module.exports={audit};
