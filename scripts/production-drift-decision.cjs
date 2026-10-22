'use strict';

/**
 * P0 production drift reconciler classifier — NO network, NO deploy.
 *
 * The canonical production-affecting path patterns come from the existing
 * Cloudflare production deploy push trigger (not a second mutable allowlist).
 * A complete local git diff, with unlimited history via checkout fetch-depth:0,
 * is used instead of GitHub compare's 300-file response limit.
 *
 * Decisions: 'deploy' only if ALL files are understood and at least one
 * production-affecting path changed; 'skip' only for known nonproduction-only
 * changes; 'blocked' for unknown/unclassifiable inputs or non-ancestor history.
 */
const fs=require('node:fs');
const path=require('node:path');
const cp=require('node:child_process');
const {matchesAny}=require('./deploy-trigger-inputs');

const ROOT=path.resolve(__dirname,'..');
const WORKFLOW=path.join(ROOT,'.github/workflows/cloudflare-production-deploy.yml');
const SHA=/^[a-f0-9]{40}$/;

// Intentionally narrow. Production patterns are checked FIRST, including any
// explicitly test-looking files in a production asset/build path.
const NONPROD_DIRS=Object.freeze(['docs/','tests/','tests-js/']);
const NONPROD_FILES=new Set([
  'README.md','CLAUDE.md',
  '.github/workflows/test.yml',
  'scripts/soc-native-d1-local-certify.cjs',
  'scripts/production-drift-decision.cjs',
]);
function sourcePatterns(raw=fs.readFileSync(WORKFLOW,'utf8')){
  // This is a deliberately strict parser for the repo's known YAML style.
  // Unsupported syntax must block, not silently reclassify.
  if(typeof raw!=='string')throw Error('DEPLOY_WORKFLOW_UNKNOWN');
  const lines=raw.split(/\r?\n/);
  const push=lines.findIndex(x=>x==='  push:');
  if(push<0||lines[0]!==lines[0])throw Error('DEPLOY_WORKFLOW_UNKNOWN');
  const tail=lines.slice(push+1);
  const branches=tail.findIndex(x=>x==='    branches: [main]');
  const paths=tail.findIndex(x=>x==='    paths:');
  if(branches<0||paths<=branches||branches>8)
    throw Error('DEPLOY_WORKFLOW_UNKNOWN');
  let stop=paths+1;
  const patterns=[];
  while(stop<tail.length){
    const s=tail[stop++];
    if(s.trim()===''||/^\s*#/.test(s))continue;
    if(!s.startsWith('      '))break;
    const m=s.match(/^      - '([^']+)'(?:\s+#.*)?\s*$/);
    if(!m||!m[1]||m[1].startsWith('!')||m[1].includes('\\')||
      m[1].includes('..')||m[1].startsWith('/'))
      throw Error('DEPLOY_WORKFLOW_UNKNOWN');
    patterns.push(m[1]);
  }
  if(patterns.length<50||!patterns.includes('api/**')||
     !patterns.includes('workers/**')||!patterns.includes('wrangler.jsonc')||
     !patterns.includes('index.html')||
     !patterns.includes('.github/workflows/production-drift-reconcile.yml'))
    throw Error('DEPLOY_WORKFLOW_UNKNOWN');
  return Object.freeze(patterns);
}
function safeName(value){
  return typeof value==='string'&&value.length>0&&value.length<4096&&
    !value.startsWith('/')&&!value.startsWith('./')&&
    !value.includes('\\')&&!value.includes('\0')&&
    !value.split('/').includes('..')&&!value.split('/').includes('.');
}
function classify(files,patterns){
  if(!Array.isArray(files)||!Array.isArray(patterns)||!patterns.length ||
     files.length>100000) return Object.freeze({decision:'blocked',reason:'INVALID_DIFF'});
  let prod=0,nonprod=0,unknown=0;
  const seen=new Set();
  for(const file of files){
    if(!safeName(file))return Object.freeze({decision:'blocked',reason:'INVALID_PATH'});
    if(seen.has(file))continue;
    seen.add(file);
    if(matchesAny(file,patterns))prod++;
    else if(NONPROD_FILES.has(file) || NONPROD_DIRS.some(prefix=>file.startsWith(prefix)))nonprod++;
    else unknown++;
  }
  if(unknown)return Object.freeze({decision:'blocked',reason:'UNCLASSIFIED_PATH',productionFiles:prod,nonproductionFiles:nonprod,unknownFiles:unknown});
  return Object.freeze({
    decision:prod?'deploy':'skip',
    reason:prod?'PRODUCTION_INPUT_CHANGED':'KNOWN_NONPRODUCTION_ONLY',
    productionFiles:prod,nonproductionFiles:nonprod,unknownFiles:0,
  });
}
function git(args){
  const r=cp.spawnSync('git',args,{cwd:ROOT,encoding:null,maxBuffer:16*1024*1024,timeout:30000});
  if(r.error||r.status!==0||!Buffer.isBuffer(r.stdout))throw Error('GIT_DIFF_UNAVAILABLE');
  return r.stdout;
}
function gitDecision(base,head,patterns=sourcePatterns()){
  if(typeof base!=='string'||!SHA.test(base)||typeof head!=='string'||!SHA.test(head))
    return Object.freeze({decision:'blocked',reason:'INVALID_SHA'});
  if(base===head)return Object.freeze({decision:'skip',reason:'ALREADY_CERTIFIED'});
  try{
    git(['rev-parse','--verify',base+'^{commit}']);
    git(['rev-parse','--verify',head+'^{commit}']);
    git(['merge-base','--is-ancestor',base,head]);
    // --no-renames includes both deleted and added path for a rename. A
    // production path renamed to a docs path must still count as production.
    const buf=git(['diff','--no-renames','--name-only','-z',base,head,'--']);
    if(buf.length>0 && buf[buf.length-1]!==0)
      return Object.freeze({decision:'blocked',reason:'DIFF_TRUNCATED'});
    const files=buf.length?buf.subarray(0,-1).toString('utf8').split('\0'):[];
    if(files.some(v=>Buffer.from(v,'utf8').includes(0xef) && v.includes('\ufffd')))
      return Object.freeze({decision:'blocked',reason:'INVALID_DIFF_ENCODING'});
    return classify(files,patterns);
  }catch(_){return Object.freeze({decision:'blocked',reason:'GIT_HISTORY_UNVERIFIED'});}
}
if(require.main===module){
  let output;
  try{
    const args=process.argv.slice(2);
    output=args.length===2?gitDecision(args[0],args[1]):
      {decision:'blocked',reason:'INVALID_ARGUMENTS'};
  }catch(_){output={decision:'blocked',reason:'DEPLOY_CLASSIFIER_UNAVAILABLE'};}
  process.stdout.write(JSON.stringify(output)+'\n');
}
module.exports={sourcePatterns,safeName,classify,gitDecision,NONPROD_DIRS,NONPROD_FILES};
