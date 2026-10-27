#!/usr/bin/env node
'use strict';
/**
 * SENTINEL APEX SOC — operator's OFFLINE, READ-ONLY preflight.
 * Never deploys, runs Wrangler, refreshes intel, mutates git, reads secrets
 * from disk, calls Cloudflare, or asserts managed-SOC customer GA.
 */
const fs=require('node:fs');
const path=require('node:path');
const cp=require('node:child_process');
const {validateBundle}=require('./certify-soc-s2n-api-release.cjs');
const {assess:assessBudget}=require('./cloudflare-account-zero-overage-gate.cjs');
const REPO='cyberdudebivash/cyberdudebivash-blog';
const SHA=/^[a-f0-9]{40}$/i;
const MAX_ATTESTATION_BYTES=16000;
const MAX_FEED_BYTES=32*1024*1024;
function isApprovedOrigin(origin){
  if(typeof origin!=='string')return false;
  return new RegExp('^(?:https:\\/\\/github\\.com\\/|git@github\\.com:|ssh:\\/\\/git@github\\.com\\/)'+
    REPO.replace('/','\\/')+'(?:\\.git)?$','i').test(origin.trim());
}
function verdict({git,approvedSha,bundle,budgetEvidence,accountId,nowMs=Date.now()}={}){
  const errors=new Set();
  if(!git||!isApprovedOrigin(git.origin))errors.add('REPOSITORY_ORIGIN_NOT_APPROVED');
  if(!SHA.test(approvedSha||'')||!git||!SHA.test(git.head||'')||
      !SHA.test(git.upstream||'')||
      approvedSha?.toLowerCase()!==git?.head?.toLowerCase()||
      git?.head?.toLowerCase()!==git?.upstream?.toLowerCase())
    errors.add('PINNED_SHA_NOT_CURRENT_MAIN');
  if(git?.clean!==true)errors.add('GIT_WORKTREE_NOT_CLEAN');
  if(git?.shallow!==false)errors.add('COMPLETE_GIT_HISTORY_NOT_VERIFIED');

  // Dynamic Cloudflare allowance evidence is private, operator-reviewed,
  // covers ALL four ecosystem workloads and must be no older than two hours.
  const budget=assessBudget(budgetEvidence,accountId,new Date(nowMs).toISOString());
  if(!budget.ok){
    errors.add('ACCOUNT_WIDE_BUDGET_UNCERTIFIED');
    for(const code of budget.codes)errors.add('BUDGET_'+code);
  }
  const source=validateBundle({...bundle,nowMs});
  if(source.status!=='PASS'){
    errors.add('SOURCE_AND_BUILT_FEEDS_NOT_CERTIFIED');
    for(const code of source.codes)errors.add('SOURCE_'+code);
  }
  return {
    status:errors.size?'HOLD':'OFFLINE_PREFLIGHT_PASS_NOT_DEPLOY_APPROVAL',
    codes:[...errors].sort(),
    approvedReleaseCommit:SHA.test(approvedSha||'')?approvedSha:null,
    // An offline preflight can never independently attest Cloudflare Worker
    // version, deployed domain, real alert receipts or managed customer SLA.
    workerDeploymentAuthorized:false,customerManagedSocGo:false
  };
}
function readLocalEvidence(root){
  const git=args=>cp.execFileSync('git',args,{cwd:root,encoding:'utf8',
    timeout:10000,maxBuffer:64*1024,stdio:['ignore','pipe','ignore']}).trim();
  const allowed=(name,max=MAX_FEED_BYTES)=>{
    const file=path.join(root,name),stat=fs.statSync(file);
    if(!stat.isFile()||stat.size<=0||stat.size>max)throw Error('SOURCE_OR_ASSET_INVALID');
    return JSON.parse(fs.readFileSync(file,'utf8'));
  };
  const status=git(['status','--porcelain=v1','--untracked-files=normal']);
  const result={
    git:{
      origin:git(['remote','get-url','origin']),
      head:git(['rev-parse','HEAD']),
      upstream:git(['rev-parse','refs/remotes/origin/main']),
      clean:status.length===0,
      shallow:git(['rev-parse','--is-shallow-repository'])==='true'
    },
    bundle:{
      state:allowed('intel-state.json'),
      rootSource:allowed('live-intel.json'),
      apiSource:allowed('api/intel/live.json'),
      rootAsset:allowed('dist-public/live-intel.json'),
      apiAsset:allowed('dist-public/api/intel/live.json')
    }
  };
  return result;
}
if(require.main===module){
  try{
    if(process.argv.length!==2)throw Error('UNEXPECTED_ARGUMENT');
    const approvedSha=process.env.CDB_SOC_APPROVED_RELEASE_SHA||'';
    const rawBudget=process.env.CDB_CF_ACCOUNT_BUDGET_ATTESTATION||'';
    if(!SHA.test(approvedSha)||!rawBudget||Buffer.byteLength(rawBudget)>MAX_ATTESTATION_BYTES)
      throw Error('RELEASE_APPROVAL_OR_PRIVATE_BUDGET_MISSING');
    const budgetEvidence=JSON.parse(rawBudget);
    const local=readLocalEvidence(path.join(__dirname,'..'));
    const result=verdict({...local,approvedSha,budgetEvidence,
      accountId:process.env.CLOUDFLARE_ACCOUNT_ID});
    // Do not print Git status paths, private usage, account IDs, raw payloads,
    // tokens, URLs returned by CLI, or customer/tenant data.
    console.log(JSON.stringify(result));
    process.exitCode=result.status==='OFFLINE_PREFLIGHT_PASS_NOT_DEPLOY_APPROVAL'?0:2;
  }catch(_){
    console.error('HOLD: LOCAL_OPERATOR_RELEASE_EVIDENCE_INVALID_OR_UNAVAILABLE');
    process.exitCode=2;
  }
}
module.exports={verdict,isApprovedOrigin,readLocalEvidence,REPO};
