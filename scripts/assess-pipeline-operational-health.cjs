#!/usr/bin/env node
'use strict';
/**
 * Independent source-only pipeline health certification, no network or writes.
 * Never a public-host/Cloudflare deployment or paid-customer GA certificate.
 * CI uses the same freshness and per-run yield classifiers as publisher gates.
 */
const fs=require('node:fs');
const path=require('node:path');
const {evaluateFreshness}=require('./check-intel-freshness.js');
const {evaluate:checkSourceYield}=require('./check-intel-source-yield.cjs');
const MAX_SKEW_MS=15*60*1000;
const MAX_SOURCE_BYTES=32*1024*1024;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function assess({feed,state,feedBytes,nowMs=Date.now()}={}){
  const codes=new Set();
  if(!Number.isFinite(nowMs)||!object(feed)||!object(state)||!Number.isSafeInteger(feedBytes)||feedBytes<=0||feedBytes>MAX_SOURCE_BYTES)
    return {status:'MONITOR_ERROR',exitCode:1,codes:['SOURCE_INPUT_INVALID']};
  const freshness=evaluateFreshness({feed,state,feedBytes,nowMs});
  const source=checkSourceYield(state,nowMs);
  if(freshness.status!=='HEALTHY')codes.add('INTEL_'+freshness.status);
  if(freshness.runtimeSource!=='intel-state.json lastRun'||freshness.contentSource!=='intel-state.json lastReportGeneratedAt')
    codes.add('AUTHORITATIVE_TIMESTAMPS_MISSING');
  if(source.status!=='COVERAGE_VERIFIED')codes.add('SOURCE_'+source.status);
  const published=Date.parse(feed.generatedAt||'');
  const stateRun=Date.parse(state.lastRun||'');
  if(!Number.isFinite(published)||!Number.isFinite(stateRun)||Math.abs(published-stateRun)>MAX_SKEW_MS||
      !Number.isSafeInteger(feed.totalPublished)||feed.totalPublished<0||
      !Number.isSafeInteger(state.totalPublished)||state.totalPublished<0||
      feed.totalPublished!==state.totalPublished)
    codes.add('PUBLISH_SOURCE_STATE_MISMATCH');
  // Source slots that were empty in THIS run must not count as active.
  // An old cumulative corpus says nothing about fresh source availability.
  if(source.status==='COVERAGE_VERIFIED' && source.activeSources<5)
    codes.add('SOURCE_COVERAGE_BELOW_FLOOR');
  return {status:codes.size?'SOURCE_PIPELINE_NOT_CERTIFIED':'SOURCE_PIPELINE_VERIFIED',
    exitCode:codes.size?2:0,
    codes:[...codes].sort(),
    // Log only coarse operational status; no feeds, secrets or customer IDs.
    sourceCoverage:object(state.lastIngestion)?{
      active:state.lastIngestion.activeSources,
      configured:state.lastIngestion.totalSources
    }:null,
    contentAgeMinutes:freshness.contentAgeMinutes};
}
if(require.main===module){
  try{
    if(process.argv.length!==2)throw Error('UNEXPECTED_ARGUMENT');
    const root=path.join(__dirname,'..');
    const raw=fs.readFileSync(path.join(root,'live-intel.json'));
    if(raw.length>MAX_SOURCE_BYTES)throw Error('FEED_OVERSIZE');
    const result=assess({feed:JSON.parse(raw.toString('utf8')),state:JSON.parse(
      fs.readFileSync(path.join(root,'intel-state.json'),'utf8')),
      feedBytes:raw.length});
    console.log(JSON.stringify(result));
    process.exitCode=result.exitCode;
  }catch(_){
    console.error('MONITOR_ERROR: SOURCE_PIPELINE_EVIDENCE_MISSING_OR_INVALID');
    process.exitCode=1;
  }
}
module.exports={assess};
