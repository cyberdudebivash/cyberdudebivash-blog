#!/usr/bin/env node
'use strict';
/**
 * Read-only P0 publication ledger consistency assertion. This runs after
 * the normal publisher writes all outputs and before Git stages/commits,
 * and before EACH push retry after rebase. It never repairs source, advances
 * timestamps, generates stories or triggers a Cloudflare deployment.
 */
const fs=require('node:fs');
const path=require('node:path');
const {assessPublicationCounts}=require('./finalize-publication-counts.cjs');
const MAX_WINDOW_MS=15*60*1000;
function check({state,widget,api}={}){
  const codes=[];
  if(!state||typeof state!=='object'||!widget||typeof widget!=='object'||!api||typeof api!=='object')
    return {status:'HOLD',codes:['SOURCE_LEDGER_UNAVAILABLE']};
  try{
    const verdict=assessPublicationCounts(state,widget,api);
    if(verdict.status!=='ALREADY_FINAL')codes.push('UNFINALIZED_REPORT_COUNT');
  }catch(_){codes.push('REPORT_COUNT_DRIFT_OR_CORRUPTION');}
  const run=Date.parse(state.lastRun||'');
  const wg=Date.parse(widget.generatedAt||'');
  const ag=Date.parse(api.generated||'');
  if(!Number.isFinite(run)||!Number.isFinite(wg)||!Number.isFinite(ag)||
    Math.abs(run-wg)>MAX_WINDOW_MS||Math.abs(run-ag)>MAX_WINDOW_MS)
    codes.push('SOURCE_FEED_RUN_DIVERGENCE');
  if(state.lastReportGeneratedAt!=null){
    const report=Date.parse(state.lastReportGeneratedAt);
    if(!Number.isFinite(report)||!Number.isFinite(run)||report>run+5*60000)
      codes.push('REPORT_TIME_INVALID');
  }
  // Count is cumulative reports ever published; feed.items is a rolling
  // top-N window and MUST NOT be compared to count as if it were a ledger.
  if(Array.isArray(widget.items)&&Number.isSafeInteger(widget.totalPublished)&&
    widget.totalPublished<widget.items.length)codes.push('WIDGET_COUNT_BELOW_WINDOW');
  if(Array.isArray(api.items)&&Number.isSafeInteger(api.total_published)&&
    api.total_published<api.items.length)codes.push('API_COUNT_BELOW_WINDOW');
  return {status:codes.length?'HOLD':'PASS',codes};
}
if(require.main===module){
  try{
    if(process.argv.length!==2)throw Error('NO_ARGUMENTS_ALLOWED');
    const root=path.join(__dirname,'..');
    const report=check({
      state:JSON.parse(fs.readFileSync(path.join(root,'intel-state.json'),'utf8')),
      widget:JSON.parse(fs.readFileSync(path.join(root,'live-intel.json'),'utf8')),
      api:JSON.parse(fs.readFileSync(path.join(root,'api/intel/live.json'),'utf8'))
    });
    console.log(JSON.stringify(report));
    process.exitCode=report.status==='PASS'?0:2;
  }catch(_){
    console.error('HOLD: PUBLICATION_SOURCE_LEDGER_UNAVAILABLE');
    process.exitCode=2;
  }
}
module.exports={check};
