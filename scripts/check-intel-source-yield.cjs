#!/usr/bin/env node
'use strict';
/**
 * This-run source-yield proof for Sentinel APEX v5.
 * Transport OK is not a claim of new verified intelligence.
 * Bounded, read-only. No remote calls, resets, delivery or deployment.
 * Called AFTER normal commit/push, so successful genuine publication is kept.
 */
const fs = require('node:fs');
const path = require('node:path');
const MIN_ACTIVE_SOURCES = 5;
const MAX_RUN_AGE_MINUTES = 120;
function evaluate(state,nowMs=Date.now()) {
  const run = state && state.lastIngestion;
  if(!state || !run || !Number.isSafeInteger(run.totalSources) || run.totalSources<1 ||
     !Number.isSafeInteger(run.activeSources) || run.activeSources<0 ||
     run.activeSources>run.totalSources ||
     !Number.isSafeInteger(run.fetchedRecords) || run.fetchedRecords<0 ||
     !Number.isSafeInteger(run.reportsGenerated) || run.reportsGenerated<0) {
    return {status:'MONITOR_ERROR',exitCode:1,code:'INGESTION_RECEIPT_MISSING_OR_INVALID'};
  }
  const checkedAt=Date.parse(run.checkedAt||''),lastRun=Date.parse(state.lastRun||'');
  if(!Number.isFinite(checkedAt)||!Number.isFinite(lastRun)||
     checkedAt>nowMs+5*60000||lastRun>nowMs+5*60000||
     nowMs-checkedAt>MAX_RUN_AGE_MINUTES*60000||
     Math.abs(lastRun-checkedAt)>15*60000) {
    return {status:'MONITOR_ERROR',exitCode:1,code:'INGESTION_RECEIPT_TIME_INVALID'};
  }
  const coverage={activeSources:run.activeSources,totalSources:run.totalSources,
    fetchedRecords:run.fetchedRecords,reportsGenerated:run.reportsGenerated};
  if(run.activeSources<MIN_ACTIVE_SOURCES) {
    return {status:'SOURCE_COVERAGE_DEGRADED',exitCode:2,
      code:'FEWER_THAN_FIVE_SOURCES_RETURNED_RECORDS',...coverage};
  }
  return {status:'COVERAGE_VERIFIED',exitCode:0,
    code:'SOURCE_YIELD_MET_MINIMUM',...coverage};
}
if(require.main===module) {
  try {
    if(process.argv.length!==2)throw Error('UNEXPECTED_CLI_ARGUMENT');
    const state=JSON.parse(fs.readFileSync(path.join(__dirname,'..','intel-state.json'),'utf8'));
    const result=evaluate(state);
    console.log(JSON.stringify(result));
    process.exitCode=result.exitCode;
  }catch(_){
    console.error('MONITOR_ERROR: INGESTION_EVIDENCE_UNAVAILABLE');
    process.exitCode=1;
  }
}
module.exports={evaluate,MIN_ACTIVE_SOURCES};
