#!/usr/bin/env node
'use strict';

/**
 * Account-wide Cloudflare ZERO OVERAGE change-control gate.
 * Does not fetch metrics, incur Cloudflare usage, or guarantee a future bill.
 * Requires a fresh, operator-reviewed private account-wide billing attestation.
 * Rejects absent/stale/partial evidence BEFORE any Wrangler deployment.
 */
const crypto=require('node:crypto');
const PLAN=Object.freeze({
  workersRequests:10000000,
  workersCpuMs:30000000,
  d1RowsRead:25000000000,
  d1RowsWritten:50000000,
  d1StorageGbMonth:5,
  kvReads:10000000,
  kvWrites:1000000,
  kvDeletes:1000000,
  kvLists:1000000,
  kvStorageGbMonth:1,
  r2StandardStorageGbMonth:10,
  r2ClassA:1000000,
  r2ClassB:10000000,
  // AI Security Hub deploy configuration includes scan-jobs producer/consumer.
  // Cloudflare bills Queues by operations (write, read, delete, retries).
  queuesStandardOperations:1000000,
  workersLogEvents:20000000
});
const STOCK=new Set(['d1StorageGbMonth','kvStorageGbMonth','r2StandardStorageGbMonth']);
// Stable inventory identifiers: an attestation cannot omit a known ecosystem
// workload while still passing a superficial three-platform count.
const REQUIRED_PLATFORMS=Object.freeze([
  'sentinel-apex-threat-intel',
  'sentinel-apex-ai-security-hub',
  'sentinel-apex-soc',
  'nilachala-devotional'
]);
const MAX_ATTESTATION_AGE_MS=2*60*60*1000;
const SAFETY_RATIO=0.80;
const FORECAST_BUFFER=1.25;
const PRICE_REVIEW_CUTOFF='2026-12-01T00:00:00.000Z';
const sha256=x=>crypto.createHash('sha256').update(x).digest('hex');
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const isValidTime=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(s)&&Number.isFinite(Date.parse(s));
const metric=x=>obj(x)&&Number.isFinite(x.used)&&x.used>=0&&
  Number.isFinite(x.forecastRemaining)&&x.forecastRemaining>=0;
const receipt=x=>typeof x==='string'&&/^[a-f0-9]{64}$/i.test(x);
const isRef=x=>typeof x==='string'&&/^[A-Za-z0-9][A-Za-z0-9._/-]{7,159}$/.test(x)&&!/(?:placeholder|tbd|unknown|demo)/i.test(x);

function assess(input, accountId,now=new Date().toISOString()){
  const codes=new Set();
  const fail=(code,pass)=>{if(!pass)codes.add(code)};
  if(!obj(input)||!isValidTime(now))return {ok:false,codes:['ATTESTATION_INVALID']};
  fail('SCHEMA_INVALID',input.schemaVersion==='cdb-cloudflare-shared-budget/v1');
  fail('SHARED_ACCOUNT_NOT_ATTESTED',input.accountScope==='ALL_PLATFORMS_SINGLE_CLOUDFLARE_ACCOUNT'&&
    input.accountCoverageConfirmed===true&&input.allActiveMeteredServicesReviewed===true&&
    Array.isArray(input.reviewedPlatforms)&&input.reviewedPlatforms.length>=3&&
    input.reviewedPlatforms.every(isRef)&&new Set(input.reviewedPlatforms).size===input.reviewedPlatforms.length&&
    REQUIRED_PLATFORMS.every(id=>input.reviewedPlatforms.includes(id)));
  fail('ACCOUNT_BINDING_INVALID',typeof accountId==='string'&&/^[a-f0-9]{32}$/i.test(accountId)&&
    input.accountFingerprintSha256===sha256(accountId.toLowerCase()));
  fail('SOURCE_AND_APPROVAL_NOT_VERIFIED',input.source==='cloudflare-account-billing-and-service-metrics'&&
    receipt(input.privateEvidenceSha256)&&isRef(input.operatorApprovalReference)&&
    input.operatorReviewed===true);
  fail('BASE_PLAN_NOT_VERIFIED',input.verifiedWorkersPlan==='paid-standard'&&
    input.r2StorageClass==='standard-only'&&input.anyInfrequentAccessStorage===false);
  fail('UNMODELED_BILLING_NOT_REVIEWED',input.unmodeledBillableServicesPresent===false&&
    input.optionalPaidProductsOrAddonsPresent===false);
  fail('OVERAGE_ALREADY_PROJECTED',input.currentAccountProjectedOverageUsd===0);
  const cycle=input.cycle||{};
  const validCycle=obj(cycle)&&isValidTime(cycle.start)&&isValidTime(cycle.end)&&isValidTime(input.capturedAt);
  if(!validCycle){
    codes.add('BILLING_WINDOW_INVALID');
    return {ok:false,codes:[...codes].sort()};
  }
  const nowMs=Date.parse(now),start=Date.parse(cycle.start),end=Date.parse(cycle.end),captured=Date.parse(input.capturedAt);
  fail('FRESH_USAGE_EVIDENCE_REQUIRED',captured<=nowMs&&nowMs-captured<=MAX_ATTESTATION_AGE_MS);
  fail('BILLING_WINDOW_INVALID',start<nowMs&&nowMs<end&&end-start>=24*60*60*1000&&
    end-start<=35*24*60*60*1000&&captured>=start);
  // 2026-12-01 changes account-wide Observability pricing; require updated
  // model before allowing any billing cycle that crosses the switch date.
  fail('NEW_PRICING_REVIEW_REQUIRED',end<=Date.parse(PRICE_REVIEW_CUTOFF));
  if(!(start<nowMs&&nowMs<end))return {ok:false,codes:[...codes].sort()};
  const expected=Object.keys(PLAN).sort();
  fail('METRIC_COVERAGE_INCOMPLETE',obj(input.metrics)&&
    Object.keys(input.metrics).sort().join('|')===expected.join('|'));
  if(!obj(input.metrics))return {ok:false,codes:[...codes].sort()};
  for(const [name,included] of Object.entries(PLAN)){
    const value=input.metrics[name];
    if(!metric(value)){codes.add('METRIC_MISSING_OR_INVALID_'+name);continue;}
    const elapsed=Math.max(60*1000,nowMs-start),remaining=end-nowMs;
    // For usage counters, require remaining forecast to be at least 125%
    // of elapsed account-wide usage pace. Storage GB-month already accrued
    // and forecast for remaining cycle are additive; max(used,remaining)
    // dangerously undercounts storage that increases late in the month.
    const pace=value.used*remaining/elapsed*FORECAST_BUFFER;
    const projected=STOCK.has(name)?
      value.used+value.forecastRemaining:
      value.used+Math.max(value.forecastRemaining,pace);
    if(!(projected<=(included*SAFETY_RATIO)+1e-9))codes.add('RESERVE_EXHAUSTED_'+name);
  }
  return {ok:codes.size===0,codes:[...codes].sort()};
}
if(require.main===module){
  let body;
  try{
    const input=process.env.CDB_CF_ACCOUNT_BUDGET_ATTESTATION||'';
    if(Buffer.byteLength(input)>16000||!input)throw new Error('MISSING_OR_OVERSIZED');
    body=JSON.parse(input);
  }catch{
    console.error('HOLD: SHARED_CLOUDFLARE_ACCOUNT_BUDGET_ATTESTATION_MISSING');
    process.exitCode=1;
  }
  if(body){
    const result=assess(body,process.env.CLOUDFLARE_ACCOUNT_ID);
    if(!result.ok){
      // Only deterministic error codes, never account IDs, metrics, tokens,
      // or the private source evidence.
      console.error('HOLD: SHARED_CLOUDFLARE_BUDGET '+result.codes.join(', '));
      process.exitCode=1;
    }else{
      console.log('PASS: ACCOUNT_WIDE_BUDGET_RELEASE_GATE with 20-percent headroom; no overage forecast on submitted evidence');
    }
  }
}
module.exports={assess,PLAN,REQUIRED_PLATFORMS,SAFETY_RATIO,FORECAST_BUFFER,PRICE_REVIEW_CUTOFF};
