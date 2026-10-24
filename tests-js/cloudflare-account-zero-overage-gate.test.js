'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {assess,PLAN,REQUIRED_PLATFORMS,SAFETY_RATIO}=require('../scripts/cloudflare-account-zero-overage-gate.cjs');
const NOW='2026-10-22T16:00:00.000Z';
const ACCOUNT='a'.repeat(32);
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
function fixture(){
  return {
    schemaVersion:'cdb-cloudflare-shared-budget/v1',
    accountScope:'ALL_PLATFORMS_SINGLE_CLOUDFLARE_ACCOUNT',
    accountCoverageConfirmed:true,
    allActiveMeteredServicesReviewed:true,
    reviewedPlatforms:['sentinel-apex-threat-intel','sentinel-apex-ai-security-hub','sentinel-apex-soc','nilachala-devotional'],
    accountFingerprintSha256:hash(ACCOUNT),
    source:'cloudflare-account-billing-and-service-metrics',
    privateEvidenceSha256:'b'.repeat(64),
    operatorApprovalReference:'OWNER-APPROVAL-20261022',
    operatorReviewed:true,
    verifiedWorkersPlan:'paid-standard',
    r2StorageClass:'standard-only',
    anyInfrequentAccessStorage:false,
    unmodeledBillableServicesPresent:false,
    optionalPaidProductsOrAddonsPresent:false,
    currentAccountProjectedOverageUsd:0,
    cycle:{start:'2026-10-01T00:00:00.000Z',end:'2026-11-01T00:00:00.000Z'},
    capturedAt:'2026-10-22T15:15:00.000Z',
    metrics:Object.fromEntries(Object.entries(PLAN).map(([name,limit])=>
      [name,{used:limit*0.1,forecastRemaining:limit*0.2}]))
  };
}
const go=(change,now=NOW,account=ACCOUNT)=>{
  const s=fixture();change(s);return assess(s,account,now);
};
function hold(code,change,now=NOW,account=ACCOUNT){
  const r=go(change,now,account);
  assert.equal(r.ok,false,'must HOLD');
  assert.ok(r.codes.includes(code),'missing '+code+': '+r.codes.join(','));
}
test('healthy synthetic shared-account inventory with projected headroom passes',()=>{
  const r=assess(fixture(),ACCOUNT,NOW);
  assert.deepEqual(r,{ok:true,codes:[]});
  assert.equal(SAFETY_RATIO,0.8);
});
test('all billable metrics are explicitly inventoried and none can be omitted',()=>{
  assert.equal(Object.keys(PLAN).length,15);
  hold('METRIC_COVERAGE_INCOMPLETE',x=>delete x.metrics.r2ClassB);
  hold('METRIC_COVERAGE_INCOMPLETE',x=>x.metrics.unknownMeter={used:0,forecastRemaining:0});
});
for(const name of Object.keys(PLAN)){
  test('reject if '+name+' already consumes safety reserve',()=>{
    hold('RESERVE_EXHAUSTED_'+name,x=>{
      x.metrics[name]={used:PLAN[name]*0.801,forecastRemaining:0};
    });
  });
  test('reject if '+name+' forecast consumes safety reserve',()=>{
    hold('RESERVE_EXHAUSTED_'+name,x=>{
      x.metrics[name]={used:PLAN[name]*0.40,forecastRemaining:PLAN[name]*0.90};
    });
  });
}
test('storage used-to-date plus future GB-month must be added before comparing reserve',()=>{
  for(const name of ['d1StorageGbMonth','kvStorageGbMonth','r2StandardStorageGbMonth']){
    hold('RESERVE_EXHAUSTED_'+name,x=>{
      x.metrics[name]={used:PLAN[name]*0.35,forecastRemaining:PLAN[name]*0.50};
    });
  }
});
test('reject growth trend if manually forecast remaining usage is too optimistic',()=>{
  hold('RESERVE_EXHAUSTED_workersRequests',x=>{
    x.cycle.start='2026-10-21T00:00:00.000Z';
    x.metrics.workersRequests={used:1600000,forecastRemaining:1};
  });
});
test('reject missing shared account coverage',()=>{
  hold('SHARED_ACCOUNT_NOT_ATTESTED',x=>x.accountCoverageConfirmed=false);
  hold('SHARED_ACCOUNT_NOT_ATTESTED',x=>x.reviewedPlatforms=['soc-only']);
  hold('SHARED_ACCOUNT_NOT_ATTESTED',x=>x.reviewedPlatforms.push(x.reviewedPlatforms[0]));
});
test('fail closed if any known ecosystem platform is missing from account-wide review',()=>{
  assert.deepEqual(REQUIRED_PLATFORMS,[
    'sentinel-apex-threat-intel','sentinel-apex-ai-security-hub',
    'sentinel-apex-soc','nilachala-devotional'
  ]);
  for(const missing of REQUIRED_PLATFORMS){
    hold('SHARED_ACCOUNT_NOT_ATTESTED',x=>{
      x.reviewedPlatforms=x.reviewedPlatforms.filter(id=>id!==missing);
      // Padding the list with plausible names must not bypass coverage.
      x.reviewedPlatforms.push('other-verified-platform','another-verified-platform');
    });
  }
  // Extra reviewed workloads remain valid when all required platforms exist.
  const ok=go(x=>x.reviewedPlatforms.push('additional-approved-worker'));
  assert.equal(ok.ok,true,ok.codes.join(','));
});
test('reject account confusion or invalid account fingerprint',()=>{
  hold('ACCOUNT_BINDING_INVALID',()=>{},NOW,'c'.repeat(32));
  hold('ACCOUNT_BINDING_INVALID',x=>x.accountFingerprintSha256='0'.repeat(64));
});
test('reject stale, future or fabricated dashboard observations',()=>{
  hold('FRESH_USAGE_EVIDENCE_REQUIRED',x=>x.capturedAt='2026-10-22T10:00:00.000Z');
  hold('FRESH_USAGE_EVIDENCE_REQUIRED',x=>x.capturedAt='2026-10-22T17:00:00.000Z');
  hold('SOURCE_AND_APPROVAL_NOT_VERIFIED',x=>x.operatorReviewed=false);
  hold('SOURCE_AND_APPROVAL_NOT_VERIFIED',x=>x.privateEvidenceSha256='NOT_VERIFIED');
});
test('reject periods inconsistent with release date or cycle duration',()=>{
  hold('BILLING_WINDOW_INVALID',x=>x.cycle.end='2026-10-20T00:00:00.000Z');
  hold('BILLING_WINDOW_INVALID',x=>x.cycle.start='2026-10-23T00:00:00.000Z');
  hold('BILLING_WINDOW_INVALID',x=>x.cycle.end='2027-01-01T00:00:00.000Z');
});
test('reject pricing after the December 2026 Observability model switch',()=>{
  hold('NEW_PRICING_REVIEW_REQUIRED',x=>{
    x.cycle.start='2026-11-20T00:00:00.000Z';
    x.cycle.end='2026-12-15T00:00:00.000Z';
    x.capturedAt='2026-11-29T15:30:00.000Z';
  },'2026-11-29T16:00:00.000Z');
});
test('Queues are account-wide and scan-job operations/retries consume budget',()=>{
  assert.equal(PLAN.queuesStandardOperations,1000000);
  hold('RESERVE_EXHAUSTED_queuesStandardOperations',x=>
    x.metrics.queuesStandardOperations={used:790000,forecastRemaining:100000});
});
test('reject unknown usage products and Infrequent Access class',()=>{
  hold('UNMODELED_BILLING_NOT_REVIEWED',x=>x.unmodeledBillableServicesPresent=true);
  hold('UNMODELED_BILLING_NOT_REVIEWED',x=>x.optionalPaidProductsOrAddonsPresent=true);
  hold('BASE_PLAN_NOT_VERIFIED',x=>x.anyInfrequentAccessStorage=true);
  hold('BASE_PLAN_NOT_VERIFIED',x=>x.verifiedWorkersPlan='free');
});
test('reject any account-wide billed overage already projected',()=>{
  hold('OVERAGE_ALREADY_PROJECTED',x=>x.currentAccountProjectedOverageUsd=0.01);
});
test('negative values and NaN cannot satisfy a metric',()=>{
  hold('METRIC_MISSING_OR_INVALID_d1RowsRead',x=>x.metrics.d1RowsRead.used=-1);
  hold('METRIC_MISSING_OR_INVALID_kvReads',x=>x.metrics.kvReads.forecastRemaining=NaN);
});
test('release workflow requires account-wide budget proof before the first deployment',()=>{
  const workflow=fs.readFileSync(path.resolve(__dirname,'../.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  const budget=workflow.indexOf('P0 shared Cloudflare account zero-overage gate');
  const deploy=workflow.indexOf('Deploy Worker assets to the existing, approved domain');
  assert.ok(budget>0&&deploy>budget);
  assert.match(workflow,/CDB_CF_ACCOUNT_BUDGET_ATTESTATION: \$\{\{ secrets\.CDB_CF_ACCOUNT_BUDGET_ATTESTATION \}\}/);
  assert.match(workflow,/node scripts\/cloudflare-account-zero-overage-gate\.cjs/);
  assert.match(workflow,/github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main'/);
  assert.doesNotMatch(workflow,/curl[^\n]+-X (?:DELETE|POST|PUT|PATCH)[^\n]+dns_records/);
});
test('SOC Wrangler configuration maintains bounded logging and existing trigger cadence',()=>{
  const file=fs.readFileSync(path.resolve(__dirname,'../wrangler.jsonc'),'utf8');
  const cfg=JSON.parse(file.replace(/^\s*\/\/.*$/gm,''));
  assert.equal(cfg.name,'cyberdudebivash-blog');
  assert.deepEqual(cfg.triggers.crons,['*/30 * * * *']);
  assert.equal(cfg.observability.enabled,true);
  assert.ok(cfg.observability.head_sampling_rate>0&&cfg.observability.head_sampling_rate<=0.1);
  for(const addon of ['ai','vectorize','queues','durable_objects','hyperdrive','browser','images']){
    assert.equal(cfg[addon],undefined,'new paid service needs fresh budget scope: '+addon);
  }
});
