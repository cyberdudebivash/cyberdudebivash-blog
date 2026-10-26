'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {assessDeliveryHealth,MAX_PENDING_AGE_SEC}=require('../scripts/soc-alert-delivery-health.cjs');
const good=()=>({records_processed:1,claimed:1,skipped_claimed_elsewhere:0,
 cancelled:0,attempts:1,delivered:1,retried:0,dead_lettered:0,unresolved:0});
test('genuine provider processing success never becomes independently validated customer receipt',()=>{
 const r=assessDeliveryHealth(good(),0);
 assert.equal(r.healthy,true);
 assert.equal(r.status,'PROCESSING_COMPLETED_NOT_CUSTOMER_CANARY');
 assert.equal(r.customerReceiptVerified,false);
});
test('zero watched entities/zero attempted alerts is an honest no-eligible status',()=>{
 const g=good();g.claimed=0;g.records_processed=0;g.attempts=0;g.delivered=0;
 assert.deepEqual(assessDeliveryHealth(g,null).status,'NO_ELIGIBLE_DELIVERIES');
 assert.equal(assessDeliveryHealth(g,null).customerReceiptVerified,false);
});
test('unresolved D1 receipt is incident-grade failure even if job ran green',()=>{
 const g=good();g.delivered=0;g.unresolved=1;
 const r=assessDeliveryHealth(g,0);
 assert.equal(r.healthy,false);assert(r.codes.includes('AMBIGUOUS_DELIVERY_STATE'));
});
test('dead letter is never masked by other successful alerts',()=>{
 const g={...good(),attempts:2,claimed:2,records_processed:2,dead_lettered:1};
 const r=assessDeliveryHealth(g,0);
 assert.equal(r.healthy,false);assert(r.codes.includes('DEAD_LETTERED_DELIVERIES'));
});
test('a retry is not proof of a customer receipt; overdue pending backlog blocks',()=>{
 const g={...good(),delivered:0,retried:1};
 assert.equal(assessDeliveryHealth(g,60).healthy,true);
 assert.equal(assessDeliveryHealth(g,60).customerReceiptVerified,false);
 assert.equal(assessDeliveryHealth(g,MAX_PENDING_AGE_SEC+1).status,'DELIVERY_PROCESSING_DEGRADED');
});
test('fail closed on malformed, negative, overflow and inconsistent receipt totals',()=>{
 for(const malformed of [undefined,{},[],null])
   assert.equal(assessDeliveryHealth(malformed,null).status,'MONITOR_ERROR');
 const bad=[{...good(),dead_lettered:-1},{...good(),attempts:0,delivered:1},
 {...good(),claimed:0},{...good(),unresolved:'0'},{...good(),retried:1},
 {...good(),attempts:1,delivered:2,claimed:2}];
 for(const b of bad) assert.equal(assessDeliveryHealth(b,null).status,'MONITOR_ERROR',JSON.stringify(b));
 for(const a of [-1,'0',3.5])assert.equal(assessDeliveryHealth(good(),a).status,'MONITOR_ERROR');
});
test('missing delivery dispositions never become green customer processing',()=>{
 for(const candidate of [
   {...good(),delivered:0},
   {...good(),attempts:2,claimed:2,records_processed:2},
   {...good(),attempts:2,claimed:2,records_processed:2,delivered:0,retried:1},
 ]) {
   const result=assessDeliveryHealth(candidate,null);
   assert.equal(result.healthy,false,JSON.stringify(candidate));
   assert.equal(result.status,'MONITOR_ERROR');
   assert(result.codes.includes('DISPOSITION_TOTAL_MISMATCH'));
   assert.equal(result.customerReceiptVerified,false);
 }
});
test('fully accounted attempts preserve normal retry and terminal classifications',()=>{
 const retry={...good(),delivered:0,retried:1};
 assert.equal(assessDeliveryHealth(retry,null).healthy,true);
 const dead={...good(),delivered:0,dead_lettered:1};
 assert.equal(assessDeliveryHealth(dead,null).status,'DELIVERY_PROCESSING_DEGRADED');
 const unresolved={...good(),delivered:0,unresolved:1};
 assert.equal(assessDeliveryHealth(unresolved,null).status,'DELIVERY_PROCESSING_DEGRADED');
 const empty={...good(),records_processed:0,claimed:0,attempts:0,delivered:0};
 assert.equal(assessDeliveryHealth(empty,null).status,'NO_ELIGIBLE_DELIVERIES');
});
test('scheduled delivery calls a zero-I/O verdict after actual D1 processing, not mock sends',()=>{
 const cli=fs.readFileSync(path.join(__dirname,'..','scripts/deliver-watchlist-notifications.js'),'utf8');
 const wf=fs.readFileSync(path.join(__dirname,'..','.github/workflows/alert-delivery.yml'),'utf8');
 assert(cli.indexOf('const results = await processDueDeliveries(')<
        cli.indexOf('assessDeliveryHealth(results, oldestPendingAgeSeconds)'));
 assert.match(cli,/throw new Error\('SOC_DELIVERY_OPERATIONAL_HEALTH_HOLD'/);
 assert.match(wf,/node scripts\/deliver-watchlist-notifications\.js --limit=50/);
 assert.doesNotMatch(wf,/soc-notification-outbox.*--apply/);
});
