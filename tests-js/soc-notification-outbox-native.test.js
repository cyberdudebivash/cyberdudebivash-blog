'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const { createOutbox, MAX_WATCHERS, MAX_RECONCILE_JOBS,
  DUE_SQL, EXPIRED_SQL, CLAIM_SQL } = require('../api/_lib/soc-notification-outbox');
const migration = fs.readFileSync(path.resolve(__dirname,'../migrations/0018_soc_notification_outbox.sql'),'utf8');
function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec(migration);
  let clock = 1_761_000_000_000;
  const events = new Map();
  const owners = new Map();
  const memberships = new Map();
  const feed = new Set();
  const deliveries = new Set();
  let handler = async x => {
    deliveries.add(x.ownerId+'|'+x.event.event_id+'|email');
    return {enqueued:true,channels:['email']};
  };
  const dbApi = {
    query:async (sql,p=[]) => db.prepare(sql).all(...p),
    runMutationWithChanges:async (sql,p=[]) => Number(db.prepare(sql).run(...p).changes),
  };
  const make = (enabled=true) => createOutbox({
    enabled,d1:dbApi,now:()=>clock,token:()=>Math.random().toString(36).slice(2).padEnd(16,'x'),
    getEvent:async id => events.get(id)||null,
    getWatchlist:async (wl,owner) => {
      const state=owners.get(owner+'|'+wl);
      return state ? {watchlist:{status:state}} : {error:'NOT_FOUND'};
    },
    listEntities:async (wl,owner) => ({
      entities:memberships.get(owner+'|'+wl)||[]
    }),
    appendToFeed:async(owner,e) => {feed.add(owner+'|'+e)},
    dispatch:async args => handler(args),
  });
  const ev=(id='evt-one')=>({event_id:id,entity_type:'cve',entity_id:'CVE-2026-0123',observed_at:'2026-10-23T00:00:00Z'});
  function add(owner='owner-1',wl='watchlist-1') {
    owners.set(owner+'|'+wl,'active');
    memberships.set(owner+'|'+wl,[{type:'cve',id:'CVE-2026-0123'}]);
    return {ownerId:owner,watchlistId:wl};
  }
  const row=()=>db.prepare('SELECT * FROM soc_notification_outbox LIMIT 1').get();
  return {db,dbApi,make,events,owners,memberships,feed,deliveries,ev,add,row,
    setDispatch:f=>handler=f,advance:ms=>{clock+=ms},now:()=>clock,
    close:()=>db.close()};
}
test('migration and bounded due/expired claim SQL use explicit indexes and do not store customer secrets',()=>{
  const f=fixture();
  try{
    const names=f.db.prepare('PRAGMA index_list(soc_notification_outbox)').all().map(x=>x.name);
    assert.ok(names.includes('idx_soc_outbox_due'));
    assert.ok(names.includes('idx_soc_outbox_retention'));
    assert.ok(names.includes('idx_soc_outbox_expired'));
    const ddl = migration.split('\n').filter(line => !/^\s*--/.test(line)).join('\n');
    assert.doesNotMatch(ddl,/webhook_secret|email_override|payload|api_token/i);
    assert.match(f.db.prepare('EXPLAIN QUERY PLAN '+DUE_SQL).all(0,5).map(x=>x.detail).join('\n'),/idx_soc_outbox_due/);
    assert.equal(MAX_WATCHERS,10);assert.equal(MAX_RECONCILE_JOBS,5);
    assert.match(EXPIRED_SQL,/LIMIT \?/);
    assert.match(f.db.prepare('EXPLAIN QUERY PLAN '+EXPIRED_SQL).all(0,5).map(x=>x.detail).join('\n'),/idx_soc_outbox_expired/);
    assert.match(CLAIM_SQL,/claim_token/);
  }finally{f.close()}
});
test('negative control: expired-claim index loss breaks bounded index-plan acceptance',()=>{
  const f=fixture();
  try{
    f.db.exec('DROP INDEX idx_soc_outbox_expired');
    const plan=f.db.prepare('EXPLAIN QUERY PLAN '+EXPIRED_SQL).all(0,5).map(x=>x.detail).join('\\n');
    assert.doesNotMatch(plan,/idx_soc_outbox_expired/);
  }finally{f.close()}
});
test('default-off guard performs zero D1 mutations',async()=>{
  const f=fixture();
  try{
    await assert.rejects(f.make(false).stageEventFanout({event:f.ev(),watchers:[f.add()]}),/SOC_OUTBOX_DISABLED/);
    await assert.rejects(f.make(false).reconcile(),/SOC_OUTBOX_DISABLED/);
    assert.equal(f.row(),undefined);
  }finally{f.close()}
});
test('idempotent tenant-specific staging and bounded membership ceiling',async()=>{
  const f=fixture();
  try{
    const e=f.ev();const w=f.add();
    assert.deepEqual(await f.make().stageEventFanout({event:e,watchers:[w,w]}),{staged:1,created:1});
    assert.deepEqual(await f.make().stageEventFanout({event:e,watchers:[w]}),{staged:1,created:0});
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM soc_notification_outbox').get().n,1);
    const tooMany=Array.from({length:11},(_,i)=>f.add('owner-'+i,'wl-'+i));
    await assert.rejects(f.make().stageEventFanout({event:e,watchers:tooMany}),/SOC_OUTBOX_INVALID_FANOUT/);
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM soc_notification_outbox').get().n,1);
  }finally{f.close()}
});
test('missing event is retried, later recovered, and feed/job are idempotent',async()=>{
  const f=fixture();
  try{
    const w=f.add();const e=f.ev();
    await f.make().stageEventFanout({event:e,watchers:[w]});
    const initial=await f.make().reconcile({limit:1});
    assert.equal(initial.retry,1);assert.equal(initial.errors,1);
    assert.equal(f.feed.size,0);assert.equal(f.deliveries.size,0);
    f.events.set(e.event_id,e);f.advance(61_000);
    const done=await f.make().reconcile({limit:1});
    assert.equal(done.complete,1);assert.equal(done.errors,0);
    assert.equal(f.feed.size,1);assert.equal(f.deliveries.size,1);
    assert.equal((await f.make().reconcile()).selected,0);
  }finally{f.close()}
});
test('customer pause/removal/ownership mismatch cancels rather than leaking alerts',async()=>{
  for(const variant of ['paused','deleted','removed']){
    const f=fixture();
    try{
      const w=f.add();const e=f.ev();f.events.set(e.event_id,e);
      await f.make().stageEventFanout({event:e,watchers:[w]});
      if(variant==='paused')f.owners.set(w.ownerId+'|'+w.watchlistId,'paused');
      if(variant==='deleted')f.owners.delete(w.ownerId+'|'+w.watchlistId);
      if(variant==='removed')f.memberships.set(w.ownerId+'|'+w.watchlistId,[]);
      const result=await f.make().reconcile();
      assert.equal(result.skipped,1);assert.equal(result.errors,0);
      assert.equal(f.deliveries.size,0);assert.equal(f.feed.size,0);
      assert.equal(f.row().state,'skipped');
    }finally{f.close()}
  }
});
test('dispatch exception after partial enqueue quarantines without automatic duplicate replay',async()=>{
  const f=fixture();
  try{
    const e=f.ev(),w=f.add();f.events.set(e.event_id,e);
    await f.make().stageEventFanout({event:e,watchers:[w]});
    let calls=0;
    f.setDispatch(async a=>{
      calls++;
      f.deliveries.add(a.ownerId+'|'+a.event.event_id+'|email');
      // A delivery job may have committed before this exception.
      throw new Error('private provider error');
    });
    const failed=await f.make().reconcile();
    assert.equal(failed.blocked,1);assert.equal(failed.retry,0);
    assert.equal(failed.complete,0);assert.equal(failed.errors,1);
    assert.equal(f.row().last_error_code,'DELIVERY_STATE_AMBIGUOUS');
    assert.equal(f.row().state,'blocked');
    assert.equal(f.feed.size,1);assert.equal(f.deliveries.size,1);
    assert.equal(calls,1);
    f.advance(3_700_000);
    assert.equal((await f.make().reconcile()).selected,0);
    assert.equal(calls,1,'ambiguous enqueue must not trigger a second send');
  }finally{f.close()}
});
test('already-existing channel delivery cannot be certified from enqueue=false',async()=>{
  const f=fixture();
  try{
    const e=f.ev(),w=f.add();f.events.set(e.event_id,e);
    await f.make().stageEventFanout({event:e,watchers:[w]});
    f.setDispatch(async()=>({enqueued:false,channels:['webhook']}));
    const result=await f.make().reconcile();
    assert.equal(result.blocked,1);assert.equal(result.complete,0);
    assert.equal(result.errors,1);
    assert.equal(f.row().state,'blocked');
  }finally{f.close()}
});
test('explicitly disabled channels are skipped; malformed dispatch responses block',async()=>{
  for(const variant of ['disabled','malformed']){
    const f=fixture();
    try{
      const e=f.ev(),w=f.add();f.events.set(e.event_id,e);
      await f.make().stageEventFanout({event:e,watchers:[w]});
      f.setDispatch(async()=>variant==='disabled'?{enqueued:false}:{});
      const result=await f.make().reconcile();
      if(variant==='disabled'){
        assert.equal(result.skipped,1);assert.equal(result.errors,0);
        assert.equal(f.row().state,'skipped');
      }else{
        assert.equal(result.blocked,1);assert.equal(result.errors,1);
        assert.equal(f.row().state,'blocked');
      }
      assert.equal(result.complete,0);
    }finally{f.close()}
  }
});
test('lease prevents competing claim and expired lease is recovered without duplication',async()=>{
  const f=fixture();
  try{
    const w=f.add(),e=f.ev();f.events.set(e.event_id,e);
    await f.make().stageEventFanout({event:e,watchers:[w]});
    const start=f.now();
    const x=f.db.prepare(CLAIM_SQL).run('token-held',start+90_000,start,
      e.event_id,w.watchlistId,w.ownerId,start,start);
    assert.equal(x.changes,1);
    assert.equal((await f.make().reconcile()).selected,0);
    f.advance(90_001);
    const result=await f.make().reconcile();
    assert.equal(result.complete,1);assert.equal(f.feed.size,1);
  }finally{f.close()}
});
test('expired claim receives recovery capacity even when five pending jobs exist',async()=>{
  const f=fixture();
  try{
    const w=f.add();
    const first=f.ev('evt-expired');f.events.set(first.event_id,first);
    await f.make().stageEventFanout({event:first,watchers:[w]});
    const at=f.now();
    assert.equal(f.db.prepare(CLAIM_SQL).run('crashed-owner',at+90_000,at,
      first.event_id,w.watchlistId,w.ownerId,at,at).changes,1);
    for(let i=0;i<5;i++){
      const event=f.ev('evt-pending-'+i);f.events.set(event.event_id,event);
      await f.make().stageEventFanout({event,watchers:[w]});
    }
    f.advance(91_000);
    const result=await f.make().reconcile({limit:5});
    assert.equal(result.selected,5);
    assert.equal(result.complete,5);
    const expired=f.db.prepare('SELECT state FROM soc_notification_outbox WHERE event_id=?').get(first.event_id);
    assert.equal(expired.state,'complete','expired lease must not starve behind pending backlog');
    const left=f.db.prepare("SELECT count(*) AS n FROM soc_notification_outbox WHERE state='pending'").get().n;
    assert.equal(left,1);
  }finally{f.close()}
});
test('persistent failures exhaust five claims and block with retained evidence',async()=>{
  const f=fixture();
  try{
    const w=f.add(),e=f.ev();f.events.set(e.event_id,e);
    await f.make().stageEventFanout({event:e,watchers:[w]});
    f.setDispatch(async()=>{throw new Error('sensitive data must not be logged')});
    for(let attempt=0;attempt<5;attempt++){
      const result=await f.make().reconcile();
      assert.equal(result.errors,1);
      f.advance(3_700_000);
    }
    assert.equal(f.row().state,'blocked');assert.equal(f.row().attempt_count,5);
    assert.equal((await f.make().reconcile()).selected,0);
    assert.equal(f.feed.size,1);assert.equal(f.deliveries.size,0);
  }finally{f.close()}
});
test('retention deletes only terminal successful records, not failed/claimed evidence',async()=>{
  const f=fixture();
  try{
    const w=f.add(),e=f.ev();f.events.set(e.event_id,e);
    await f.make().stageEventFanout({event:e,watchers:[w]});
    assert.equal((await f.make().reconcile()).complete,1);
    const w2=f.add('owner-2','wl-2');
    await f.make().stageEventFanout({event:f.ev('evt-pending'),watchers:[w2]});
    f.advance(31*86400000);
    const count=await f.make().pruneCompleted();
    assert.equal(count,1);
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM soc_notification_outbox').get().n,1);
    assert.equal(f.db.prepare('SELECT state FROM soc_notification_outbox').get().state,'pending');
    await assert.rejects(f.make().pruneCompleted({days:1}),/SOC_OUTBOX_RETENTION_RANGE/);
  }finally{f.close()}
});
test('manual CLI has zero database access without --apply and rejects unsafe arguments',()=>{
  const cli=path.resolve(__dirname,'../scripts/reconcile-soc-notification-outbox.js');
  const p=cp.spawnSync(process.execPath,[cli],{encoding:'utf8',
    env:{...process.env,CDB_SOC_OUTBOX_ENABLED:'false',CLOUDFLARE_API_TOKEN:''}});
  assert.equal(p.status,0,p.stderr);
  assert.match(p.stdout,/READINESS ONLY/);assert.doesNotMatch(p.stdout+p.stderr,/\[D1\]/);
  const {parse}=require('../scripts/reconcile-soc-notification-outbox.js');
  assert.deepEqual(parse(['--apply','--limit=1']),{apply:true,prune:false,limit:1});
  for(const argv of [['--limit=6'],['--apply','--limit=0'],
    ['--apply','--limit=1','--limit=2'],['--prune-completed'],['--unknown']])
    assert.throws(()=>parse(argv),/SOC_OUTBOX_/);
});
test('change-engine stages outbox before event persistence with no automatic scheduler wiring',()=>{
  const engine=fs.readFileSync(path.resolve(__dirname,'../api/_lib/change-engine.js'),'utf8');
  const outbox=engine.indexOf('await writer.stageEventFanout');
  const persist=engine.indexOf('const result = await persistEventIfNew(event);');
  assert.ok(outbox>=0 && persist>outbox);
  assert.match(engine,/if \(outboxEnabled\) \{/);
  const workflow=fs.readFileSync(path.resolve(__dirname,'../.github/workflows/alert-delivery.yml'),'utf8');
  assert.doesNotMatch(workflow,/reconcile-soc-notification-outbox/);
});
