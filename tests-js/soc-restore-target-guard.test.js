'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {verifyRestoreTarget}=require('../scripts/restore-customer-data');
const {buildSnapshot,encryptSnapshot}=require('../scripts/backup-customer-data');

const LIVE='https://live-customer-redis.upstash.io';
const ISOLATED='https://isolated-rehearsal-redis.upstash.io';
const fingerprint=url=>crypto.createHash('sha256').update(url).digest('hex');
const standard=()=>({
  UPSTASH_REDIS_REST_URL:ISOLATED,
  SOC_RESTORE_TARGET_URL_SHA256:fingerprint(ISOLATED),
  SOC_RESTORE_LIVE_URL_SHA256:fingerprint(LIVE),
  SOC_RESTORE_APPROVAL_REF:'CDB-INC-2026-494',
  SOC_RESTORE_MODE:'isolated-rehearsal'
});

test('explicitly pinned isolated Upstash origin passes only as a rehearsal',()=>{
  assert.deepEqual(verifyRestoreTarget(standard()),
    {mode:'isolated-rehearsal',authorized:true});
});
test('rehearsal cannot target the declared production endpoint, even if pinned',()=>{
  const env=standard();
  env.UPSTASH_REDIS_REST_URL=LIVE;
  env.SOC_RESTORE_TARGET_URL_SHA256=fingerprint(LIVE);
  assert.throws(()=>verifyRestoreTarget(env),/SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
});
test('absent, stale or forged target pin, production fingerprint and approval block',()=>{
  for(const mutation of [
    {SOC_RESTORE_TARGET_URL_SHA256:undefined},
    {SOC_RESTORE_TARGET_URL_SHA256:'0'.repeat(64)},
    {SOC_RESTORE_LIVE_URL_SHA256:undefined},
    {SOC_RESTORE_LIVE_URL_SHA256:'not-a-sha'},
    {SOC_RESTORE_APPROVAL_REF:undefined},
    {SOC_RESTORE_APPROVAL_REF:'approved'},
    {SOC_RESTORE_MODE:'unrestricted'},
    {SOC_RESTORE_MODE:undefined}
  ]){
    assert.throws(()=>verifyRestoreTarget({...standard(),...mutation}),
      /SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
  }
});
test('only an exact credential-free HTTPS Upstash origin is allowed',()=>{
  const bad=[
    'http://isolated-rehearsal-redis.upstash.io',
    'https://isolated-rehearsal-redis.upstash.io:8443',
    'https://user:pass@isolated-rehearsal-redis.upstash.io',
    'https://isolated-rehearsal-redis.upstash.io/pipeline',
    'https://isolated-rehearsal-redis.upstash.io?unsafe=true',
    'https://isolated-rehearsal-redis.upstash.io/#fragment',
    'https://isolated-rehearsal-redis.upstash.io.attacker.example',
    'https://localhost',
    'https://127.0.0.1',
    'https://isolated-rehearsal-redis.upstash.io/',
    'invalid'
  ];
  for(const url of bad){
    const env={...standard(),UPSTASH_REDIS_REST_URL:url,
      SOC_RESTORE_TARGET_URL_SHA256:fingerprint(url)};
    assert.throws(()=>verifyRestoreTarget(env),/SOC_RESTORE_TARGET_NOT_AUTHORIZED/,url);
  }
});
test('production recovery requires a separate explicit break-glass confirmation',()=>{
  const prod={...standard(),SOC_RESTORE_MODE:'production-break-glass',
    UPSTASH_REDIS_REST_URL:LIVE,
    SOC_RESTORE_TARGET_URL_SHA256:fingerprint(LIVE)};
  assert.throws(()=>verifyRestoreTarget(prod),/SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
  assert.throws(()=>verifyRestoreTarget({...prod,SOC_RESTORE_BREAK_GLASS_CONFIRM:'yes'}),
    /SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
  const authorized={...prod,
    SOC_RESTORE_BREAK_GLASS_CONFIRM:'I_AUTHORIZE_PRODUCTION_CUSTOMER_DATA_RESTORE'};
  // Ordinary --confirm can never authorize live customer writes, even
  // when an operator has already populated break-glass environment values.
  assert.throws(()=>verifyRestoreTarget(authorized,'--confirm'),
    /SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
  assert.deepEqual(verifyRestoreTarget(authorized,'--confirm-production'),
    {mode:'production-break-glass',authorized:true});
  assert.throws(()=>verifyRestoreTarget(standard(),'--confirm-production'),
    /SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
  assert.throws(()=>verifyRestoreTarget({...authorized,UPSTASH_REDIS_REST_URL:ISOLATED,
    SOC_RESTORE_TARGET_URL_SHA256:fingerprint(ISOLATED)},'--confirm-production'),
    /SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
});
test('CLI --confirm fails before live Upstash access when destination approval is absent',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cdb-restore-target-'));
  try{
    const fixture=path.join(dir,'disposable.enc');
    const key='a'.repeat(64);
    fs.writeFileSync(fixture,encryptSnapshot(buildSnapshot({
      hashes:{'user:key:synthetic':{email:'synthetic@example.invalid',tier:'free'}},
      strings:{},auditLog:[]
    }),key),'utf8');
    const r=spawnSync(process.execPath,['scripts/restore-customer-data.js',fixture,'--confirm'],{
      cwd:path.resolve(__dirname,'..'),encoding:'utf8',timeout:10000,
      env:{PATH:process.env.PATH,HOME:dir,BACKUP_ENCRYPTION_KEY:key,
        UPSTASH_REDIS_REST_URL:LIVE,
        UPSTASH_REDIS_REST_TOKEN:'synthetic-token-do-not-use'}
    });
    assert.equal(r.status,1,r.stderr);
    assert.match(r.stderr,/SOC_RESTORE_TARGET_NOT_AUTHORIZED/);
    assert.doesNotMatch(r.stdout,/Wrote .* into Redis/);
    assert.doesNotMatch(r.stderr,/synthetic-token-do-not-use/);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
