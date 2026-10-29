'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {
  buildSnapshot, decryptSnapshot, writeVerifiedEncryptedSnapshot,
}=require('../scripts/backup-customer-data');

const KEY='a'.repeat(64); // disposable test fixture; NEVER production material
const fixture=()=>buildSnapshot({
  hashes:{'user:key:disposable':{email:'no-one@example.invalid',tier:'test'}},
  strings:{'user:id:disposable':'disposable'},
  auditLog:[['{"type":"test"}','1700000000123']],
});
function tmp(t) {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'soc-backup-artifact-test-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  return directory;
}
test('P0: encrypted output is fully authenticated before final publication',t=>{
  const dir=tmp(t),dest=path.join(dir,'backup.enc'),data=fixture();
  assert.equal(writeVerifiedEncryptedSnapshot(data,KEY,dest),dest);
  assert.deepEqual(decryptSnapshot(fs.readFileSync(dest,'utf8'),KEY),data);
  assert.deepEqual(fs.readdirSync(dir),['backup.enc']);
  if(process.platform!=='win32'){
    assert.equal(fs.statSync(dest).mode & 0o777,0o600,'backup file must not be world-readable');
  }
});
test('P0: existing encrypted snapshot is never overwritten, even when new data differs',t=>{
  const dir=tmp(t),dest=path.join(dir,'backup.enc');
  writeVerifiedEncryptedSnapshot(fixture(),KEY,dest);
  const before=fs.readFileSync(dest,'utf8');
  const newData={...fixture(),createdAt:'2026-10-29T16:00:00.000Z'};
  assert.throws(()=>writeVerifiedEncryptedSnapshot(newData,KEY,dest),/EEXIST/);
  assert.equal(fs.readFileSync(dest,'utf8'),before);
  assert.deepEqual(fs.readdirSync(dir),['backup.enc'],'no failed temp artifacts left behind');
});
test('P0: invalid key, destination or malformed input fail before writing any artifact',t=>{
  const dir=tmp(t),dest=path.join(dir,'backup.enc');
  assert.throws(()=>writeVerifiedEncryptedSnapshot(fixture(),'too-short',dest),/64-character hex/);
  assert.throws(()=>writeVerifiedEncryptedSnapshot(fixture(),KEY,''),/SOC_BACKUP_INVALID_OUTPUT_PATH/);
  assert.deepEqual(fs.readdirSync(dir),[]);
});
test('P0: corrupted disk readback never publishes a final backup file',t=>{
  const dir=tmp(t),dest=path.join(dir,'backup.enc');
  const original=fs.readFileSync;
  try{
    fs.readFileSync=(p,...args)=>{
      if(typeof p==='string'&&p.endsWith('.tmp')) return 'not-an-authenticated-snapshot';
      return original.call(fs,p,...args);
    };
    assert.throws(()=>writeVerifiedEncryptedSnapshot(fixture(),KEY,dest));
  }finally{fs.readFileSync=original;}
  assert.deepEqual(fs.readdirSync(dir),[]);
  assert.equal(fs.existsSync(dest),false);
});
test('P0: final path symlink is never followed or overwritten',t=>{
  const dir=tmp(t),target=path.join(dir,'keep.txt'),dest=path.join(dir,'backup.enc');
  fs.writeFileSync(target,'DO NOT CHANGE');
  try {fs.symlinkSync(target,dest,'file');}
  catch(e){if(process.platform==='win32')return;throw e;}
  assert.throws(()=>writeVerifiedEncryptedSnapshot(fixture(),KEY,dest),/EEXIST/);
  assert.equal(fs.readFileSync(target,'utf8'),'DO NOT CHANGE');
  assert.equal(fs.lstatSync(dest).isSymbolicLink(),true);
});
test('P0: invalid configured encryption key stops CLI before Redis/network or file writes',t=>{
  const dir=tmp(t),dest=path.join(dir,'must-not-exist.enc');
  const env={...process.env,
    BACKUP_ENCRYPTION_KEY:'broken-key',
    UPSTASH_REDIS_REST_URL:'http://127.0.0.1:9',
    UPSTASH_REDIS_REST_TOKEN:'DISPOSABLE_INVALID_TOKEN'};
  const x=spawnSync(process.execPath,['scripts/backup-customer-data.js',dest],{
    cwd:path.join(__dirname,'..'),encoding:'utf8',timeout:10000,env
  });
  assert.equal(x.status,1,x.stderr);
  assert.match(x.stderr,/64-character hex/);
  assert.doesNotMatch(x.stderr,/Redis HTTP|fetch failed|ECONNREFUSED/);
  assert.equal(fs.existsSync(dest),false);
});
