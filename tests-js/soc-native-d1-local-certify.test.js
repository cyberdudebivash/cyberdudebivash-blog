'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const os=require('node:os');
const path=require('node:path');
const fs=require('node:fs');
const {
 config,safeInvocation,admission,seedSQL,renderBoundSql,certifyIncidentOwnerCommit,NAME
}=require('../scripts/soc-native-d1-local-certify.cjs');

test('local D1 binding is a reserved synthetic isolated name and ID',()=>{
  const c=config();
  assert.equal(c.d1_databases.length,1);
  assert.equal(c.d1_databases[0].database_name,NAME);
  assert.notEqual(NAME,'sentinel-apex-core');
  assert.match(c.d1_databases[0].database_id,/^00000000-0000-4000-8000-/);
  assert.equal(c.d1_databases[0].migrations_dir,'./migrations');
  assert.equal(c.routes,undefined);
  assert.equal(c.vars,undefined);
  assert.equal(c.services,undefined);
  assert.equal(c.assets,undefined);
});

test('every CLI migration and SQL invocation explicitly pins local DB and temp state',()=>{
  const conf=path.join(os.tmpdir(),'local-config.json');
  const state=path.join(os.tmpdir(),'local-d1-state');
  for(const kind of ['execute','migrate']){
    const args=safeInvocation(kind,conf,state);
    assert.equal(args[0],'d1');
    assert.ok(args.includes('--local'));
    assert.ok(args.includes('--persist-to'));
    assert.ok(args.includes('--config'));
    assert.ok(args.includes(NAME));
    assert.ok(!args.includes('--remote'));
    assert.ok(!args.includes('--preview'));
  }
  assert.throws(()=>safeInvocation('deploy',conf,state));
});

test('quota SQL is actual exported service SQL rendered with synthetic-only inputs',()=>{
  const stmt=admission('acme','siem');
  assert.match(stmt,/ON CONFLICT\(tenant_id,connector_id,window_start_epoch\)/);
  assert.match(stmt,/RETURNING consumed/);
  assert.match(stmt,/c.state='APPROVED'/);
  assert.match(stmt,/t.status='ACTIVE'/);
  assert.ok(!stmt.includes('?'));
  assert.throws(()=>admission('attacker','siem'));
  assert.throws(()=>admission('acme','endpoint'));
});

test('seed data is strictly offline synthetic without credentials or real customers',()=>{
  const s=seedSQL();
  assert.match(s,/INSERT INTO soc_connectors/);
  assert.match(s,/Offline synthetic/);
  assert.ok(!s.includes('cyberdudebivash.com'));
  assert.ok(!s.includes('CLOUDFLARE_API_TOKEN'));
});

test('harness never includes remote D1 options, deploy command or real database',()=>{
  const source=fs.readFileSync(
    path.join(__dirname,'..','scripts','soc-native-d1-local-certify.cjs'),'utf8');
  assert.doesNotMatch(source,/wrangler deploy|migrations apply.*--remote/);
  assert.doesNotMatch(source,/database_name:'sentinel-apex-core'/);
  assert.match(source,/WRANGLER_SEND_METRICS='false'/);
});

test('real-service native-D1 certificate is callable and uses only a disposable local SQLite harness',()=>{
  assert.equal(typeof certifyIncidentOwnerCommit,'function');
  const script=fs.readFileSync(path.join(__dirname,'..','scripts','soc-native-d1-local-certify.cjs'),'utf8');
  assert.match(script,/await certifyIncidentOwnerCommit\(conf,state\)/);
  assert.match(script,/createSocIncidentService/);
  assert.match(script,/INSERT INTO soc_incidents|certifyIncidentOwnerCommit/);
  assert.match(script,/runMutationWithChanges/);
  assert.match(script,/SELECT changes\(\) AS affected/);
  assert.match(script,/Revocation-race INSERT must not create an audit row/);
  assert.match(script,/Revocation-race UPDATE must not create audit rows/);
  assert.match(script,/!args\.includes\('--remote'\)/);
  assert.doesNotMatch(script,/wrangler deploy/);
});
test('disposable native-D1 query binder preserves text, null and integers without accepting ambiguous binds',()=>{
  assert.equal(renderBoundSql('SELECT ? AS subject, ? AS owner, ? AS count',
    ["O'Malley",null,5]),
    "SELECT 'O''Malley' AS subject, NULL AS owner, 5 AS count");
  assert.throws(()=>renderBoundSql('SELECT ?',[]));
  assert.throws(()=>renderBoundSql('SELECT ?',[1,2]));
  assert.throws(()=>renderBoundSql('SELECT ?',[{payload:'evil'}]));
  assert.throws(()=>renderBoundSql('SELECT ?',[1.5]));
});
