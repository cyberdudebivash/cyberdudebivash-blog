'use strict';

/**
 * Read-only with respect to real Cloudflare: disposable local Wrangler D1.
 * Source-only rehearsal; no remote credentials, customer data, DNS, or deploy.
 * CI command: node scripts/soc-native-d1-local-certify.cjs
 */
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const cp=require('node:child_process');
const assert=require('node:assert/strict');
const {ADMIT_SQL}=require('../api/_lib/soc-evidence-read-budget');

const ROOT=path.resolve(__dirname,'..');
const NAME='soc-native-offline-certification';
const NOW=1792663205;
function config(){
  return {name:'soc-offline-native-d1-check',
    main:'workers/entry.js',compatibility_date:'2026-08-17',
    compatibility_flags:['nodejs_compat'],
    d1_databases:[{binding:'DB',database_name:NAME,
      database_id:'00000000-0000-4000-8000-000000001516',
      migrations_dir:'./migrations'}]};
}
function safeInvocation(kind,conf,state,extra=[]){
  assert.ok(kind==='migrate'||kind==='execute');
  assert.ok(path.isAbsolute(conf)&&path.isAbsolute(state));
  assert.ok(extra.every(x=>typeof x==='string'&&!x.includes('\0')));
  const verb=kind==='migrate'?['d1','migrations','apply',NAME]:
    ['d1','execute',NAME];
  const args=[...verb,'--local','--config',conf,'--persist-to',state,
    ...(kind==='migrate'?[]:['--json']),...extra];
  assert.ok(args.includes('--local')&&!args.includes('--remote')&&
    !args.includes('--preview')&&!args.includes('--env'));
  return args;
}
function wrangler(args){
  const binary=path.join(ROOT,'node_modules','.bin',
    process.platform==='win32'?'wrangler.cmd':'wrangler');
  if(!fs.existsSync(binary))throw Error('Pinned Wrangler absent; run npm ci first');
  const env={...process.env};
  for(const k of Object.keys(env)){
    if(/^(CLOUDFLARE|CF_|WRANGLER_)/i.test(k))delete env[k];
  }
  env.WRANGLER_SEND_METRICS='false';
  const r=cp.spawnSync(binary,args,{
    cwd:ROOT,env,encoding:'utf8',timeout:120000,maxBuffer:1024*1024,
    ...(process.platform==='win32'?{shell:true}:{})
  });
  if(r.error||r.status!==0)
    throw Error('Local-only Wrangler command failed (see offline log for test environment)');
  return r.stdout;
}
function parseRows(out){
  let data;
  try{data=JSON.parse(out.trim());}catch(_){throw Error('Local Wrangler JSON result not parseable');}
  if(!Array.isArray(data)||!data.length||
     data.some(row=>row.success!==true||!Array.isArray(row.results)))
    throw Error('Invalid local Wrangler D1 JSON result');
  return data[data.length-1].results;
}
function execute(conf,state,sql){
  return parseRows(wrangler(safeInvocation('execute',conf,state,['--command',sql])));
}
function admission(tenant,connector,epoch=NOW,limit=2){
  assert.ok(['acme','contoso'].includes(tenant));
  assert.ok(['siem','edr'].includes(connector));
  assert.ok(Number.isSafeInteger(epoch)&&epoch>=0);
  assert.ok(Number.isSafeInteger(limit)&&limit>=1&&limit<=60);
  const args=[Math.floor(epoch/300)*300,epoch,tenant,connector,limit];
  let count=0;
  const sql=ADMIT_SQL.replace(/\?/g,()=>{
    const v=args[count++];
    return typeof v==='number'?String(v):"'"+v.replace(/'/g,"''")+"'";
  });
  assert.equal(count,5,'Production admission SQL placeholders changed');
  return sql;
}
function seedSQL(){
  const stamp="'2026-10-22T00:00:00.000Z'";
  const tenant=t=> "('"+t+"','Offline synthetic','ACTIVE','IN',30,"+stamp+","+stamp+")";
  const principal=t=> "('"+t+"','admin','https://idp.invalid','offline-"+t+"','TENANT_ADMIN','ACTIVE',"+stamp+","+stamp+")";
  const connector=(t,c)=>
    "('"+t+"','"+c+"','"+c.toUpperCase()+"','synthetic-local','APPROVED','admin',"+stamp+","+stamp+")";
  return [
    "INSERT INTO soc_tenants (tenant_id,legal_name,status,data_region,retention_days,created_at,updated_at) VALUES "+
      [tenant('acme'),tenant('contoso')].join(',')+";",
    "INSERT INTO soc_principals (tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) VALUES "+
      [principal('acme'),principal('contoso')].join(',')+";",
    "INSERT INTO soc_connectors (tenant_id,connector_id,type,authorized_scope,state,created_by,created_at,updated_at) VALUES "+
      [connector('acme','siem'),connector('acme','edr'),connector('contoso','siem')].join(',')+";"
  ].join('\n');
}
function equal(rows,n){assert.deepEqual(rows.map(x=>Number(x.consumed)),n);}

// A synthetic binding adapter for the already-migrated disposable local D1.
// This exercises the EXACT queries emitted by soc-incident-service.js rather
// than duplicating the mutation SQL in a test. No production database, token,
// user record or network connection is available to this process.
function renderBoundSql(sql,params=[]) {
  assert.ok(typeof sql==='string'&&sql.length&&Array.isArray(params));
  let i=0;
  const rendered=sql.replace(/\?/g,()=>{
    assert.ok(i<params.length,'Missing synthetic SQL bind');
    const v=params[i++];
    if(v===null)return 'NULL';
    if(typeof v==='string')return "'"+v.replace(/'/g,"''")+"'";
    if(Number.isSafeInteger(v))return String(v);
    throw Error('Unsupported synthetic D1 bind type');
  });
  assert.equal(i,params.length,'Unused synthetic SQL bind');
  return rendered;
}
function localIncidentDb(conf,state) {
  const query=async(sql,params=[])=>execute(conf,state,renderBoundSql(sql,params));
  return {
    query,
    run:async(sql,params=[])=>{
      execute(conf,state,renderBoundSql(sql,params));
      return {success:true};
    },
    runMutationWithChanges:async(sql,params=[])=>{
      // These two statements execute in the same disposable D1 invocation.
      // No API metadata changes/rows_written field is assumed.
      const rows=execute(conf,state,renderBoundSql(sql,params)+
        '; SELECT changes() AS affected');
      assert.equal(rows.length,1,'D1 affected-row receipt missing');
      assert.ok(Number.isSafeInteger(rows[0].affected),'D1 affected-row receipt malformed');
      return rows[0].affected;
    },
  };
}
async function certifyIncidentOwnerCommit(conf,state) {
  const {createSocIncidentService}=require('../api/_lib/soc-incident-service');
  const stamp="'2026-10-22T00:00:00.000Z'";
  const principal=(tenant,id,role,status)=>
    "('"+tenant+"','"+id+"','https://idp.invalid','synthetic-"+tenant+"-"+id+
    "','"+role+"','"+status+"',"+stamp+","+stamp+")";
  execute(conf,state,
    'INSERT INTO soc_principals '+
    '(tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) VALUES '+
    [
      principal('acme','active-lead','LEAD_ANALYST','ACTIVE'),
      principal('acme','read-only','READ_ONLY','ACTIVE'),
      principal('acme','revoked-lead','LEAD_ANALYST','REVOKED'),
      principal('contoso','foreign-lead','LEAD_ANALYST','ACTIVE'),
    ].join(','));
  const db=localIncidentDb(conf,state);
  const identity=async()=>({verified:true,issuer:'https://idp.invalid',subject:'offline-acme'});
  let counter=0;
  const make=(database)=>createSocIncidentService({
    db:database,verifyIdentity:identity,
    queryMembership:(sql,params)=>db.query(sql,params),
    now:()=> '2026-10-22T00:00:00.000Z',
    randomUUID:()=> '00000000-0000-4000-8000-'+
      (++counter).toString(16).padStart(12,'0'),
  });
  const service=make(db);
  const ctx={accessToken:'OFFLINE_DISPOSABLE_ONLY',tenantId:'acme'};
  const failCode=async(promise,code)=>assert.rejects(promise,e=>e&&e.code===code);
  const audit=()=>Number(execute(conf,state,
    "SELECT count(*) AS n FROM soc_audit_events WHERE tenant_id='acme' "+
    "AND action IN ('INCIDENT_CREATED','INCIDENT_UPDATED','INCIDENT_STATE_CHANGED')")[0].n);

  // Production service SQL + real 0009/0010 audit triggers, not Jest mocks:
  const created=await service.create({...ctx,requestId:'offline-create-000000001',
    input:{title:'Synthetic analyst review',severity:'HIGH',ownerId:'active-lead'}});
  assert.equal(created.ownerId,'active-lead');
  assert.equal(audit(),1,'Creation and append-only audit must be atomic');
  for(const ownerId of ['read-only','revoked-lead','foreign-lead','unknown']) {
    await failCode(service.create({...ctx,requestId:'offline-deny-'+ownerId+'-000001',
      input:{title:'Must not persist',severity:'HIGH',ownerId}}),'INVALID_INCIDENT_OWNER');
  }
  assert.equal(audit(),1,'Denied preflight must not produce audit rows');

  // Revoke precisely AFTER the preflight accepts an assignee, BEFORE the
  // actual DB statement, to prove the single-statement EXISTS blocks TOCTOU.
  const race=()=>{
    let pending=true;
    const racedDb={...db,runMutationWithChanges:async(sql,params)=>{
      if(pending) {
        pending=false;
        execute(conf,state,
          "UPDATE soc_principals SET status='REVOKED' "+
          "WHERE tenant_id='acme' AND principal_id='active-lead'");
      }
      return db.runMutationWithChanges(sql,params);
    }};
    return make(racedDb);
  };
  await failCode(race().create({...ctx,requestId:'offline-revocation-race-0001',
    input:{title:'Must not persist after revocation',severity:'CRITICAL',
      ownerId:'active-lead'}}),'INCIDENT_WRITE_REJECTED');
  assert.equal(audit(),1,'Revocation-race INSERT must not create an audit row');

  execute(conf,state,
    "UPDATE soc_principals SET status='ACTIVE' "+
    "WHERE tenant_id='acme' AND principal_id='active-lead'");
  const unassigned=await service.create({...ctx,requestId:'offline-unassigned-000001',
    input:{title:'Unassigned investigation',severity:'MEDIUM'}});
  assert.equal(unassigned.ownerId,null);
  assert.equal(audit(),2);

  await failCode(race().update({...ctx,id:unassigned.incidentId,
    expectedVersion:1,requestId:'offline-update-race-000001',
    changes:{ownerId:'active-lead'}}),'VERSION_CONFLICT');
  const intact=await service.get({...ctx,id:unassigned.incidentId});
  assert.equal(intact.ownerId,null);
  assert.equal(intact.version,1);
  assert.equal(audit(),2,'Revocation-race UPDATE must not create audit rows');

  execute(conf,state,
    "UPDATE soc_principals SET status='ACTIVE' "+
    "WHERE tenant_id='acme' AND principal_id='active-lead'");
  const updated=await service.update({...ctx,id:unassigned.incidentId,
    expectedVersion:1,requestId:'offline-authorized-update-000001',
    changes:{ownerId:'active-lead'}});
  assert.equal(updated.ownerId,'active-lead');
  assert.equal(updated.version,2);
  assert.equal(audit(),3,'Valid reassignment must append exactly one audit row');

  await failCode(service.get({...ctx,tenantId:'contoso',id:unassigned.incidentId}),
    'FORBIDDEN');
  assert.equal(audit(),3,'Cross-tenant identity cannot mutate or enumerate incidents');
  process.stdout.write('PASS: native local D1 SOC incident tenant/owner atomic revocation, audit and CAS\n');
}
async function main(){
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'cdb-soc-d1-local-'));
  const conf=path.join(ROOT,'.soc-native-local-'+process.pid+'.json');
  const state=path.join(scratch,'state');
  fs.mkdirSync(state,{recursive:true});
  try{
    fs.writeFileSync(conf,JSON.stringify(config(),null,2),{flag:'wx',mode:0o600});
    wrangler(safeInvocation('migrate',conf,state));
    const applied=execute(conf,state,'SELECT count(*) AS n FROM d1_migrations');
    assert.ok(applied.length===1&&Number(applied[0].n)>=16,
      'Local D1 did not apply full 0001..0016 chain');
    assert.equal(execute(conf,state,
      "SELECT name FROM sqlite_master WHERE type='table' AND name='soc_evidence_read_windows'").length,1);
    execute(conf,state,seedSQL());
    await certifyIncidentOwnerCommit(conf,state);
    equal(execute(conf,state,admission('acme','siem')),[1]);
    equal(execute(conf,state,admission('acme','siem')),[2]);
    equal(execute(conf,state,admission('acme','siem')),[]);
    equal(execute(conf,state,admission('acme','edr')),[1]);
    equal(execute(conf,state,admission('contoso','siem')),[1]);
    execute(conf,state,"UPDATE soc_connectors SET state='PAUSED' WHERE tenant_id='acme' AND connector_id='siem'");
    equal(execute(conf,state,admission('acme','siem',NOW+300)),[]);
    execute(conf,state,"UPDATE soc_tenants SET status='SUSPENDED' WHERE tenant_id='acme'");
    equal(execute(conf,state,admission('acme','edr',NOW+300)),[]);
    const stats=execute(conf,state,'SELECT count(*) AS n FROM soc_evidence_read_windows');
    assert.equal(Number(stats[0].n),3);
    process.stdout.write('PASS: local Wrangler D1 migrations 0001..0016 + tenant quota/revocation\n');
  }finally{
    try{fs.rmSync(conf,{force:true});}catch(_){}
    try{fs.rmSync(scratch,{force:true,recursive:true});}catch(_){}
  }
}
if(require.main===module){
  main().catch(e=>{
    process.stderr.write('NO-GO: '+String(e.message).slice(0,200)+'\n');
    process.exitCode=1;
  });
}
module.exports={config,safeInvocation,admission,seedSQL,renderBoundSql,localIncidentDb,certifyIncidentOwnerCommit,main,NAME};
