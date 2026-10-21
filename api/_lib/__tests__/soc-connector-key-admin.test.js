'use strict';

const crypto=require('node:crypto');
const {
  createSocConnectorKeyAdminService,createSocConnectorOperatorBoundary,
}=require('../soc-connector-key-admin');
const {createSocEncryptedConnectorVault}=require('../soc-encrypted-connector-vault');

const NOW=Date.parse('2026-10-21T18:20:00.000Z');
const EPOCH=Math.floor(NOW/1000);
const TENANT='acme',CONNECTOR='edr-main',KEY='key-20261021';
const secret=()=>crypto.randomBytes(32);
const {publicKey,privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const JWK={...publicKey.export({format:'jwk'}),kid:'approved-soc-idp',alg:'RS256',use:'sig'};
const ISSUER='https://issuer.example', AUDIENCE='sentinel-apex-soc';
const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');

function realToken(changes={}) {
  const header=b64({alg:'RS256',typ:'at+jwt',kid:JWK.kid});
  const payload=b64({
    iss:ISSUER,sub:'admin-identity',aud:AUDIENCE,
    iat:EPOCH-30,exp:EPOCH+600,
    jti:'operator-token-20261021-001',amr:['pwd','mfa'],...changes,
  });
  const data=header+'.'+payload;
  return data+'.'+crypto.createSign('RSA-SHA256').update(data).end()
    .sign(privateKey).toString('base64url');
}

function fixture({registered=true,authorized=true,failWrite=false,failVault=false}={}) {
  const records=new Map(),store=new Map(),statements=[];
  const kv={
    get:jest.fn(async key=>store.has(key)?store.get(key):null),
    put:jest.fn(async (key,data)=>{
      if(failVault)throw new Error('vault secret backend unavailable');
      store.set(key,data);
    }),
  };
  const masterKey=secret();
  const vault=createSocEncryptedConnectorVault({kv,masterKey});
  const session={
    prepare:jest.fn(sql=>{
      const entry={sql,params:[]};statements.push(entry);
      return {bind:(...values)=>{
        entry.params=values;
        return {
          first:async()=>{
            if(sql.includes('FROM soc_auth_sessions'))return registered?{allowed:1}:null;
            if(sql.includes('SELECT p.principal_id'))return authorized?{principal_id:'tenant-admin'}:null;
            throw Error('unexpected SELECT: '+sql);
          },
          run:async()=>{
            if(failWrite)throw Error('D1 constraint/audit insertion failure; sensitive detail');
            const [tenant,connector,key]=sql.startsWith('INSERT')?values.slice(0,3):values.slice(-3);
            const loc=[tenant,connector,key].join(':');
            if(sql.startsWith('INSERT')) {
              if(records.has(loc))return {success:true,meta:{changes:0}};
              records.set(loc,'PENDING');return {success:true,meta:{changes:1}};
            }
            const old=records.get(loc);
            if(sql.includes("state='ACTIVE'")) {
              if(old!=='PENDING')return {success:true,meta:{changes:0}};
              records.set(loc,'ACTIVE');
            }else if(sql.includes("state='REVOKED'")){
              if(old!=='PENDING'&&old!=='ACTIVE')return {success:true,meta:{changes:0}};
              records.set(loc,'REVOKED');
            }else throw Error('unknown mutation');
            return {success:true,meta:{changes:1}};
          },
        };
      }};
    }),
  };
  const nativeD1={withSession:jest.fn(mode=>{
    if(mode!=='first-primary')throw Error('replica unavailable');
    return session;
  })};
  const fetcher=jest.fn(async()=>({
    ok:true,headers:{get:()=>null},
    text:async()=>JSON.stringify({keys:[JWK]}),
  }));
  const oidc={issuer:ISSUER,audience:AUDIENCE,jwksUrl:ISSUER+'/.well-known/jwks.json'};
  const admin=createSocConnectorOperatorBoundary({
    nativeD1,kv,masterKey,oidc,fetcher,nowMillis:()=>NOW,
  });
  const args={accessToken:realToken(),tenantId:TENANT,connectorId:CONNECTOR,keyId:KEY};
  return {admin,args,records,store,statements,kv,vault,nativeD1,fetcher};
}

describe('Operator connector key lifecycle — authenticated + primary D1 + sealed KV',()=>{
  test('refuses configuration without identity, primary DB or vault',()=>{
    expect(()=>createSocConnectorOperatorBoundary()).toThrow();
    expect(()=>createSocConnectorOperatorBoundary({
      nativeD1:{withSession:()=>{}},
      oidc:{issuer:ISSUER,audience:AUDIENCE,jwksUrl:ISSUER+'/jwks'},
    })).toThrow('VAULT_BINDING_REQUIRED');
    expect(()=>createSocConnectorKeyAdminService({
      nativeD1:{withSession:()=>{}},
      vault:{sealKey:async()=>true,resolveSecret:async()=>secret()},
    })).toThrow('SOC_OPERATOR_AUTHORITY_REQUIRED');
  });

  test('real signed MFA access token enrolls PENDING first and encrypts key second',async()=>{
    const h=fixture(), key=secret();
    const out=await h.admin.enroll({
      ...h.args,secret:key,validFromEpoch:EPOCH-30,expiresEpoch:EPOCH+3600,
      principalId:'spoofed-user',
    });
    expect(out).toEqual({tenantId:TENANT,connectorId:CONNECTOR,keyId:KEY,state:'PENDING',sealed:true});
    expect(h.records.get('acme:edr-main:key-20261021')).toBe('PENDING');
    expect(h.store.size).toBe(1);
    expect([...h.store.values()][0]).not.toContain(key.toString('base64'));
    expect(h.statements[0].sql).toContain('FROM soc_auth_sessions');
    expect(h.statements[1].sql).toContain("p.role='TENANT_ADMIN'");
    expect(h.statements[2].sql).toContain('INSERT INTO soc_connector_signing_keys');
    expect(h.statements[2].params[5]).toBe('tenant-admin');
    expect(h.statements[2].params[6]).toBe('tenant-admin');
    expect(h.nativeD1.withSession).toHaveBeenCalledWith('first-primary');
    expect(JSON.stringify(out)).not.toContain(key.toString('hex'));
  });

  test('enrollment idempotency enforces D1 uniqueness before KV override',async()=>{
    const h=fixture();
    const a={...h.args,secret:secret(),validFromEpoch:EPOCH-30,expiresEpoch:EPOCH+3600};
    await h.admin.enroll(a);
    await expect(h.admin.enroll({...a,secret:secret()}))
      .rejects.toMatchObject({code:'SOC_KEY_MUTATION_REJECTED',status:409});
    expect(h.kv.put).toHaveBeenCalledTimes(1);
  });

  test('activation verifies encrypted record, then sets ACTIVE using signed DB admin actor',async()=>{
    const h=fixture();
    const signed=secret();
    await h.admin.enroll({...h.args,secret:signed,validFromEpoch:EPOCH-30,expiresEpoch:EPOCH+3600});
    const value=await h.admin.activate(h.args);
    expect(value.state).toBe('ACTIVE');
    expect(h.records.get('acme:edr-main:key-20261021')).toBe('ACTIVE');
    expect(h.statements.at(-1).sql).toContain("state='PENDING'");
    expect(h.statements.at(-1).params[0]).toBe('tenant-admin');
    const stored=await h.vault.resolveSecret(TENANT,CONNECTOR,KEY);
    expect(stored).toEqual(signed);
  });

  test('revoke disables ACTIVE key even while encrypted ciphertext remains in KV',async()=>{
    const h=fixture();
    await h.admin.enroll({...h.args,secret:secret(),validFromEpoch:EPOCH-30,expiresEpoch:EPOCH+3600});
    await h.admin.activate(h.args);
    expect((await h.admin.revoke(h.args)).state).toBe('REVOKED');
    expect(h.records.get('acme:edr-main:key-20261021')).toBe('REVOKED');
    expect(h.store.size).toBe(1);
    await expect(h.admin.activate(h.args))
      .rejects.toMatchObject({code:'SOC_KEY_MUTATION_REJECTED'});
    await expect(h.admin.revoke(h.args))
      .rejects.toMatchObject({code:'SOC_KEY_MUTATION_REJECTED'});
  });

  test('failed KV seal leaves PENDING only and reports no active key',async()=>{
    const h=fixture({failVault:true});
    await expect(h.admin.enroll({
      ...h.args,secret:secret(),validFromEpoch:EPOCH-30,expiresEpoch:EPOCH+3600,
    })).rejects.toMatchObject({code:'KEY_ENROLLED_BUT_VAULT_UNAVAILABLE',status:503});
    expect(h.records.get('acme:edr-main:key-20261021')).toBe('PENDING');
    await expect(h.admin.activate(h.args))
      .rejects.toMatchObject({code:'SEALED_KEY_UNAVAILABLE',status:503});
    expect(h.records.get('acme:edr-main:key-20261021')).toBe('PENDING');
  });

  test('unregistered token is rejected before tenant admin or mutation checks',async()=>{
    const h=fixture({registered:false});
    await expect(h.admin.revoke(h.args)).rejects.toMatchObject({code:'UNAUTHENTICATED',status:401});
    expect(h.statements.some(z=>z.sql.includes('SELECT p.principal_id'))).toBe(false);
    expect(h.kv.put).not.toHaveBeenCalled();
  });

  test('valid signed token without ACTIVE tenant admin is forbidden',async()=>{
    const h=fixture({authorized:false});
    await expect(h.admin.revoke(h.args)).rejects.toMatchObject({code:'FORBIDDEN',status:403});
    expect(h.records.size).toBe(0);
  });

  test('wrong signed audience or missing MFA cannot mutate the registry',async()=>{
    const h=fixture();
    for(const changes of [{aud:'unrelated-app'},{amr:['pwd']}]) {
      await expect(h.admin.revoke({...h.args,accessToken:realToken(changes)}))
        .rejects.toMatchObject({code:'UNAUTHENTICATED',status:401});
    }
    expect(h.nativeD1.withSession).not.toHaveBeenCalled();
  });

  test('tenants and identity selectors are constrained before touching DB',async()=>{
    const h=fixture();
    for(const invalid of [
      {tenantId:'../escape'},{connectorId:'../../paths'},{keyId:'https://evil.example/a'},
      {keyId:'UPPERCASE'},{tenantId:''},
    ]) await expect(h.admin.revoke({...h.args,...invalid}))
      .rejects.toMatchObject({code:'INVALID_CONNECTOR_KEY'});
    expect(h.nativeD1.withSession).not.toHaveBeenCalled();
  });

  test('invalid secret or overly long lifetime cannot create an enrollment record',async()=>{
    const h=fixture();
    for(const changes of [
      {secret:Buffer.alloc(8),validFromEpoch:EPOCH,expiresEpoch:EPOCH+3600},
      {secret:secret(),validFromEpoch:EPOCH-30,expiresEpoch:EPOCH+100*86400},
      {secret:secret(),validFromEpoch:EPOCH+600,expiresEpoch:EPOCH+3600},
      {secret:secret(),validFromEpoch:EPOCH,expiresEpoch:EPOCH-1},
    ])await expect(h.admin.enroll({...h.args,...changes})).rejects.toThrow();
    expect(h.records.size).toBe(0);
  });

  test('database failure or audit-trigger rejection denies enrollment and revocation',async()=>{
    const h=fixture({failWrite:true});
    await expect(h.admin.enroll({
      ...h.args,secret:secret(),validFromEpoch:EPOCH-30,expiresEpoch:EPOCH+3600,
    })).rejects.toMatchObject({code:'SOC_KEY_MUTATION_REJECTED'});
    expect(h.kv.put).not.toHaveBeenCalled();
    await expect(h.admin.revoke(h.args))
      .rejects.toMatchObject({code:'SOC_KEY_MUTATION_REJECTED'});
  });
});
