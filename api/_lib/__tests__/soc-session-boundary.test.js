'use strict';

const { createHash, generateKeyPairSync, createSign } = require('node:crypto');
const { createSocSessionAuthority } = require('../soc-session-authority');
const { createSocIncidentBoundary } = require('../soc-incident-boundary');

const { publicKey, privateKey } = generateKeyPairSync('rsa', {modulusLength:2048});
const jwk = {...publicKey.export({format:'jwk'}),kid:'soc-idp-key',alg:'RS256',use:'sig'};
const AT = Date.parse('2026-10-21T16:00:00Z');
const EPOCH = Math.floor(AT / 1000);
const ISSUER = 'https://idp.example';
const AUDIENCE = 'sentinel-apex-soc';
const JTI = 'soc-idp-token-20261021-00000001';
const ID = 'inc_00000000-0000-4000-8000-000000000001';
const enc = value => Buffer.from(JSON.stringify(value)).toString('base64url');

function token(changes={}) {
  const header=enc({alg:'RS256',typ:'at+jwt',kid:'soc-idp-key'});
  const claims=enc({
    iss:ISSUER,sub:'subject-01',aud:AUDIENCE,iat:EPOCH-20,
    exp:EPOCH+600,jti:JTI,amr:['pwd','mfa'],...changes,
  });
  const data=header+'.'+claims;
  return data+'.'+createSign('RSA-SHA256').update(data).end().sign(privateKey).toString('base64url');
}

function fixture({registered=true,member=true}={}) {
  const first=jest.fn(async () => registered ? {allowed:1} : null);
  const bind=jest.fn((...args) => ({first}));
  const prepare=jest.fn((sql) => ({bind}));
  const withSession=jest.fn(() => ({prepare}));
  const nativeD1={withSession};
  const incident={
    tenant_id:'acme',incident_id:ID,title:'Pilot finding',severity:'HIGH',
    state:'OPEN',owner_id:null,version:1,
    created_at:'2026-10-21T16:00:00Z',updated_at:'2026-10-21T16:00:00Z',
    audit_actor_id:'internal-secret',audit_request_id:'internal-request',
  };
  const incidentDb={
    query:jest.fn(async (sql,params) => {
      if (sql.includes('FROM soc_principals')) return member
        ? [{tenant_id:params[0],principal_id:'analyst',role:'ANALYST'}]
        : [];
      if (sql.includes('FROM soc_incidents')) return [incident];
      throw new Error('unexpected database SQL');
    }),
    run:jest.fn(async () => ({success:true})),
    runMutationWithChanges:jest.fn(async () => 1),
  };
  const fetcher=jest.fn(async () => ({
    ok:true,headers:{get:()=>null},text:async()=>JSON.stringify({keys:[jwk]}),
  }));
  const service=createSocIncidentBoundary({
    nativeD1,incidentDb,oidc:{issuer:ISSUER,audience:AUDIENCE,jwksUrl:ISSUER+'/jwks'},
    fetcher,nowMillis:()=>AT,randomUUID:()=>ID.slice(4),
  });
  return {service,fetcher,nativeD1,withSession,prepare,bind,first,incidentDb};
}

describe('Primary-consistent SOC session authority',() => {
  test('requires the D1 sessions API; no fallback to stale replica',() => {
    expect(() => createSocSessionAuthority({db:{prepare:()=>{}}}))
      .toThrow('PRIMARY_D1_SESSION_REQUIRED');
  });
  test('checks SHA256 JTI against primary without persisting clear JWT ID',async () => {
    const f=fixture();
    const res=await f.service.get({
      accessToken:token(),tenantId:'acme',id:ID,
    });
    expect(res.incidentId).toBe(ID);
    expect(f.withSession).toHaveBeenCalledWith('first-primary');
    const sql=f.prepare.mock.calls[0][0];
    expect(sql).toMatch(/s\.jti_sha256=\?/);
    expect(sql).toMatch(/u\.status='ACTIVE'/);
    expect(sql).toMatch(/s\.token_iat_epoch>u\.valid_after_epoch/);
    const params=f.bind.mock.calls[0];
    expect(params).toEqual([
      ISSUER,'subject-01',createHash('sha256').update(JTI).digest('hex'),
      EPOCH-20,EPOCH+600,EPOCH,
    ]);
    expect(params.join(' ')).not.toContain(JTI);
    expect(f.incidentDb.query.mock.calls.some(([query])=>query.includes('FROM soc_principals'))).toBe(true);
  });
  test('unregistered JWT cannot reach any incident data',async () => {
    const f=fixture({registered:false});
    await expect(f.service.list({
      accessToken:token(),tenantId:'acme',
    })).rejects.toMatchObject({code:'UNAUTHENTICATED'});
    expect(f.incidentDb.query).not.toHaveBeenCalled();
  });
  test('JWT with valid signature still must have ACTIVE tenant membership',async () => {
    const f=fixture({member:false});
    await expect(f.service.list({
      accessToken:token(),tenantId:'acme',
    })).rejects.toMatchObject({code:'FORBIDDEN'});
  });
  test('wrong JWT audience never reaches D1 session authority',async () => {
    const f=fixture();
    await expect(f.service.list({
      accessToken:token({aud:'unrelated-api'}),tenantId:'acme',
    })).rejects.toMatchObject({code:'UNAUTHENTICATED'});
    expect(f.withSession).not.toHaveBeenCalled();
    expect(f.incidentDb.query).not.toHaveBeenCalled();
  });
  test('mutation only uses signed subject and D1 actor, not body-supplied actor',async () => {
    const f=fixture();
    await f.service.create({
      accessToken:token(),tenantId:'acme',
      requestId:'request-abcdef12345678',
      input:{title:'Relevant finding',severity:'HIGH'},
    });
    // Incident creation now requires a checked affected-row receipt, so the
    // atomic owner guard can never report a zero-row write as a creation.
    expect(f.incidentDb.runMutationWithChanges).toHaveBeenCalledTimes(1);
    const [sql,params]=f.incidentDb.runMutationWithChanges.mock.calls[0];
    expect(sql).toContain('INSERT INTO soc_incidents');
    expect(sql).toContain('WHERE ? IS NULL OR EXISTS');
    expect(params[0]).toBe('acme');
    expect(params[5]).toBe('analyst');
    expect(params.slice(-3)).toEqual([null,'acme',null]);
  });
  test('primary D1 read outage fails closed before incident reads',async () => {
    const f=fixture();
    f.first.mockRejectedValue(new Error('primary database unavailable'));
    await expect(f.service.get({
      accessToken:token(),tenantId:'acme',id:ID,
    })).rejects.toMatchObject({code:'UNAUTHENTICATED'});
    expect(f.incidentDb.query).not.toHaveBeenCalled();
  });
  test('cannot initialize without explicit identity provider config',() => {
    expect(() => createSocIncidentBoundary({
      nativeD1:{withSession:()=>{}},
      incidentDb:{query:()=>{},run:()=>{},runMutationWithChanges:()=>{}},
      oidc:{},
    })).toThrow();
  });
});

describe('Revocation checker standalone fail closed',() => {
  test('expired and malformed claims do not query database',async () => {
    const f=fixture();
    const authority=createSocSessionAuthority({db:f.nativeD1,now:()=>EPOCH});
    expect(await authority.checkRevocation({
      issuer:ISSUER,subject:'subject-01',jti:JTI,
      tokenIssuedAt:EPOCH-10,expiresAt:EPOCH,
    })).toBe(false);
    expect(await authority.checkRevocation({
      issuer:ISSUER,subject:'subject-01',jti:'x',
      tokenIssuedAt:EPOCH-10,expiresAt:EPOCH+600,
    })).toBe(false);
    expect(f.withSession).not.toHaveBeenCalled();
  });
  test('malformed primary D1 session rejects, never reads a replica',async () => {
    const authority=createSocSessionAuthority({db:{withSession:()=>({})},now:()=>EPOCH});
    await expect(authority.checkRevocation({
      issuer:ISSUER,subject:'subject-01',jti:JTI,
      tokenIssuedAt:EPOCH-20,expiresAt:EPOCH+600,
    })).rejects.toThrow('PRIMARY_D1_SESSION_REQUIRED');
  });
});
