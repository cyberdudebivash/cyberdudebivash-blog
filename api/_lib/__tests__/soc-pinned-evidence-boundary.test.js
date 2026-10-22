'use strict';

const crypto=require('node:crypto');
const {createSocPinnedEvidenceBoundary}=require('../soc-pinned-evidence-boundary');
const {receiptId}=require('../soc-event-receipt-service');

const NOW=Date.parse('2026-10-22T05:00:00.000Z');
const ISSUER='https://secure-idp.example';
const AUDIENCE='sentinel-apex-evidence-review';
const RAW=Buffer.from('offline bytes: independently reviewed synthetic SIEM event');
const DIGEST=crypto.createHash('sha256').update(RAW).digest('hex');
const SOURCE='siem-20261022-incident-042';
const EVENT=receiptId({tenantId:'acme',connectorId:'siem',sourceEventId:SOURCE});
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const JWK={...publicKey.export({format:'jwk'}),alg:'RS256',kid:'operator-signer',use:'sig'};
const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(changes={}){
  const header=b64({alg:'RS256',typ:'at+jwt',kid:JWK.kid});
  const payload=b64({
    iss:ISSUER,sub:'reviewer',aud:AUDIENCE,
    iat:Math.floor(NOW/1000)-30,exp:Math.floor(NOW/1000)+300,
    jti:'signed-analyst-20261022-01',amr:['pwd','mfa'],...changes,
  });
  const message=header+'.'+payload;
  return message+'.'+crypto.createSign('RSA-SHA256').update(message).end()
    .sign(privateKey).toString('base64url');
}
function fixture({tenantMember=true,authSession=true,providerBytes=RAW}={}){
  const reads=[],writes=[];
  const nativeD1={withSession:jest.fn(mode=>{
    if(mode!=='first-primary')throw Error('stale replica');
    return {prepare:sql=>({bind:(...params)=>({
      first:async()=>{
        reads.push({sql,params});
        if(sql.includes('soc_auth_sessions'))return authSession?{allowed:1}:null;
        if(sql.includes('FROM soc_principals'))return tenantMember?{principal_id:'analyst-acme'}:null;
        if(sql.includes('FROM soc_detections'))return {
          detection_id:'det_siem-analyst-01',event_id:EVENT,
          evidence_state:'SOURCE_REPORTED',review_version:0,
          digest_sha256:DIGEST,attestation_sha256:'a'.repeat(64),
          connector_id:'siem',source_event_id:SOURCE,
          signing_key_id:'key-20261022',
          source_event_at:'2026-10-22T04:59:00.000Z',
        };
        throw Error('Unexpected SQL query');
      },
      all:async()=>{
        writes.push({sql,params});
        if(sql.startsWith('UPDATE soc_detections'))return {
          success:true,results:[{detection_id:'det_siem-analyst-01',
            evidence_state:'ANALYST_VERIFIED',review_version:1}],
        };
        throw Error('Unexpected write');
      },
    })})};
  })};
  const identityFetcher=jest.fn(async()=>({ok:true,headers:{get:()=>null},
    text:async()=>JSON.stringify({keys:[JWK]})}));
  const providerFetcher=jest.fn(async()=>
    new Response(providerBytes,{status:200,headers:{
      'content-type':'application/octet-stream',
      'x-soc-tenant-id':'acme','x-soc-connector-id':'siem',
      'x-soc-source-event-id':SOURCE,
    }}));
  const resolveToken=jest.fn(async()=> 'operator-issued-fixture-token-'+('x'.repeat(50)));
  const boundary=createSocPinnedEvidenceBoundary({
    nativeD1,
    oidc:{issuer:ISSUER,audience:AUDIENCE,jwksUrl:ISSUER+'/jwks.json'},
    bindings:[{tenantId:'acme',connectorId:'siem',
      endpoint:'https://customer-proxy.example/v1/evidence'}],
    identityFetcher,providerFetcher,resolveToken,nowMillis:()=>NOW,
    maxBytes:2048,timeoutMs:500,
  });
  const args={
    accessToken:token(),tenantId:'acme',
    detectionId:'det_siem-analyst-01',
    decision:'ANALYST_VERIFIED',requestId:'review-20261022-1024',
    reviewNote:'Independently checked the signed source payload against authorized proxy bytes.',
  };
  return {boundary,args,reads,writes,nativeD1,providerFetcher,resolveToken};
}
describe('SOC pinned evidence: RSA-MFA/OIDC + D1 + bounded HTTPS -> verified review',()=>{
  test('real RSA token, primary tenant analyst and bytes can create one audited review',async()=>{
    const f=fixture();
    const out=await f.boundary.review(f.args);
    expect(out).toMatchObject({evidenceState:'ANALYST_VERIFIED',reviewVersion:1});
    expect(f.nativeD1.withSession).toHaveBeenCalledWith('first-primary');
    expect(f.reads.some(x=>x.sql.includes('soc_auth_sessions'))).toBe(true);
    expect(f.reads.some(x=>x.sql.includes('FROM soc_principals'))).toBe(true);
    expect(f.resolveToken).toHaveBeenCalledWith('acme','siem');
    expect(f.providerFetcher).toHaveBeenCalledTimes(1);
    const [uri,options]=f.providerFetcher.mock.calls[0];
    expect(uri).toBe('https://customer-proxy.example/v1/evidence?event_id=siem-20261022-incident-042');
    expect(options.headers.Authorization).toMatch(/^Bearer /);
    expect(f.writes).toHaveLength(1);
    expect(f.writes[0].params[5]).toBe(DIGEST);
    expect(JSON.stringify(out)).not.toContain(RAW.toString('utf8'));
  });

  test('missing live session or permission cannot resolve secrets or contact proxy',async()=>{
    for(const scenario of [{authSession:false},{tenantMember:false}]){
      const f=fixture(scenario);
      await expect(f.boundary.review(f.args)).rejects.toThrow();
      expect(f.resolveToken).not.toHaveBeenCalled();
      expect(f.providerFetcher).not.toHaveBeenCalled();
      expect(f.writes).toHaveLength(0);
    }
  });

  test('wrong signed audience or absent MFA rejects before provider read',async()=>{
    const f=fixture();
    for(const claims of [{aud:'unauthorized'},{amr:['pwd']}]){
      await expect(f.boundary.review({...f.args,accessToken:token(claims)}))
        .rejects.toMatchObject({code:'UNAUTHENTICATED'});
    }
    expect(f.providerFetcher).not.toHaveBeenCalled();
  });

  test('changed retrieved content fails closed, even when HTTP response is 200',async()=>{
    const f=fixture({providerBytes:Buffer.from('different payload')});
    await expect(f.boundary.review(f.args))
      .rejects.toMatchObject({code:'INDEPENDENT_EVIDENCE_UNVERIFIED'});
    expect(f.writes).toHaveLength(0);
  });

  test('provider identity drift or source outage does not reach review write',async()=>{
    const f=fixture();
    f.providerFetcher.mockImplementation(async()=>new Response(RAW,{
      status:200,headers:{
        'content-type':'application/octet-stream',
        'x-soc-tenant-id':'contoso','x-soc-connector-id':'siem',
        'x-soc-source-event-id':SOURCE,
      },
    }));
    await expect(f.boundary.review(f.args))
      .rejects.toMatchObject({code:'INDEPENDENT_EVIDENCE_UNAVAILABLE'});
    expect(f.writes).toHaveLength(0);
  });

  test('no public source URL, candidate creation or key export capability',()=>{
    const f=fixture();
    expect(Object.keys(f.boundary)).toEqual(['review','linkToIncident']);
    expect(Object.isFrozen(f.boundary)).toBe(true);
  });
});
