'use strict';

const crypto=require('node:crypto');
const {createSocDetectionSourceBoundary}=require('../soc-detection-source-boundary');
const {receiptId}=require('../soc-event-receipt-service');

const NOW=Date.parse('2026-10-22T08:40:00.000Z');
const EPOCH=Math.floor(NOW/1000);
const ISSUER='https://soc-idp.example',AUD='sentinel-soc-audience';
const SOURCE='approved-siem-event-1007';
const raw=Buffer.from('OFFLINE generated test fixture, never a customer source event');
const digest=crypto.createHash('sha256').update(raw).digest('hex');
const expectedEvent=receiptId({
  tenantId:'acme',connectorId:'siem-primary',sourceEventId:SOURCE,
});
const [privateKey,publicKey]=(()=>{
  const k=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
  return [k.privateKey,k.publicKey];
})();
const JWK={...publicKey.export({format:'jwk'}),alg:'RS256',kid:'idp-key-20261022',use:'sig'};
const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(changes={}) {
  const h=b64({alg:'RS256',typ:'at+jwt',kid:JWK.kid});
  const p=b64({
    iss:ISSUER,sub:'case-reviewer',aud:AUD,iat:EPOCH-20,exp:EPOCH+300,
    jti:'soc-analyst-review-20261022',amr:['pwd','mfa'],...changes,
  });
  const signed=h+'.'+p;
  return signed+'.'+crypto.createSign('RSA-SHA256').update(signed).end()
    .sign(privateKey).toString('base64url');
}

function setup({source=Buffer.from(raw),member=true,session=true}={}) {
  const reads=[],writes=[];
  const primary={
    prepare:jest.fn(sql=>{
      return {bind:(...params)=>({
        first:async()=>{
          reads.push({sql,params});
          if(sql.includes('FROM soc_auth_sessions'))return session?{allowed:1}:null;
          if(sql.includes('FROM soc_principals'))return member?{principal_id:'reviewer'}:null;
          if(sql.includes('FROM soc_detections'))return {
            detection_id:'det_verified-source-01',event_id:expectedEvent,
            evidence_state:'SOURCE_REPORTED',review_version:0,
            digest_sha256:digest,attestation_sha256:'c'.repeat(64),
            connector_id:'siem-primary',source_event_id:SOURCE,
            signing_key_id:'key-20261022',
            source_event_at:'2026-10-22T08:20:00.000Z',
          };
          throw Error('Unrecognized source query');
        },
        all:async()=>{
          writes.push({sql,params});
          if(sql.startsWith('UPDATE soc_detections'))
            return {success:true,results:[{
              detection_id:'det_verified-source-01',evidence_state:'ANALYST_VERIFIED',review_version:1,
            }]};
          throw Error('Unexpected SQL write');
        },
      })};
    }),
  };
  const nativeD1={withSession:jest.fn(mode=>{
    if(mode!=='first-primary')throw Error('no replicas');
    return primary;
  })};
  const fetcher=jest.fn(async()=>({ok:true,headers:{get:()=>null},
    text:async()=>JSON.stringify({keys:[JWK]})}));
  const readAuthorizedEvent=jest.fn(async request=>({
    tenantId:request.tenantId,connectorId:request.connectorId,
    sourceEventId:request.sourceEventId,payloadBytes:source,
  }));
  const boundary=createSocDetectionSourceBoundary({
    nativeD1,
    oidc:{issuer:ISSUER,audience:AUD,jwksUrl:ISSUER+'/jwks.json'},
    fetcher,readAuthorizedEvent,nowMillis:()=>NOW,
  });
  const args={accessToken:token(),tenantId:'acme',
    detectionId:'det_verified-source-01',decision:'ANALYST_VERIFIED',
    requestId:'review-20261022-001',reviewNote:
    'Independent authorized SIEM source bytes reviewed for this test fixture.',
  };
  return {boundary,args,reads,writes,readAuthorizedEvent,nativeD1};
}

describe('SOC integrated OIDC + primary D1 + independent source-byte review',()=>{
  test('rejects any construction lacking trust authority or approved source adapter',()=>{
    expect(()=>createSocDetectionSourceBoundary()).toThrow('SOC_EVIDENCE_BOUNDARY_NOT_CONFIGURED');
    expect(()=>createSocDetectionSourceBoundary({nativeD1:{withSession:()=>{}},oidc:{}}))
      .toThrow('SOC_EVIDENCE_BOUNDARY_NOT_CONFIGURED');
  });
  test('requires real signed MFA OIDC session and current analyst and raw source-byte match',async()=>{
    const f=setup();
    const result=await f.boundary.review(f.args);
    expect(result).toMatchObject({
      tenantId:'acme',evidenceState:'ANALYST_VERIFIED',reviewVersion:1,
    });
    expect(f.nativeD1.withSession).toHaveBeenCalledWith('first-primary');
    expect(f.reads.some(x=>x.sql.includes('soc_auth_sessions'))).toBe(true);
    expect(f.reads.some(x=>x.sql.includes("p.status='ACTIVE'"))).toBe(true);
    expect(f.readAuthorizedEvent).toHaveBeenCalledWith(expect.objectContaining({
      tenantId:'acme',connectorId:'siem-primary',sourceEventId:SOURCE,
    }));
    expect(f.writes).toHaveLength(1);
    expect(f.writes[0].params[5]).toBe(digest);
    expect(JSON.stringify(result)).not.toContain(raw.toString('utf8'));
  });
  test('wrong actual source bytes do not update a detection',async()=>{
    const f=setup({source:Buffer.from('unrelated attacker data')});
    await expect(f.boundary.review(f.args))
      .rejects.toMatchObject({code:'INDEPENDENT_EVIDENCE_UNVERIFIED'});
    expect(f.writes).toHaveLength(0);
  });
  test('unregistered OIDC token denies before source access',async()=>{
    const f=setup({session:false});
    await expect(f.boundary.review(f.args)).rejects.toMatchObject({code:'UNAUTHENTICATED'});
    expect(f.readAuthorizedEvent).not.toHaveBeenCalled();
    expect(f.writes).toHaveLength(0);
  });
  test('absent tenant analyst membership denies even with valid source digest',async()=>{
    const f=setup({member:false});
    await expect(f.boundary.review(f.args)).rejects.toMatchObject({code:'FORBIDDEN'});
    expect(f.readAuthorizedEvent).not.toHaveBeenCalled();
    expect(f.writes).toHaveLength(0);
  });
  test('wrong token audience or missing MFA rejects before D1',async()=>{
    const f=setup();
    for(const claims of [{aud:'other-app'},{amr:['pwd']}]) {
      await expect(f.boundary.review({...f.args,accessToken:token(claims)}))
        .rejects.toMatchObject({code:'UNAUTHENTICATED'});
    }
    expect(f.nativeD1.withSession).not.toHaveBeenCalled();
  });
  test('composition has no candidate creator, public route or auto response actions',()=>{
    const f=setup();
    expect(Object.keys(f.boundary)).toEqual(['review','linkToIncident']);
  });
});
