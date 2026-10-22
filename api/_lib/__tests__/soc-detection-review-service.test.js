'use strict';

const {createSocDetectionReviewService}=require('../soc-detection-review-service');

const TENANT='acme';
const DIGEST='a'.repeat(64),ATTEST='b'.repeat(64);
const DET='det_'+('d'.repeat(24));
const INC='inc_00000000-0000-4000-8000-000000000001';
const NOTE='Independent source evidence was retrieved and reviewed by analyst.';
const REQUEST='review-2026102100001';
const identity=Object.freeze({verified:true,issuer:'https://issuer.example',subject:'analyst-user'});

function fixture({actor='analyst',exists=true,reviewed=false,verify=true,auth=true}={}){
  let state=reviewed?'ANALYST_VERIFIED':'SOURCE_REPORTED',version=reviewed?1:0;
  const calls=[];
  const session={prepare:jest.fn(sql=>({
    bind:(...params)=>{
      calls.push({sql,params});
      return {
        first:async()=>{
          if(sql.includes('FROM soc_principals'))return auth?{principal_id:actor}:null;
          if(sql.includes('FROM soc_detections'))return exists?{
            detection_id:DET,event_id:'evt_'+'c'.repeat(64),
            evidence_state:state,review_version:version,
            digest_sha256:DIGEST,attestation_sha256:ATTEST,
            connector_id:'edr',signing_key_id:'key-20261021',source_event_id:'edr-provider-event-001',
            source_event_at:'2026-10-21T15:59:00.000Z',
          }:null;
          throw Error('Unexpected SQL: '+sql);
        },
        all:async()=>{
          if(sql.startsWith('UPDATE soc_detections')){
            if(reviewed||state!=='SOURCE_REPORTED')return {success:true,results:[]};
            state=params[0];version++;
            return {success:true,results:[{
              detection_id:DET,evidence_state:state,review_version:version,
            }]};
          }
          if(sql.startsWith('INSERT INTO soc_incident_detections')){
            return {success:true,results:[{incident_id:INC,detection_id:DET}]};
          }
          throw Error('Unexpected mutation');
        },
      };
    },
  }))};
  const nativeD1={withSession:jest.fn(mode=>{
    if(mode!=='first-primary')throw Error('Never use stale replica');
    return session;
  })};
  const verifyIdentity=jest.fn(async()=>identity);
  const verifySourceEvidence=jest.fn(async()=>verify?{
    verified:true,recomputedDigestSha256:DIGEST,
  }:{verified:false});
  const service=createSocDetectionReviewService({
    nativeD1,verifyIdentity,verifySourceEvidence,
    now:()=> '2026-10-21T16:00:00.000Z',
  });
  const args={accessToken:'opaque-signed-token',tenantId:TENANT,detectionId:DET,
    decision:'ANALYST_VERIFIED',requestId:REQUEST,reviewNote:NOTE};
  return {service,nativeD1,session,calls,verifyIdentity,verifySourceEvidence,args};
}
describe('SOC detection human review — trusted evidence and tenant boundaries',()=>{
  test('cannot initialize without a trusted signer/independent evidence verifier/primary D1',()=>{
    const good=fixture();
    expect(()=>createSocDetectionReviewService()).toThrow('SOC_DETECTION_AUTHORITY_REQUIRED');
    expect(()=>createSocDetectionReviewService({
      nativeD1:good.nativeD1,
      verifyIdentity:async()=>identity,
    })).toThrow('SOC_DETECTION_AUTHORITY_REQUIRED');
  });

  test('trusted analyst review requires independent matching digest and active tenant actor',async()=>{
    const f=fixture();
    const result=await f.service.review(f.args);
    expect(result).toEqual({
      tenantId:TENANT,detectionId:DET,
      evidenceState:'ANALYST_VERIFIED',reviewVersion:1,
    });
    expect(f.nativeD1.withSession).toHaveBeenCalledWith('first-primary');
    const membership=f.calls.find(c=>c.sql.includes('FROM soc_principals'));
    expect(membership.sql).toMatch(/p\.role IN/);
    expect(membership.params).toEqual([TENANT,identity.issuer,identity.subject]);
    const evidence=f.verifySourceEvidence.mock.calls[0][0];
    expect(evidence).toEqual(expect.objectContaining({
      tenantId:TENANT,digestSha256:DIGEST,attestationSha256:ATTEST,
      signingKeyId:'key-20261021',sourceEventId:'edr-provider-event-001',
    }));
    const write=f.calls.find(c=>c.sql.startsWith('UPDATE soc_detections'));
    expect(write.sql).toContain("evidence_state='SOURCE_REPORTED'");
    expect(write.sql).toContain('review_version=0 RETURNING');
    expect(write.params).toEqual([
      'ANALYST_VERIFIED','analyst',REQUEST,NOTE,
      '2026-10-21T16:00:00.000Z',DIGEST,TENANT,DET,
    ]);
    expect(JSON.stringify(result)).not.toContain('opaque-signed-token');
  });

  test('unverified external content cannot produce analyst-verified decision',async()=>{
    const f=fixture({verify:false});
    await expect(f.service.review(f.args)).rejects.toMatchObject({
      code:'INDEPENDENT_EVIDENCE_UNVERIFIED',status:409,
    });
    expect(f.calls.some(x=>x.sql.startsWith('UPDATE soc_detections'))).toBe(false);
  });

  test('matching digest must be recomputed by verifier, not caller-supplied',async()=>{
    const f=fixture();
    f.verifySourceEvidence.mockResolvedValue({
      verified:true,recomputedDigestSha256:'f'.repeat(64),
    });
    await expect(f.service.review({...f.args,reviewBasisSha256:DIGEST}))
      .rejects.toMatchObject({code:'INDEPENDENT_EVIDENCE_UNVERIFIED'});
    expect(f.calls.some(x=>x.sql.startsWith('UPDATE soc_detections'))).toBe(false);
  });

  test('source verification unavailable denies even if JWT is valid',async()=>{
    const f=fixture();
    f.verifySourceEvidence.mockRejectedValue(new Error('internal source API credentials'));
    await expect(f.service.review(f.args)).rejects.toMatchObject({
      code:'INDEPENDENT_EVIDENCE_UNAVAILABLE',status:503,
    });
    expect(f.calls.some(x=>x.sql.startsWith('UPDATE soc_detections'))).toBe(false);
  });

  test('analyst can reject with documented rationale without claiming verified evidence',async()=>{
    const f=fixture();
    const res=await f.service.review({...f.args,decision:'REJECTED'});
    expect(res.evidenceState).toBe('REJECTED');
    expect(f.verifySourceEvidence).not.toHaveBeenCalled();
    const write=f.calls.find(x=>x.sql.startsWith('UPDATE soc_detections'));
    expect(write.params[5]).toBeNull();
  });

  test('unregistered actor or revoked signed session denies before detection source access',async()=>{
    const f=fixture({auth:false});
    await expect(f.service.review(f.args))
      .rejects.toMatchObject({code:'FORBIDDEN',status:403});
    expect(f.verifySourceEvidence).not.toHaveBeenCalled();
    expect(f.calls.some(x=>x.sql.includes('FROM soc_detections'))).toBe(false);
    const bad=fixture();
    bad.verifyIdentity.mockRejectedValue(new Error('revoked JWT'));
    await expect(bad.service.review(bad.args))
      .rejects.toMatchObject({code:'UNAUTHENTICATED',status:401});
    expect(bad.nativeD1.withSession).not.toHaveBeenCalled();
  });

  test('already reviewed case cannot be silently overwritten',async()=>{
    const f=fixture({reviewed:true});
    await expect(f.service.review(f.args)).rejects.toMatchObject({
      code:'DETECTION_ALREADY_REVIEWED',status:409,
    });
    expect(f.verifySourceEvidence).not.toHaveBeenCalled();
  });

  test('tenant- and ID-input validation runs before identity/DB read',async()=>{
    const f=fixture();
    for(const bad of [{tenantId:'../contoso'},{detectionId:'../../passwd'},
      {decision:'AUTO_VERIFIED'},{requestId:'short'},{reviewNote:'no evidence'}]){
      await expect(f.service.review({...f.args,...bad})).rejects.toMatchObject({status:400});
    }
    expect(f.nativeD1.withSession).not.toHaveBeenCalled();
  });

  test('verified detection links only using active analyst and primary D1 (DB trigger enforces evidence state)',async()=>{
    const f=fixture();
    const result=await f.service.linkToIncident({
      ...f.args,incidentId:INC,
    });
    expect(result).toEqual({tenantId:TENANT,incidentId:INC,detectionId:DET,linked:true});
    expect(f.nativeD1.withSession).toHaveBeenCalledWith('first-primary');
    const write=f.calls.find(x=>x.sql.startsWith('INSERT INTO soc_incident_detections'));
    expect(write.params).toEqual([
      TENANT,INC,DET,'2026-10-21T16:00:00.000Z','analyst',REQUEST,
    ]);
  });

  test('a database trigger rejection never reports a successful link',async()=>{
    const f=fixture();
    f.session.prepare.mockImplementation(sql=>({
      bind:(...args)=>({
        first:async()=>sql.includes('FROM soc_principals')?{principal_id:'analyst'}:null,
        all:async()=>{throw Error('SOC incident link rejected due to unverified detection');},
      }),
    }));
    await expect(f.service.linkToIncident({...f.args,incidentId:INC}))
      .rejects.toMatchObject({code:'DETECTION_LINK_REJECTED',status:409});
  });

  test('service offers no public candidate creation, no containment, and no source payload access',()=>{
    const f=fixture();
    expect(Object.keys(f.service)).toEqual(['review','linkToIncident']);
    expect(Object.isFrozen(f.service)).toBe(true);
  });
});
