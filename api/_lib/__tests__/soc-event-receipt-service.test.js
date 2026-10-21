'use strict';

const crypto = require('node:crypto');
const {
  createSocEventReceiptService,canonicalFields,receiptId,
} = require('../soc-event-receipt-service');

const NOW = Date.parse('2026-10-21T16:00:00.000Z');
const SECRET = crypto.randomBytes(32);
const PAYLOAD_DIGEST = crypto.createHash('sha256').update('opaque-real-source-payload').digest('hex');
const BASE = Object.freeze({
  version:1,
  tenantId:'acme',
  connectorId:'edr-primary',
  sourceEventId:'edr-detection-98421',
  eventTime:'2026-10-21T15:55:00.000Z',
  signedAt:'2026-10-21T16:00:00.000Z',
  payloadSha256:PAYLOAD_DIGEST,
});

function signed(overrides={},secret=SECRET) {
  const base={...BASE,...overrides};
  return {
    ...base,
    signature:crypto.createHmac('sha256',secret)
      .update(canonicalFields(base)).digest('base64url'),
  };
}
function fixture({allowed=true,secret=SECRET,failRead=false,failWrite=false}={}) {
  const first=jest.fn(async()=> {
    if(failRead)throw new Error('do not disclose primary secrets');
    return allowed?{connector_id:'edr-primary'}:null;
  });
  const run=jest.fn(async()=> {
    if(failWrite)throw new Error('unique conflict or audit trigger rejected');
    return {success:true};
  });
  const bind=jest.fn((...params)=>({first,run}));
  const prepare=jest.fn((sql)=>({bind}));
  const withSession=jest.fn(()=>({prepare}));
  const resolveSecret=jest.fn(async()=>secret);
  const nativeD1={withSession};
  const service=createSocEventReceiptService({nativeD1,resolveSecret,now:()=>NOW});
  return {service,nativeD1,withSession,prepare,bind,first,run,resolveSecret};
}

describe('SENTINEL APEX SOC source-attested intake',()=>{
  test('refuses construction without native D1 and cryptographic secret resolver',()=>{
    expect(()=>createSocEventReceiptService({resolveSecret:async()=>SECRET}))
      .toThrow('INTAKE_AUTHORITY_NOT_CONFIGURED');
    expect(()=>createSocEventReceiptService({nativeD1:{withSession:()=>({})}}))
      .toThrow('INTAKE_AUTHORITY_NOT_CONFIGURED');
  });
  test('accepts a current, real signed envelope only when connector approved and tenant active',async()=>{
    const h=fixture();
    const event=signed();
    const accepted=await h.service.ingest(event);
    expect(accepted).toMatchObject({
      tenantId:'acme',eventId:receiptId(BASE),source:'SOURCE_ATTESTED',
      state:'RECEIVED_NOT_ANALYST_VERIFIED',
      sourceEventAt:BASE.eventTime,
    });
    expect(accepted).not.toHaveProperty('signature');
    expect(accepted).not.toHaveProperty('payload');
    expect(h.resolveSecret).toHaveBeenCalledWith('acme','edr-primary');
    expect(h.withSession).toHaveBeenCalledWith('first-primary');
    const query=h.prepare.mock.calls[0][0];
    expect(query).toMatch(/c.state='APPROVED'/);
    expect(query).toMatch(/t.status='ACTIVE'/);
    expect(h.bind.mock.calls[0]).toEqual(['acme','edr-primary']);
    const insert=h.prepare.mock.calls[1][0];
    expect(insert).toMatch(/INSERT INTO soc_event_receipts/);
    expect(h.bind.mock.calls[1]).toEqual([
      'acme',receiptId(BASE),'edr-primary',BASE.eventTime,
      '2026-10-21T16:00:00.000Z',PAYLOAD_DIGEST,'2026-10-21T16:00:00.000Z',
    ]);
  });
  test('deterministic receipt ID for same source and connector prevents replay',()=>{
    expect(receiptId(BASE)).toEqual(receiptId(BASE));
    expect(receiptId({...BASE,sourceEventId:'different'})).not.toEqual(receiptId(BASE));
    expect(receiptId({...BASE,tenantId:'contoso'})).not.toEqual(receiptId(BASE));
    expect(receiptId({...BASE,connectorId:'other'})).not.toEqual(receiptId(BASE));
    expect(receiptId(BASE)).toMatch(/^evt_[a-f0-9]{64}$/);
  });
  test('HMAC changes if source event identity, tenant, time or digest are tampered',async()=>{
    const h=fixture();
    for(const changes of [
      {tenantId:'contoso'},{connectorId:'another'},{sourceEventId:'different'},
      {payloadSha256:'c'.repeat(64)},
      {eventTime:'2026-10-21T15:54:00.000Z'},
      {signedAt:'2026-10-21T15:59:00.000Z'},
    ]) {
      const tampered={...signed(),...changes};
      await expect(h.service.ingest(tampered))
        .rejects.toMatchObject({code:'INVALID_SIGNATURE',status:401});
    }
    expect(h.withSession).not.toHaveBeenCalled();
  });
  test('incorrect connector signing key rejected before hitting D1',async()=>{
    const h=fixture({secret:crypto.randomBytes(32)});
    await expect(h.service.ingest(signed())).rejects.toMatchObject({code:'INVALID_SIGNATURE'});
    expect(h.withSession).not.toHaveBeenCalled();
  });
  test('missing credential fails closed',async()=>{
    const h=fixture({secret:null});
    await expect(h.service.ingest(signed())).rejects.toMatchObject({code:'CONNECTOR_NOT_AUTHORIZED'});
    expect(h.withSession).not.toHaveBeenCalled();
  });
  test('secret provider unavailable fails closed without leaking credential source',async()=>{
    const h=fixture();
    h.resolveSecret.mockRejectedValue(new Error('vault secret token private'));
    await expect(h.service.ingest(signed())).rejects.toMatchObject({code:'CONNECTOR_AUTH_UNAVAILABLE'});
    expect(h.withSession).not.toHaveBeenCalled();
  });
  test('revoked connector or suspended tenant denied by primary D1 state',async()=>{
    const h=fixture({allowed:false});
    await expect(h.service.ingest(signed()))
      .rejects.toMatchObject({code:'CONNECTOR_NOT_AUTHORIZED',status:403});
    expect(h.run).not.toHaveBeenCalled();
  });
  test('failed primary D1 reads are denied; no bypass',async()=>{
    const h=fixture({failRead:true});
    await expect(h.service.ingest(signed()))
      .rejects.toMatchObject({code:'INTAKE_PRIMARY_UNAVAILABLE',status:503});
    expect(h.run).not.toHaveBeenCalled();
  });
  test('duplicate source receipt or audit trigger failures are rejected and not reported success',async()=>{
    const h=fixture({failWrite:true});
    await expect(h.service.ingest(signed()))
      .rejects.toMatchObject({code:'RECEIPT_REJECTED',status:409});
  });
  test('no client raw event, spoofed state or extra payload keys are accepted',async()=>{
    const h=fixture();
    for(const injected of [
      {...signed(),rawPayload:{secret:'data'}},
      {...signed(),state:'CONFIRMED'},
      {...signed(),incidentId:'inc_fake'},
      {...signed(),tenant_id:'contoso'},
    ]) await expect(h.service.ingest(injected))
      .rejects.toMatchObject({code:'INVALID_ENVELOPE'});
    expect(h.resolveSecret).not.toHaveBeenCalled();
  });
  test('stale signed timestamps and impossible event times rejected pre-auth',async()=>{
    const h=fixture();
    for(const changes of [
      {signedAt:'2026-10-21T15:54:59.000Z'},
      {signedAt:'2026-10-21T16:05:01.000Z'},
      {eventTime:'2026-10-21T16:05:01.000Z'},
      {eventTime:'2026-08-01T00:00:00.000Z'},
      {eventTime:'2026-02-30T01:00:00.000Z'},
    ]) await expect(h.service.ingest(signed(changes)))
      .rejects.toMatchObject({code:'EVENT_TIME_REJECTED'});
    expect(h.resolveSecret).not.toHaveBeenCalled();
  });
  test('rejects malformed signatures and digests',async()=>{
    const h=fixture();
    for(const changes of [
      {signature:'%'},{signature:'a'.repeat(300)},
      {payloadSha256:'0'.repeat(63)},
      {payloadSha256:'A'.repeat(64)},
      {connectorId:'../c'},
    ]) await expect(h.service.ingest({...signed(),...changes}))
      .rejects.toMatchObject({code:'INVALID_ENVELOPE'});
    expect(h.resolveSecret).not.toHaveBeenCalled();
  });
  test('signature attests receipt metadata only, not independent source verification',async()=>{
    const accepted=await fixture().service.ingest(signed());
    expect(accepted.source).toBe('SOURCE_ATTESTED');
    expect(accepted.state).not.toMatch(/ANALYST_VERIFIED|CONFIRMED/);
  });
});
