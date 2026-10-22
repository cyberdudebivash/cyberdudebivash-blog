'use strict';

const crypto=require('node:crypto');
const {receiptId}=require('../soc-event-receipt-service');
const {createSocSourceByteVerifier}=require('../soc-source-byte-verifier');
const bytes=Buffer.from('Sample source bytes for OFFLINE trust-boundary tests only.');
const SOURCE='source-offline-case-144';
const BASE={
  tenantId:'acme',
  connectorId:'edr-primary',
  sourceEventId:SOURCE,
  signingKeyId:'key-20261022',
  digestSha256:crypto.createHash('sha256').update(bytes).digest('hex'),
  attestationSha256:'f'.repeat(64),
  sourceEventAt:'2026-10-22T08:00:00.000Z',
};
BASE.eventId=receiptId(BASE);
function fixture(options={}) {
  const readAuthorizedEvent=jest.fn(async ref=>({
    tenantId:ref.tenantId,
    connectorId:ref.connectorId,
    sourceEventId:ref.sourceEventId,
    payloadBytes:Buffer.from(bytes),
    ...options.record,
  }));
  const verify=createSocSourceByteVerifier({
    readAuthorizedEvent,maxBytes:2048,timeoutMs:500,...options.settings,
  });
  return {readAuthorizedEvent,verify};
}

describe('SOC independent source-byte evidence verifier',()=>{
  test('refuses missing provider and unsafe limits',()=>{
    expect(()=>createSocSourceByteVerifier()).toThrow('SOURCE_ADAPTER_NOT_CONFIGURED');
    expect(()=>createSocSourceByteVerifier({
      readAuthorizedEvent:async()=>null,maxBytes:1048577,
    })).toThrow('SOURCE_ADAPTER_NOT_CONFIGURED');
    expect(()=>createSocSourceByteVerifier({
      readAuthorizedEvent:async()=>null,timeoutMs:0,
    })).toThrow('SOURCE_ADAPTER_NOT_CONFIGURED');
  });
  test('genuine bytes from approved adapter independently reproduce signed digest',async()=>{
    const h=fixture();
    const result=await h.verify(BASE);
    expect(result).toEqual({
      verified:true,recomputedDigestSha256:BASE.digestSha256,
    });
    expect(h.readAuthorizedEvent).toHaveBeenCalledTimes(1);
    const req=h.readAuthorizedEvent.mock.calls[0][0];
    expect(req).toEqual(expect.objectContaining({
      tenantId:'acme',connectorId:'edr-primary',sourceEventId:SOURCE,
    }));
    expect(Object.isFrozen(req)).toBe(true);
    expect(req.signal).toBeInstanceOf(AbortSignal);
    expect(result).not.toHaveProperty('payloadBytes');
    expect(result).not.toHaveProperty('sourceEventId');
  });
  test('source byte tampering fails despite provider-side claimed valid labels',async()=>{
    const h=fixture({record:{
      payloadBytes:Buffer.from('completely different content'),
    }});
    const result=await h.verify(BASE);
    expect(result.verified).toBe(false);
    expect(result.recomputedDigestSha256).not.toBe(BASE.digestSha256);
  });
  test('fake provider verified:true fields are rejected, never trusted',async()=>{
    const h=fixture({record:{
      verified:true,recomputedDigestSha256:BASE.digestSha256,
      payloadBytes:Buffer.from(bytes),
    }});
    await expect(h.verify(BASE)).rejects.toMatchObject({
      code:'SOURCE_RESPONSE_INVALID',
    });
  });
  test('wrong tenant/connector/source identification cannot borrow matching bytes',async()=>{
    for(const record of [
      {tenantId:'contoso'},
      {connectorId:'other-siem'},
      {sourceEventId:'other-event'},
    ]){
      const h=fixture({record});
      await expect(h.verify(BASE)).rejects.toMatchObject({
        code:'SOURCE_RESPONSE_SCOPE_MISMATCH',
      });
    }
  });
  test('a forged or mismatched deterministic event ID is denied before adapter access',async()=>{
    const h=fixture();
    await expect(h.verify({...BASE,eventId:'evt_'+'0'.repeat(64)}))
      .rejects.toMatchObject({code:'SOURCE_EVENT_ID_MISMATCH'});
    expect(h.readAuthorizedEvent).not.toHaveBeenCalled();
  });
  test('raw URLs, unexpected fields and untrusted source paths are rejected',async()=>{
    const h=fixture();
    for(const value of [
      {...BASE,sourceEventId:'../../secret'},
      {...BASE,tenantId:'../bypass'},
      {...BASE,providerUrl:'https://evil.example'},
      {...BASE,sourceEventId:'https://evil.example'},
      {...BASE,digestSha256:'0'.repeat(63)},
      {...BASE,attestationSha256:'A'.repeat(64)},
      {...BASE,sourceEventAt:'not-a-date'},
    ]){
      await expect(h.verify(value)).rejects.toMatchObject({
        code:'EVIDENCE_REFERENCE_INVALID',
      });
    }
    expect(h.readAuthorizedEvent).not.toHaveBeenCalled();
  });
  test('untrusted string/raw object and oversized bytes cannot enter reviewer',async()=>{
    for(const payloadBytes of [
      'caller-supplied digest',
      {hash:BASE.digestSha256},
      Buffer.alloc(3000),
      Buffer.alloc(0),
    ]) {
      const h=fixture({record:{payloadBytes}});
      await expect(h.verify(BASE)).rejects.toMatchObject({code:'SOURCE_BYTES_INVALID'});
    }
  });
  test('provider outage is fail closed without exposing provider diagnostic details',async()=>{
    const h=fixture();
    h.readAuthorizedEvent.mockRejectedValue(new Error('private EDR access token 54321'));
    await expect(h.verify(BASE)).rejects.toMatchObject({code:'SOURCE_READ_UNAVAILABLE'});
  });
  test('unresponsive source adapter times out and aborts fetch signal',async()=>{
    const h=fixture({settings:{timeoutMs:100}});
    h.readAuthorizedEvent.mockImplementation(async()=>new Promise(()=>{}));
    await expect(h.verify(BASE)).rejects.toMatchObject({code:'SOURCE_READ_TIMEOUT'});
    const arg=h.readAuthorizedEvent.mock.calls[0][0];
    expect(arg.signal.aborted).toBe(true);
  });
  test('never trust the adapter to report the expected hash instead of actual bytes',async()=>{
    const h=fixture({record:{payloadBytes:new Uint8Array(Buffer.from('tampered bytes'))}});
    expect((await h.verify(BASE)).verified).toBe(false);
  });
});
