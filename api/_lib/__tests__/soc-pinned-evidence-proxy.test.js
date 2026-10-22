'use strict';

const crypto=require('node:crypto');
const {createSocPinnedEvidenceProxy}=require('../soc-pinned-evidence-proxy');
const {createSocSourceByteVerifier}=require('../soc-source-byte-verifier');
const {receiptId}=require('../soc-event-receipt-service');

const BINDING=Object.freeze({
  tenantId:'acme',connectorId:'edr-main',
  endpoint:'https://evidence.example/v1/events',
});
const TOKEN='operator-only-fixture-token-'+('k'.repeat(48));
const SOURCE='source.log:2026-10-22-018';
const PAYLOAD=Buffer.from('offline customer-independent source evidence bytes');
function response(body=PAYLOAD,overrides={}){
  return new Response(body,{
    status:overrides.status||200,
    headers:{
      'content-type':overrides.type||'application/octet-stream',
      'x-soc-tenant-id':overrides.tenantId||BINDING.tenantId,
      'x-soc-connector-id':overrides.connectorId||BINDING.connectorId,
      'x-soc-source-event-id':overrides.sourceEventId||SOURCE,
      ...(overrides.length?{'content-length':String(overrides.length)}:{}),
      ...(overrides.encoding?{'content-encoding':overrides.encoding}:{}),
    },
  });
}
function fixture({bindings=[BINDING],credential=TOKEN,fetchImpl}={}){
  const resolveToken=jest.fn(async()=>credential);
  const fetcher=jest.fn(fetchImpl|| (async()=>response()));
  const {readAuthorizedEvent}=createSocPinnedEvidenceProxy({
    bindings,resolveToken,fetcher,maxBytes:2048,timeoutMs:350,
  });
  const signal=new AbortController().signal;
  const request=Object.freeze({
    tenantId:'acme',connectorId:'edr-main',
    sourceEventId:SOURCE,signal,
  });
  return {readAuthorizedEvent,resolveToken,fetcher,request};
}

describe('SOC pinned evidence network proxy — source-only trust boundary',()=>{
  test('approved exact tenant and connector retrieve original bytes over pinned endpoint',async()=>{
    const f=fixture();
    const record=await f.readAuthorizedEvent(f.request);
    expect(record).toEqual({
      tenantId:'acme',connectorId:'edr-main',
      sourceEventId:SOURCE,payloadBytes:PAYLOAD,
    });
    expect(Object.isFrozen(record)).toBe(true);
    expect(f.resolveToken).toHaveBeenCalledWith('acme','edr-main');
    expect(f.fetcher).toHaveBeenCalledTimes(1);
    const [uri,opts]=f.fetcher.mock.calls[0];
    expect(uri).toBe('https://evidence.example/v1/events?event_id=source.log%3A2026-10-22-018');
    expect(opts).toMatchObject({
      method:'GET',redirect:'error',cache:'no-store',
      headers:{Accept:'application/octet-stream',Authorization:'Bearer '+TOKEN},
    });
    expect(opts.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.stringify(record)).not.toContain(TOKEN);
  });

  test('fully composed independent source verifier hashes actual bytes from proxy',async()=>{
    const f=fixture();
    const verify=createSocSourceByteVerifier({
      readAuthorizedEvent:f.readAuthorizedEvent,maxBytes:2048,timeoutMs:500,
    });
    const ref={
      tenantId:'acme',connectorId:'edr-main',sourceEventId:SOURCE,
      signingKeyId:'key-20261022',
      digestSha256:crypto.createHash('sha256').update(PAYLOAD).digest('hex'),
      attestationSha256:'a'.repeat(64),
      sourceEventAt:'2026-10-22T10:00:00.000Z',
    };
    ref.eventId=receiptId(ref);
    expect(await verify(ref)).toEqual({
      verified:true,recomputedDigestSha256:ref.digestSha256,
    });
    const mismatch=await verify({...ref,digestSha256:'0'.repeat(64)});
    expect(mismatch.verified).toBe(false);
    expect(mismatch.recomputedDigestSha256).toBe(ref.digestSha256);
  });

  test('denies unauthorized tenant/connector before token lookup and network',async()=>{
    const f=fixture();
    for(const change of [
      {tenantId:'contoso'},{connectorId:'other-siem'},
    ]){
      await expect(f.readAuthorizedEvent({...f.request,...change}))
        .rejects.toMatchObject({code:'SOURCE_NOT_ENROLLED'});
    }
    expect(f.resolveToken).not.toHaveBeenCalled();
    expect(f.fetcher).not.toHaveBeenCalled();
  });

  test('requires immutable, well-formed operator source config, never caller URL',()=>{
    for(const bindings of [[],null,[BINDING,BINDING],[
      {...BINDING,endpoint:'http://evidence.example/v1/events'},
    ],[
      {...BINDING,endpoint:'https://localhost/v1/events'},
    ],[
      {...BINDING,endpoint:'https://127.0.0.1/v1/events'},
    ],[
      {...BINDING,endpoint:'https://10.0.0.1/v1/events'},
    ],[
      {...BINDING,endpoint:'https://a.internal/v1/events'},
    ],[
      {...BINDING,endpoint:'https://evidence.example/v1/events?url=https://evil.example'},
    ],[
      {...BINDING,endpoint:'https://user:pass@evidence.example/v1/events'},
    ],[
      {...BINDING,endpoint:'https://evidence.example/v1/../events'},
    ],[
      {...BINDING,endpoint:'https://evidence.example/'},
    ]]){
      expect(()=>createSocPinnedEvidenceProxy({
        bindings,resolveToken:async()=>TOKEN,fetcher:async()=>response(),
      })).toThrow();
    }
  });

  test('invalid event input, URL attempts and extra caller request fields are rejected',async()=>{
    const f=fixture();
    for(const value of [
      {...f.request,sourceEventId:'../../secrets'},
      {...f.request,sourceEventId:'https://malicious.example'},
      {...f.request,sourceEventId:'id?token=secret'},
      {...f.request,providerUrl:'https://malicious.example'},
      {...f.request,signal:null},
      {...f.request,tenantId:'../acme'},
    ])await expect(f.readAuthorizedEvent(value)).rejects.toMatchObject({
      code:expect.stringMatching(/^SOURCE_/),
    });
    expect(f.resolveToken).not.toHaveBeenCalled();
    expect(f.fetcher).not.toHaveBeenCalled();
  });

  test('missing or untrusted provider token is fail closed and not sent to network',async()=>{
    for(const credential of [null,'short','bad\ninjection','a'.repeat(5000)]){
      const f=fixture({credential});
      await expect(f.readAuthorizedEvent(f.request))
        .rejects.toMatchObject({code:'SOURCE_CREDENTIAL_UNAVAILABLE'});
      expect(f.fetcher).not.toHaveBeenCalled();
    }
    const f=fixture();
    f.resolveToken.mockRejectedValue(new Error('internal vault secret 123'));
    await expect(f.readAuthorizedEvent(f.request)).rejects.toMatchObject({
      code:'SOURCE_CREDENTIAL_UNAVAILABLE',
    });
  });

  test('proxy must echo exact tenant, connector and original source event ID',async()=>{
    for(const changes of [
      {tenantId:'contoso'},{connectorId:'other-source'},{sourceEventId:'another-event'},
    ]){
      const f=fixture({fetchImpl:async()=>response(PAYLOAD,changes)});
      await expect(f.readAuthorizedEvent(f.request))
        .rejects.toMatchObject({code:'SOURCE_RESPONSE_IDENTITY_MISMATCH'});
    }
  });

  test('rejects JSON, compressed responses, 401/429/503, and external redirects',async()=>{
    const inputs=[
      {impl:async()=>response(PAYLOAD,{type:'application/json'}),code:'SOURCE_CONTENT_TYPE_REJECTED'},
      {impl:async()=>response(PAYLOAD,{encoding:'gzip'}),code:'SOURCE_CONTENT_TYPE_REJECTED'},
      {impl:async()=>response(null,{status:401}),code:'SOURCE_HTTP_NOT_ACCEPTED'},
      {impl:async()=>response(null,{status:429}),code:'SOURCE_HTTP_NOT_ACCEPTED'},
      {impl:async()=>response(null,{status:503}),code:'SOURCE_HTTP_NOT_ACCEPTED'},
      {impl:async()=>({status:200,url:'https://evil.example/',headers:response().headers}),code:'SOURCE_REDIRECT_REJECTED'},
    ];
    for(const t of inputs){
      const f=fixture({fetchImpl:t.impl});
      await expect(f.readAuthorizedEvent(f.request))
        .rejects.toMatchObject({code:t.code});
    }
  });

  test('checks content-length and actual stream chunk limit, including forged short lengths',async()=>{
    const a=fixture({fetchImpl:async()=>response(PAYLOAD,{length:3000})});
    await expect(a.readAuthorizedEvent(a.request))
      .rejects.toMatchObject({code:'SOURCE_BODY_OVERSIZE'});
    const large=Buffer.alloc(2400);
    const b=fixture({fetchImpl:async()=>response(large)});
    await expect(b.readAuthorizedEvent(b.request))
      .rejects.toMatchObject({code:'SOURCE_BODY_OVERSIZE'});
  });

  test('missing and empty byte streams deny review',async()=>{
    for(const impl of [
      async()=>response(Buffer.alloc(0)),
      async()=>({status:200,headers:response().headers,body:null}),
    ]){
      const f=fixture({fetchImpl:impl});
      await expect(f.readAuthorizedEvent(f.request)).rejects.toMatchObject({
        code:expect.stringMatching(/^SOURCE_/),
      });
    }
  });

  test('network errors and provider exceptions return redacted errors',async()=>{
    const f=fixture({fetchImpl:async()=>{throw Error('secret provider DNS/auth headers');}});
    let error;
    try {await f.readAuthorizedEvent(f.request);}catch(e){error=e;}
    expect(error.code).toBe('SOURCE_FETCH_UNAVAILABLE');
    expect(error.message).not.toContain('secret');
  });

  test('hung fetch resolves to timeout rather than accepted evidence',async()=>{
    const f=fixture({fetchImpl:async()=>new Promise(()=>{})});
    await expect(f.readAuthorizedEvent(f.request))
      .rejects.toMatchObject({code:'SOURCE_FETCH_TIMEOUT'});
  });

  test('caller-aborted requests deny before any credential retrieval',async()=>{
    const f=fixture();
    const controller=new AbortController();
    controller.abort();
    await expect(f.readAuthorizedEvent({...f.request,signal:controller.signal}))
      .rejects.toMatchObject({code:'SOURCE_FETCH_ABORTED'});
    expect(f.resolveToken).not.toHaveBeenCalled();
  });

  test('client cannot mutate original configured endpoint after construction',async()=>{
    const source={...BINDING};
    const f=fixture({bindings:[source]});
    source.endpoint='https://evil.example/v1/events';
    await f.readAuthorizedEvent(f.request);
    expect(f.fetcher.mock.calls[0][0]).toMatch(/^https:\/\/evidence\.example\/v1\/events\?/);
  });
});
