'use strict';

const {generateKeyPairSync,createSign} = require('node:crypto');
const {createSocOidcVerifier,SocOidcError} = require('../soc-oidc-verifier');

const URL = 'https://issuer.example';
const AUDIENCE = 'sentinel-apex-soc';
const KID = 'rsa-key-2026';
const EPOCH = 1761060000;
const {publicKey,privateKey} = generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:0x10001});
const JWK = {...publicKey.export({format:'jwk'}),kid:KID,alg:'RS256',use:'sig',key_ops:['verify']};
const b64 = value => Buffer.from(JSON.stringify(value),'utf8').toString('base64url');

function signed(payload = {}, header = {}, key = privateKey) {
  const h = b64({alg:'RS256',typ:'at+jwt',kid:KID,...header});
  const p = b64({
    iss:URL,sub:'analyst-001',aud:AUDIENCE,exp:EPOCH+600,iat:EPOCH-30,
    jti:'unique-token-1234567890',amr:['pwd','mfa'],...payload,
  });
  const sig=createSign('RSA-SHA256').update(h+'.'+p).end().sign(key).toString('base64url');
  return h+'.'+p+'.'+sig;
}
function harness(opts = {}) {
  const response = opts.response === undefined ? {keys:[JWK]} : opts.response;
  const fetcher = jest.fn(async () => ({
    ok:true,headers:{get:() => null},text:async () => JSON.stringify(response),
  }));
  const checkRevocation = jest.fn(async () => true);
  const verifier = createSocOidcVerifier({
    issuer:URL,audience:AUDIENCE,jwksUrl:URL+'/.well-known/jwks.json',
    fetcher,checkRevocation,now:()=>EPOCH*1000,...opts,
  });
  return {verifier,fetcher,checkRevocation};
}

test('requires pinned HTTPS provider settings and revocation policy',() => {
  expect(() => createSocOidcVerifier({
    issuer:URL,audience:AUDIENCE,jwksUrl:URL+'/keys',
  })).toThrow('OIDC_CONFIGURATION');
  expect(() => createSocOidcVerifier({
    issuer:'http://idp.example',audience:AUDIENCE,jwksUrl:'http://idp.example/keys',
    checkRevocation:async()=>true,
  })).toThrow('OIDC_CONFIGURATION');
  expect(() => createSocOidcVerifier({
    issuer:URL,audience:AUDIENCE,jwksUrl:'https://evil.example/keys',
    checkRevocation:async()=>true,
  })).toThrow('OIDC_CONFIGURATION');
});

test('genuine RS256 signature + exact issuer/audience/MFA + active revocation returns verified identity',async () => {
  const h=harness();
  const identity=await h.verifier(signed());
  expect(identity).toEqual({verified:true,issuer:URL,subject:'analyst-001'});
  expect(Object.isFrozen(identity)).toBe(true);
  expect(h.checkRevocation).toHaveBeenCalledWith(expect.objectContaining({jti:'unique-token-1234567890'}));
  const [url,request]=h.fetcher.mock.calls[0];
  expect(url).toBe(URL+'/.well-known/jwks.json');
  expect(request.redirect).toBe('error');
  expect(request.cache).toBe('no-store');
});

test('caches a pinned JWKS for repeated valid tokens',async () => {
  const h=harness();
  await h.verifier(signed({jti:'unique-token-1234567891'}));
  await h.verifier(signed({jti:'unique-token-1234567892'}));
  expect(h.fetcher).toHaveBeenCalledTimes(1);
  expect(h.checkRevocation).toHaveBeenCalledTimes(2);
});

test('tampered signed payload is rejected even with trusted signing key',async () => {
  const h=harness();
  const token=signed();
  const bits=token.split('.');
  bits[1]=b64({
    iss:URL,sub:'admin',aud:AUDIENCE,exp:EPOCH+600,iat:EPOCH-30,
    jti:'unique-token-1234567890',amr:['mfa'],
  });
  await expect(h.verifier(bits.join('.'))).rejects.toMatchObject({code:'JWT_SIGNATURE'});
  expect(h.checkRevocation).not.toHaveBeenCalled();
});

test.each([
  [{iss:'https://wrong.example'},'JWT_CLAIMS'],
  [{aud:'different-service'},'JWT_CLAIMS'],
  [{aud:[AUDIENCE,'other-service']},'JWT_CLAIMS'],
  [{aud:[AUDIENCE,'other-service'],azp:'wrong-service'},'JWT_CLAIMS'],
  [{exp:EPOCH-1},'JWT_EXPIRED_OR_INVALID_TIME'],
  [{iat:EPOCH+600},'JWT_EXPIRED_OR_INVALID_TIME'],
  [{iat:EPOCH-4000},'JWT_EXPIRED_OR_INVALID_TIME'],
  [{nbf:EPOCH+600},'JWT_EXPIRED_OR_INVALID_TIME'],
  [{amr:['pwd']},'JWT_ASSURANCE'],
  [{jti:null},'JWT_ASSURANCE'],
])('rejects invalid signed claims %j',async (changes,code) => {
  const h=harness();
  await expect(h.verifier(signed(changes))).rejects.toMatchObject({code});
});

test('allows multi-audience only when signed azp equals configured recipient',async () => {
  const h=harness();
  expect(await h.verifier(signed({aud:[AUDIENCE,'other-service'],azp:AUDIENCE})))
    .toMatchObject({verified:true});
});

test.each([
  [{alg:'none'},'JWT_HEADER'],
  [{alg:'HS256'},'JWT_HEADER'],
  [{typ:'JWT'},'JWT_HEADER'],
  [{jku:'https://evil.example/keys'},'JWT_HEADER'],
  [{x5u:'https://evil.example/certificate'},'JWT_HEADER'],
  [{jwk:JWK},'JWT_HEADER'],
  [{crit:['exp']},'JWT_HEADER'],
])('refuses algorithm confusion, token-type and remote-key JOSE headers',async (header,code) => {
  const h=harness();
  await expect(h.verifier(signed({},header))).rejects.toMatchObject({code});
  expect(h.fetcher).not.toHaveBeenCalled();
});

test('wrong signing key and unknown key ID are not accepted',async () => {
  const h=harness();
  const other = generateKeyPairSync('rsa',{modulusLength:2048});
  await expect(h.verifier(signed({}, {}, other.privateKey))).rejects.toMatchObject({code:'JWT_SIGNATURE'});
  await expect(h.verifier(signed({}, {kid:'untrusted-id'}))).rejects.toMatchObject({code:'JWKS_KEY'});
});

test('duplicate matching keys and malformed JWKS reject rather than choosing arbitrarily',async () => {
  await expect(harness({response:{keys:[JWK,JWK]}}).verifier(signed()))
    .rejects.toMatchObject({code:'JWKS_KEY'});
  await expect(harness({response:{keys:[]}}).verifier(signed()))
    .rejects.toMatchObject({code:'JWKS_INVALID'});
});

test('weak RSA key under 2048 bits rejected before cryptographic import',async () => {
  const short = generateKeyPairSync('rsa',{modulusLength:1024});
  const weakJwk={...short.publicKey.export({format:'jwk'}),kid:KID,alg:'RS256',use:'sig'};
  const h=harness({response:{keys:[weakJwk]}});
  await expect(h.verifier(signed({}, {}, short.privateKey))).rejects.toMatchObject({code:'JWKS_KEY'});
});

test('revocation unavailable fails closed even with a valid signature',async () => {
  const h=harness();
  h.checkRevocation.mockRejectedValue(new Error('backend down'));
  await expect(h.verifier(signed())).rejects.toMatchObject({code:'REVOCATION_UNAVAILABLE'});
  h.checkRevocation.mockResolvedValue(false);
  await expect(h.verifier(signed())).rejects.toMatchObject({code:'JWT_REVOKED'});
});

test('malformed token rejected before network request',async () => {
  const h=harness();
  await expect(h.verifier('a.b.c')).rejects.toBeInstanceOf(SocOidcError);
  await expect(h.verifier('a'.repeat(9000))).rejects.toMatchObject({code:'JWT_FORMAT'});
  expect(h.fetcher).not.toHaveBeenCalled();
});

test('JWKS fetch failure does not mark token authenticated',async () => {
  const h=harness();
  h.fetcher.mockRejectedValue(new Error('provider offline'));
  await expect(h.verifier(signed())).rejects.toMatchObject({code:'JWKS_UNAVAILABLE'});
  expect(h.checkRevocation).not.toHaveBeenCalled();
});


test('JWKS streamed body enforces the byte ceiling before allocating full response',async () => {
  let reads=0;
  const stream=new ReadableStream({
    pull(controller) {
      reads+=1;
      controller.enqueue(new Uint8Array(50 * 1024));
      if (reads >= 2) controller.close();
    },
  });
  const fetcher=jest.fn(async () => ({
    ok:true,headers:{get:()=>null},body:stream,
  }));
  const h=harness({fetcher});
  await expect(h.verifier(signed())).rejects.toMatchObject({code:'JWKS_OVERSIZE'});
  expect(h.checkRevocation).not.toHaveBeenCalled();
});

test('valid streamed JWKS is accepted with strict UTF-8 decoding',async () => {
  const bytes=Buffer.from(JSON.stringify({keys:[JWK]}),'utf8');
  const stream=new ReadableStream({start(controller){controller.enqueue(bytes);controller.close();}});
  const fetcher=jest.fn(async () => ({ok:true,headers:{get:()=>null},body:stream}));
  const h=harness({fetcher});
  await expect(h.verifier(signed())).resolves.toEqual({
    verified:true,issuer:URL,subject:'analyst-001',
  });
});
