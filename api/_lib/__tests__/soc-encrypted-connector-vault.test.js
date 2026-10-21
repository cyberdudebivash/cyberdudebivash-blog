'use strict';

const crypto=require('node:crypto');
const {createSocEncryptedConnectorVault}=require('../soc-encrypted-connector-vault');

function fixture({masterKey=crypto.randomBytes(32)}={}) {
  const values=new Map();
  const kv={
    get:jest.fn(async key=>values.has(key)?values.get(key):null),
    put:jest.fn(async (key,value)=>{values.set(key,value);}),
  };
  const vault=createSocEncryptedConnectorVault({kv,masterKey});
  const context={tenantId:'acme',connectorId:'edr-main',keyId:'key-20261021'};
  const secret=crypto.randomBytes(32);
  return {vault,values,kv,context,secret,masterKey};
}

describe('SOC sealed HMAC signing-key vault',()=>{
  test('requires a server-provided KV binding and 32-byte cryptographic master secret',()=>{
    expect(()=>createSocEncryptedConnectorVault()).toThrow('VAULT_BINDING_REQUIRED');
    expect(()=>createSocEncryptedConnectorVault({kv:{get:async()=>null,put:async()=>{}},masterKey:'plaintext-passphrase'}))
      .toThrow('VAULT_MASTER_KEY_REQUIRED');
    expect(()=>createSocEncryptedConnectorVault({kv:{get:async()=>null,put:async()=>{}},masterKey:Buffer.alloc(16)}))
      .toThrow('VAULT_MASTER_KEY_REQUIRED');
  });

  test('encrypts real key material: no plaintext in KV, no secret in result',async()=>{
    const f=fixture();
    const result=await f.vault.sealKey({...f.context,secret:f.secret});
    expect(result).toEqual({...f.context,sealed:true});
    expect(JSON.stringify(result)).not.toContain(f.secret.toString('base64url'));
    const [key,record]=f.kv.put.mock.calls[0];
    expect(key).toBe('soc:hmac:v1:acme:edr-main:key-20261021');
    expect(record).not.toContain(f.secret.toString('hex'));
    expect(record).not.toContain(f.secret.toString('base64'));
    const stored=JSON.parse(record);
    expect(stored).toMatchObject({v:1});
    expect(Buffer.from(stored.iv,'base64url')).toHaveLength(12);
    expect(Buffer.from(stored.tag,'base64url')).toHaveLength(16);
    expect(Buffer.from(stored.ct,'base64url')).toHaveLength(32);
    const resolved=await f.vault.resolveSecret('acme','edr-main','key-20261021');
    expect(resolved).toEqual(f.secret);
  });

  test('does not overwrite an existing sealed key ID',async()=>{
    const f=fixture();
    await f.vault.sealKey({...f.context,secret:f.secret});
    await expect(f.vault.sealKey({...f.context,secret:crypto.randomBytes(32)}))
      .rejects.toMatchObject({code:'KEY_ALREADY_SEALED'});
    expect(f.kv.put).toHaveBeenCalledTimes(1);
  });

  test('tenant/connector/key identity is authenticated and cannot cross-decrypt',async()=>{
    const f=fixture();
    await f.vault.sealKey({...f.context,secret:f.secret});
    await expect(f.vault.resolveSecret('contoso','edr-main','key-20261021'))
      .rejects.toMatchObject({code:'KEY_NOT_FOUND'});
    await expect(f.vault.resolveSecret('acme','other-edr','key-20261021'))
      .rejects.toMatchObject({code:'KEY_NOT_FOUND'});
    await expect(f.vault.resolveSecret('acme','edr-main','new-key-22'))
      .rejects.toMatchObject({code:'KEY_NOT_FOUND'});

    const original=f.values.get('soc:hmac:v1:acme:edr-main:key-20261021');
    f.values.set('soc:hmac:v1:contoso:edr-main:key-20261021',original);
    await expect(f.vault.resolveSecret('contoso','edr-main','key-20261021'))
      .rejects.toMatchObject({code:'KEY_AUTHENTICATION_FAILED'});
  });

  test('wrong master key cannot decode stored ciphertext',async()=>{
    const f=fixture();
    await f.vault.sealKey({...f.context,secret:f.secret});
    const second=createSocEncryptedConnectorVault({kv:f.kv,masterKey:crypto.randomBytes(32)});
    await expect(second.resolveSecret('acme','edr-main','key-20261021'))
      .rejects.toMatchObject({code:'KEY_AUTHENTICATION_FAILED'});
  });

  test.each(['iv','ct','tag'])('tampered %s is rejected by length/authentication',async field=>{
    const f=fixture();
    await f.vault.sealKey({...f.context,secret:f.secret});
    const loc=[...f.values.keys()][0];
    const record=JSON.parse(f.values.get(loc));
    const bytes=Buffer.from(record[field],'base64url');
    bytes[0]^=1;
    record[field]=bytes.toString('base64url');
    f.values.set(loc,JSON.stringify(record));
    await expect(f.vault.resolveSecret('acme','edr-main','key-20261021'))
      .rejects.toMatchObject({code:'KEY_AUTHENTICATION_FAILED'});
  });

  test('invalid record schema and oversize payload reject before decryption',async()=>{
    const f=fixture();
    await f.vault.sealKey({...f.context,secret:f.secret});
    const loc=[...f.values.keys()][0];
    f.values.set(loc,'{"v":1,"iv":"x","ct":"x","tag":"x","secret":"plaintext"}');
    await expect(f.vault.resolveSecret('acme','edr-main','key-20261021'))
      .rejects.toMatchObject({code:'CIPHERTEXT_INVALID'});
    f.values.set(loc,'x'.repeat(3000));
    await expect(f.vault.resolveSecret('acme','edr-main','key-20261021'))
      .rejects.toMatchObject({code:'CIPHERTEXT_INVALID'});
  });

  test('invalid key names, path injection and weak signing material are denied',async()=>{
    const f=fixture();
    for(const k of ['../../../key','https://evil.example/key','..','UPPERCASE-KEY','',':']) {
      await expect(f.vault.resolveSecret('acme','edr-main',k))
        .rejects.toMatchObject({code:'INVALID_KEY_IDENTITY'});
    }
    await expect(f.vault.sealKey({...f.context,secret:Buffer.alloc(12)}))
      .rejects.toMatchObject({code:'SIGNING_SECRET_REQUIRED'});
    expect(f.kv.put).not.toHaveBeenCalled();
  });

  test('backend read/write outages fail closed, without propagating secret provider errors',async()=>{
    const f=fixture();
    f.kv.get.mockRejectedValue(new Error('sensitive provider credentials'));
    await expect(f.vault.resolveSecret('acme','edr-main','key-20261021'))
      .rejects.toMatchObject({code:'VAULT_UNAVAILABLE'});
    await expect(f.vault.sealKey({...f.context,secret:f.secret}))
      .rejects.toMatchObject({code:'VAULT_UNAVAILABLE'});
    f.kv.get.mockResolvedValue(null);
    f.kv.put.mockRejectedValue(new Error('internal storage details'));
    await expect(f.vault.sealKey({...f.context,secret:f.secret}))
      .rejects.toMatchObject({code:'VAULT_UNAVAILABLE'});
  });

  test('master secret is copied at construction and mutations to caller buffer do not alter derived key',async()=>{
    const original=crypto.randomBytes(32);
    const f=fixture({masterKey:original});
    await f.vault.sealKey({...f.context,secret:f.secret});
    original.fill(0);
    const resolved=await f.vault.resolveSecret('acme','edr-main','key-20261021');
    expect(resolved).toEqual(f.secret);
  });

  test('two key versions have independent ciphertext and authenticated contexts',async()=>{
    const f=fixture();
    await f.vault.sealKey({...f.context,secret:f.secret});
    await f.vault.sealKey({...f.context,keyId:'key-20261022',secret:crypto.randomBytes(32)});
    const old=await f.vault.resolveSecret('acme','edr-main','key-20261021');
    const next=await f.vault.resolveSecret('acme','edr-main','key-20261022');
    expect(old).toEqual(f.secret);
    expect(next).not.toEqual(old);
  });
});
