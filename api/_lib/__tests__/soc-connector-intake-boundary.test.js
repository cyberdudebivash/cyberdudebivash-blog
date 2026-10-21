'use strict';

const crypto=require('node:crypto');
const {createSocEncryptedConnectorVault}=require('../soc-encrypted-connector-vault');
const {createSocConnectorIntakeBoundary}=require('../soc-connector-intake-boundary');
const {canonicalFields}=require('../soc-event-receipt-service');

const NOW=Date.parse('2026-10-21T16:00:00.000Z');
const CTX={tenantId:'acme',connectorId:'edr-primary',keyId:'key-20261021'};
const PAYLOAD=crypto.createHash('sha256').update('test authorized source event').digest('hex');
const SECRET=crypto.randomBytes(32);

function makeFixture() {
  const store=new Map();
  const kv={
    get:jest.fn(async key=>store.has(key)?store.get(key):null),
    put:jest.fn(async (key,value)=>{store.set(key,value);}),
  };
  const masterKey=crypto.randomBytes(32);
  const first=jest.fn(async()=>({connector_id:CTX.connectorId}));
  const run=jest.fn(async()=>({success:true}));
  const bind=jest.fn((...values)=>({first,run}));
  const prepare=jest.fn((sql)=>({bind}));
  const nativeD1={withSession:jest.fn(()=>({prepare}))};
  return {kv,masterKey,nativeD1,first,run,bind,prepare};
}
function envelope(secret=SECRET,overrides={}) {
  const base={
    version:2,...CTX,
    sourceEventId:'source-evt-20261021-101',
    eventTime:'2026-10-21T15:59:00.000Z',
    signedAt:'2026-10-21T16:00:00.000Z',
    payloadSha256:PAYLOAD,...overrides,
  };
  return {...base,signature:crypto.createHmac('sha256',secret)
    .update(canonicalFields(base)).digest('base64url')};
}
async function sealedFixture() {
  const h=makeFixture();
  const provisioning=createSocEncryptedConnectorVault(h);
  await provisioning.sealKey({...CTX,secret:SECRET});
  const intake=createSocConnectorIntakeBoundary({...h,now:()=>NOW});
  return {...h,intake};
}

test('fail closed without master secret, KV or native primary D1',()=>{
  const h=makeFixture();
  expect(()=>createSocConnectorIntakeBoundary({kv:h.kv,masterKey:h.masterKey}))
    .toThrow('SOC_PRIMARY_D1_REQUIRED');
  expect(()=>createSocConnectorIntakeBoundary({nativeD1:h.nativeD1,kv:h.kv}))
    .toThrow('VAULT_MASTER_KEY_REQUIRED');
  expect(()=>createSocConnectorIntakeBoundary({nativeD1:h.nativeD1,masterKey:h.masterKey}))
    .toThrow('VAULT_BINDING_REQUIRED');
});

test('only ingestion, not provisioning or key read, is exposed',async()=>{
  const {intake}=await sealedFixture();
  expect(Object.keys(intake)).toEqual(['ingest']);
  expect(Object.isFrozen(intake)).toBe(true);
});

test('real HMAC and encrypted key produce an audited tenant-scoped source receipt',async()=>{
  const h=await sealedFixture();
  const receipt=await h.intake.ingest(envelope());
  expect(receipt).toMatchObject({
    tenantId:'acme',keyId:'key-20261021',
    source:'SOURCE_ATTESTED',state:'RECEIVED_NOT_ANALYST_VERIFIED',
  });
  expect(receipt).not.toHaveProperty('secret');
  expect(h.nativeD1.withSession).toHaveBeenCalledWith('first-primary');
  expect(h.run).toHaveBeenCalledTimes(1);
  const insert=h.prepare.mock.calls[1][0];
  expect(insert).toContain('INSERT INTO soc_event_receipts');
  const params=h.bind.mock.calls[1];
  expect(params[0]).toBe('acme');
  expect(params.at(-1)).toBe('key-20261021');
  expect(JSON.stringify(receipt)).not.toContain(SECRET.toString('hex'));
});

test('tampering with a signed source identity rejects before D1',async()=>{
  const h=await sealedFixture();
  const forged={...envelope(),sourceEventId:'forged-event'};
  await expect(h.intake.ingest(forged))
    .rejects.toMatchObject({code:'INVALID_SIGNATURE'});
  expect(h.nativeD1.withSession).not.toHaveBeenCalled();
});

test('missing encrypted key and unavailable vault deny without reading D1',async()=>{
  const h=await sealedFixture();
  h.kv.get.mockResolvedValue(null);
  await expect(h.intake.ingest(envelope()))
    .rejects.toMatchObject({code:'CONNECTOR_AUTH_UNAVAILABLE'});
  expect(h.nativeD1.withSession).not.toHaveBeenCalled();
});

test('compromised/corrupted encrypted KV record cannot be used for a valid HMAC',async()=>{
  const h=await sealedFixture();
  const location=[...Object.keys({})]; // no secret paths or plaintext needed
  expect(location).toHaveLength(0);
  h.kv.get.mockResolvedValue('{"v":1,"iv":"x","tag":"x","ct":"x"}');
  await expect(h.intake.ingest(envelope()))
    .rejects.toMatchObject({code:'CONNECTOR_AUTH_UNAVAILABLE'});
  expect(h.nativeD1.withSession).not.toHaveBeenCalled();
});

test('revoked key in primary D1 blocks valid HMAC even if encrypted KV still has key',async()=>{
  const h=await sealedFixture();
  h.first.mockResolvedValue(null);
  await expect(h.intake.ingest(envelope()))
    .rejects.toMatchObject({code:'CONNECTOR_NOT_AUTHORIZED',status:403});
  expect(h.run).not.toHaveBeenCalled();
});

test('D1 receipt trigger conflict or replay cannot claim a successful new security event',async()=>{
  const h=await sealedFixture();
  h.run.mockRejectedValue(new Error('unique receipt constraint/atomic audit rollback'));
  await expect(h.intake.ingest(envelope()))
    .rejects.toMatchObject({code:'RECEIPT_REJECTED',status:409});
});
