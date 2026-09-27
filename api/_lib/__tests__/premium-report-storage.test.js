'use strict';

const storage = require('../premium-report-storage');

function fakeBucket() {
  const map = new Map();
  return {
    async put(key, body, opts = {}) {
      const bytes = body instanceof Uint8Array ? body : new Uint8Array(body);
      map.set(key, { bytes, size: bytes.byteLength, customMetadata: opts.customMetadata || {}, httpMetadata: opts.httpMetadata || {}, etag: 'etag-1' });
    },
    async head(key) {
      const o = map.get(key);
      return o ? { size: o.size, customMetadata: o.customMetadata, httpMetadata: o.httpMetadata, etag: o.etag } : null;
    },
    async get(key) {
      const o = map.get(key);
      if (!o) return null;
      return { arrayBuffer: async () => o.bytes.slice().buffer, customMetadata: o.customMetadata, size: o.size };
    },
    _map: map,
  };
}

afterEach(() => storage.setR2Binding(null));

test('fails closed when no Cloudflare R2 binding exists', async () => {
  expect(storage.isConfigured()).toBe(false);
  await expect(storage.putCertifiedArtifact({reportId:'R1',sha256:'a'.repeat(64),renderedText:'x'})).rejects.toThrow(/R2 binding/);
  await expect(storage.headCertifiedArtifact({key:'x',reportId:'R1',sha256:'a'.repeat(64)})).resolves.toEqual({ok:false,reason:'R2_NOT_CONFIGURED'});
});

test('stores private artifact under content-addressed key with integrity metadata', async () => {
  const bucket=fakeBucket();storage.setR2Binding(bucket);
  const stored=await storage.putCertifiedArtifact({reportId:'RPT 1',sha256:'a'.repeat(64),renderedText:'# report',filename:'Premium Malware'});
  expect(stored.key).toBe(`premium-reports/rpt-1/${'a'.repeat(64)}.md`);
  const head=await storage.headCertifiedArtifact({key:stored.key,reportId:'RPT 1',sha256:'a'.repeat(64),expectedSize:stored.size});
  expect(head.ok).toBe(true);
});

test('rejects report/hash/size mismatch during sellability or fulfillment check', async () => {
  const bucket=fakeBucket();storage.setR2Binding(bucket);
  const stored=await storage.putCertifiedArtifact({reportId:'R1',sha256:'a'.repeat(64),renderedText:'abcd'});
  await expect(storage.headCertifiedArtifact({key:stored.key,reportId:'R2',sha256:'a'.repeat(64),expectedSize:4})).resolves.toMatchObject({ok:false,reason:'ARTIFACT_REPORT_ID_MISMATCH'});
  await expect(storage.headCertifiedArtifact({key:stored.key,reportId:'R1',sha256:'b'.repeat(64),expectedSize:4})).resolves.toMatchObject({ok:false,reason:'ARTIFACT_HASH_METADATA_MISMATCH'});
  await expect(storage.headCertifiedArtifact({key:stored.key,reportId:'R1',sha256:'a'.repeat(64),expectedSize:99})).resolves.toMatchObject({ok:false,reason:'ARTIFACT_SIZE_MISMATCH'});
});


test('stores canonical ReportX evidence bound to reviewed rendered artifact hash', async () => {
  const bucket=fakeBucket();storage.setR2Binding(bucket);
  const renderedSha='a'.repeat(64), evidenceSha='b'.repeat(64);
  const stored=await storage.putCanonicalEvidence({reportId:'RPT 1',renderedSha256:renderedSha,evidenceSha256:evidenceSha,reportxJson:'{"bundle":{}}'});
  expect(stored.key).toBe(`premium-reports/rpt-1/${renderedSha}.reportx.json`);
  await expect(storage.headCanonicalEvidence({key:stored.key,reportId:'RPT 1',renderedSha256:renderedSha,evidenceSha256:evidenceSha,expectedSize:stored.size}))
    .resolves.toMatchObject({ok:true,evidenceSha256:evidenceSha});
});

test('canonical evidence verification fails closed on rendered hash or evidence hash mismatch', async () => {
  const bucket=fakeBucket();storage.setR2Binding(bucket);
  const stored=await storage.putCanonicalEvidence({reportId:'R1',renderedSha256:'a'.repeat(64),evidenceSha256:'b'.repeat(64),reportxJson:'{}'});
  await expect(storage.headCanonicalEvidence({key:stored.key,reportId:'R1',renderedSha256:'c'.repeat(64)})).resolves.toMatchObject({ok:false,reason:'EVIDENCE_RENDERED_HASH_MISMATCH'});
  await expect(storage.headCanonicalEvidence({key:stored.key,reportId:'R1',renderedSha256:'a'.repeat(64),evidenceSha256:'d'.repeat(64)})).resolves.toMatchObject({ok:false,reason:'EVIDENCE_HASH_METADATA_MISMATCH'});
});
