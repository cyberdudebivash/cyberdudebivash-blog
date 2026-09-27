'use strict';

/**
 * Cloudflare-native premium intelligence artifact storage.
 *
 * No S3/AWS compatibility shim and no plaintext credential path exists here:
 * production must provide the `PREMIUM_REPORTS` R2 binding declared in
 * wrangler.jsonc. Tests may inject an in-memory bucket through setR2Binding().
 */
let bucket = null;

function setR2Binding(binding) {
  bucket = binding || null;
}

function isConfigured() {
  return Boolean(bucket && typeof bucket.put === 'function' && typeof bucket.get === 'function');
}

function safePart(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 120) || 'report';
}

function buildArtifactKey(reportId, sha256) {
  return `premium-reports/${safePart(reportId)}/${String(sha256).toLowerCase()}.md`;
}

function buildEvidenceKey(reportId, renderedSha256) {
  return `premium-reports/${safePart(reportId)}/${String(renderedSha256).toLowerCase()}.reportx.json`;
}

async function putCertifiedArtifact({ reportId, sha256, renderedText, filename }) {
  if (!isConfigured()) throw new Error('Premium report R2 binding not configured');
  const key = buildArtifactKey(reportId, sha256);
  const bytes = new TextEncoder().encode(String(renderedText));
  await bucket.put(key, bytes, {
    httpMetadata: {
      contentType: 'text/markdown; charset=utf-8',
      contentDisposition: `attachment; filename="${safePart(filename || reportId)}.md"`,
    },
    customMetadata: {
      report_id: String(reportId),
      sha256: String(sha256).toLowerCase(),
      artifact_kind: 'reportx_rendered_text',
    },
  });
  return { key, size: bytes.byteLength, contentType: 'text/markdown; charset=utf-8' };
}

async function putCanonicalEvidence({ reportId, renderedSha256, evidenceSha256, reportxJson }) {
  if (!isConfigured()) throw new Error('Premium report R2 binding not configured');
  const key = buildEvidenceKey(reportId, renderedSha256);
  const bytes = new TextEncoder().encode(String(reportxJson));
  await bucket.put(key, bytes, {
    httpMetadata: { contentType: 'application/json; charset=utf-8' },
    customMetadata: {
      report_id: String(reportId),
      rendered_sha256: String(renderedSha256).toLowerCase(),
      evidence_sha256: String(evidenceSha256).toLowerCase(),
      artifact_kind: 'reportx_canonical_evidence',
    },
  });
  return { key, size: bytes.byteLength, contentType: 'application/json; charset=utf-8' };
}

async function headCanonicalEvidence({ key, reportId, renderedSha256, evidenceSha256, expectedSize }) {
  if (!isConfigured()) return { ok: false, reason: 'R2_NOT_CONFIGURED' };
  const head = await bucket.head(key);
  if (!head) return { ok: false, reason: 'EVIDENCE_NOT_FOUND' };
  const metadata = head.customMetadata || {};
  if (String(metadata.artifact_kind || '') !== 'reportx_canonical_evidence') return { ok: false, reason: 'EVIDENCE_KIND_MISMATCH' };
  if (String(metadata.report_id || '') !== String(reportId)) return { ok: false, reason: 'EVIDENCE_REPORT_ID_MISMATCH' };
  if (String(metadata.rendered_sha256 || '').toLowerCase() !== String(renderedSha256).toLowerCase()) return { ok: false, reason: 'EVIDENCE_RENDERED_HASH_MISMATCH' };
  if (evidenceSha256 && String(metadata.evidence_sha256 || '').toLowerCase() !== String(evidenceSha256).toLowerCase()) return { ok: false, reason: 'EVIDENCE_HASH_METADATA_MISMATCH' };
  if (Number.isFinite(Number(expectedSize)) && Number(expectedSize) > 0 && Number(head.size) !== Number(expectedSize)) return { ok: false, reason: 'EVIDENCE_SIZE_MISMATCH' };
  return { ok: true, size: Number(head.size || 0), evidenceSha256: String(metadata.evidence_sha256 || '').toLowerCase(), etag: head.etag || '' };
}

async function getCanonicalEvidence(key) {
  if (!isConfigured()) throw new Error('Premium report R2 binding not configured');
  return bucket.get(key);
}

async function headCertifiedArtifact({ key, reportId, sha256, expectedSize }) {
  if (!isConfigured()) return { ok: false, reason: 'R2_NOT_CONFIGURED' };
  const head = await bucket.head(key);
  if (!head) return { ok: false, reason: 'ARTIFACT_NOT_FOUND' };
  const metadata = head.customMetadata || {};
  if (String(metadata.report_id || '') !== String(reportId)) {
    return { ok: false, reason: 'ARTIFACT_REPORT_ID_MISMATCH' };
  }
  if (String(metadata.sha256 || '').toLowerCase() !== String(sha256).toLowerCase()) {
    return { ok: false, reason: 'ARTIFACT_HASH_METADATA_MISMATCH' };
  }
  if (Number.isFinite(Number(expectedSize)) && Number(expectedSize) > 0 && Number(head.size) !== Number(expectedSize)) {
    return { ok: false, reason: 'ARTIFACT_SIZE_MISMATCH' };
  }
  return { ok: true, size: Number(head.size || 0), etag: head.etag || '' };
}

async function getCertifiedArtifact(key) {
  if (!isConfigured()) throw new Error('Premium report R2 binding not configured');
  return bucket.get(key);
}

module.exports = {
  setR2Binding,
  isConfigured,
  buildArtifactKey,
  buildEvidenceKey,
  putCertifiedArtifact,
  putCanonicalEvidence,
  headCanonicalEvidence,
  getCanonicalEvidence,
  headCertifiedArtifact,
  getCertifiedArtifact,
};
