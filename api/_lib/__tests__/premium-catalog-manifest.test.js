'use strict';

// The products in config/premium-catalog.json must be real, human-approved,
// deliverable artifacts. These tests run each manifest entry through the REAL
// certifier and the REAL publishCertifiedReport service (only D1/R2 I/O is
// stubbed), so a product can only be listed if production would accept it.

jest.mock('../premium-commerce-store', () => ({ upsertCertifiedReport: jest.fn() }));
jest.mock('../premium-report-storage', () => ({
  putCertifiedArtifact: jest.fn(), headCertifiedArtifact: jest.fn(),
  putCanonicalEvidence: jest.fn(), headCanonicalEvidence: jest.fn(),
}));

const crypto = require('crypto');
const path = require('path');
const store = require('../premium-commerce-store');
const storage = require('../premium-report-storage');
const service = require('../premium-commerce-service');
const { loadManifest, prepareProduct, prepareAll, publish } = require('../../../scripts/publish-premium-reports');

const manifest = loadManifest();
const sha = t => crypto.createHash('sha256').update(String(t), 'utf8').digest('hex');

beforeEach(() => {
  jest.clearAllMocks();
  process.env.PREMIUM_COMMERCE_CURRENCIES = 'INR';
  storage.putCertifiedArtifact.mockImplementation(async ({ reportId, sha256, renderedText }) => ({
    key: `premium-reports/${reportId}/${sha256}.md`, size: Buffer.byteLength(renderedText, 'utf8'), contentType: 'text/markdown; charset=utf-8',
  }));
  storage.putCanonicalEvidence.mockImplementation(async ({ reportId, reportxJson }) => ({ key: `premium-reports/${reportId}/evidence.json`, size: reportxJson.length }));
  storage.headCanonicalEvidence.mockResolvedValue({ ok: true });
  storage.headCertifiedArtifact.mockResolvedValue({ ok: true });
  store.upsertCertifiedReport.mockImplementation(async row => ({
    report_id: row.reportId, slug: row.slug, title: row.title, report_type: row.reportType, summary: row.summary,
    price_minor: row.priceMinor, currency: row.currency, artifact_filename: row.artifactFilename,
    artifact_size_bytes: row.artifactSizeBytes, published_at: row.publishedAt, updated_at: row.publishedAt,
  }));
});
afterAll(() => { delete process.env.PREMIUM_COMMERCE_CURRENCIES; });

const fs = require('fs');
const os = require('os');

// Customer-facing copy gate (mirrors INTERNAL_COPY in
// reportx-canary/premium_reissue_v2.py). Scoped so legitimate intelligence
// vocabulary ("proof sample", "Mimikatz module", "browser session") passes.
const INTERNAL_COPY = /premium intelligence canary|\bcanar(?:y|ies)\b|this session|checked-in raw files|hand-typed|reportx|GENERIC_DEFENSIVE_READINESS|content_sha256|internal pipeline|test artifact|test-only|fixture|\bstaging\b|demo-only/i;

const readJson = rel => JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', rel), 'utf8'));
// Stand-in for the human step (`cli.py reportx-review approve`), written to a
// temp file so the real file-based path is exercised. Never written to the repo.
function withReview(product, overrides = {}) {
  const text = readJson(product.export).bundle.rendered_text;
  const review = {
    report_id: product.report_id, artifact_sha256: sha(text), reviewer_identity: 'TEST REVIEWER', reviewer_role: 'LEAD ANALYST',
    review_timestamp: '2026-10-01T00:00:00Z', decision: 'APPROVE', review_version: 1, notes: '', is_test_only_fixture: false, ...overrides,
  };
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pir-')), 'review.json');
  fs.writeFileSync(file, JSON.stringify(review));
  return { ...product, review: path.relative(path.join(__dirname, '..', '..', '..'), file) };
}

describe('premium catalog manifest (schema 2: versioned)', () => {
  test('a small, deliberate catalog: 3–5 products, unique SKUs, slugs and report ids, INR, version 2.0', () => {
    expect(manifest.schema_version).toBe(2);
    expect(manifest.products.length).toBeGreaterThanOrEqual(3);
    expect(manifest.products.length).toBeLessThanOrEqual(5);
    for (const key of ['sku', 'slug', 'report_id']) expect(new Set(manifest.products.map(p => p[key])).size).toBe(manifest.products.length);
    expect(manifest.currency).toBe('INR');
    for (const p of manifest.products) {
      expect(p.version).toBe('2.0');
      expect(p.price_minor).toBe(199900); // operator decision 2026-10-01: INR 1,999
      expect(p.supersedes).toMatchObject({ version: '1.0' });
      expect(p.slug).not.toBe(p.supersedes.slug); // slugs are unique in D1 across versions
    }
  });

  test.each(manifest.history.map(p => [p.sku, p]))('v1 %s (live today) still certifies with its genuine human review', (_sku, product) => {
    const r = prepareProduct(product, { ...manifest });
    expect(r.reasons).toEqual([]);
    expect(r.certification.artifactSha256).toBe(product.artifact_sha256);
  });

  test.each(manifest.products.map(p => [p.sku, p]))('v2 %s is NOT publishable until a human review record exists', (_sku, product) => {
    const r = prepareProduct(product, manifest);
    expect(r.ok).toBe(false);
    expect(r.reasons).toContain('REVIEW_UNREADABLE');
  });

  test.each(manifest.products.map(p => [p.sku, p]))('v2 %s: export hash is pinned in the manifest and the gate is 23/23', (_sku, product) => {
    const exported = readJson(product.export);
    expect(sha(exported.bundle.rendered_text)).toBe(product.artifact_sha256);
    expect(exported.bundle.report_id).toBe(product.report_id);
    expect(exported.bundle.review).toBeNull();
    expect(exported.commercial_readiness).toMatchObject({ verdict: 'COMMERCIAL-READY', pass_count: 23, total_count: 23 });
  });

  test.each(manifest.products.map(p => [p.sku, p]))('v2 %s: once approved, certifies and is accepted by the publish service with exactly the reviewed bytes', async (_sku, product) => {
    const r = prepareProduct(withReview(product), manifest);
    expect(r.reasons).toEqual([]);
    expect(r.ok).toBe(true);
    const out = await service.publishCertifiedReport({
      reportxExport: r.body.reportx_export, title: r.body.title, slug: r.body.slug, reportType: r.body.report_type,
      summary: r.body.summary, priceMinor: r.body.price_minor, currency: r.body.currency, filename: r.body.filename,
    });
    expect(out.certification).toBe('PREMIUM_CERTIFIED');
    expect(out.price_minor).toBe(199900);
    const stored = storage.putCertifiedArtifact.mock.calls[0][0];
    expect(stored.sha256).toBe(product.artifact_sha256);
    expect(sha(stored.renderedText)).toBe(product.artifact_sha256);
    // R2 write and R2 verify happen before the catalog row exists.
    const putOrder = storage.putCertifiedArtifact.mock.invocationCallOrder[0];
    const headOrder = storage.headCertifiedArtifact.mock.invocationCallOrder[0];
    const upsertOrder = store.upsertCertifiedReport.mock.invocationCallOrder[0];
    expect(putOrder).toBeLessThan(headOrder);
    expect(headOrder).toBeLessThan(upsertOrder);
  });
});

describe('customer-facing copy gate', () => {
  test.each(manifest.products.map(p => [p.sku, p]))('v2 %s artifact and product metadata carry no internal/canary terminology', (_sku, product) => {
    const text = readJson(product.export).bundle.rendered_text;
    expect(text.match(INTERNAL_COPY)).toBeNull();
    for (const field of ['title', 'summary', 'slug', 'report_id', 'filename']) expect(String(product[field]).match(INTERNAL_COPY)).toBeNull();
    expect(text).toMatch(/^# Sentinel APEX (Ransomware Intelligence Report|Vulnerability Intelligence Assessment) -- /);
    expect(text).toContain('**CYBERDUDEBIVASH SENTINEL APEX INTEL FACTORY** · Premium Intelligence Report · Version 2.0');
    expect(text).toMatch(/Evidence cut-off: \d{4}-\d{2}-\d{2}/);
  });

  test('the gate is effective: every superseded v1 artifact fails it', () => {
    for (const h of manifest.history) expect(readJson(h.export).bundle.rendered_text).toMatch(INTERNAL_COPY);
  });

  test('legitimate intelligence vocabulary is not blocked', () => {
    expect('No proof sample was reviewed; an embedded Mimikatz module; a DNS-rebinding-capable browser session').not.toMatch(INTERNAL_COPY);
  });
});

describe('negative controls: nothing unreviewed or altered can be listed', () => {
  const product = manifest.products[0];

  test('altered report text (one character) fails certification', () => {
    const r = prepareProduct(withReview(product), manifest);
    const tampered = { ...r.body.reportx_export, bundle: { ...r.body.reportx_export.bundle, rendered_text: r.body.reportx_export.bundle.rendered_text + ' ' } };
    const { evaluatePremiumCertification } = require('../premium-report-certification');
    expect(evaluatePremiumCertification(tampered).reasons).toContain('ARTIFACT_HASH_MISMATCH');
  });

  test('a test-only review is refused', () => {
    expect(prepareProduct(withReview(product, { is_test_only_fixture: true }), manifest).reasons).toContain('TEST_ONLY_REVIEW_FORBIDDEN');
  });

  test('a REJECT decision is refused', () => {
    expect(prepareProduct(withReview(product, { decision: 'REJECT' }), manifest).reasons).toContain('REVIEW_NOT_APPROVED');
  });

  test('a review record for a different report is refused', () => {
    const r = prepareProduct({ ...withReview(manifest.products[1]), export: product.export, report_id: product.report_id, artifact_sha256: product.artifact_sha256 }, manifest);
    expect(r.ok).toBe(false);
    expect(r.reasons).toEqual(expect.arrayContaining(['REVIEW_REPORT_ID_MISMATCH', 'ARTIFACT_HASH_MISMATCH']));
  });

  test('an export that is not the pinned artifact is refused even with a matching review', () => {
    const r = prepareProduct({ ...withReview(product), artifact_sha256: 'f'.repeat(64) }, manifest);
    expect(r.reasons).toContain('ARTIFACT_HASH_NOT_PINNED');
  });

  test('the unreviewed flagship export cannot be listed', () => {
    const r = prepareProduct({ ...product, export: 'reportx-canary/exports/cve-2025-62593-ray-flagship-executive-product-export.json' }, manifest);
    expect(r.ok).toBe(false);
  });

  test.each([[0], [-1], [1.5], [100000001]])('price_minor %p is refused', price => {
    expect(prepareProduct({ ...product, price_minor: price }, manifest).reasons).toContain('INVALID_PRICE');
  });

  test('duplicate slugs are refused', () => {
    const dup = { ...manifest, products: [product, { ...manifest.products[1], slug: product.slug }] };
    expect(prepareAll(dup).some(p => p.reasons.includes('DUPLICATE_SLUG'))).toBe(true);
  });
});

describe('publisher transport and activation sequence', () => {
  const approved = () => prepareProduct(withReview(manifest.products[0]), manifest);
  function fakeApi({ liveSha = null, publishOk = true, retireStatus = 200 } = {}) {
    const calls = [];
    let live = liveSha ? { slug: 's', report_id: 'x', artifact_sha256: liveSha } : null;
    const fetchImpl = async (url, opts = {}) => {
      calls.push({ url, opts });
      const reply = (status, body) => ({ ok: status < 400, status, json: async () => body });
      if (url.includes('action=detail')) return live ? reply(200, { success: true, data: { report: live } }) : reply(404, { success: false });
      if (url.includes('publish-certified')) {
        if (!publishOk) return reply(401, { success: false, error: { code: 'UNAUTHORIZED', message: 'bad key' } });
        const body = JSON.parse(opts.body);
        live = { slug: body.slug, report_id: body.reportx_export.bundle.report_id, artifact_sha256: sha(body.reportx_export.bundle.rendered_text) };
        return reply(201, { success: true, data: { report: live } });
      }
      if (url.includes('set-status')) return reply(retireStatus, { success: retireStatus < 400 });
      return reply(500, {});
    };
    return { calls, fetchImpl };
  }

  test('publish -> confirm live hash -> only then retire the superseded v1; key only in a header', async () => {
    const r = approved();
    const { calls, fetchImpl } = fakeApi();
    const report = await publish(r, { base: 'https://blog.example.test', key: 'k-123', fetchImpl });
    const order = calls.map(c => (c.url.match(/action=([a-z-]+)/) || [])[1]);
    expect(order).toEqual(['detail', 'publish-certified', 'detail', 'set-status']);
    expect(JSON.parse(calls[3].opts.body)).toEqual({ report_id: manifest.products[0].supersedes.report_id, status: 'RETIRED' });
    expect(report.retired).toBe(manifest.products[0].supersedes.report_id);
    for (const c of calls.filter(c => c.opts.method === 'POST')) {
      expect(c.opts.headers['X-Analyst-Key']).toBe('k-123');
      expect(c.opts.body).not.toContain('k-123');
    }
  });

  test('an unchanged artifact is not re-uploaded', async () => {
    const r = approved();
    const { calls, fetchImpl } = fakeApi({ liveSha: manifest.products[0].artifact_sha256 });
    const report = await publish(r, { base: 'https://blog.example.test', key: 'k', fetchImpl });
    expect(report.unchanged).toBe(true);
    expect(calls.some(c => c.url.includes('publish-certified'))).toBe(false);
  });

  test('a rejected publish stops before touching the superseded product', async () => {
    const r = approved();
    const { calls, fetchImpl } = fakeApi({ publishOk: false });
    await expect(publish(r, { base: 'https://blog.example.test', key: 'x', fetchImpl })).rejects.toThrow(/HTTP 401 UNAUTHORIZED/);
    expect(calls.some(c => c.url.includes('set-status'))).toBe(false);
  });
});

describe('public preview (premium-previews.json)', () => {
  const previews = readJson('premium-previews.json').reports;
  const { build } = require('../../../scripts/build-premium-previews');

  test('is up to date with the manifest and exports (re-run scripts/build-premium-previews.js)', () => {
    expect(build().reports).toEqual(previews);
  });

  test.each(manifest.products.map(p => [p.sku, p]))('%s preview reveals no paid content', (_sku, product) => {
    const p = previews[product.report_id];
    expect(p).toBeTruthy();
    const json = JSON.stringify(p);
    expect(json).not.toMatch(/detection:|logsource|condition:|selection_|https?:\/\/|\b[a-f0-9]{64}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    expect(json.match(INTERNAL_COPY)).toBeNull();
    expect(p.stats.detection_rules.every(r => ['REFERENCE', 'SYNTAX_VALIDATED', 'TESTED', 'LAB_VALIDATED', 'PRODUCTION_VALIDATED', 'DRAFT'].includes(r.maturity))).toBe(true);
  });
});
