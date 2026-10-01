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

describe('premium catalog manifest', () => {
  test('a small, deliberate catalog: 3–5 products, unique SKUs and slugs, INR', () => {
    expect(manifest.products.length).toBeGreaterThanOrEqual(3);
    expect(manifest.products.length).toBeLessThanOrEqual(5);
    expect(new Set(manifest.products.map(p => p.sku)).size).toBe(manifest.products.length);
    expect(new Set(manifest.products.map(p => p.slug)).size).toBe(manifest.products.length);
    expect(manifest.currency).toBe('INR');
  });

  test.each(manifest.products.map(p => [p.sku, p]))('%s certifies with a genuine human APPROVE review bound to the exact artifact', (_sku, product) => {
    const r = prepareProduct(product, manifest);
    expect(r.reasons).toEqual([]);
    expect(r.ok).toBe(true);
    const review = r.body.reportx_export.bundle.review;
    expect(review.decision).toBe('APPROVE');
    expect(review.is_test_only_fixture).toBe(false);
    expect(review.reviewer_identity).toBeTruthy();
    expect(review.artifact_sha256).toBe(sha(r.body.reportx_export.bundle.rendered_text));
    expect(r.body.price_minor).toBe(199900); // operator decision 2026-10-01: INR 1,999
  });

  test.each(manifest.products.map(p => [p.sku, p]))('%s is accepted by the production publish service and stores exactly the reviewed bytes', async (_sku, product) => {
    const r = prepareProduct(product, manifest);
    const out = await service.publishCertifiedReport({
      reportxExport: r.body.reportx_export, title: r.body.title, slug: r.body.slug, reportType: r.body.report_type,
      summary: r.body.summary, priceMinor: r.body.price_minor, currency: r.body.currency, filename: r.body.filename,
    });
    expect(out.certification).toBe('PREMIUM_CERTIFIED');
    expect(out.price_minor).toBe(199900);
    const stored = storage.putCertifiedArtifact.mock.calls[0][0];
    expect(stored.sha256).toBe(r.body.reportx_export.bundle.review.artifact_sha256);
    expect(sha(stored.renderedText)).toBe(stored.sha256);
    expect(store.upsertCertifiedReport.mock.calls[0][0]).toMatchObject({ reviewerIdentity: 'BIVASH NAYAK', priceMinor: 199900, currency: 'INR' });
  });
});

describe('negative controls: nothing unreviewed or altered can be listed', () => {
  const product = manifest.products[0];

  test('altered report text (one character) fails certification', () => {
    const r = prepareProduct(product, manifest);
    const tampered = { ...r.body.reportx_export, bundle: { ...r.body.reportx_export.bundle, rendered_text: r.body.reportx_export.bundle.rendered_text + ' ' } };
    const { evaluatePremiumCertification } = require('../premium-report-certification');
    expect(evaluatePremiumCertification(tampered).reasons).toContain('ARTIFACT_HASH_MISMATCH');
  });

  test('an export without its review record is refused', () => {
    const r = prepareProduct({ ...product, review: 'reportx-canary/exports/does-not-exist.json' }, manifest);
    expect(r.ok).toBe(false);
    expect(r.reasons).toContain('REVIEW_UNREADABLE');
  });

  test('a review record for a different report is refused', () => {
    const other = manifest.products[1];
    const r = prepareProduct({ ...product, review: other.review }, manifest);
    expect(r.ok).toBe(false);
    expect(r.reasons).toEqual(expect.arrayContaining(['REVIEW_REPORT_ID_MISMATCH', 'ARTIFACT_HASH_MISMATCH']));
  });

  test('the unreviewed flagship export cannot be listed', () => {
    const r = prepareProduct({ ...product, export: 'reportx-canary/exports/cve-2025-62593-ray-flagship-executive-product-export.json', review: product.review }, manifest);
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

describe('publisher transport', () => {
  test('sends the analyst key only as a header to the configured base and verifies via detail', async () => {
    const r = prepareProduct(manifest.products[0], manifest);
    const calls = [];
    const fetchImpl = async (url, opts = {}) => {
      calls.push({ url, opts });
      if (url.includes('publish-certified')) return { ok: true, status: 201, json: async () => ({ success: true, data: { report: { slug: r.body.slug } } }) };
      return { ok: true, status: 200, json: async () => ({ success: true, data: { report: { slug: r.body.slug } } }) };
    };
    const report = await publish(r, { base: 'https://blog.example.test', key: 'k-123', fetchImpl });
    expect(report.slug).toBe(r.body.slug);
    expect(calls[0].opts.headers['X-Analyst-Key']).toBe('k-123');
    expect(calls[0].opts.body).not.toContain('k-123');
    expect(calls[1].url).toContain(`action=detail&slug=${r.body.slug}`);
  });

  test('a rejected publish surfaces the server error and stops', async () => {
    const r = prepareProduct(manifest.products[0], manifest);
    const fetchImpl = async () => ({ ok: false, status: 401, json: async () => ({ success: false, error: { code: 'UNAUTHORIZED', message: 'bad key' } }) });
    await expect(publish(r, { base: 'https://blog.example.test', key: 'x', fetchImpl })).rejects.toThrow(/HTTP 401 UNAUTHORIZED/);
  });
});
