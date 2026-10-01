#!/usr/bin/env node
'use strict';

/**
 * Publish the Premium Intelligence products in config/premium-catalog.json.
 *
 * Reuses the production publication path (POST
 * /api/v1/premium-intelligence?action=publish-certified), so R2 storage,
 * integrity verification and the D1 catalog write all run through the same
 * tested service code; this script never writes to D1 or R2 itself.
 *
 *   node scripts/publish-premium-reports.js            # dry run (default): certify locally, print plan
 *   PREMIUM_ANALYST_KEY=... node scripts/publish-premium-reports.js --publish
 *       [--base https://blog.cyberdudebivash.in] [--only <sku>]
 *
 * Versioned reissue (manifest schema 2): an entry may name the product it
 * `supersedes`. Sequence per product, never reordered:
 *   local certification (human review bound to the exact artifact hash, and
 *   the hash pinned in the manifest) -> skip if the live product already
 *   serves this hash -> publish-certified (R2 put + verify, then catalog
 *   row) -> confirm the new product is live with the expected hash -> only
 *   then retire the superseded product. Customers never see a catalog entry
 *   without a verified artifact, and the old one disappears only after the
 *   new one is live.
 *
 * Fails closed: a product is only sent if the export plus its human review
 * record certify locally with the same certifier the server runs. The
 * analyst key is read from the environment and never printed.
 */

const fs = require('fs');
const path = require('path');
const { evaluatePremiumCertification } = require('../api/_lib/premium-report-certification');

const ROOT = path.resolve(__dirname, '..');
const MANIFEST = path.join(ROOT, 'config', 'premium-catalog.json');
const MAX_PRICE_MINOR = 10000000; // INR 1,00,000 — sanity ceiling against a typo'd price
const SLUG_RE = /^[a-z0-9][a-z0-9-]{2,119}$/;

function loadManifest(file = MANIFEST) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Build the publish request for one product and certify it locally.
 * Returns { sku, ok, reasons, body, certification }.
 */
function prepareProduct(product, manifest, root = ROOT) {
  const reasons = [];
  const read = rel => JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));
  let exported;
  let review;
  try { exported = read(product.export); } catch (_) { reasons.push('EXPORT_UNREADABLE'); }
  try { review = read(product.review); } catch (_) { reasons.push('REVIEW_UNREADABLE'); }
  if (!SLUG_RE.test(String(product.slug || ''))) reasons.push('INVALID_SLUG');
  if (!String(product.title || '').trim()) reasons.push('MISSING_TITLE');
  if (!String(product.report_type || '').trim()) reasons.push('MISSING_REPORT_TYPE');
  const price = Number(product.price_minor);
  if (!Number.isInteger(price) || price <= 0 || price > MAX_PRICE_MINOR) reasons.push('INVALID_PRICE');
  if (!/^[A-Z]{3}$/.test(String(manifest.currency || ''))) reasons.push('INVALID_CURRENCY');
  if (reasons.length) return { sku: product.sku, ok: false, reasons };

  // The export predates its review; the certified bundle is the export with
  // the human review record attached (ReportX bundle_io semantics).
  const reportxExport = { ...exported, bundle: { ...exported.bundle, review } };
  const certification = evaluatePremiumCertification(reportxExport);
  if (!certification.certified) return { sku: product.sku, ok: false, reasons: certification.reasons, certification };
  // Schema 2 pins: the export must be exactly the artifact the manifest names.
  if (product.report_id && certification.reportId !== product.report_id) {
    return { sku: product.sku, ok: false, reasons: ['REPORT_ID_MISMATCH'], certification };
  }
  if (product.artifact_sha256 && certification.artifactSha256 !== product.artifact_sha256) {
    return { sku: product.sku, ok: false, reasons: ['ARTIFACT_HASH_NOT_PINNED'], certification };
  }

  return {
    sku: product.sku,
    ok: true,
    reasons: [],
    certification,
    body: {
      reportx_export: reportxExport,
      title: product.title,
      slug: product.slug,
      report_type: product.report_type,
      summary: product.summary || '',
      price_minor: price,
      currency: manifest.currency,
      filename: product.filename || product.slug,
    },
    supersedes: product.supersedes || null,
  };
}

function prepareAll(manifest, root = ROOT) {
  const seen = new Set();
  return manifest.products.map(p => {
    const r = prepareProduct(p, manifest, root);
    if (seen.has(p.slug)) { r.ok = false; r.reasons = [...r.reasons, 'DUPLICATE_SLUG']; }
    seen.add(p.slug);
    return r;
  });
}

async function liveDetail(base, slug, fetchImpl) {
  const res = await fetchImpl(`${base}/api/v1/premium-intelligence?action=detail&slug=${encodeURIComponent(slug)}`);
  const json = await res.json().catch(() => ({}));
  return res.ok && json.success ? json.data.report : null;
}

async function publish(prepared, { base, key, fetchImpl = fetch }) {
  const sha = prepared.certification && prepared.certification.artifactSha256;
  const current = await liveDetail(base, prepared.body.slug, fetchImpl);
  let report = current;
  if (current && sha && current.artifact_sha256 === sha) {
    report = { ...current, unchanged: true }; // same bytes already live: no R2 write
  } else {
    const res = await fetchImpl(`${base}/api/v1/premium-intelligence?action=publish-certified`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Analyst-Key': key },
      body: JSON.stringify(prepared.body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.success) {
      const err = json.error || {};
      throw new Error(`publish failed for ${prepared.sku}: HTTP ${res.status} ${err.code || ''} ${err.message || ''}`.trim());
    }
    report = await liveDetail(base, prepared.body.slug, fetchImpl);
    if (!report) throw new Error(`published ${prepared.sku} but detail lookup failed`);
  }
  if (sha && report.artifact_sha256 && report.artifact_sha256 !== sha) {
    throw new Error(`live ${prepared.sku} serves ${report.artifact_sha256}, expected ${sha}; superseded product left untouched`);
  }

  const old = prepared.supersedes;
  if (old && old.report_id && old.report_id !== report.report_id) {
    const res = await fetchImpl(`${base}/api/v1/premium-intelligence?action=set-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Analyst-Key': key },
      body: JSON.stringify({ report_id: old.report_id, status: 'RETIRED' }),
    });
    const json = await res.json().catch(() => ({}));
    // 404 = already retired/never published; anything else is a real failure.
    if (!(res.ok && json.success) && res.status !== 404) {
      throw new Error(`v2 of ${prepared.sku} is live but retiring ${old.report_id} failed: HTTP ${res.status}`);
    }
    report = { ...report, retired: old.report_id };
  }
  return report;
}

async function main() {
  const args = process.argv.slice(2);
  const doPublish = args.includes('--publish');
  const baseIdx = args.indexOf('--base');
  const onlyIdx = args.indexOf('--only');
  const base = (baseIdx >= 0 ? args[baseIdx + 1] : 'https://blog.cyberdudebivash.in').replace(/\/+$/, '');
  const only = onlyIdx >= 0 ? args[onlyIdx + 1] : null;

  const manifest = loadManifest();
  const prepared = prepareAll(manifest).filter(p => !only || p.sku === only);
  for (const p of prepared) {
    const c = p.certification || {};
    console.log(`${p.ok ? 'CERTIFIED' : 'REJECTED '} ${p.sku}  ${p.ok ? `${p.body.price_minor / 100} ${p.body.currency}  sha256=${c.artifactSha256}  reviewer=${c.reviewerIdentity}` : p.reasons.join(',')}`);
  }
  const bad = prepared.filter(p => !p.ok);
  if (bad.length) { console.error(`${bad.length} product(s) failed local certification; nothing published.`); process.exit(1); }
  if (!doPublish) { console.log('Dry run only. Re-run with --publish and PREMIUM_ANALYST_KEY set to publish.'); return; }

  const key = process.env.PREMIUM_ANALYST_KEY || '';
  if (!key) { console.error('PREMIUM_ANALYST_KEY is not set.'); process.exit(1); }
  if (!/^https:\/\//.test(base)) { console.error('--base must be https.'); process.exit(1); }
  for (const p of prepared) {
    const report = await publish(p, { base, key });
    console.log(`${report.unchanged ? 'UNCHANGED' : 'PUBLISHED'} ${p.sku} -> ${report.slug} sha256=${report.artifact_sha256 || '?'}${report.retired ? ` (retired ${report.retired})` : ''}`);
  }
}

if (require.main === module) {
  main().catch(e => { console.error(String(e.message || e)); process.exit(1); });
}

module.exports = { loadManifest, prepareProduct, prepareAll, publish, liveDetail, MANIFEST };
