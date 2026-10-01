#!/usr/bin/env node
'use strict';

/**
 * Builds premium-previews.json: the public "what's inside" preview for each
 * premium report version in config/premium-catalog.json (current products and
 * superseded history), keyed by report_id.
 *
 * A preview carries only what a buyer needs to judge value -- the section
 * list, evidence cut-off, and counts (words, sources, ATT&CK techniques,
 * detection rules with their honest maturity, hypotheses, intelligence gaps,
 * recommendations). It never carries rule bodies, indicators, claim text or
 * source URLs: those are the paid content.
 *
 * Static asset (served by Cloudflare ASSETS, no Worker or D1 cost). Re-run
 * after any reissue:  node scripts/build-premium-previews.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'premium-previews.json');
const AUDIENCE = {
  RANSOMWARE_INCIDENT: 'SOC leads, incident responders, threat-intelligence and third-party-risk teams',
  VULNERABILITY: 'Vulnerability management, AI/ML platform owners, SOC detection engineers',
};

function preview(product, version) {
  const exported = JSON.parse(fs.readFileSync(path.join(ROOT, product.export), 'utf8'));
  const bundle = exported.bundle;
  const text = bundle.rendered_text;
  const sections = text.split('\n').filter(l => /^## /.test(l)).map(l => l.slice(3).trim())
    .map(s => s.replace(/\s*\((?:[A-Z_]+)\)$/, '')); // drop internal tags on superseded versions
  const techniques = new Set(text.match(/\bT\d{4}(?:\.\d{3})?\b/g) || []);
  const retrieved = (bundle.sources || []).map(s => String(s.retrieved_at || '').slice(0, 10)).filter(Boolean).sort();
  return {
    report_id: bundle.report_id,
    version,
    title: product.title,
    report_type: product.report_type,
    audience: AUDIENCE[product.report_type] || 'Security teams',
    evidence_cutoff: retrieved[retrieved.length - 1] || null,
    sections,
    stats: {
      words: text.split(/\s+/).filter(Boolean).length,
      sources: (bundle.sources || []).length,
      attack_techniques: techniques.size,
      detection_rules: (bundle.detection_rules || []).map(r => ({ format: r.format, maturity: r.validation_state })),
      hypotheses: (bundle.hypothesis_sets || []).reduce((n, h) => n + ((h.hypotheses || []).length || 1), 0),
      intelligence_gaps: (bundle.intelligence_gaps || []).length,
      technical_recommendations: bundle.technical_recommendation_count || 0,
    },
    commercial_readiness: `${exported.commercial_readiness.pass_count}/${exported.commercial_readiness.total_count}`,
  };
}

function build() {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'config', 'premium-catalog.json'), 'utf8'));
  const out = { generated_from: 'config/premium-catalog.json', reports: {} };
  for (const p of manifest.products) out.reports[p.report_id] = preview(p, p.version);
  for (const h of manifest.history || []) out.reports[h.report_id] = preview(h, h.version);
  return out;
}

if (require.main === module) {
  fs.writeFileSync(OUT, JSON.stringify(build(), null, 2) + '\n');
  console.log(`wrote ${path.relative(ROOT, OUT)}`);
}

module.exports = { build, preview };
