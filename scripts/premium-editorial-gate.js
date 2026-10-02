'use strict';

/**
 * Editorial release gate for paid Premium Intelligence artifacts.
 *
 * The ReportX certifier (api/_lib/premium-report-certification.js) proves an
 * artifact is the exact text a named human approved. It does not prove the
 * text is fit to sell. This gate catches the defect classes found in the
 * 2026-10-01 human review of the v2 reissue, so an approval alone can never
 * push them to a paying customer:
 *
 *   CUSTOMER_COPY_INTERNAL_TERMS  engineering / canary vocabulary in the artifact
 *   DETECTION_FIELD_LOGSOURCE_MISMATCH  a Sigma rule keys on a field its
 *                                 logsource category does not carry, so that
 *                                 selection can never match
 *   EVIDENCE_CUTOFF_MISSING / EVIDENCE_STALE / EVIDENCE_CUTOFF_IN_FUTURE
 *                                 the evidence cut-off is absent, older than the
 *                                 release window, or later than today
 *
 * Pure functions, no I/O. Used by scripts/publish-premium-reports.js and the
 * catalog tests; reportx-canary/premium_reissue_v2.py mirrors INTERNAL_COPY.
 */

const yaml = require('js-yaml');

// Terms that must never reach a paying customer. Scoped so that legitimate
// intelligence vocabulary ("proof sample", "Mimikatz module", "browser
// session", "pipeline" describing a threat) is not blocked.
const INTERNAL_COPY = new RegExp([
  'premium intelligence canary', '\\bcanar(?:y|ies)\\b', 'this session', 'checked-in raw files', 'hand-typed',
  'reportx', 'GENERIC_DEFENSIVE_READINESS', 'content_sha256', 'internal pipeline', 'pipeline test', 'test artifact',
  'test-only', 'fixture', '\\bstaging\\b', 'demo-only', 'validation artifact', 'synthetic customer', 'placeholder',
  // Evidence-graph internals that leaked into the v2 text (review 2026-10-01).
  'evidence_refs', 'source_refs', 'evidence_integrity', '\\(evidence: c-', 'this bundle', '`forecasts` field',
  'Claim Ledger appendix',
].join('|'), 'i');

// Fields that exist only in specific Sigma logsource categories. A selection
// on one of these under another category never matches.
const CATEGORY_ONLY_FIELDS = {
  TargetFilename: ['file_event', 'file_change', 'file_delete', 'file_rename', 'file_access', 'create_stream_hash', 'file_executable_detected'],
  TargetObject: ['registry_event', 'registry_set', 'registry_add', 'registry_delete', 'registry_rename'],
  QueryName: ['dns_query', 'dns'],
  ImageLoaded: ['image_load', 'driver_load'],
  PipeName: ['pipe_created'],
};

const DEFAULT_MAX_EVIDENCE_AGE_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

function internalTerms(text) {
  const re = new RegExp(INTERNAL_COPY.source, 'gi');
  return [...new Set((String(text).match(re) || []).map(m => m.toLowerCase()))].sort();
}

function sigmaRules(text) {
  const blocks = String(text).match(/```ya?ml\n[\s\S]*?```/g) || [];
  return blocks.map(b => {
    try { return yaml.load(b.replace(/^```ya?ml\n/, '').replace(/```$/, '')); } catch (_) { return null; }
  }).filter(r => r && typeof r === 'object' && r.detection);
}

function detectionFieldMismatches(text) {
  const out = [];
  for (const rule of sigmaRules(text)) {
    const category = String((rule.logsource || {}).category || '');
    for (const [name, selection] of Object.entries(rule.detection)) {
      if (!selection || typeof selection !== 'object') continue;
      const items = Array.isArray(selection) ? selection : [selection];
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        for (const key of Object.keys(item)) {
          const field = key.split('|')[0];
          const allowed = CATEGORY_ONLY_FIELDS[field];
          if (allowed && !allowed.includes(category)) out.push(`${rule.id || rule.title}: ${name}.${field} under ${category || 'no category'}`);
        }
      }
    }
  }
  return out;
}

function evidenceCutoff(text) {
  const m = String(text).match(/Evidence cut-off: (\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : null;
}

/**
 * Returns { ok, reasons, details } for one rendered artifact.
 * `now` and `maxEvidenceAgeDays` are injectable for tests and for a
 * deliberate, documented manifest override.
 */
function editorialFindings(text, { now = new Date(), maxEvidenceAgeDays = DEFAULT_MAX_EVIDENCE_AGE_DAYS } = {}) {
  const reasons = [];
  const details = {};
  const terms = internalTerms(text);
  if (terms.length) { reasons.push('CUSTOMER_COPY_INTERNAL_TERMS'); details.internal_terms = terms; }
  const mismatches = detectionFieldMismatches(text);
  if (mismatches.length) { reasons.push('DETECTION_FIELD_LOGSOURCE_MISMATCH'); details.detection_mismatches = mismatches; }
  const cutoff = evidenceCutoff(text);
  if (!cutoff) {
    reasons.push('EVIDENCE_CUTOFF_MISSING');
  } else {
    const ageDays = Math.floor((now.getTime() - Date.parse(`${cutoff}T00:00:00Z`)) / DAY_MS);
    details.evidence_cutoff = cutoff;
    details.evidence_age_days = ageDays;
    if (ageDays < 0) reasons.push('EVIDENCE_CUTOFF_IN_FUTURE');
    else if (!(ageDays <= maxEvidenceAgeDays)) reasons.push('EVIDENCE_STALE');
  }
  return { ok: reasons.length === 0, reasons, details };
}

module.exports = {
  INTERNAL_COPY,
  CATEGORY_ONLY_FIELDS,
  DEFAULT_MAX_EVIDENCE_AGE_DAYS,
  internalTerms,
  detectionFieldMismatches,
  evidenceCutoff,
  editorialFindings,
};
