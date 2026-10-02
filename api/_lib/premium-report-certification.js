'use strict';

/**
 * Premium Intelligence sellability certification adapter.
 *
 * This module intentionally mirrors ReportX System 3's human-review truth
 * boundary without recomputing any of its 23 quality controls. It only reads
 * the exported bundle and proves that the exact rendered_text being offered
 * for sale is the same byte sequence a real APPROVE ReviewRecord bound to.
 *
 * Production deliberately rejects `is_test_only_fixture=true`, even though
 * ReportX's Python model permits that flag in unit fixtures. Automated gate
 * success without a valid human review remains PREMIUM_READY_PENDING_HUMAN
 * and is never sellable here.
 */
const crypto = require('crypto');

function sha256Text(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

function evaluatePremiumCertification(exported) {
  const reasons = [];
  const bundle = exported && exported.bundle;
  const readiness = exported && exported.commercial_readiness;

  if (!bundle || !readiness) {
    return { certified: false, state: 'INVALID_REPORTX_EXPORT', reasons: ['MISSING_REPORTX_EXPORT_KEYS'] };
  }

  const reportId = String(bundle.report_id || '').trim();
  const renderedText = typeof bundle.rendered_text === 'string' ? bundle.rendered_text : '';
  const review = bundle.review || null;
  const artifactSha256 = sha256Text(renderedText);

  if (!reportId) reasons.push('MISSING_REPORT_ID');
  if (!bundle.is_premium_tier) reasons.push('NOT_PREMIUM_TIER');
  if (!renderedText) reasons.push('EMPTY_RENDERED_ARTIFACT');
  if (readiness.verdict !== 'COMMERCIAL-READY') reasons.push('AUTOMATED_GATES_NOT_COMMERCIAL_READY');
  if (!review) reasons.push('MISSING_HUMAN_REVIEW');

  if (review) {
    if (String(review.report_id || '') !== reportId) reasons.push('REVIEW_REPORT_ID_MISMATCH');
    if (String(review.decision || '') !== 'APPROVE') reasons.push('REVIEW_NOT_APPROVED');
    if (review.is_test_only_fixture === true) reasons.push('TEST_ONLY_REVIEW_FORBIDDEN');
    if (review.reviewer_type && String(review.reviewer_type) !== 'cdb_internal') reasons.push('UNSUPPORTED_REVIEWER_TYPE');
    if (!String(review.reviewer_identity || '').trim()) reasons.push('MISSING_REVIEWER_IDENTITY');
    if (!String(review.review_timestamp || '').trim()) reasons.push('MISSING_REVIEW_TIMESTAMP');
    if (String(review.artifact_sha256 || '').toLowerCase() !== artifactSha256) {
      reasons.push('ARTIFACT_HASH_MISMATCH');
    }
  }

  return {
    certified: reasons.length === 0,
    state: reasons.length === 0 ? 'PREMIUM_CERTIFIED' : 'NOT_CERTIFIED',
    reasons,
    reportId,
    artifactSha256,
    renderedText,
    reviewerIdentity: review ? String(review.reviewer_identity || '') : '',
    reviewTimestamp: review ? String(review.review_timestamp || '') : '',
  };
}

module.exports = { sha256Text, evaluatePremiumCertification };