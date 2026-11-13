'use strict';

/**
 * P0 paid-API live-intelligence authority. Cloudflare Worker JSON is frozen
 * at build time; a newly received HTTP request does not make its data fresh.
 * Only genuinely recent, provenance-verified root records may appear in paid
 * operational live/top/ransomware feeds. Archive/research lookups are separate.
 */
const {assessPublicIntel} = require('./public-intel-freshness');
const MAX_GENERATION_SKEW_MS = 2 * 60 * 1000;
const FUTURE_TOLERANCE_MS = 5 * 60 * 1000;

function verifyOperationalSource(root, routeGeneratedAt, nowMs = Date.now(), routeReportGeneratedAt) {
  const checked = assessPublicIntel(root, nowMs);
  if (!checked.ok) return {
    ok:false, code:'OPERATIONAL_INTELLIGENCE_STALE',
    reason:checked.reason || 'UNVERIFIED_ROOT_SOURCE', state:checked.state,
    ids:new Set(), items:[]
  };
  // Route-specific S2N assets can be older than the root bundle even when
  // it is current. Require the same publication build, not a current request.
  const rootMs = Date.parse(root?.generatedAt || '');
  const routeMs = typeof routeGeneratedAt === 'string' && /(?:Z|[+-]\d\d:\d\d)$/.test(routeGeneratedAt)
    ? Date.parse(routeGeneratedAt) : NaN;
  if(!Number.isFinite(routeMs) || !Number.isFinite(rootMs) ||
      routeMs > nowMs + FUTURE_TOLERANCE_MS ||
      Math.abs(routeMs - rootMs) > MAX_GENERATION_SKEW_MS) {
    return {
      ok:false, code:'OPERATIONAL_ASSET_GENERATION_DIVERGED',
      reason:'S2N_OR_ROOT_BUILD_TIMESTAMP_DIVERGED',
      state:'UNVERIFIED', ids:new Set(), items:[]
    };
  }
  // Root publication and S2N asset must attest the SAME genuine report.
  // Equal JSON-generation clocks can coexist with different report receipts.
  // Such a pair cannot be sold or displayed as one verified live snapshot.
  const receipt=root?.metadata?.lastReportGeneratedAt;
  if(typeof routeReportGeneratedAt!=='string' ||
     typeof receipt!=='string' ||
     !Number.isFinite(Date.parse(routeReportGeneratedAt)) ||
     routeReportGeneratedAt!==receipt) {
    return {
      ok:false, code:'OPERATIONAL_REPORT_RECEIPT_DIVERGED',
      reason:'S2N_REPORT_RECEIPT_DOES_NOT_MATCH_AUTHORITATIVE_ROOT',
      state:'UNVERIFIED', ids:new Set(), items:[]
    };
  }
  return {
    ok:true, code:null, state:checked.state,
    generated_at:root.generatedAt,
    report_generated_at:root.metadata?.lastReportGeneratedAt || null,
    ids:new Set(checked.items.map(item => String(item.id || '')).filter(Boolean)),
    items:checked.items
  };
}

module.exports={verifyOperationalSource,MAX_GENERATION_SKEW_MS};
