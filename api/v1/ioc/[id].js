'use strict';
/**
 * Legacy compatibility endpoint for IOC detail/subresources.
 * Canonical successor: /api/v1/intel?action=ioc&id=ioc:...
 */

const sec = require('../../_lib/security');
const { authenticate, apiError } = require('../../_lib/middleware');
const { tierAtLeast } = require('../../_lib/tier-entitlements');
const { getSearchIndex, getIocDetailAPI } = require('../../_lib/intel');

function markDeprecated(res) {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Link', '</api/v1/intel?action=ioc>; rel="successor-version"');
  res.setHeader('X-Sentinel-Deprecated-Endpoint', '/api/v1/ioc/:id');
}

function resolveCanonicalId(rawId) {
  const raw = String(rawId || '').trim();
  if (!raw || raw.length > 512) return null;
  const lower = raw.toLowerCase();
  const docs = (getSearchIndex().documents || []).filter(d => d.type === 'ioc');
  const exact = docs.find(d => String(d.id || '').toLowerCase() === lower || String(d.name || '').toLowerCase() === lower);
  return exact ? exact.id : null;
}

module.exports = async (req, res) => {
  const ok = await sec.guardRequest(req, res, { allowedMethods: ['GET', 'OPTIONS'], maxBodyBytes: 2048 });
  if (!ok) return;
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const user = await authenticate(req, res);
  if (!user) return;
  if (!tierAtLeast(user.tier, 'pro')) {
    return apiError(res, 403, 'TIER_RESTRICTED', 'IOC detail requires Pro or Enterprise plan.');
  }

  markDeprecated(res);

  try {
    const canonicalId = resolveCanonicalId(req.query && req.query.id);
    if (!canonicalId) return apiError(res, 404, 'IOC_NOT_FOUND', 'IOC not found in the canonical SENTINEL APEX threat graph.');

    const result = getIocDetailAPI(canonicalId);
    if (!result || !result.found || !result.ioc) {
      return apiError(res, 404, 'IOC_NOT_FOUND', 'IOC not found in the canonical SENTINEL APEX threat graph.');
    }

    const ioc = result.ioc;
    const path = String(req.url || '').split('?')[0];

    if (path.endsWith('/history')) {
      return res.status(200).json({
        success: true,
        ioc_id: ioc.id,
        value: ioc.name,
        timeline: ioc.timeline || [],
        deprecated: true,
        successor: `/api/v1/intel?action=ioc&id=${encodeURIComponent(ioc.id)}`,
      });
    }

    if (path.endsWith('/mentions') || path.endsWith('/correlations')) {
      return res.status(200).json({
        success: true,
        ioc_id: ioc.id,
        value: ioc.name,
        linked_intel: ioc.linked_intel || [],
        related_count: (ioc.linked_intel || []).length,
        deprecated: true,
        successor: `/api/v1/intel?action=ioc&id=${encodeURIComponent(ioc.id)}`,
      });
    }

    return res.status(200).json({
      success: true,
      ioc,
      deprecated: true,
      successor: `/api/v1/intel?action=ioc&id=${encodeURIComponent(ioc.id)}`,
    });
  } catch (e) {
    console.error('[IOC API] canonical compatibility detail failed:', e && e.message ? e.message : 'unknown');
    return apiError(res, 500, 'IOC_DETAIL_FAILED', 'IOC detail is temporarily unavailable.');
  }
};
