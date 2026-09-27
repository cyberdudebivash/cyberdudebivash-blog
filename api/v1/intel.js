/**
 * SENTINEL APEX — Consolidated Intel Router
 * Single serverless function handling ALL intelligence endpoints.
 *
 * Routing: GET /api/v1/intel?action={action}
 *
 *  action=live         GET  All live threat intelligence (tier-gated depth)
 *  action=top          GET  Top-priority threats (priority_score >= 65)
 *  action=cve          GET  CVE detail lookup  (?id=CVE-2024-xxxx)
 *  action=iocs         GET  IOC feed — PRO+ only, STIX export for Enterprise
 *  action=ransomware   GET  Ransomware campaign feed
 *  action=search       GET  Full-text search across all intel (?q=query)
 *  action=stats        GET  Platform stats — no auth required
 *  action=dashboard    GET  Sanitized first-party dashboard feed — no auth required
 *  action=graph        GET  Threat actor relationship graph (tier-gated)
 *  action=campaigns    GET  Campaign clusters (?severity=&has_kev=)
 *  action=campaign     GET  Single campaign detail (?id=campaign:...)
 *  action=top-actors   GET  Most active threat actors ranked by activity
 *  action=unified-search GET Cross-entity search: CVE/campaign/actor/IOC/report (?q=query&type=)
 *  action=actor        GET  Single threat actor detail + relationships (?id=actor:...)
 *  action=ioc          GET  Single IOC detail + linked intel — PRO+ only (?id=ioc:...)
 *  action=report       GET  Single published intelligence report detail (?id=SA-YYYY-NNNN)
 *  action=dossier      GET  Evidence-backed intelligence dossier — CVE or campaign only
 *                           (?type=cve&id=CVE-YYYY-NNNNN or ?type=campaign&id=campaign:...)
 *  action=detections   GET  List validated detection intelligence (?entity_type=&entity_id=&attack_technique=&format=&validation_status=&limit=&cursor=)
 *  action=detection    GET  Single detection detail (?id=...)
 *  action=detection-download GET Raw single-format download (?id=&format=sigma|kql|splunk|osquery|suricata)
 *  action=detection-coverage GET ATT&CK detection coverage for a CVE or campaign (?type=cve|campaign&id=...)
 *  action=detection-pack     GET Pro/Enterprise: evidence-backed pack of released detections (?type=cve|campaign&id=...)
 *  action=defense-coverage   GET Customer-environment-aware detection coverage for a CVE or campaign
 *                                 (?type=cve|campaign&id=...) -- extends detection-coverage with the caller's
 *                                 own Defense Profile (see api/v1/defense-profile.js); safe with no profile configured.
 *
 * Backward-compat rewrites in vercel.json map old paths to ?action= params.
 */
'use strict';
const crypto = require('crypto');
const { authenticate, successResponse, apiError, corsHeaders } = require('../_lib/middleware');
const { getIntel, getCVEDetail, searchIntel, getPlatformStats,
        getGraph, getCampaigns, getCampaignDetail, getTopActorsAPI,
        unifiedSearch, getActorDetailAPI, getIocDetailAPI, getReportDetailAPI,
        getDossierAPI } = require('../_lib/intel');
const detectionRules = require('../_lib/detection-rules');
const detectionIntelligence = require('../_lib/detection-intelligence');
const defenseProfileStore = require('../_lib/defense-profile-store');
const defenseCompatibility = require('../_lib/defense-compatibility');
const sec = require('../_lib/security');
const reportsIndex = require('../intel/reports-index.json');

function safeHttps(raw) {
  try {
    const u = new URL(String(raw || '').trim());
    return (u.protocol === 'https:' && !u.username && !u.password) ? u.href : null;
  } catch (_) { return null; }
}

function dashboardReportFor(item) {
  const cves = new Set([...(item.cves || []), item.id]
    .filter(v => /^CVE-\d{4}-\d{4,7}$/i.test(String(v || '')))
    .map(v => String(v).toUpperCase()));
  if (!cves.size) return null;
  return (reportsIndex.reports || []).find(r =>
    (r.cves || []).some(cve => cves.has(String(cve).toUpperCase()))
  ) || null;
}

function publicDashboardItems(section, limit) {
  const raw = getIntel('live', 'enterprise', { page: 1, limit: 100 });
  let items = Array.isArray(raw.items) ? raw.items.slice() : [];
  if (section === 'malware') {
    items = items.filter(i => i.ransomware === true ||
      /malware|ransomware|trojan|worm|botnet|spyware|stealer|\brat\b/i
        .test(String(i.title || '') + ' ' + String(i.description || i.desc || '')));
  } else if (section === 'ai_security') {
    items = items.filter(i =>
      /\bai\b|llm|gpt|artificial intelligence|machine learning|prompt injection|copilot|chatgpt|claude|gemini/i
        .test(String(i.title || '') + ' ' + String(i.description || i.desc || '')));
  }
  items = items.slice(0, limit);
  return {
    generated_at: raw.intel_meta && raw.intel_meta.generated_at || null,
    source_platform: raw.intel_meta && raw.intel_meta.source_platform || 'CYBERDUDEBIVASH SENTINEL APEX',
    items: items.map(i => {
      const report = dashboardReportFor(i);
      const refs = Array.isArray(i.refs) ? i.refs : [];
      const reportUrl = report && report.url
        ? new URL(report.url, 'https://blog.cyberdudebivash.in').href
        : null;
      const sourceUrl = refs.map(safeHttps).find(Boolean) || safeHttps(reportUrl);
      return {
        id: String(i.id || ''),
        title: String(i.title || 'Untitled intelligence record'),
        description: String(i.description || i.desc || '').slice(0, 600),
        published: i.published || i.pubDate || i.last_seen || i.first_seen || null,
        severity: String(i.threat_level || 'NOT_ASSESSED').toUpperCase(),
        exploited: i.exploited === true,
        cisa_kev: i.cisa_kev === true || i.cisaKev === true,
        ransomware: i.ransomware === true,
        cvss: Number.isFinite(Number(i.cvss)) ? Number(i.cvss) : null,
        vendor: i.vendor || null,
        product: i.product || null,
        source: i.source || 'sentinel_apex',
        source_url: sourceUrl,
        cves: Array.isArray(i.cves) ? i.cves.slice(0, 10) :
          (/^CVE-/i.test(String(i.id || '')) ? [String(i.id).toUpperCase()] : []),
        report_id: report ? report.report_id : null,
        report_url: report ? report.url : null
      };
    })
  };
}


/* ─── Main Router ────────────────────────────────────────────── */
module.exports = async (req, res) => {
  /* Phase 1: global guard — security headers + method check + size limit */
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes:   10240,
  });
  if (!ok_guard) return;

  /* Phase 4: global IP rate limit (10 req/min) */
  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();

  /* ── Public: stats — no API key required ───────────────────── */
  if (action === 'stats') {
    try {
      const stats = getPlatformStats();
      return res.status(200).json({
        success: true,
        stats,
        meta: { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      });
    } catch (e) {
      return res.status(500).json({ success: false, error: 'Stats unavailable' });
    }
  }
  
  /* ── Public: sanitized dashboard feed — no API key required ── */
  if (action === 'dashboard') {
    if (req.method !== 'GET') {
      return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required for dashboard feed');
    }
    const sectionRaw = String(req.query.section || 'intel').toLowerCase().trim().replace(/-/g, '_');
    const section = ['intel', 'malware', 'ai_security'].includes(sectionRaw) ? sectionRaw : 'intel';
    const limit = Math.min(25, Math.max(1, parseInt(req.query.limit || '25', 10) || 25));
    try {
      const data = publicDashboardItems(section, limit);
      sec.applySecurityHeaders(res);
      res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=120');
      return res.status(200).json({
        success: true,
        data: { section, ...data },
        meta: {
          platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0',
          timestamp: new Date().toISOString(),
          contract: 'cdb.dashboard-feed.v1'
        }
      });
    } catch (e) {
      sec.applySecurityHeaders(res);
      res.setHeader('Cache-Control', 'no-store');
      return res.status(503).json({
        success: false,
        error: {
          code: 'DASHBOARD_FEED_UNAVAILABLE',
          message: 'First-party dashboard intelligence is temporarily unavailable.'
        },
        meta: {
          platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0',
          timestamp: new Date().toISOString()
        }
      });
    }
  }

  /* ── All other actions require authentication ───────────────── */
  if (req.method !== 'GET') {
    return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required for intel endpoints');
  }

  if (!action) {
    return apiError(res, 400, 'MISSING_ACTION',
      'action parameter required. Valid: live, top, cve, iocs, ransomware, search, stats. ' +
      'Example: GET /api/v1/intel?action=live');
  }

  const user = await authenticate(req, res);
  if (!user) return;

  /* ─── Route Dispatcher ───────────────────────────────────────── */
  try {
    switch (action) {

      /* ── GET ?action=live ──────────────────────────────────── */
      case 'live': {
        const result = getIntel('live', user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=live',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=top ───────────────────────────────────── */
      case 'top': {
        const result = getIntel('topThreats', user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=top',
          description:    'Top priority threats (priority score ≥ 65/100)',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=cve&id=CVE-YYYY-NNNN ─────────────────── */
      case 'cve': {
        const id = String(req.query.id || '').trim().toUpperCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_CVE_ID',
            'CVE ID required. Example: GET /api/v1/intel?action=cve&id=CVE-2024-12345');
        }
        if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) {
          return apiError(res, 400, 'INVALID_CVE_ID',
            `Invalid CVE ID format: "${id}". Expected: CVE-YYYY-NNNNN`);
        }
        const { found, item } = getCVEDetail(id, user.tier);
        if (!found) {
          return apiError(res, 404, 'CVE_NOT_FOUND',
            `${id} not found in SENTINEL APEX database. ` +
            `May not meet CVSS ≥ 7.0 threshold or not yet ingested. ` +
            `Check: https://nvd.nist.gov/vuln/detail/${id}`);
        }
        return successResponse(res, {
          cve_id:     id,
          item,
          report_url: item.report_url || null,
        }, {
          endpoint:       `/api/v1/intel?action=cve&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=iocs ──────────────────────────────────── */
      case 'iocs': {
        if (user.tier !== 'pro' && user.tier !== 'enterprise') {
          return apiError(res, 403, 'TIER_RESTRICTED',
            'IOC feed requires Pro or Enterprise plan. Upgrade at https://blog.cyberdudebivash.in/pricing.html',
            { 'X-Upgrade-URL': 'https://blog.cyberdudebivash.in/pricing.html' });
        }
        const raw   = getIntel('iocs', user.tier, {});
        let items   = raw.items || [];

        // Additional filters
        if (req.query.type) {
          const t = req.query.type.toLowerCase();
          items = items.filter(i => (i.type || '').toLowerCase() === t);
        }
        if (req.query.min_confidence) {
          const mc = parseFloat(req.query.min_confidence);
          if (!isNaN(mc)) items = items.filter(i => (i.confidence_score || 0) >= mc);
        }
        if (req.query.related_id) {
          const rid = req.query.related_id.toUpperCase();
          items = items.filter(i => (i.related_id || '').toUpperCase() === rid);
        }

        // Pagination
        const page   = Math.max(1, parseInt(req.query.page  || '1',  10));
        const limit  = Math.min(200, parseInt(req.query.limit || '50', 10));
        const offset = (page - 1) * limit;
        const paged  = items.slice(offset, offset + limit);

        // Enterprise STIX 2.1 export
        let stixBundle = null;
        if (user.tier === 'enterprise' && req.query.format === 'stix') {
          stixBundle = buildSTIXBundle(paged);
        }

        return successResponse(res, {
          iocs: paged,
          stix: stixBundle,
          pagination: {
            page, limit, total: items.length,
            total_pages: Math.ceil(items.length / limit),
            has_next: offset + limit < items.length,
          },
          ioc_types:  [...new Set(items.map(i => i.type).filter(Boolean))],
          intel_meta: raw.intel_meta,
          tier_info:  raw.tier_info,
        }, {
          endpoint:       '/api/v1/intel?action=iocs',
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=ransomware ────────────────────────────── */
      case 'ransomware': {
        const result = getIntel('ransomware', user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=ransomware',
          description:    'Active ransomware campaigns, actor TTPs, and IOC feeds',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=search&q=query ────────────────────────── */
      case 'search': {
        const q = String(req.query.q || '').trim();
        if (!q || q.length < 2) {
          return apiError(res, 400, 'INVALID_QUERY',
            'Search query (q) required and must be ≥ 2 characters. Example: ?action=search&q=log4j');
        }
        if (q.length > 200) {
          return apiError(res, 400, 'QUERY_TOO_LONG', 'Search query must be under 200 characters.');
        }
        const result = searchIntel(q, user.tier, req.query);
        if (user.tier === 'free' && result.items.length > 5) {
          result.items = result.items.slice(0, 5);
          result._free_limit = `Showing 5 of ${result.total} results. Upgrade to Pro for full search.`;
        }
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=search',
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=graph ────────────────────────────────────── */
      case 'graph': {
        const result = getGraph(user.tier);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=graph',
          description:    'Threat actor relationship graph — nodes (CVE/Actor/Campaign/IOC) and edges',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=campaigns ────────────────────────────────── */
      case 'campaigns': {
        const result = getCampaigns(user.tier, req.query);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=campaigns',
          description:    'Threat campaign clusters grouped by shared IOCs, CVEs, and actor TTPs',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=campaign&id=campaign:... ─────────────────── */
      case 'campaign': {
        const campaignId = String(req.query.id || '').trim();
        if (!campaignId || campaignId.length < 3) {
          return apiError(res, 400, 'MISSING_CAMPAIGN_ID',
            'Campaign ID required. Example: GET /api/v1/intel?action=campaign&id=campaign:cve-2024-27199');
        }
        const { found, campaign } = getCampaignDetail(campaignId, user.tier);
        if (!found) {
          return apiError(res, 404, 'CAMPAIGN_NOT_FOUND',
            `Campaign "${campaignId}" not found. List all at GET /api/v1/intel?action=campaigns`);
        }
        return successResponse(res, { campaign }, {
          endpoint:       `/api/v1/intel?action=campaign&id=${campaignId}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=top-actors ───────────────────────────────── */
      case 'top-actors': {
        const actorLimit = Math.min(20, parseInt(req.query.limit || '10', 10));
        const result     = getTopActorsAPI(user.tier, actorLimit);
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=top-actors',
          description:    'Most active threat actors ranked by graph connectivity and CVE exploitation count',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=unified-search&q=query&type=cve,campaign ─── */
      case 'unified-search': {
        const q = String(req.query.q || '').trim();
        const result = unifiedSearch(q, user.tier, {
          type:     req.query.type,
          severity: req.query.severity,
          from:     req.query.from_date,
          to:       req.query.to_date,
          limit:    req.query.limit,
          offset:   req.query.offset,
        });
        if (!result.ok) {
          return apiError(res, 400, result.error, result.message);
        }
        if (user.tier === 'free' && result.results.length > 5) {
          result.results = result.results.slice(0, 5);
          result._free_limit = `Showing 5 of ${result.pagination.total} results. Upgrade to Pro for full search.`;
        }
        return successResponse(res, result, {
          endpoint:       '/api/v1/intel?action=unified-search',
          description:    'Cross-entity search across CVE, campaign, threat actor, IOC, and published-report intelligence',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=actor&id=actor:... ───────────────────────── */
      case 'actor': {
        const id = String(req.query.id || '').trim().toLowerCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_ACTOR_ID',
            'Actor ID required. Example: GET /api/v1/intel?action=actor&id=actor:lockbit');
        }
        const { found, actor } = getActorDetailAPI(id);
        if (!found) {
          return apiError(res, 404, 'ACTOR_NOT_FOUND',
            `Actor "${id}" not found. List all at GET /api/v1/intel?action=top-actors`);
        }
        // Free/starter: identity only, no relationships/timeline — mirrors
        // getGraphForTier()'s own free/starter node-detail restriction.
        const payload = (user.tier === 'free' || user.tier === 'starter') ? {
          id: actor.id, type: actor.type, name: actor.name,
          attributes: {
            aliases: actor.attributes.aliases, category: actor.attributes.category,
            motivation: actor.attributes.motivation, active: actor.attributes.active,
          },
          _upgrade: 'Full relationships, timeline, and TTP detail available on Pro plan',
        } : actor;
        return successResponse(res, { actor: payload }, {
          endpoint:       `/api/v1/intel?action=actor&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=ioc&id=ioc:... — PRO+ only ───────────────── */
      case 'ioc': {
        if (user.tier !== 'pro' && user.tier !== 'enterprise') {
          return apiError(res, 403, 'TIER_RESTRICTED',
            'IOC detail requires Pro or Enterprise plan. Upgrade at https://blog.cyberdudebivash.in/pricing.html',
            { 'X-Upgrade-URL': 'https://blog.cyberdudebivash.in/pricing.html' });
        }
        const id = String(req.query.id || '').trim().toLowerCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_IOC_ID',
            'IOC ID required. Example: GET /api/v1/intel?action=ioc&id=ioc:domain:example.com');
        }
        const { found, ioc } = getIocDetailAPI(id);
        if (!found) {
          return apiError(res, 404, 'IOC_NOT_FOUND', `IOC "${id}" not found.`);
        }
        return successResponse(res, { ioc }, {
          endpoint:       `/api/v1/intel?action=ioc&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=report&id=SA-YYYY-NNNN ───────────────────── */
      case 'report': {
        const id = String(req.query.id || '').trim().toUpperCase();
        if (!id) {
          return apiError(res, 400, 'MISSING_REPORT_ID',
            'Report ID required. Example: GET /api/v1/intel?action=report&id=SA-2026-0001');
        }
        const { found, report } = getReportDetailAPI(id);
        if (!found) {
          return apiError(res, 404, 'REPORT_NOT_FOUND', `Report "${id}" not found.`);
        }
        return successResponse(res, { report }, {
          endpoint:       `/api/v1/intel?action=report&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=dossier&type=cve|campaign&id=... ─────────── */
      case 'dossier': {
        const type = String(req.query.type || '').trim().toLowerCase();
        if (type !== 'cve' && type !== 'campaign') {
          return apiError(res, 400, 'UNSUPPORTED_ENTITY_TYPE',
            `Dossier type "${type || '(missing)'}" is not supported. Valid: cve, campaign. ` +
            'Example: GET /api/v1/intel?action=dossier&type=cve&id=CVE-2024-12345');
        }
        const rawId = String(req.query.id || '').trim();
        if (!rawId) {
          return apiError(res, 400, 'MISSING_DOSSIER_ID',
            `${type} ID required. Example: GET /api/v1/intel?action=dossier&type=${type}&id=` +
            (type === 'cve' ? 'CVE-2024-12345' : 'campaign:cve-2024-27199'));
        }
        if (type === 'cve' && !/^CVE-\d{4}-\d{4,7}$/i.test(rawId)) {
          return apiError(res, 400, 'INVALID_CVE_ID', `Invalid CVE ID format: "${rawId}". Expected: CVE-YYYY-NNNNN`);
        }
        const { found, dossier } = getDossierAPI(type, rawId, user.tier);
        if (!found) {
          return apiError(res, 404, 'DOSSIER_NOT_FOUND',
            `No ${type} record found for "${rawId}". A dossier can only be assembled for an entity already tracked by SENTINEL APEX.`);
        }
        return successResponse(res, { dossier }, {
          endpoint:       `/api/v1/intel?action=dossier&type=${type}&id=${encodeURIComponent(rawId)}`,
          description:    'Evidence-backed intelligence dossier — deterministic assessment, relationships, evidence, timeline, ATT&CK context, and analyst actions',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=detections&entity_type=&entity_id=&attack_technique=&format=&validation_status=&limit=&cursor= ─── */
      case 'detections': {
        const entityType = String(req.query.entity_type || '').trim().toLowerCase();
        const entityId = String(req.query.entity_id || '').trim();
        let rules;
        if (entityType === 'cve' && entityId) {
          rules = detectionRules.getRulesByCVE(entityId);
        } else if (entityType === 'campaign' && entityId) {
          rules = detectionRules.getRulesByCampaign(entityId);
        } else {
          const filters = {};
          if (req.query.attack_technique) filters.technique_id = String(req.query.attack_technique).trim();
          rules = detectionRules.searchRules(filters);
        }
        const format = String(req.query.format || '').trim().toLowerCase();
        if (format) {
          rules = rules.filter(r => (format === 'suricata' ? (r.suricata || []).length > 0 : !!r.platforms[format]));
        }
        let detections = rules.map(r => detectionIntelligence.toCanonicalDetectionObject(r));
        const validationStatus = String(req.query.validation_status || '').trim().toUpperCase();
        if (validationStatus) detections = detections.filter(d => d.status === validationStatus);

        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '25', 10) || 25));
        const cursor = Math.max(0, parseInt(req.query.cursor || '0', 10) || 0);
        const paged = detections.slice(cursor, cursor + limit);

        return successResponse(res, {
          detections: paged,
          pagination: {
            total: detections.length,
            limit,
            cursor,
            next_cursor: cursor + limit < detections.length ? cursor + limit : null,
          },
        }, {
          endpoint:       '/api/v1/intel?action=detections',
          description:    'Evidence-backed, validated detection intelligence -- Sigma/KQL/Splunk/OSQuery/Suricata, each carrying its L1-L7 validation record',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=detection&id=...&entity_type=&entity_id= ─── */
      case 'detection': {
        const id = String(req.query.id || '').trim();
        if (!id) {
          return apiError(res, 400, 'MISSING_DETECTION_ID', 'Detection ID required. Example: GET /api/v1/intel?action=detection&id=...');
        }
        const rule = detectionRules.getRule(id);
        if (!rule) {
          return apiError(res, 404, 'DETECTION_NOT_FOUND', `No detection found for ID "${id}".`);
        }
        // Optional entity context (mandate Phase 57's "Search -> Dossier ->
        // Detection Coverage -> Detection Detail" flow): a customer arriving
        // here from a specific CVE/campaign's coverage view already has
        // that entity's evidence-graded ATT&CK linkage established -- reuse
        // it so this same rule reports the identical status the coverage
        // view just showed, rather than the conservative UNKNOWN-evidence
        // default a bare catalog lookup must use. Never trusts the rule's
        // own source.articles/source.campaigns claim on its own; only an
        // entity whose dossier independently confirms this technique
        // resolves a non-UNKNOWN evidence state (same integrity check
        // computeCoverage() applies).
        let attackEvidenceState = 'UNKNOWN';
        const ctxType = String(req.query.entity_type || '').trim().toLowerCase();
        const ctxId = String(req.query.entity_id || '').trim();
        if ((ctxType === 'cve' || ctxType === 'campaign') && ctxId) {
          const { found: ctxFound, dossier: ctxDossier } = getDossierAPI(ctxType, ctxId, user.tier);
          if (ctxFound) {
            const match = (ctxDossier.attack_context.techniques || []).find(t => t.id === rule.technique_id);
            if (match) attackEvidenceState = detectionIntelligence.classifyAttackEvidence(match);
          }
        }
        return successResponse(res, { detection: detectionIntelligence.toCanonicalDetectionObject(rule, { attackEvidenceState }) }, {
          endpoint:       `/api/v1/intel?action=detection&id=${id}`,
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=detection-download&id=&format= ───────────── */
      case 'detection-download': {
        const id = String(req.query.id || '').trim();
        const format = String(req.query.format || '').trim().toLowerCase();
        if (!id || !format) {
          return apiError(res, 400, 'MISSING_PARAMETERS', 'Both id and format required. Example: GET /api/v1/intel?action=detection-download&id=...&format=sigma');
        }
        if (!detectionIntelligence.SUPPORTED_FORMATS.includes(format)) {
          return apiError(res, 400, 'UNSUPPORTED_FORMAT',
            `Format "${format}" is not supported. Supported: ${detectionIntelligence.SUPPORTED_FORMATS.join(', ')}.`);
        }
        const rule = detectionRules.getRule(id);
        if (!rule) return apiError(res, 404, 'DETECTION_NOT_FOUND', `No detection found for ID "${id}".`);
        const content = format === 'suricata' ? (rule.suricata || []).join('\n') : rule.platforms[format];
        if (!content) return apiError(res, 404, 'FORMAT_NOT_AVAILABLE', `Detection "${id}" has no "${format}" content.`);
        // Safe filename: derived only from the already-validated rule id
        // (hex string) and format (checked against SUPPORTED_FORMATS
        // above) -- no user-controlled path component, no traversal risk.
        const ext = format === 'sigma' ? 'yml' : format === 'suricata' ? 'rules' : 'txt';
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="detection-${rule.id}-${format}.${ext}"`);
        return res.send(content);
      }

      /* ── GET ?action=detection-coverage&type=cve|campaign&id=... ─ */
      case 'detection-coverage': {
        const type = String(req.query.type || '').trim().toLowerCase();
        if (type !== 'cve' && type !== 'campaign') {
          return apiError(res, 400, 'UNSUPPORTED_ENTITY_TYPE',
            `Coverage type "${type || '(missing)'}" is not supported. Valid: cve, campaign.`);
        }
        const id = String(req.query.id || '').trim();
        if (!id) return apiError(res, 400, 'MISSING_COVERAGE_ID', `${type} ID required.`);
        const { found, dossier } = getDossierAPI(type, id, user.tier);
        if (!found) {
          return apiError(res, 404, 'ENTITY_NOT_FOUND', `No ${type} record found for "${id}".`);
        }
        const coverage = detectionIntelligence.computeCoverage({ attackContext: dossier.attack_context, entityType: type, entityId: id });
        return successResponse(res, { coverage }, {
          endpoint:       `/api/v1/intel?action=detection-coverage&type=${type}&id=${encodeURIComponent(id)}`,
          description:    'Observed ATT&CK techniques for this entity cross-referenced against validated detection coverage -- never counts an unreleased or unvalidated rule as covered',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=detection-pack&type=cve|campaign&id=... — PRO+ only ─ */
      case 'detection-pack': {
        if (user.tier !== 'pro' && user.tier !== 'enterprise') {
          return apiError(res, 403, 'TIER_RESTRICTED',
            'Detection packs require Pro or Enterprise plan. Upgrade at https://blog.cyberdudebivash.in/pricing.html',
            { 'X-Upgrade-URL': 'https://blog.cyberdudebivash.in/pricing.html' });
        }
        const type = String(req.query.type || '').trim().toLowerCase();
        if (type !== 'cve' && type !== 'campaign') {
          return apiError(res, 400, 'UNSUPPORTED_ENTITY_TYPE', `Pack type "${type || '(missing)'}" is not supported. Valid: cve, campaign.`);
        }
        const id = String(req.query.id || '').trim();
        if (!id) return apiError(res, 400, 'MISSING_PACK_ID', `${type} ID required.`);
        const { found, dossier } = getDossierAPI(type, id, user.tier);
        if (!found) {
          return apiError(res, 404, 'ENTITY_NOT_FOUND', `No ${type} record found for "${id}".`);
        }
        const pack = detectionIntelligence.buildDetectionPack({ attackContext: dossier.attack_context, entityType: type, entityId: id });
        return successResponse(res, { pack }, {
          endpoint:       `/api/v1/intel?action=detection-pack&type=${type}&id=${encodeURIComponent(id)}`,
          description:    'A pack contains only RELEASED (fully validated) detections -- never a generated-but-unvalidated rule',
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── GET ?action=defense-coverage&type=cve|campaign&id=... ─ */
      case 'defense-coverage': {
        const type = String(req.query.type || '').trim().toLowerCase();
        if (type !== 'cve' && type !== 'campaign') {
          return apiError(res, 400, 'UNSUPPORTED_ENTITY_TYPE',
            `Coverage type "${type || '(missing)'}" is not supported. Valid: cve, campaign.`);
        }
        const id = String(req.query.id || '').trim();
        if (!id) return apiError(res, 400, 'MISSING_COVERAGE_ID', `${type} ID required.`);
        const { found, dossier } = getDossierAPI(type, id, user.tier);
        if (!found) {
          return apiError(res, 404, 'ENTITY_NOT_FOUND', `No ${type} record found for "${id}".`);
        }
        // Ownership is always re-derived from the authenticated caller's
        // userId (mandate Phase 9) -- a missing profile is not an error,
        // it is the documented safe default (mandate Phase 37): global
        // coverage is still fully computed and returned either way.
        const { profile } = await defenseProfileStore.getProfile(user.userId);
        const coverage = defenseCompatibility.computeCustomerCoverage({ attackContext: dossier.attack_context, entityType: type, entityId: id, profile });
        return successResponse(res, { coverage }, {
          endpoint:       `/api/v1/intel?action=defense-coverage&type=${type}&id=${encodeURIComponent(id)}`,
          description:    "Detection coverage cross-referenced against the caller's own Defense Profile -- READY/PARTIALLY_READY/TELEMETRY_GAP/UNSUPPORTED_PLATFORM/UNKNOWN/NO_VALIDATED_DETECTION are all deterministic, never LLM-decided",
          tier:           user.tier,
          requests_used:  user.requestsUsed,
          requests_limit: user.requestsLimit,
        });
      }

      /* ── Unknown action ────────────────────────────────────── */
      default:
        return apiError(res, 400, 'INVALID_ACTION',
          `Unknown action: "${action}". Valid actions: live, top, cve, iocs, ransomware, search, stats, graph, campaigns, campaign, top-actors, unified-search, actor, ioc, report, dossier, detections, detection, detection-download, detection-coverage, detection-pack, defense-coverage`);
    }
  } catch (e) {
    return apiError(res, 500, 'INTERNAL_ERROR',
      sec.safeError(e, 'Intel service temporarily unavailable. Please retry.'));
  }
};

/* ─── STIX 2.1 Bundle Builder (Enterprise only) ──────────────── */
function buildSTIXBundle(iocs) {
  const typeMap = {
    ipv4: 'ipv4-addr', domain: 'domain-name', url: 'url',
    sha256: 'file', md5: 'file', sha1: 'file',
  };
  return {
    type:         'bundle',
    id:           `bundle--${crypto.randomUUID()}`,
    spec_version: '2.1',
    created:      new Date().toISOString(),
    objects:      iocs.map(ioc => ({
      type:            'indicator',
      spec_version:    '2.1',
      id:              `indicator--${crypto.randomUUID()}`,
      created:         ioc.first_seen || new Date().toISOString(),
      modified:        new Date().toISOString(),
      name:            `${ioc.type}: ${ioc.value}`,
      description:     `SENTINEL APEX IOC — ${ioc.related_id || ''} | Confidence: ${Math.round((ioc.confidence_score || 0.8) * 100)}%`,
      indicator_types: [ioc.related_type === 'RANSOMWARE' ? 'malicious-activity' : 'compromised'],
      pattern:         `[${typeMap[ioc.type] || 'artifact'}:value = '${ioc.value}']`,
      pattern_type:    'stix',
      valid_from:      ioc.first_seen || new Date().toISOString(),
      confidence:      Math.round((ioc.confidence_score || 0.8) * 100),
      labels:          ['cyberdudebivash-sentinel-apex', ioc.type, ioc.related_type || 'threat'].filter(Boolean),
    })),
    extensions: { 'x-sentinel-apex': { version: '4.0', platform: 'blog.cyberdudebivash.in' } },
  };
}
