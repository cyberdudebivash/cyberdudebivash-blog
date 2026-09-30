/**
 * SENTINEL APEX — Unified Intelligence Search Index
 *
 * Computes a typed, rebuildable, versioned search projection FROM
 * already-canonical intelligence (the live threat graph, campaigns.json,
 * and the published-reports manifest) — it does not persist a second,
 * independently-mutable store. Nothing here can drift out of sync with
 * its source the way api/intel/campaigns.json did before the campaign
 * delivery integrity v1 fix (see
 * docs/audits/SENTINEL-APEX-CAMPAIGN-DELIVERY-INTEGRITY-V1-CERTIFICATION.md):
 * this index is derived fresh from already-loaded canonical data on every
 * cache-refresh, in memory, never written to disk as a second source of
 * truth. Deleting nothing here and rebuilding from graph+campaigns+reports
 * always reproduces the same index (deterministic, order-stable).
 *
 * SUPPORTED TYPES (v1) — chosen because real canonical data backs them:
 *   cve, campaign, actor, ioc, report
 *
 * DELIBERATELY NOT SUPPORTED (v1) — do not add without new real data:
 *   malware   — 0 populated Malware-type graph nodes exist anywhere in
 *               production data (confirmed directly against the live
 *               graph; also documented across 4+ sprints in
 *               platform/open-issues.md Issue 8). Offering malware
 *               search would be a search UI over a promise, not data.
 *   attack_technique (as a standalone searchable TYPE) — no canonical
 *               technique registry exists in this codebase; real
 *               technique IDs are surfaced as metadata on actor/report
 *               documents instead (see buildActorDoc/buildReportDoc),
 *               never as a first-class search entity a customer can
 *               query in isolation and expect complete results from.
 */
'use strict';

const { loadGraph, getNode, getNeighbors, getTopActors } = require('./threat-graph');
const { correctedScore } = require('./cvss-corrections');

const SEARCH_SCHEMA_VERSION = '1.0';
const SUPPORTED_TYPES = ['cve', 'campaign', 'actor', 'ioc', 'report'];

// Types excluded from free/starter search results entirely, mirroring
// threat-graph.js's own getGraphForTier() node-type gate exactly (IOC
// nodes are already withheld from free/starter graph views today) —
// reused convention, not a new entitlement decision invented here.
const FREE_TIER_EXCLUDED_TYPES = new Set(['ioc']);

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

/* ───────────────────────── per-type document builders ───────────────────────── */

function buildCveDoc(node, reportsById) {
  const a = node.attributes || {};
  const tags = [];
  if (a.cisa_kev)   tags.push('cisa_kev');
  if (a.exploited)  tags.push('exploited');
  if (a.ransomware) tags.push('ransomware');

  const reportRefs = reportsById.filter(r => r.cves.includes(node.id)).map(r => r.report_id);

  return {
    schema_version: SEARCH_SCHEMA_VERSION,
    id:          node.id,
    type:        'cve',
    name:        node.id,
    aliases:     [],
    summary:     [a.vendor, a.product].filter(Boolean).join(' — ') || null,
    severity:    a.threat_level || null,
    confidence:  null,
    first_seen:  a.published || null,
    last_seen:   a.published || null,
    updated_at:  null,
    tags,
    techniques:  [],
    sectors:     [],
    report_refs: reportRefs,
    vendor:      a.vendor || null,
    product:     a.product || null,
    cvss:        correctedScore(node.id, a.cvss),
    priority_score: typeof a.priority_score === 'number' ? a.priority_score : null,
    detail_url:  `/api/v1/intel?action=cve&id=${encodeURIComponent(node.id)}`,
    // Phase 24 (Intelligence Dossiers v1): CVE is one of the two dossier-
    // supported entity types -- additive pivot alongside detail_url, not
    // a replacement for it. Only added where a real dossier assembler
    // exists (cve/campaign); actor/ioc/report docs deliberately have no
    // dossier_url below, since no dossier type covers them yet.
    dossier_url: `/dossier.html?type=cve&id=${encodeURIComponent(node.id)}`,
  };
}

function buildCampaignDoc(campaign) {
  return {
    schema_version: SEARCH_SCHEMA_VERSION,
    id:          campaign.campaign_id,
    type:        'campaign',
    name:        campaign.name || campaign.campaign_id,
    aliases:     [],
    summary:     Array.isArray(campaign.reasoning) && campaign.reasoning[0] ? String(campaign.reasoning[0]).slice(0, 200) : null,
    severity:    campaign.severity || null,
    confidence:  typeof campaign.confidence === 'number' ? campaign.confidence : null,
    first_seen:  campaign.first_seen || null,
    last_seen:   campaign.last_seen || null,
    updated_at:  null,
    tags: [
      campaign.has_kev && 'cisa_kev',
      campaign.has_ransomware && 'ransomware',
      campaign.has_exploited && 'exploited',
    ].filter(Boolean),
    techniques:  [],
    sectors:     [],
    report_refs: [],
    item_count:  typeof campaign.item_count === 'number' ? campaign.item_count : (safeArray(campaign.related_intel).length || null),
    clustering_model: campaign.clustering_model || null,
    detail_url:  `/api/v1/intel?action=campaign&id=${encodeURIComponent(campaign.campaign_id)}`,
    // Phase 24: see buildCveDoc's identical note -- campaign is the other
    // dossier-supported entity type.
    dossier_url: `/dossier.html?type=campaign&id=${encodeURIComponent(campaign.campaign_id)}`,
  };
}

function buildActorDoc(node, reportsById) {
  const a = node.attributes || {};
  const reportRefs = reportsById
    .filter(r => safeArray(r.threat_actors).some(name => name && node.name && name.toLowerCase() === node.name.toLowerCase()))
    .map(r => r.report_id);

  return {
    schema_version: SEARCH_SCHEMA_VERSION,
    id:          node.id,
    type:        'actor',
    name:        node.name || node.id,
    aliases:     safeArray(a.aliases),
    summary:     a.description ? String(a.description).slice(0, 300) : null,
    severity:    null,
    confidence:  null,
    first_seen:  a.first_seen || null,
    last_seen:   a.last_seen || null,
    updated_at:  null,
    tags: [a.category, a.motivation, a.active ? 'active' : null].filter(Boolean),
    techniques:  safeArray(a.ttps),
    sectors:     safeArray(a.target_sectors),
    regions:     safeArray(a.target_regions),
    report_refs: reportRefs,
    cve_count:      typeof node.cve_count === 'number' ? node.cve_count : null,
    campaign_count: typeof node.campaign_count === 'number' ? node.campaign_count : null,
    activity_score: typeof node.activity_score === 'number' ? node.activity_score : null,
    detail_url:  `/api/v1/intel?action=actor&id=${encodeURIComponent(node.id)}`,
  };
}

function buildIocDoc(node) {
  const a = node.attributes || {};
  return {
    schema_version: SEARCH_SCHEMA_VERSION,
    id:          node.id,
    type:        'ioc',
    name:        node.name || node.id,
    aliases:     [],
    summary:     a.ioc_type ? `${a.ioc_type} indicator` : null,
    severity:    null,
    confidence:  typeof a.confidence === 'number' ? a.confidence : (a.confidence || null),
    first_seen:  a.first_seen || null,
    last_seen:   a.first_seen || null,
    updated_at:  null,
    tags:        a.ioc_type ? [a.ioc_type] : [],
    techniques:  [],
    sectors:     [],
    report_refs: [],
    ioc_type:    a.ioc_type || null,
    detail_url:  `/api/v1/intel?action=ioc&id=${encodeURIComponent(node.id)}`,
  };
}

function buildReportDoc(report) {
  return {
    schema_version: SEARCH_SCHEMA_VERSION,
    id:          report.report_id,
    type:        'report',
    name:        report.title || report.report_id,
    aliases:     [],
    summary:     report.title ? report.title.slice(0, 240) : null,
    severity:    report.severity || null,
    confidence:  report.overall_confidence || null,
    first_seen:  report.date || null,
    last_seen:   report.last_updated || report.date || null,
    updated_at:  report.last_updated || null,
    tags:        [report.tlp].filter(Boolean),
    techniques:  safeArray(report.attack_ids),
    sectors:     safeArray(report.sectors),
    cves:        safeArray(report.cves),
    threat_actors: safeArray(report.threat_actors),
    malware_families: safeArray(report.malware_families),
    report_refs: [report.report_id],
    url:         report.url || null,
    detail_url:  `/api/v1/intel?action=report&id=${encodeURIComponent(report.report_id)}`,
  };
}

/* ───────────────────────── index assembly ───────────────────────── */

/**
 * Pure function: canonical intelligence in, typed search documents out.
 * No I/O — callers pass already-loaded graph/campaigns/reports data, so
 * this can be unit-tested against fixtures with zero file-system or
 * runtime dependency, and reused identically on Vercel and Workers.
 */
function buildSearchIndex({ graph, campaignsData, reportsIndexData }) {
  const nodes = Object.values((graph && graph.nodes) || {});
  const reports = safeArray(reportsIndexData && reportsIndexData.reports);

  const documents = [];

  for (const node of nodes) {
    if (node.type === 'CVE')      documents.push(buildCveDoc(node, reports));
    else if (node.type === 'IOC') documents.push(buildIocDoc(node));
    // ThreatActor nodes are indexed below via getTopActors(), which
    // computes cve_count/campaign_count/activity_score from live graph
    // edges — reused unchanged rather than reimplementing that
    // computation here (there are only 8 actors total today; a high
    // limit effectively means "all of them," not literally top-N).
    //
    // Campaign identity also exists as a graph node, but campaigns.json
    // carries the richer projection (see
    // docs/architecture/INTELLIGENCE-SOURCE-OF-TRUTH-MATRIX.md's "why
    // Campaign has two contributing sources" section) — indexed from
    // campaignsData below instead, not from the graph node, to avoid
    // indexing a thinner duplicate of the same identity.
  }

  for (const actor of getTopActors(graph || { nodes: {}, edges: [] }, 100000)) {
    documents.push(buildActorDoc(actor, reports));
  }

  for (const campaign of safeArray(campaignsData && campaignsData.campaigns)) {
    if (campaign && campaign.campaign_id) documents.push(buildCampaignDoc(campaign));
  }

  for (const report of reports) {
    if (report && report.report_id) documents.push(buildReportDoc(report));
  }

  return {
    schema_version: SEARCH_SCHEMA_VERSION,
    generated:      new Date().toISOString(),
    counts: {
      cve:      documents.filter(d => d.type === 'cve').length,
      campaign: documents.filter(d => d.type === 'campaign').length,
      actor:    documents.filter(d => d.type === 'actor').length,
      ioc:      documents.filter(d => d.type === 'ioc').length,
      report:   documents.filter(d => d.type === 'report').length,
      total:    documents.length,
    },
    documents,
  };
}

/**
 * Integrity check: the index must never silently under-represent its own
 * canonical sources. This is the search-index equivalent of the
 * catastrophic-drop guard added to campaign-engine.js's saveCampaigns()
 * — except there is no persisted artifact here to protect from a bad
 * write, so the check instead validates the computed index against its
 * own inputs at build time, every time, and reports an anomaly rather
 * than silently serving a suspiciously small index.
 */
function validateSearchIndex(index, { graph, campaignsData, reportsIndexData }) {
  const problems = [];
  const graphCveCount    = Object.values((graph && graph.nodes) || {}).filter(n => n.type === 'CVE').length;
  const graphActorCount  = Object.values((graph && graph.nodes) || {}).filter(n => n.type === 'ThreatActor').length;
  const graphIocCount    = Object.values((graph && graph.nodes) || {}).filter(n => n.type === 'IOC').length;
  const campaignCount    = safeArray(campaignsData && campaignsData.campaigns).length;
  const reportCount      = safeArray(reportsIndexData && reportsIndexData.reports).length;

  if (index.counts.cve !== graphCveCount)           problems.push(`cve: indexed ${index.counts.cve} != graph ${graphCveCount}`);
  if (index.counts.actor !== graphActorCount)        problems.push(`actor: indexed ${index.counts.actor} != graph ${graphActorCount}`);
  if (index.counts.ioc !== graphIocCount)             problems.push(`ioc: indexed ${index.counts.ioc} != graph ${graphIocCount}`);
  if (index.counts.campaign !== campaignCount)        problems.push(`campaign: indexed ${index.counts.campaign} != canonical ${campaignCount}`);
  if (index.counts.report !== reportCount)            problems.push(`report: indexed ${index.counts.report} != canonical ${reportCount}`);

  const ids = index.documents.map(d => d.id);
  if (new Set(ids).size !== ids.length) problems.push('duplicate document IDs found in index');

  for (const d of index.documents) {
    if (!SUPPORTED_TYPES.includes(d.type)) problems.push(`unsupported type leaked into index: ${d.type} (id=${d.id})`);
  }

  return { valid: problems.length === 0, problems };
}

/* ───────────────────────── query / ranking ───────────────────────── */

const MIN_QUERY_LENGTH = 2;
const MAX_QUERY_LENGTH = 200;   // matches the existing action=search precedent (api/v1/intel.js)
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;          // matches parsePagination()'s existing cap in api/_lib/intel.js
const MAX_TYPE_FILTERS = SUPPORTED_TYPES.length; // bounds an abusive "type=a,b,c,...x1000" list
const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}/;

/**
 * Deterministic, documented ranking — no fuzzy/opaque scoring in v1
 * (Phase 11's own instruction). Exact id/name/alias match ranks above
 * prefix match, which ranks above substring match; ties break on
 * freshness (last_seen desc) then severity (CRITICAL first).
 */
function matchScore(doc, qLower) {
  const id   = doc.id.toLowerCase();
  const name = (doc.name || '').toLowerCase();

  if (id === qLower)   return { score: 100, matched_field: 'id' };
  if (name === qLower) return { score: 95,  matched_field: 'name' };
  for (const alias of doc.aliases || []) {
    if (alias.toLowerCase() === qLower) return { score: 90, matched_field: 'alias' };
  }
  if (id.startsWith(qLower))   return { score: 75, matched_field: 'id' };
  if (name.startsWith(qLower)) return { score: 70, matched_field: 'name' };
  if (name.includes(qLower))   return { score: 55, matched_field: 'name' };
  for (const alias of doc.aliases || []) {
    if (alias.toLowerCase().includes(qLower)) return { score: 50, matched_field: 'alias' };
  }
  if (doc.summary && doc.summary.toLowerCase().includes(qLower)) return { score: 40, matched_field: 'summary' };
  if (doc.vendor  && doc.vendor.toLowerCase().includes(qLower))  return { score: 35, matched_field: 'vendor' };
  if (doc.product && doc.product.toLowerCase().includes(qLower)) return { score: 35, matched_field: 'product' };
  return null;
}

function clampInt(value, fallback, min, max) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

/**
 * Bounded, typed, paginated search over an already-built index. Pure
 * function — no I/O, no auth, no tier lookup of its own; the caller
 * (api/v1/intel.js's action=unified-search) applies auth/rate-limiting
 * before this ever runs, and passes the resolved tier through.
 *
 * Every filter here is bounded (Phase 41): query length 2-200 chars
 * (matching the existing action=search precedent exactly), limit
 * clamped 1-100, offset clamped >=0, type-filter list capped at the
 * number of actually-supported types, malformed/reversed date ranges
 * degrade to an empty result rather than throwing or scanning unbounded.
 */
function searchDocuments(index, rawQuery, options = {}) {
  const query = String(rawQuery || '').trim();

  if (query.length < MIN_QUERY_LENGTH) {
    return { ok: false, error: 'QUERY_TOO_SHORT', message: `Query must be at least ${MIN_QUERY_LENGTH} characters.` };
  }
  if (query.length > MAX_QUERY_LENGTH) {
    return { ok: false, error: 'QUERY_TOO_LONG', message: `Query must be under ${MAX_QUERY_LENGTH} characters.` };
  }

  const qLower = query.toLowerCase();
  const tier   = options.tier;
  const limit  = clampInt(options.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = clampInt(options.offset, 0, 0, Number.MAX_SAFE_INTEGER);

  let candidates = index.documents;

  if (tier === 'free' || tier === 'starter') {
    candidates = candidates.filter(d => !FREE_TIER_EXCLUDED_TYPES.has(d.type));
  }

  if (options.type) {
    const requested = String(options.type).toLowerCase().split(',').map(t => t.trim()).filter(Boolean).slice(0, MAX_TYPE_FILTERS);
    const validTypes = requested.filter(t => SUPPORTED_TYPES.includes(t));
    if (validTypes.length > 0) candidates = candidates.filter(d => validTypes.includes(d.type));
  }

  if (options.severity) {
    const sev = String(options.severity).toUpperCase();
    candidates = candidates.filter(d => d.severity === sev);
  }

  // Date semantics (Phase 17): filters apply to last_seen only — the
  // single, unambiguous "most recently observed/updated" field every
  // supported type populates consistently. A document with no last_seen
  // is excluded from a date-filtered query rather than guessed at.
  if (options.from && ISO_DATE_RE.test(options.from)) {
    candidates = candidates.filter(d => d.last_seen && d.last_seen >= options.from);
  }
  if (options.to && ISO_DATE_RE.test(options.to)) {
    candidates = candidates.filter(d => d.last_seen && d.last_seen <= options.to);
  }

  const scored = [];
  for (const doc of candidates) {
    const m = matchScore(doc, qLower);
    if (m) scored.push({ doc, score: m.score, matched_field: m.matched_field });
  }

  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const aDate = a.doc.last_seen || '';
    const bDate = b.doc.last_seen || '';
    if (aDate !== bDate) return bDate.localeCompare(aDate);
    return (SEVERITY_ORDER[b.doc.severity] || 0) - (SEVERITY_ORDER[a.doc.severity] || 0);
  });

  const total = scored.length;
  const page  = scored.slice(offset, offset + limit);

  return {
    ok: true,
    query,
    results: page.map(r => ({
      id:           r.doc.id,
      type:         r.doc.type,
      name:         r.doc.name,
      summary:      r.doc.summary,
      severity:     r.doc.severity,
      tags:         r.doc.tags,
      last_seen:    r.doc.last_seen,
      score:        r.score,
      matched_field: r.matched_field,
      detail_url:   r.doc.detail_url,
    })),
    pagination: {
      limit, offset, total,
      has_more: offset + limit < total,
    },
    schema_version: index.schema_version,
    index_generated: index.generated,
  };
}

/* ───────────────────────── entity detail + relationships ───────────────────────── */

/**
 * Builds a chronological timeline from a set of {date, label} candidates.
 * Only events with a real, known date are included — Phase 31's own
 * instruction not to invent exact timestamps when only a date is known
 * is honored by omitting undated events entirely rather than guessing.
 * Duplicate (date, label) pairs are collapsed; sort is stable and
 * ascending by date string (all source dates here are ISO-prefixed,
 * so lexicographic order is chronological order).
 */
function buildTimeline(candidates) {
  const seen = new Set();
  const events = [];
  for (const c of candidates) {
    if (!c || !c.date || typeof c.date !== 'string' || !ISO_DATE_RE.test(c.date)) continue;
    const key = `${c.date}|${c.label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    events.push({ date: c.date, label: c.label, type: c.type || 'event' });
  }
  events.sort((a, b) => a.date.localeCompare(b.date));
  return events;
}

function relatedFromEdges(edges) {
  return edges.map(e => ({
    id:           e.node.id,
    type:         e.node.type,
    name:         e.node.name,
    relationship: e.relationship,
    confidence:   typeof e.confidence === 'number' ? e.confidence : null,
    direction:    e.direction,
    // Evidence/provenance (Phase 26/27): real citations already carried
    // on the edge, not a separate evidence store -- an empty array here
    // honestly means "no source citation recorded for this specific
    // edge," not "not evidence-backed at all" (confidence/relationship
    // still stand on their own).
    evidence: {
      sources:    Array.isArray(e.sources) ? e.sources : [],
      first_seen: e.first_seen || null,
    },
  }));
}

/**
 * Single-actor detail: identity + real graph relationships (exploits ->
 * CVEs, executes -> Campaigns, co_occurs_with -> other Actors) computed
 * live via getNeighbors() — the same primitive already proven by
 * campaign-engine.js, not a new relationship engine (Phase 28).
 */
function getActorDetail(graph, actorId) {
  const node = getNode(graph, actorId);
  if (!node || node.type !== 'ThreatActor') return { found: false, actor: null };

  const a = node.attributes || {};
  const relatedCves      = relatedFromEdges(getNeighbors(graph, actorId, 'exploits'));
  const relatedCampaigns = relatedFromEdges(getNeighbors(graph, actorId, 'executes'));
  const relatedActors    = relatedFromEdges(getNeighbors(graph, actorId, 'co_occurs_with'));

  const timeline = buildTimeline([
    a.first_seen && { date: a.first_seen, label: `${node.name} first observed`, type: 'first_observed' },
    a.last_seen  && { date: a.last_seen,  label: `${node.name} last observed`,  type: 'last_observed' },
  ].filter(Boolean));

  return {
    found: true,
    actor: {
      id: node.id, type: node.type, name: node.name, attributes: a,
      related_cves: relatedCves,
      related_campaigns: relatedCampaigns,
      related_actors: relatedActors,
      timeline,
    },
  };
}

/**
 * Single-IOC detail. IOC "freshness"/evidence semantics (Phase 24): this
 * only reports what the graph actually knows — a first_seen date and
 * whatever it is linked to — and never claims an IOC is "currently
 * active" or "malicious" beyond what its own attributes/edges already
 * assert. A citation URL that merely co-occurred with an item is not
 * upgraded into a maliciousness claim here.
 */
function getIocDetail(graph, iocId) {
  const node = getNode(graph, iocId);
  if (!node || node.type !== 'IOC') return { found: false, ioc: null };

  const a = node.attributes || {};
  const linkedFrom = relatedFromEdges(getNeighbors(graph, iocId, 'linked_to'));

  return {
    found: true,
    ioc: {
      id: node.id, type: node.type, name: node.name, attributes: a,
      linked_intel: linkedFrom,
      timeline: buildTimeline([
        a.first_seen && { date: a.first_seen, label: `${node.name} first observed`, type: 'first_observed' },
      ].filter(Boolean)),
    },
  };
}

/**
 * Real relationships for a single CVE, via the same getNeighbors()
 * primitive as every other entity here -- campaigns that include it
 * ('includes', inbound), actors that exploit it ('exploits', inbound),
 * and any co_occurs_with correlation to other CVEs. Returns empty
 * arrays (not an error) for a CVE with no linked campaigns/actors --
 * true for the large majority of the 4,300+ CVE nodes today, and
 * honestly represented as "none found," not omitted or guessed at.
 */
function getCveRelated(graph, cveId) {
  return {
    related_campaigns: relatedFromEdges(getNeighbors(graph, cveId, 'includes')),
    related_actors:    relatedFromEdges(getNeighbors(graph, cveId, 'exploits')),
    related_cves:      relatedFromEdges(getNeighbors(graph, cveId, 'co_occurs_with')),
  };
}

/**
 * Single-report detail, sourced from the reports-index manifest (built
 * by scripts/generate-reports-index.js from real front matter — nothing
 * here is re-derived or guessed).
 */
function getReportDetail(reportsIndexData, reportId) {
  const reports = safeArray(reportsIndexData && reportsIndexData.reports);
  const normalized = String(reportId || '').toUpperCase();
  const report = reports.find(r => String(r.report_id).toUpperCase() === normalized);
  if (!report) return { found: false, report: null };

  const timeline = buildTimeline([
    report.date          && { date: report.date, label: `${report.report_id} published`, type: 'published' },
    report.last_updated && report.last_updated !== report.date &&
      { date: report.last_updated, label: `${report.report_id} last updated`, type: 'updated' },
  ].filter(Boolean));

  return { found: true, report: { ...report, timeline } };
}

module.exports = {
  SEARCH_SCHEMA_VERSION, SUPPORTED_TYPES, FREE_TIER_EXCLUDED_TYPES,
  buildCveDoc, buildCampaignDoc, buildActorDoc, buildIocDoc, buildReportDoc,
  buildSearchIndex, validateSearchIndex, searchDocuments,
  buildTimeline, getActorDetail, getIocDetail, getReportDetail, getCveRelated,
};
