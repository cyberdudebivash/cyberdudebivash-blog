/**
 * SENTINEL APEX — Intelligence Dossier Assembler
 *
 * A dossier is a customer-safe, evidence-backed, decision-oriented
 * PROJECTION of one canonical intelligence object (CVE or Campaign). It
 * is not a new intelligence store: every field here is read from, or
 * directly derived from, data that already exists in
 * api/_lib/threat-graph.js's graph, api/intel/campaigns.json, the
 * published-reports manifest, or the CVE enrichment index -- the exact
 * same canonical sources api/_lib/intel.js and api/_lib/search-index.js
 * already serve. Nothing here is persisted; a dossier is computed fresh
 * on every request from already-loaded data, the same "no second store"
 * discipline search-index.js's own header documents and this file
 * inherits deliberately.
 *
 * LLM POLICY: nothing in this module calls an LLM. Every assessment,
 * evidence claim, timeline entry, and analyst action below is derived
 * deterministically from structured facts already present on the
 * canonical record. If an LLM-authored language summary is ever added on
 * top of this, it must consume this module's own output as its only
 * input and may not introduce a new entity, exploitation claim,
 * attribution, confidence value, or statistic beyond what is already
 * here -- this structured dossier remains authoritative.
 */
'use strict';

const { getNeighbors } = require('./threat-graph');
const { tierAtLeast } = require('./tier-entitlements');
const detectionIntelligence = require('./detection-intelligence');

const DOSSIER_SCHEMA_VERSION = '1.0';

/* ───────────────────────── shared helpers ───────────────────────── */

function relatedFromEdges(edges, limit) {
  const mapped = edges.map(e => ({
    id:           e.node.id,
    type:         e.node.type,
    name:         e.node.name,
    relationship: e.relationship,
    confidence:   typeof e.confidence === 'number' ? e.confidence : null,
    evidence: {
      sources:    Array.isArray(e.sources) ? e.sources : [],
      first_seen: e.first_seen || null,
    },
  }));
  return {
    items: typeof limit === 'number' ? mapped.slice(0, limit) : mapped,
    total: mapped.length,
  };
}

// Phase 31: bound an already-shaped relationship array (e.g. the output
// of getCveRelated(), already {id, type, name, relationship, confidence,
// evidence}) to at most `limit` items, while preserving the real total
// count so the caller can show "12 related, showing 20" honestly rather
// than silently truncating.
function boundList(items, limit) {
  const list = Array.isArray(items) ? items : [];
  return { items: list.slice(0, limit), total: list.length };
}

// Phase 17: deterministic timeline ordering; unknown/malformed dates are
// dropped rather than falsely placed, and exact date+label duplicates
// (the same fact reaching this function from two paths) are collapsed.
function buildDossierTimeline(candidates) {
  const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}/;
  const seen = new Set();
  const events = [];
  for (const c of candidates) {
    if (!c || !c.date || typeof c.date !== 'string' || !ISO_DATE_RE.test(c.date)) continue;
    const key = `${c.date}|${c.label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    events.push({ date: c.date, label: c.label, type: c.type || 'event', source_refs: c.source_refs || [] });
  }
  events.sort((a, b) => a.date.localeCompare(b.date));
  return events;
}

// Phase 13: data-quality panel. Rules are deterministic and documented
// here, not invented per-call -- see the certification doc for the exact
// thresholds this function encodes.
function computeDataQuality({ sourceCount, hasStrongConfidenceSignal, lastKnownDate }) {
  const evidence_coverage =
    sourceCount >= 2 ? 'STRONG' : sourceCount === 1 ? 'MODERATE' : 'LIMITED';

  const confidence =
    hasStrongConfidenceSignal ? 'HIGH' : sourceCount >= 1 ? 'MEDIUM' : 'UNKNOWN';

  let freshness = 'UNKNOWN';
  if (lastKnownDate) {
    const days = (Date.now() - new Date(lastKnownDate).getTime()) / 86400000;
    if (!isNaN(days)) {
      freshness = days <= 30 ? 'CURRENT' : days <= 180 ? 'RECENT' : 'HISTORICAL';
    }
  }

  return { evidence_coverage, confidence, freshness, source_count: sourceCount };
}

// Shared with api/_lib/watchable-state.js (watchlist change detection) so
// a campaign's confidence bucket can never disagree between its dossier
// and its change-detection state -- one threshold definition, not two.
function campaignConfidenceBucket(confidence) {
  if (typeof confidence !== 'number') return 'UNKNOWN';
  if (confidence >= 0.8) return 'HIGH';
  if (confidence >= 0.5) return 'MEDIUM';
  return 'LOW';
}

// Phase 18: ATT&CK techniques are never generated for a CVE/Campaign
// directly -- confirmed against real data that no live automated mapping
// exists at that level (see the certification doc's reuse audit). The
// only two real, evidence-backed paths are a linked report's own
// attack_ids, or a linked actor's static, curated ttps -- both surfaced
// with an explicit "via" attribution, never presented as the CVE/
// campaign's own established techniques.
function buildAttackContext(relatedActorNodes, matchingReports) {
  const techniques = [];
  const seen = new Set();

  for (const report of matchingReports) {
    for (const id of (report.attack_ids || [])) {
      const key = `report:${id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      techniques.push({ id, source: 'linked_report', via: report.report_id });
    }
  }
  for (const actor of relatedActorNodes) {
    const ttps = (actor.attributes && actor.attributes.ttps) || [];
    for (const id of ttps) {
      const key = `actor:${actor.id}:${id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      techniques.push({ id, source: 'linked_actor', via: actor.id, via_name: actor.name });
    }
  }

  // Phase 31/60: bounded output. relatedActorNodes is already capped at
  // 20 by boundList() upstream, but each actor can carry several TTPs and
  // matchingReports is not itself size-limited -- cap the final list so a
  // dense future data set can never produce an unbounded response.
  return {
    status: techniques.length > 0 ? 'established' : 'not_established',
    techniques: techniques.slice(0, 50),
    total_techniques: techniques.length,
  };
}

// Phase 19/20: detections are deliberately not wired to a per-CVE/
// campaign lookup in this tranche -- verified directly against
// api/intel/products/*.json that only 314/1,664 (19%) files carry any
// real detection content, that content is not reliably keyed to a CVE ID
// (the checked sample had an empty cves[] and low-signal content, e.g. a
// Suricata rule matching a citation URL rather than a genuine
// exploitation indicator), and a live per-request scan of 1,664 files
// would itself be a real performance risk this dossier's own bounded-
// output discipline exists to avoid. "No detection artifact currently
// available" is the honest, mandate-sanctioned default until a clean,
// reliable, CVE/campaign-keyed detection index exists (tracked in
// platform/open-issues.md).
// Threat-to-Defense Fabric v1: delegates to detection-intelligence.js,
// which cross-references the canonical detection-rule store
// (api/_lib/detection-rules.js) by technique ID and CVE/campaign ID
// against the already-evidence-graded attack_context this function's
// callers pass in. See docs/audits/SENTINEL-APEX-DETECTION-CAPABILITY-
// INVENTORY-V1.md for why no new detection store was built.
function buildDetectionsSection(attackContext, entityType, entityId) {
  return detectionIntelligence.buildDossierDetectionsSection(attackContext, entityType, entityId);
}

/* ───────────────────────── CVE dossier ───────────────────────── */

// Phase 6: CVE evidence states. cisa_kev is a government-verified
// registry entry -- treated as CONFIRMED. exploited (without cisa_kev)
// is an ingestion-pipeline signal of unknown independent verification --
// treated as ASSESSED, not CONFIRMED. Neither flag set is UNKNOWN, never
// silently treated as "not exploited."
function classifyExploitation(attrs) {
  if (attrs.cisa_kev) {
    return { status: 'CONFIRMED', basis: 'Listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.' };
  }
  if (attrs.exploited) {
    return { status: 'ASSESSED', basis: 'Flagged as exploited by ingestion-pipeline signals; not independently KEV-confirmed.' };
  }
  return { status: 'UNKNOWN', basis: 'No exploitation signal recorded for this CVE.' };
}

// Overall confidence label for the CVE record itself (distinct from
// per-relationship confidence already carried on each graph edge): a
// government-verified KEV listing is HIGH regardless of source count; a
// record with at least one cited source is MEDIUM; an uncited record is
// UNKNOWN, never silently assumed to be reliable.
function cveConfidence(attrs, sourceCount) {
  if (attrs.cisa_kev) return { overall: 'HIGH', basis: 'CISA KEV-confirmed.' };
  if (sourceCount > 0) return { overall: 'MEDIUM', basis: 'Single-source record.' };
  return { overall: 'UNKNOWN', basis: 'No source citations recorded.' };
}

function cveAssessment(cveId, attrs, enrichment) {
  const factors = [];
  if (enrichment && enrichment.explanation && Array.isArray(enrichment.explanation.priority)) {
    factors.push(...enrichment.explanation.priority);
  }
  const parts = [];
  if (typeof attrs.cvss === 'number' && attrs.cvss > 0) parts.push(`CVSS ${attrs.cvss}`);
  if (attrs.cisa_kev) parts.push('CISA KEV-listed');
  else if (attrs.exploited) parts.push('exploitation signals present (not KEV-confirmed)');
  if (attrs.ransomware) parts.push('linked to ransomware activity');
  const summary = parts.length
    ? `${cveId}: ${parts.join(', ')}.`
    : `${cveId}: no elevated risk signals currently recorded.`;
  return { summary, factors };
}

// NOTE on source_refs below: graph-edge evidence.sources (relationships,
// above) are always real citation URLs. enrichment.sources (this CVE's
// own record provenance, e.g. "cisa_kev") are short provenance TAGS, not
// URLs -- both land in a claim's source_refs[] here since both are
// legitimate provenance, but a UI rendering source_refs as clickable
// links MUST validate each entry looks like a real http(s) URL first
// (Phase 40) rather than assume every entry is one.
function cveEvidenceClaims(cveId, attrs, enrichment) {
  const claims = [];
  const exploitation = classifyExploitation(attrs);
  claims.push({
    claim: `${cveId} is under active exploitation`,
    status: exploitation.status.toLowerCase(),
    confidence: exploitation.status === 'CONFIRMED' ? 'high' : exploitation.status === 'ASSESSED' ? 'medium' : 'unknown',
    source_refs: (enrichment && enrichment.sources) || [],
    // No distinct "last verified" timestamp exists in this platform's data
    // model (separate from the record's own published/updated date) --
    // honestly null rather than reusing a different date under a
    // misleading label.
    last_verified: null,
  });
  if (attrs.cisa_kev) {
    claims.push({
      claim: `${cveId} is listed in the CISA KEV catalog`,
      status: 'confirmed',
      confidence: 'high',
      source_refs: (enrichment && enrichment.sources) || [],
      last_verified: null,
    });
  }
  return claims;
}

function cveAnalystActions(cveId, attrs, exploitation, hasCampaignLink) {
  const actions = [];
  if (exploitation.status === 'CONFIRMED') {
    actions.push({ action: 'Validate exposure to this CVE in your environment now', rationale: 'Confirmed active exploitation (CISA KEV-listed).' });
  } else if (exploitation.status === 'ASSESSED') {
    actions.push({ action: 'Review exploitation indicators before prioritizing remediation', rationale: 'Exploitation signals present but not independently confirmed.' });
  }
  if (typeof attrs.cvss === 'number' && attrs.cvss >= 9) {
    actions.push({ action: 'Treat as a critical-priority patch/mitigation candidate', rationale: `CVSS ${attrs.cvss} (critical range).` });
  }
  if (hasCampaignLink) {
    actions.push({ action: 'Review the linked campaign for related infrastructure and activity', rationale: 'This CVE is associated with a tracked campaign.' });
  }
  actions.push({ action: 'Hunt for related activity in your environment using available evidence sources', rationale: 'Standard follow-up for any tracked vulnerability record.' });
  return actions;
}

/**
 * Assemble a CVE dossier.
 *
 * @param graph          the loaded threat graph (from loadGraph())
 * @param cveItem         the tier-filtered item already returned by getCVEDetail()
 * @param enrichment      this CVE's entry from the cve-enrichment-index, or null
 * @param reportsIndexData the loaded reports-index.json data
 * @param tier            the requesting user's tier
 */
function buildCveDossier({ graph, cveId, cveItem, enrichment, reportsIndexData, tier }) {
  const attrs = {
    cvss:           typeof cveItem.cvss === 'number' ? cveItem.cvss : null,
    threat_level:   cveItem.threat_level || null,
    priority_score: typeof cveItem.priority_score === 'number' ? cveItem.priority_score : null,
    exploited:      !!cveItem.exploited,
    cisa_kev:       !!(cveItem.cisa_kev || cveItem.cisaKev),
    ransomware:     !!cveItem.ransomware,
    vendor:         cveItem.vendor || null,
    product:        cveItem.product || null,
    published:      cveItem.published || cveItem.pubDate || null,
  };

  // Phase 37/39 (entitlements, tier bypass): relationships are computed
  // directly from the graph -- not read off cveItem.related, which only
  // exists at all when the caller already tier-gated it (pro/enterprise
  // via attachCveRelated()) -- so this module enforces the exact same
  // free/starter gate itself, deterministically, rather than trusting an
  // upstream caller to have done so. A free/starter dossier must see
  // empty relationships here, matching action=cve's own contract exactly;
  // it must never gain fuller relationship access through this endpoint
  // than it already has through the existing one.
  const tierAllowsRelationships = tierAtLeast(tier, 'pro');
  const related = (tierAllowsRelationships && graph) ? {
    related_campaigns: relatedFromEdges(getNeighbors(graph, cveId, 'includes')).items,
    related_actors:    relatedFromEdges(getNeighbors(graph, cveId, 'exploits')).items,
    related_cves:      relatedFromEdges(getNeighbors(graph, cveId, 'co_occurs_with')).items,
  } : { related_campaigns: [], related_actors: [], related_cves: [] };

  const boundedCampaigns = boundList(related.related_campaigns, 20);
  const boundedActors    = boundList(related.related_actors, 20);
  const boundedCves      = boundList(related.related_cves, 20);

  const reports = ((reportsIndexData && reportsIndexData.reports) || [])
    .filter(r => Array.isArray(r.cves) && r.cves.includes(cveId));

  const actorNodes = (related.related_actors || [])
    .map(r => graph ? graph.nodes[r.id] : null)
    .filter(Boolean);

  const exploitation = classifyExploitation(attrs);
  const sources = (enrichment && enrichment.sources) || [];

  const dossier = {
    schema_version: DOSSIER_SCHEMA_VERSION,
    entity_id:   cveId,
    entity_type: 'cve',
    generated_at: new Date().toISOString(),
    data_updated_at: (graph && graph.generated) || null,

    identity: {
      cve_id:  cveId,
      vendor:  attrs.vendor,
      product: attrs.product,
    },

    overview: [attrs.vendor, attrs.product].filter(Boolean).join(' — ') || null,

    assessment: cveAssessment(cveId, attrs, enrichment),

    risk: {
      cvss:            attrs.cvss,
      threat_level:    attrs.threat_level,
      priority_score:  attrs.priority_score,
      epss_score:      (enrichment && enrichment.epss_score) ?? null,
      epss_percentile: (enrichment && enrichment.epss_percentile) ?? null,
    },

    exploitation: {
      active_exploitation: exploitation,
      kev_listed:      attrs.cisa_kev,
      poc_status:      { status: 'UNKNOWN', basis: 'No proof-of-concept tracking signal exists in this platform\'s data model.' },
      due_date:        (enrichment && enrichment.due_date) || null,
      required_action: (enrichment && enrichment.required_action) || null,
    },

    confidence: cveConfidence(attrs, (enrichment && enrichment.sources_confirmed) || sources.length),

    relationships: {
      related_campaigns: boundedCampaigns.items,
      related_actors:     boundedActors.items,
      related_cves:       boundedCves.items,
      counts: {
        campaigns: boundedCampaigns.total,
        actors:    boundedActors.total,
        cves:      boundedCves.total,
      },
    },

    evidence: cveEvidenceClaims(cveId, attrs, enrichment),

    timeline: buildDossierTimeline([
      attrs.published && { date: attrs.published, label: `${cveId} published`, type: 'published' },
      (enrichment && enrichment.due_date) && { date: enrichment.due_date, label: `${cveId} KEV remediation due`, type: 'kev_due' },
      ...reports.map(r => ({ date: r.date, label: `${r.report_id} published, covers ${cveId}`, type: 'report_published', source_refs: [r.url] })),
    ].filter(Boolean)),

    attack_context: buildAttackContext(actorNodes, reports),

    detections: buildDetectionsSection(buildAttackContext(actorNodes, reports), 'cve', cveId),

    reports: reports.map(r => ({ report_id: r.report_id, title: r.title, url: r.url, date: r.date })),

    analyst_actions: cveAnalystActions(cveId, attrs, exploitation, boundedCampaigns.total > 0),

    data_quality: computeDataQuality({
      sourceCount: (enrichment && enrichment.sources_confirmed) || sources.length,
      hasStrongConfidenceSignal: attrs.cisa_kev,
      lastKnownDate: attrs.published,
    }),

    // Phase 29 (customer-safe null states): a free/starter dossier's
    // empty relationships must be distinguishable from a genuinely sparse
    // record's empty relationships -- relationships_gated: true tells the
    // UI "this is hidden by your plan," not "nothing exists here."
    tier_info: {
      tier,
      relationships_gated: !tierAllowsRelationships,
      upgrade_message: !tierAllowsRelationships ? (cveItem._upgrade || null) : null,
    },
  };

  return dossier;
}

/* ───────────────────────── Campaign dossier ───────────────────────── */

function campaignAssessment(campaign) {
  // Phase 53 (adversarial: "campaign missing name"): fall back to
  // campaign_id, matching search-index.js's buildCampaignDoc() precedent
  // exactly -- a summary must never literally read "undefined: ...".
  const displayName = campaign.name || campaign.campaign_id;
  const parts = [];
  if (campaign.severity) parts.push(`${campaign.severity} severity`);
  if (campaign.has_kev) parts.push('includes CISA KEV-listed vulnerabilities');
  if (campaign.has_ransomware) parts.push('linked to ransomware activity');
  if (campaign.has_exploited) parts.push('includes actively exploited vulnerabilities');
  if (Array.isArray(campaign.threat_actors) && campaign.threat_actors.length) {
    parts.push(`attributed to ${campaign.threat_actors.map(a => a.name).join(', ')}`);
  }
  const summary = parts.length
    ? `${displayName}: ${parts.join(', ')}.`
    : `${displayName}: no elevated risk signals currently recorded.`;
  const factors = Array.isArray(campaign.reasoning) ? campaign.reasoning.slice(0, 5) : [];
  return { summary, factors };
}

// Phase 8: campaign attribution truth states. This platform's data model
// carries a single numeric confidence per attributed actor, not a
// separate CONFIRMED/VENDOR-ATTRIBUTED/DISPUTED taxonomy -- rather than
// fabricate a distinction the data cannot support, attribution is
// reported as ASSESSED (with its real confidence score) whenever an
// actor is attributed, and UNKNOWN when none is. This is deliberately
// coarser than the mandate's full state list; see the certification
// doc's Known Limitations for why a finer distinction is not built here.
function campaignAttribution(campaign) {
  const actors = Array.isArray(campaign.threat_actors) ? campaign.threat_actors : [];
  if (actors.length === 0) {
    return { status: 'UNKNOWN', actors: [], basis: 'No evidence-backed actor association currently established.' };
  }
  return {
    status: 'ASSESSED',
    actors: actors.map(a => ({ id: a.id, name: a.name, confidence: a.confidence, category: a.category })),
    basis: 'Actor attribution derived from the platform\'s CVE/IOC/keyword correlation signals; see individual actor confidence scores.',
  };
}

function campaignAnalystActions(campaign, attribution) {
  const actions = [];
  if (attribution.status === 'ASSESSED') {
    actions.push({ action: 'Review actor-related infrastructure and known TTPs', rationale: `Attributed to ${attribution.actors.map(a => a.name).join(', ')}.` });
  }
  if ((campaign.shared_iocs || []).length) {
    actions.push({ action: 'Hunt for the campaign\'s known indicators in your environment', rationale: `${campaign.shared_iocs.length} shared indicator(s) recorded.` });
  }
  if ((campaign.shared_cves || []).length) {
    actions.push({ action: 'Confirm remediation status for all CVEs linked to this campaign', rationale: `${campaign.shared_cves.length} linked CVE(s).` });
  }
  actions.push({ action: 'Monitor this campaign for new related activity', rationale: 'Standard follow-up for any tracked campaign.' });
  return actions;
}

function buildCampaignDossier({ graph, campaign, reportsIndexData, tier }) {
  const campaignId = campaign.campaign_id;
  const attribution = campaignAttribution(campaign);

  // Phase 37/39: related-campaign correlation (co_occurs_with) is new
  // relationship depth this dossier adds beyond getCampaignDetail()'s
  // existing contract -- gated free/starter-excluded to match the
  // established pattern for every other cross-entity relationship in
  // this codebase (action=cve/actor's related_* fields), not left
  // ungated by default.
  const tierAllowsRelationships = tierAtLeast(tier, 'pro');
  const relatedCampaigns = (tierAllowsRelationships && graph)
    ? relatedFromEdges(getNeighbors(graph, campaignId, 'co_occurs_with'), 20)
    : { items: [], total: 0 };

  const reports = ((reportsIndexData && reportsIndexData.reports) || [])
    .filter(r => Array.isArray(r.cves) && (campaign.shared_cves || []).some(c => r.cves.includes(c)));

  const actorNodes = attribution.actors
    .map(a => graph ? graph.nodes[a.id] : null)
    .filter(Boolean);

  const sourceCount = (campaign.related_intel || []).length || (campaign.item_count || 0);

  const dossier = {
    schema_version: DOSSIER_SCHEMA_VERSION,
    entity_id:   campaignId,
    entity_type: 'campaign',
    generated_at: new Date().toISOString(),
    data_updated_at: null,

    identity: {
      campaign_id: campaignId,
      name:        campaign.name || campaignId,
      aliases:     [],
    },

    overview: Array.isArray(campaign.reasoning) && campaign.reasoning[0] ? String(campaign.reasoning[0]) : null,

    assessment: campaignAssessment(campaign),

    risk: {
      severity:           campaign.severity || null,
      confidence:         typeof campaign.confidence === 'number' ? campaign.confidence : null,
      max_priority_score: typeof campaign.max_priority_score === 'number' ? campaign.max_priority_score : null,
      item_count:         typeof campaign.item_count === 'number' ? campaign.item_count : null,
    },

    exploitation: {
      has_kev:       !!campaign.has_kev,
      has_exploited: !!campaign.has_exploited,
      has_ransomware: !!campaign.has_ransomware,
    },

    confidence: {
      overall: campaignConfidenceBucket(campaign.confidence),
      basis:   'Derived from the campaign clustering engine\'s own composite confidence score.',
    },

    attribution,

    relationships: {
      related_campaigns: relatedCampaigns.items,
      related_actors:     attribution.actors,
      related_cves:       (campaign.shared_cves || []).map(id => ({ id, type: 'cve', name: id })),
      counts: {
        campaigns: relatedCampaigns.total,
        actors:    attribution.actors.length,
        cves:      (campaign.shared_cves || []).length,
        iocs:      (campaign.shared_iocs || []).length,
      },
    },

    evidence: (Array.isArray(campaign.reasoning) ? campaign.reasoning : []).map(r => ({
      claim: r,
      status: 'confirmed',
      confidence: 'medium',
      source_refs: [],
      last_verified: null,
    })),

    timeline: buildDossierTimeline([
      campaign.first_seen && { date: campaign.first_seen, label: `${campaign.name} first observed`, type: 'first_observed' },
      campaign.last_seen  && { date: campaign.last_seen,  label: `${campaign.name} last observed`,  type: 'last_observed' },
      ...reports.map(r => ({ date: r.date, label: `${r.report_id} published, covers linked CVE(s)`, type: 'report_published', source_refs: [r.url] })),
    ].filter(Boolean)),

    attack_context: buildAttackContext(actorNodes, reports),

    detections: buildDetectionsSection(buildAttackContext(actorNodes, reports), 'campaign', campaignId),

    reports: reports.map(r => ({ report_id: r.report_id, title: r.title, url: r.url, date: r.date })),

    analyst_actions: campaignAnalystActions(campaign, attribution),

    data_quality: computeDataQuality({
      sourceCount,
      hasStrongConfidenceSignal: typeof campaign.confidence === 'number' && campaign.confidence >= 0.8,
      lastKnownDate: campaign.last_seen,
    }),

    // Phase 29: see buildCveDossier's identical note. campaign.shared_iocs
    // is already stripped to [] by getCampaignDetail() itself for free/
    // starter (not something this module re-derives), so IOC counts are
    // gated the same way regardless of the correlation gate below.
    tier_info: {
      tier,
      relationships_gated: !tierAllowsRelationships,
      upgrade_message: !tierAllowsRelationships ? (campaign._upgrade || null) : null,
    },
  };

  return dossier;
}

module.exports = {
  DOSSIER_SCHEMA_VERSION,
  buildCveDossier,
  buildCampaignDossier,
  buildDossierTimeline,
  computeDataQuality,
  classifyExploitation,
  campaignConfidenceBucket,
};
