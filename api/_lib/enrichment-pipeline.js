/**
 * SENTINEL APEX — Intelligence Enrichment Pipeline v2.0
 * Phase 6 Hardening: 8-step two-pass pipeline with explainability engine.
 *
 * PIPELINE ORDER:
 *   1. validateAndExtract(items)         → filter bad items, extract entities
 *   2. computeDataConfidence per item    → LOW/MEDIUM/HIGH data quality tier
 *   3. buildGraphFromIntel               → threat graph with nodes + edges
 *   4. Pass 1: computeActorAttribution   → without campaign context
 *   5. buildCampaigns (actor-aware)      → clustering uses Pass 1 attributions
 *   6. linkActorsToCampaigns             → campaign nodes wired into graph
 *   6b. linkCorrelatedCampaigns          → co_occurs_with edges between
 *                                          campaigns sharing a CVE (GEPMO v1)
 *   6c. linkCorrelatedCVEs               → co_occurs_with edges between CVEs
 *                                          sharing a campaign (GCDOM v1)
 *   6d. linkCorrelatedActors             → co_occurs_with edges between
 *                                          actors sharing a CVE or campaign
 *                                          (GPEP v1)
 *   7. Pass 2: computeActorAttribution   → with campaign context (final)
 *   8. computeNormalizedScore per item   → with final actor + campaign context
 *   9. generateExplanation per item      → human-readable _explanation block
 *  10. Assemble enriched objects
 *
 * QUALITY RULES (Phase 8):
 *   - No attribution without evidence (confidence < 0.50 → "Unknown")
 *   - No weak clusters (cluster_score < 0.60)
 *   - No inflated scores (all features normalized 0–1)
 *   - All outputs explainable (every item has _explanation block)
 *   - All confidence values strictly bounded [0, 1]
 *
 * API TIER GATING (Phase 7):
 *   FREE:       actor name + data_confidence.tier only
 *   PRO:        full explanation + confidence, actor_attribution without signal_detail
 *   ENTERPRISE: raw signals + scoring.breakdown + all_attributions
 *
 * © 2026 CYBERDUDEBIVASH PRIVATE LIMITED
 */
'use strict';

const {
  buildGraphFromIntel,
  saveGraph,
  addNode,
  addEdge,
  getActorsForItem,
  getTopActors,
  KEYWORD_ACTOR_MAP,
  CVE_ACTOR_MAP,
  computeActorAttribution,
  boundConfidence,
} = require('./threat-graph');

const {
  buildCampaigns,
  linkActorsToCampaigns: linkActorsToCampaignsEngine,
  loadCampaigns,
  saveCampaigns,
  mergeCampaigns,
} = require('./campaign-engine');

const {
  computeDataConfidence,
  computeNormalizedScore,
} = require('./threat-scorer');
const { dataProfile } = require('./tier-entitlements');

/* ═══════════════════════════════════════════════════════════════════════
   STEP 1: VALIDATE + EXTRACT
═══════════════════════════════════════════════════════════════════════ */
function validateAndExtract(items) {
  const validItems   = [];
  const skippedItems = [];

  for (const item of (items || [])) {
    const id = String(item.id || '');

    // Must have an ID
    if (!id || id.length < 2) {
      skippedItems.push({ item, reason: 'Missing or invalid id' });
      continue;
    }

    // Must have a title
    if (!item.title || String(item.title).length < 3) {
      skippedItems.push({ item, reason: 'Missing or too-short title' });
      continue;
    }

    // Enrich with normalized fields for downstream use
    const normalized = {
      ...item,
      id,
      title:     String(item.title || ''),
      desc:      String(item.desc || item.description || item.summary || ''),
      cvss:      parseFloat(item.cvss || item.cvssScore || 0) || 0,
      exploited: !!(item.exploited),
      cisa_kev:  !!(item.cisaKev || item.cisa_kev),
      ransomware: !!(item.ransomware || item.type === 'RANSOMWARE'),
      iocs:       Array.isArray(item.iocs) ? item.iocs : [],
    };

    validItems.push(normalized);
  }

  return { validItems, skippedItems };
}

/* ═══════════════════════════════════════════════════════════════════════
   STEP 9: EXPLANATION GENERATOR
   Every output includes _explanation: { actor, campaign, score, data }
═══════════════════════════════════════════════════════════════════════ */
function generateExplanation(item, attribution, campaign, scoring, dataConf) {
  // ── Actor explanation ────────────────────────────────────────────────
  let actorExplanation;
  if (attribution.unattributed) {
    actorExplanation = `No actor attribution: ${attribution.evidence_summary}. ` +
      `Best candidate scored ${
        attribution.all_attributions.length > 0
          ? attribution.all_attributions[0].confidence.toFixed(3)
          : '0.000'
      } — below 0.50 threshold.`;
  } else {
    actorExplanation = `Attributed to ${attribution.primary_actor} with confidence ` +
      `${attribution.primary_confidence.toFixed(3)} (${attribution.attribution_quality}). ` +
      `Evidence: ${attribution.evidence_summary}. ` +
      `Signals: IOC overlap=${attribution.signals.ioc_overlap.toFixed(2)}, ` +
      `keyword=${attribution.signals.keyword_match.toFixed(2)}, ` +
      `source mentions=${attribution.signals.source_mentions.toFixed(2)}, ` +
      `campaign overlap=${attribution.signals.campaign_overlap.toFixed(2)}.`;
  }

  // ── Campaign explanation ─────────────────────────────────────────────
  let campaignExplanation;
  if (!campaign) {
    campaignExplanation = `Not assigned to any campaign. Item similarity score against all clusters ` +
      `fell below the 0.60 threshold (weighted model: ioc_overlap*0.35 + cve_match*0.25 + ` +
      `time_proximity*0.20 + text_similarity*0.20).`;
  } else {
    const topReason = (campaign.reasoning || [])[0] || 'Clustered by weighted similarity';
    campaignExplanation = `Part of campaign "${campaign.name}" (${campaign.campaign_id}) ` +
      `with ${campaign.item_count} item(s), confidence ${campaign.confidence.toFixed(3)}, ` +
      `severity ${campaign.severity}. ` +
      `Clustering reason: ${topReason}`;
  }

  // ── Score explanation ────────────────────────────────────────────────
  const topReasons = (scoring.reasoning || []).slice(0, 4);
  const scoreExplanation = `Priority score ${scoring.priority_score}/100 (${scoring.threat_level}). ` +
    `Normalized score ${scoring.normalized_score.toFixed(4)}. ` +
    `Key drivers: ${topReasons.join('; ')}.`;

  // ── Data confidence explanation ──────────────────────────────────────
  const dataExplanation = `Data confidence: ${dataConf.tier} (score=${dataConf.score.toFixed(3)}). ` +
    `Sources: ${dataConf.factors.source_count.raw} (norm=${dataConf.factors.source_count.normalized.toFixed(2)}), ` +
    `structured fields: ${dataConf.factors.structured_data.populated}/${dataConf.factors.structured_data.of}, ` +
    `IOCs: ${dataConf.factors.ioc_presence.raw}. ` +
    (dataConf.suppressed ? 'WARNING: Low data confidence — suppressed from top threats.' : '');

  return {
    actor:    actorExplanation,
    campaign: campaignExplanation,
    score:    scoreExplanation,
    data:     dataExplanation,
  };
}

/* ═══════════════════════════════════════════════════════════════════════
   LINK ACTORS TO CAMPAIGNS (graph-level wiring)
═══════════════════════════════════════════════════════════════════════ */
function linkActorsToCampaignsGraph(graph, campaigns) {
  for (const campaign of campaigns) {
    // Add campaign node to graph
    addNode(graph, {
      id:   campaign.campaign_id,
      type: 'Campaign',
      name: campaign.name,
      attributes: {
        severity:   campaign.severity,
        item_count: campaign.item_count,
        first_seen: campaign.first_seen,
        last_seen:  campaign.last_seen,
        confidence: campaign.confidence,
        reasoning:  (campaign.reasoning || []).slice(0, 3).join(' | '),
      },
    });

    // Collect actor IDs for this campaign
    const actorIds = new Set();
    for (const actor of (campaign.threat_actors || [])) {
      if (actor && actor.id) actorIds.add(actor.id);
    }
    // Also check graph edges for items in campaign
    for (const intelId of (campaign.related_intel_ids || [])) {
      getActorsForItem(graph, intelId).forEach(a => actorIds.add(a.id));
    }

    // Update campaign.threat_actors if empty
    if (campaign.threat_actors.length === 0 && actorIds.size > 0) {
      campaign.threat_actors = [...actorIds].map(id => {
        const node = graph.nodes[id];
        return node ? { id, name: node.name, confidence: 0.75, category: node.attributes?.category } : null;
      }).filter(Boolean);
      if (campaign.threat_actors.length > 0) {
        campaign.threat_actor = campaign.threat_actors[0].name;
      }
    }

    // Actor → executes → Campaign edges
    for (const actorId of actorIds) {
      addEdge(graph, actorId, campaign.campaign_id, 'executes', 0.85);
    }

    // Campaign → includes → CVE/Intel edges
    for (const intelId of (campaign.related_intel_ids || [])) {
      addEdge(graph, campaign.campaign_id, intelId, 'includes', 1.0);
    }
  }

  return campaigns;
}

/* ═══════════════════════════════════════════════════════════════════════
   CAMPAIGN CORRELATION (GEPMO v1 / Issue 8)
   Every existing edge in the graph is hierarchical (Campaign→includes→CVE,
   Actor→exploits→CVE, etc.) — none connect two entities of the same type,
   so campaigns that clearly share a CVE were never linked to each other.
   This adds one new, purely additive 'co_occurs_with' edge between any two
   Campaign nodes that both include the same CVE, computed entirely from
   Campaign→CVE 'includes' edges already in the graph. No existing node or
   edge is read differently or modified. Runs over the full accumulated
   graph (not just this run's newly-clustered campaigns) so it also
   catches correlations across campaigns clustered in different runs.
═══════════════════════════════════════════════════════════════════════ */
const MAX_CAMPAIGNS_PER_CVE_FOR_CORRELATION = 20;

/* ═══════════════════════════════════════════════════════════════════════
   CVE CORRELATION (Issue 8 continuation, GCDOM v1)
   Same gap as campaign correlation, other direction: two CVE nodes that
   are both included by the same campaign were never linked to each other
   either -- every edge remains hierarchical, none symmetric. This adds one
   new, purely additive 'co_occurs_with' edge between any two CVE nodes that
   share an including Campaign, computed entirely from existing
   Campaign->CVE 'includes' edges already in the graph. No existing node or
   edge is read differently or modified.
   Real data check at filing time (api/intel/threat-graph.json): 265
   campaigns have at least one Campaign->CVE edge; 28 of those include more
   than one CVE (max observed: 5) and so produce correlation edges here.
═══════════════════════════════════════════════════════════════════════ */
const MAX_CVES_PER_CAMPAIGN_FOR_CORRELATION = 20;

function linkCorrelatedCVEs(graph) {
  const campaignToCVEs = new Map(); // campaignId -> Set(cveId)

  for (const edge of (graph.edges || [])) {
    if (edge.relationship !== 'includes') continue;
    const source = graph.nodes[edge.source];
    const target = graph.nodes[edge.target];
    if (!source || source.type !== 'Campaign') continue;
    if (!target || target.type !== 'CVE') continue;

    if (!campaignToCVEs.has(edge.source)) campaignToCVEs.set(edge.source, new Set());
    campaignToCVEs.get(edge.source).add(edge.target);
  }

  let newEdgeCount = 0;
  for (const [campaignId, cveSet] of campaignToCVEs.entries()) {
    const cveIds = [...cveSet].sort();
    if (cveIds.length < 2) continue;
    if (cveIds.length > MAX_CVES_PER_CAMPAIGN_FOR_CORRELATION) {
      console.warn(`[GRAPH] Skipping CVE correlation for ${campaignId} — ${cveIds.length} CVEs exceeds cap of ${MAX_CVES_PER_CAMPAIGN_FOR_CORRELATION}`);
      continue;
    }
    for (let i = 0; i < cveIds.length; i++) {
      for (let j = i + 1; j < cveIds.length; j++) {
        const before = graph.edges.length;
        addEdge(graph, cveIds[i], cveIds[j], 'co_occurs_with', 0.7, {
          sources: [`shared campaign: ${campaignId}`],
        });
        if (graph.edges.length > before) newEdgeCount++;
      }
    }
  }

  return newEdgeCount;
}

/* ═══════════════════════════════════════════════════════════════════════
   ACTOR CORRELATION (Issue 8 continuation, GPEP v1)
   Same gap, third direction: two ThreatActor nodes that both exploit the
   same CVE, or both executed the same Campaign, were never linked to each
   other -- "which actors share an initial-access vector or campaign" is a
   real CTI question (if actor A's TTPs are observed, should actor B's also
   be a concern?), not just structural completeness. Computed entirely from
   existing Actor->CVE 'exploits' and Actor->Campaign 'executes' edges. No
   existing node or edge is read differently or modified.
   Real data check at filing time (api/intel/threat-graph.json): only 6-8
   of the graph's 8 curated ThreatActor nodes have any exploits/executes
   edge at all (matches Issue 8's original ~2%/~1% attribution-coverage
   finding) -- of those, 20 of 35 actor-linked CVEs are shared by 2+ actors
   (20 pairs), and 3 of 20 actor-linked campaigns are shared by 2+ actors
   (5 pairs). A small labeled sample, but the correlation logic itself is
   sound and gets more valuable as actor curation grows, same reasoning as
   the two correlation functions above.
   If a pair shares both a CVE and a Campaign, only one edge is recorded
   (whichever basis is found first) -- addEdge()'s existing idempotent
   dedup on (source,target,relationship) means a second call for the same
   pair is a no-op; this matches the same limitation the two functions
   above already have, not a new inconsistency.
═══════════════════════════════════════════════════════════════════════ */
const MAX_ACTORS_PER_SHARED_ITEM_FOR_CORRELATION = 20;

function linkCorrelatedActors(graph) {
  const cveToActors = new Map();      // cveId -> Set(actorId)
  const campaignToActors = new Map(); // campaignId -> Set(actorId)

  for (const edge of (graph.edges || [])) {
    const source = graph.nodes[edge.source];
    if (!source || source.type !== 'ThreatActor') continue;

    if (edge.relationship === 'exploits') {
      const target = graph.nodes[edge.target];
      if (!target || target.type !== 'CVE') continue;
      if (!cveToActors.has(edge.target)) cveToActors.set(edge.target, new Set());
      cveToActors.get(edge.target).add(edge.source);
    } else if (edge.relationship === 'executes') {
      const target = graph.nodes[edge.target];
      if (!target || target.type !== 'Campaign') continue;
      if (!campaignToActors.has(edge.target)) campaignToActors.set(edge.target, new Set());
      campaignToActors.get(edge.target).add(edge.source);
    }
  }

  let newEdgeCount = 0;
  const correlate = (itemToActors, describeItem) => {
    for (const [itemId, actorSet] of itemToActors.entries()) {
      const actorIds = [...actorSet].sort();
      if (actorIds.length < 2) continue;
      if (actorIds.length > MAX_ACTORS_PER_SHARED_ITEM_FOR_CORRELATION) {
        console.warn(`[GRAPH] Skipping actor correlation for ${itemId} — ${actorIds.length} actors exceeds cap of ${MAX_ACTORS_PER_SHARED_ITEM_FOR_CORRELATION}`);
        continue;
      }
      for (let i = 0; i < actorIds.length; i++) {
        for (let j = i + 1; j < actorIds.length; j++) {
          const before = graph.edges.length;
          addEdge(graph, actorIds[i], actorIds[j], 'co_occurs_with', 0.7, {
            sources: [describeItem(itemId)],
          });
          if (graph.edges.length > before) newEdgeCount++;
        }
      }
    }
  };

  correlate(cveToActors, id => `shared CVE: ${id}`);
  correlate(campaignToActors, id => `shared campaign: ${id}`);

  return newEdgeCount;
}

function linkCorrelatedCampaigns(graph) {
  const cveToCampaigns = new Map(); // cveId -> Set(campaignId)

  for (const edge of (graph.edges || [])) {
    if (edge.relationship !== 'includes') continue;
    const source = graph.nodes[edge.source];
    const target = graph.nodes[edge.target];
    if (!source || source.type !== 'Campaign') continue;
    if (!target || target.type !== 'CVE') continue;

    if (!cveToCampaigns.has(edge.target)) cveToCampaigns.set(edge.target, new Set());
    cveToCampaigns.get(edge.target).add(edge.source);
  }

  let newEdgeCount = 0;
  for (const [cveId, campaignSet] of cveToCampaigns.entries()) {
    const campaignIds = [...campaignSet].sort();
    if (campaignIds.length < 2) continue;
    if (campaignIds.length > MAX_CAMPAIGNS_PER_CVE_FOR_CORRELATION) {
      console.warn(`[GRAPH] Skipping campaign correlation for ${cveId} — ${campaignIds.length} campaigns exceeds cap of ${MAX_CAMPAIGNS_PER_CVE_FOR_CORRELATION}`);
      continue;
    }
    for (let i = 0; i < campaignIds.length; i++) {
      for (let j = i + 1; j < campaignIds.length; j++) {
        const before = graph.edges.length;
        addEdge(graph, campaignIds[i], campaignIds[j], 'co_occurs_with', 0.7, {
          sources: [`shared CVE: ${cveId}`],
        });
        if (graph.edges.length > before) newEdgeCount++;
      }
    }
  }

  return newEdgeCount;
}

/* ═══════════════════════════════════════════════════════════════════════
   MAIN PIPELINE — runEnrichmentPipeline(intelItems)
═══════════════════════════════════════════════════════════════════════ */
function runEnrichmentPipeline(intelItems) {
  const startTime = Date.now();
  const log = (msg) => console.log(`[ENRICH] ${msg}`);

  log(`Starting 8-step hardened enrichment pipeline for ${(intelItems || []).length} items...`);

  // ── STEP 1: Validate + extract ───────────────────────────────────────
  const { validItems, skippedItems } = validateAndExtract(intelItems);
  log(`Step 1 — Validated: ${validItems.length} valid, ${skippedItems.length} skipped`);

  if (validItems.length === 0) {
    log('No valid items to process — pipeline aborted');
    return {
      enrichedItems: [],
      graph:         { nodes: {}, edges: [] },
      campaigns:     [],
      stats:         { items_processed: 0, skipped: skippedItems.length, elapsed_ms: 0 },
    };
  }

  // ── STEP 2: Data confidence per item ────────────────────────────────
  const dataConfMap = new Map();
  let suppressedCount = 0;
  for (const item of validItems) {
    const dc = computeDataConfidence(item);
    dataConfMap.set(item.id, dc);
    if (dc.suppressed) suppressedCount++;
  }
  log(`Step 2 — Data confidence: ${validItems.length - suppressedCount} HIGH/MEDIUM, ${suppressedCount} LOW (suppressed from top threats)`);

  // ── STEP 3: Build threat graph ───────────────────────────────────────
  const graph = buildGraphFromIntel(validItems);
  log(`Step 3 — Graph built: ${Object.keys(graph.nodes).length} nodes, ${graph.edges.length} edges`);

  // ── STEP 4: Pass 1 actor attribution (no campaign context yet) ───────
  const pass1Attribution = new Map();
  for (const item of validItems) {
    const attr = computeActorAttribution(item, graph, []);
    pass1Attribution.set(item.id, attr);
    // Attach to item for campaign clustering signal
    item.actor_attribution = attr;
  }
  const pass1Attributed = validItems.filter(i => !pass1Attribution.get(i.id).unattributed).length;
  log(`Step 4 — Pass 1 attribution: ${pass1Attributed}/${validItems.length} attributed (≥0.50 confidence)`);

  // ── STEP 5: Build campaigns (uses Pass 1 attributions as signal) ─────
  const campaigns = buildCampaigns(validItems);
  log(`Step 5 — Campaigns clustered: ${campaigns.length} campaign(s) (threshold=0.60)`);

  // ── STEP 6: Link actors to campaigns + wire graph ────────────────────
  linkActorsToCampaignsGraph(graph, campaigns);
  log(`Step 6 — Campaign nodes wired into graph`);

  // ── STEP 6b: Correlate campaigns that share a CVE ────────────────────
  const correlationEdges = linkCorrelatedCampaigns(graph);
  log(`Step 6b — Campaign correlation: ${correlationEdges} co_occurs_with edge(s) added`);

  // ── STEP 6c: Correlate CVEs that share a campaign ────────────────────
  const cveCorrelationEdges = linkCorrelatedCVEs(graph);
  log(`Step 6c — CVE correlation: ${cveCorrelationEdges} co_occurs_with edge(s) added`);

  // ── STEP 6d: Correlate actors sharing a CVE or campaign ──────────────
  const actorCorrelationEdges = linkCorrelatedActors(graph);
  log(`Step 6d — Actor correlation: ${actorCorrelationEdges} co_occurs_with edge(s) added`);

  // ── STEP 7: Pass 2 actor attribution (with campaign context) ─────────
  const pass2Attribution = new Map();
  for (const item of validItems) {
    const attr = computeActorAttribution(item, graph, campaigns);
    pass2Attribution.set(item.id, attr);
    // Update item with final attribution
    item.actor_attribution = attr;
  }
  const pass2Attributed = validItems.filter(i => !pass2Attribution.get(i.id).unattributed).length;
  log(`Step 7 — Pass 2 attribution: ${pass2Attributed}/${validItems.length} attributed (final)`);

  // ── STEPS 8–10: Score + explain + assemble ────────────────────────────
  const enrichedItems = validItems.map(item => {
    const attribution = pass2Attribution.get(item.id);
    const dataConf    = dataConfMap.get(item.id);

    // Find associated campaign
    const campaign = campaigns.find(c => c.related_intel_ids?.includes(item.id)) || null;

    // Graph context for normalized scoring
    const graphContext = {
      actorCount:       attribution.unattributed ? 0 : 1,
      actorConfidence:  attribution.primary_confidence || 0,
      inCampaign:       !!campaign,
      campaignSize:     campaign?.item_count || 0,
      campaignSeverity: campaign?.severity   || null,
    };

    // Step 8: Normalized score
    const scoring = computeNormalizedScore(item, graphContext);

    // Step 9: Generate explanation
    const explanation = generateExplanation(item, attribution, campaign, scoring, dataConf);

    // Step 10: Assemble enriched object
    const graphActors = getActorsForItem(graph, item.id);

    return {
      ...item,
      // Updated scores from normalized model
      priority_score:   scoring.priority_score,
      threat_level:     scoring.threat_level,
      confidence_score: scoring.confidence_score,

      // Phase 1: Actor attribution
      actor_attribution: {
        primary_actor:       attribution.primary_actor,
        primary_actor_id:    attribution.primary_actor_id,
        primary_confidence:  attribution.primary_confidence,
        unattributed:        attribution.unattributed,
        attribution_quality: attribution.attribution_quality,
        evidence_summary:    attribution.evidence_summary,
        signals:             attribution.signals,
        all_attributions:    attribution.all_attributions,
      },

      // Phase 4: Data confidence
      data_confidence: dataConf,

      // Phase 3: Normalized scoring
      scoring: {
        priority_score:   scoring.priority_score,
        normalized_score: scoring.normalized_score,
        threat_level:     scoring.threat_level,
        confidence_score: scoring.confidence_score,
        reasoning:        scoring.reasoning,
        breakdown:        scoring.breakdown,
        scoring_model:    scoring.scoring_model,
      },

      // Phase 5: Explainability
      _explanation: explanation,

      // Intelligence context
      _intelligence: {
        linked_actors: graphActors.map(a => ({
          id:         a.id,
          name:       a.name,
          category:   a.attributes?.category,
          motivation: a.attributes?.motivation,
          origin:     a.attributes?.origin,
          ttps:       (a.attributes?.ttps || []).slice(0, 5),
        })),
        campaign_id:         campaign?.campaign_id     || null,
        campaign_name:       campaign?.name            || null,
        campaign_severity:   campaign?.severity        || null,
        campaign_item_count: campaign?.item_count      || 0,
        graph_node_id:       item.id,
        enriched_at:         new Date().toISOString(),
        pipeline_version:    'SENTINEL_APEX_v4.2_HARDENED',
      },
    };
  });

  // ── Persist to disk ────────────────────────────────────────────────
  saveGraph(graph);

  // Accumulate, don't overwrite: `campaigns` above is only what this run's
  // batch clustered -- it has no knowledge of campaigns discovered in any
  // earlier cycle. mergeCampaigns() upserts this batch into the
  // previously-persisted set by campaign_id instead of replacing it
  // outright, which is the fix for the production defect where
  // campaigns.json could go from 1,187 accumulated campaigns to 0 in a
  // single overwrite (campaign delivery integrity v1). saveCampaigns()'s
  // own catastrophic-drop guard is a second, independent line of defense
  // at the actual write chokepoint.
  const existingCampaignsState = loadCampaigns();
  const existingCampaignIds    = new Set((existingCampaignsState.campaigns || []).map(c => c.campaign_id));
  const mergedCampaigns        = mergeCampaigns(existingCampaignsState.campaigns || [], campaigns);
  const campaignSaveResult     = saveCampaigns({ campaigns: mergedCampaigns });
  const campaignsCreated       = campaigns.filter(c => !existingCampaignIds.has(c.campaign_id)).length;
  const campaignsUpdated       = campaigns.length - campaignsCreated;

  const elapsed = Date.now() - startTime;
  const topThreatCount = enrichedItems.filter(i => !i.data_confidence.suppressed).length;

  log(`Pipeline complete in ${elapsed}ms`);
  log(`  Items enriched:     ${enrichedItems.length}`);
  log(`  Attributed:         ${pass2Attributed}/${validItems.length}`);
  log(`  Campaigns:          ${campaigns.length} this run (${campaignsCreated} new, ${campaignsUpdated} updated) -> ${mergedCampaigns.length} accumulated total`);
  if (!campaignSaveResult.saved) {
    log(`  CAMPAIGN SAVE ${campaignSaveResult.blocked ? 'BLOCKED by catastrophic-drop guard' : 'FAILED'} -- see [CAMPAIGNS] log above`);
  }
  log(`  High/Med conf data: ${topThreatCount} (${suppressedCount} suppressed)`);

  return {
    enrichedItems,
    graph,
    campaigns: mergedCampaigns,
    stats: {
      items_processed:        validItems.length,
      skipped:                skippedItems.length,
      attributed:             pass2Attributed,
      unattributed:           validItems.length - pass2Attributed,
      // Kept as "this run's batch count" for backward compatibility --
      // fetch-live-intel.js already logs this field under that meaning.
      campaigns:              campaigns.length,
      campaigns_created:      campaignsCreated,
      campaigns_updated:      campaignsUpdated,
      campaigns_total:        mergedCampaigns.length,
      campaigns_save_blocked: campaignSaveResult.blocked === true,
      suppressed_low_data:    suppressedCount,
      top_threat_items:       topThreatCount,
      graph_nodes:            Object.keys(graph.nodes).length,
      graph_edges:            graph.edges.length,
      elapsed_ms:             elapsed,
    },
  };
}

/* ═══════════════════════════════════════════════════════════════════════
   API TIER GATING (Phase 7)
   Strips fields based on subscriber tier.
═══════════════════════════════════════════════════════════════════════ */

/**
 * FREE tier: actor name + data_confidence.tier only.
 * No explanations, no signals, no breakdown.
 */
function filterForFree(item) {
  return {
    ...item,
    actor_attribution: {
      primary_actor: item.actor_attribution?.primary_actor || 'Unknown',
      unattributed:  item.actor_attribution?.unattributed ?? true,
    },
    data_confidence: {
      tier: item.data_confidence?.tier || 'UNKNOWN',
    },
    // Strip enriched fields
    scoring:          undefined,
    _explanation:     undefined,
    _intelligence:    undefined,
  };
}

/**
 * PRO tier: full explanation + confidence, actor attribution without raw signals.
 * No breakdown, no all_attributions signal detail.
 */
function filterForPro(item) {
  const attr = item.actor_attribution || {};
  return {
    ...item,
    actor_attribution: {
      primary_actor:       attr.primary_actor,
      primary_actor_id:    attr.primary_actor_id,
      primary_confidence:  attr.primary_confidence,
      unattributed:        attr.unattributed,
      attribution_quality: attr.attribution_quality,
      evidence_summary:    attr.evidence_summary,
      // signals and all_attributions detail stripped for PRO
    },
    data_confidence: {
      score:      item.data_confidence?.score,
      tier:       item.data_confidence?.tier,
      suppressed: item.data_confidence?.suppressed,
    },
    scoring: item.scoring ? {
      priority_score:   item.scoring.priority_score,
      normalized_score: item.scoring.normalized_score,
      threat_level:     item.scoring.threat_level,
      confidence_score: item.scoring.confidence_score,
      reasoning:        item.scoring.reasoning,
      // breakdown stripped for PRO
    } : undefined,
    _explanation: item._explanation,
    _intelligence: item._intelligence ? {
      linked_actors:       item._intelligence.linked_actors,
      campaign_id:         item._intelligence.campaign_id,
      campaign_name:       item._intelligence.campaign_name,
      campaign_severity:   item._intelligence.campaign_severity,
      campaign_item_count: item._intelligence.campaign_item_count,
      enriched_at:         item._intelligence.enriched_at,
    } : undefined,
  };
}

/**
 * ENTERPRISE tier: everything — raw signals + scoring.breakdown + all_attributions.
 */
function filterForEnterprise(item) {
  return item; // Full enriched object, nothing stripped
}

/**
 * Apply tier gating to an array of enriched items.
 */
function applyTierGating(items, tier) {
  if (!items) return [];
  const profile = dataProfile(tier);
  const filter = profile === 'enterprise' ? filterForEnterprise
               : profile === 'pro'        ? filterForPro
               :                        filterForFree;
  return items.map(filter);
}

/**
 * Lightweight enrichment for API-time single-item use (no disk writes).
 */
function enrichItemForAPI(item, graph, campaigns) {
  const { validItems } = validateAndExtract([item]);
  if (!validItems.length) return item;

  const normalizedItem   = validItems[0];
  const dataConf         = computeDataConfidence(normalizedItem);
  const attribution      = computeActorAttribution(normalizedItem, graph, campaigns || []);
  const campaign         = (campaigns || []).find(c => c.related_intel_ids?.includes(normalizedItem.id)) || null;

  const graphContext = {
    actorCount:       attribution.unattributed ? 0 : 1,
    actorConfidence:  attribution.primary_confidence || 0,
    inCampaign:       !!campaign,
    campaignSize:     campaign?.item_count || 0,
    campaignSeverity: campaign?.severity   || null,
  };

  const scoring     = computeNormalizedScore(normalizedItem, graphContext);
  const explanation = generateExplanation(normalizedItem, attribution, campaign, scoring, dataConf);
  const graphActors = getActorsForItem(graph, normalizedItem.id);

  return {
    ...normalizedItem,
    priority_score:    scoring.priority_score,
    threat_level:      scoring.threat_level,
    confidence_score:  scoring.confidence_score,
    actor_attribution: { ...attribution },
    data_confidence:   dataConf,
    scoring,
    _explanation:      explanation,
    _intelligence: {
      linked_actors:       graphActors.map(a => ({ id: a.id, name: a.name, category: a.attributes?.category })),
      campaign_id:         campaign?.campaign_id   || null,
      campaign_name:       campaign?.name          || null,
      campaign_severity:   campaign?.severity      || null,
      campaign_item_count: campaign?.item_count    || 0,
      graph_node_id:       normalizedItem.id,
      enriched_at:         new Date().toISOString(),
      pipeline_version:    'SENTINEL_APEX_v4.2_HARDENED',
    },
  };
}

module.exports = {
  runEnrichmentPipeline,
  enrichItemForAPI,
  validateAndExtract,
  generateExplanation,
  applyTierGating,
  filterForFree,
  filterForPro,
  filterForEnterprise,
  linkActorsToCampaignsGraph,
  linkCorrelatedCampaigns,
  linkCorrelatedCVEs,
  linkCorrelatedActors,
};
