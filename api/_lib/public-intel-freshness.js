'use strict';

/**
 * P0 public SOC API freshness authority.
 *
 * Shared contract with the browser's runtime-state.js, not a parallel
 * "timestamp looks new" heuristic. Cloudflare Workers embed the JSON at
 * bundle time: a request made today against October's Worker is NOT evidence
 * of today's intelligence. Withhold live results unless the bundled source
 * proves its pipeline timestamp AND each record's original publication date
 * and immutable first-ingestion timestamp.
 *
 * Pure/synchronous: no external requests, D1/R2/KV costs, cookies or secrets.
 */
const RS = require('../../runtime-state.js');

function assessPublicIntel(feed, nowMs = Date.now()) {
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  if (!feed || typeof feed !== 'object' || Array.isArray(feed) ||
      !Array.isArray(feed.items)) {
    return {
      ok: false, state: 'UNAVAILABLE', timestamp: null, age_minutes: null,
      reason: 'INVALID_FEED_SHAPE', items: [], considered: 0
    };
  }

  const state = RS.classifyFeed({ok:true,feed,nowMs:now});
  const base = {
    ok: false,
    state: state.state,
    timestamp: state.timestamp,
    age_minutes: state.ageMinutes,
    items: [],
    considered: feed.items.length
  };

  if (!RS.pipelineAllowsLive(state, now)) {
    return {...base, reason: 'PUBLIC_SOURCE_NOT_CURRENT'};
  }

  const selected = RS.selectLiveRecords(feed.items, now);
  // The source may contain duplicate ingestion events for the same report.
  // Dedup IDs without expanding the permitted publication/ingestion windows.
  const seen = new Set();
  const items = selected.items.filter(item => {
    const id = String(item?.id || item?.link || item?.slug || '').trim();
    if (!id || seen.has(id)) return false;
    seen.add(id);
    return true;
  });

  return {
    ...base, ok: true, reason: 'SOURCE_VERIFIED',
    items, excluded: selected.excluded
  };
}

module.exports = { assessPublicIntel };
