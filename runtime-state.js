/* SENTINEL APEX — public runtime state model (single source for customer pages).
 *
 * States are derived only from what the browser actually observed:
 *   CHECKING     a request is in flight (initial markup state)
 *   HEALTHY      feed reachable; genuine-report receipt AND source generation within freshness window
 *   DEGRADED     feed reachable but genuine report/source freshness is delayed or unprovable
 *   STALE        feed reachable; oldest report receipt/source generation exceeds freshness window
 *   UNAVAILABLE  request failed, returned non-2xx/invalid JSON, or timed out
 *
 * Thresholds mirror scripts/check-intel-freshness.js (the CI freshness monitor);
 * tests-js/runtime-state.test.js fails if the two drift apart. Every fetch has a
 * hard timeout, so no page can remain in CHECKING indefinitely.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SentinelRuntimeState = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var THRESHOLDS = Object.freeze({
    healthyMaxMinutes: 90,   // = WARN_RUNTIME_MINUTES
    staleAfterMinutes: 180,  // = DOWN_RUNTIME_MINUTES
    futureToleranceMinutes: 5,
    fetchTimeoutMs: 8000,
  });

  var STATES = Object.freeze({
    CHECKING: 'CHECKING', HEALTHY: 'HEALTHY', DEGRADED: 'DEGRADED',
    STALE: 'STALE', UNAVAILABLE: 'UNAVAILABLE',
  });

  // Existing command-center CSS keys off data-state = live | warn | bad.
  var TONE = Object.freeze({
    CHECKING: 'warn', HEALTHY: 'live', DEGRADED: 'warn', STALE: 'warn', UNAVAILABLE: 'bad',
  });

  // Publication truth needs TWO clocks. A recent scheduled run or JSON
  // serialization cannot make an old intelligence report newly current.
  // The report receipt is written only after real articles are generated and
  // the publication ledger is committed. No receipt => no live authority.
  function feedTimestamp(feed) {
    if (!feed || typeof feed !== 'object' || Array.isArray(feed)) return null;
    var meta = feed.metadata || {};
    var receipt = meta.lastReportGeneratedAt || feed.lastReportGeneratedAt;
    var generated = feed.generatedAt || meta.generated || feed.generated || feed.lastUpdated;
    if (typeof receipt !== 'string' || typeof generated !== 'string') return null;
    var reportMs = Date.parse(receipt), sourceMs = Date.parse(generated);
    if (!isFinite(reportMs) || !isFinite(sourceMs) || reportMs < 0 || sourceMs < 0 ||
        !/(Z|[+-]\\d\\d:\\d\\d)$/.test(receipt) ||
        !/(Z|[+-]\\d\\d:\\d\\d)$/.test(generated)) return null;
    return new Date(Math.min(reportMs, sourceMs)).toISOString();
  }

  function formatAge(minutes) {
    if (typeof minutes !== 'number' || !isFinite(minutes)) return 'UNKNOWN';
    if (minutes < 60) return minutes + 'm';
    if (minutes < 1440) return Math.floor(minutes / 60) + 'h ' + (minutes % 60) + 'm';
    return Math.floor(minutes / 1440) + 'd ' + Math.floor((minutes % 1440) / 60) + 'h';
  }

  function classifyFeed(observation) {
    var obs = observation || {};
    var nowMs = typeof obs.nowMs === 'number' ? obs.nowMs : Date.now();
    if (!obs.ok) {
      return { state: STATES.UNAVAILABLE, reachable: false, ageMinutes: null, timestamp: null,
        reason: 'First-party feed could not be retrieved' + (obs.error ? ' (' + String(obs.error) + ')' : '') + '.' };
    }
    var stamp = feedTimestamp(obs.feed);
    var ms = stamp ? Date.parse(stamp) : NaN;
    if (!isFinite(ms)) {
      return { state: STATES.DEGRADED, reachable: true, ageMinutes: null, timestamp: null,
        reason: 'Feed reachable; genuine report receipt or source-generation time missing/invalid. Heartbeat is not a report.' };
    }
    var iso = new Date(ms).toISOString();
    if (ms - nowMs > THRESHOLDS.futureToleranceMinutes * 60000) {
      return { state: STATES.DEGRADED, reachable: true, ageMinutes: null, timestamp: iso,
        reason: 'Feed reachable; report/source timestamp is in the future, so freshness is not established.' };
    }
    var age = Math.max(0, Math.floor((nowMs - ms) / 60000));
    if (age <= THRESHOLDS.healthyMaxMinutes) {
      return { state: STATES.HEALTHY, reachable: true, ageMinutes: age, timestamp: iso,
        reason: 'Genuine report/source freshness verified ' + formatAge(age) + ' ago (' + iso + ').' };
    }
    if (age <= THRESHOLDS.staleAfterMinutes) {
      return { state: STATES.DEGRADED, reachable: true, ageMinutes: age, timestamp: iso,
        reason: 'Latest genuine report or source generation is ' + formatAge(age) + ' old; behind freshness policy.' };
    }
    return { state: STATES.STALE, reachable: true, ageMinutes: age, timestamp: iso,
      reason: 'Latest genuine report or source generation is ' + formatAge(age) + ' old; operational intelligence is withheld.' };
  }

  function toneFor(state) {
    return Object.prototype.hasOwnProperty.call(TONE, state) ? TONE[state] : 'warn';
  }

  // Text for a compact status badge (e.g. the homepage Intelligence Hub widget).
  // "LIVE" is claimed ONLY for HEALTHY, i.e. a pipeline completion within
  // THRESHOLDS.healthyMaxMinutes. Every other state names what was observed, and
  // CHECKING / unknown input yields no badge at all (hidden), so a badge can never
  // outlive the evidence for it. Takes a classifyFeed() result.
  function badgeFor(classification) {
    var c = classification || {};
    var hasAge = typeof c.ageMinutes === 'number' && isFinite(c.ageMinutes);
    switch (c.state) {
      case STATES.HEALTHY:
        return { text: 'LIVE', tone: toneFor(STATES.HEALTHY), hidden: false };
      case STATES.DEGRADED:
        return { text: hasAge ? 'DELAYED · ' + formatAge(c.ageMinutes) : 'UNVERIFIED', tone: toneFor(STATES.DEGRADED), hidden: false };
      case STATES.STALE:
        return { text: hasAge ? 'STALE · ' + formatAge(c.ageMinutes) : 'STALE', tone: toneFor(STATES.STALE), hidden: false };
      case STATES.UNAVAILABLE:
        return { text: 'UNAVAILABLE', tone: toneFor(STATES.UNAVAILABLE), hidden: false };
      default:
        return { text: '', tone: toneFor(STATES.CHECKING), hidden: true };
    }
  }

  // ── Live-record window policy ────────────────────────────────────────────
  // Four concepts that must never be conflated:
  //   pipeline freshness   classifyFeed()      did the pipeline complete recently?
  //   record freshness     classifyRecord()    is THIS record new enough to be shown as live?
  //   incident activity    (not modelled)      the feed carries no confirmation/update timestamp
  //   availability         fetchJson()         could the feed be retrieved at all?
  // A fresh feed timestamp is NEVER evidence that the records inside it are new:
  // a healthy pipeline can legitimately contain no new reports.
  //
  // A record is LIVE only when BOTH hold:
  //   - the pipeline first added it within ingestMaxHours   (_addedAt; preserved on
  //     re-ingestion by fetch-live-intel.js, so it is not reset by re-fetching), AND
  //   - the SOURCE published it within publicationMaxHours  (pubDate; the larger window
  //     tolerates date-only precision and ingestion lag). An old advisory that was only
  //     ingested recently is therefore NOT live.
  // Everything else belongs in the archive/historical view, never in a live list.
  var LIVE_WINDOWS = Object.freeze({
    ingestMaxHours: 24,
    publicationMaxHours: 72,
    futureToleranceMinutes: 5,
  });

  var DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
  // A date-time must name its offset. `Date.parse('2026-11-12T10:00:00')` is LOCAL time, so a
  // zone-less timestamp means a different instant in every browser: unverifiable, fail closed.
  var DATE_TIME_WITH_ZONE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;

  // → {startMs, endMs} | null.
  // allowDateOnly=true  (source publication dates): YYYY-MM-DD is accepted and means "some time
  //   that UTC day", so the latest the record can have been published is the end of that day.
  // allowDateOnly=false (machine timestamps such as _addedAt): only a zoned date-time is valid.
  function parseWhen(value, allowDateOnly) {
    if (typeof value !== 'string') return null;
    var s = value.trim();
    if (!s) return null;
    var dateOnly = DATE_ONLY.test(s);
    if (dateOnly ? !allowDateOnly : !DATE_TIME_WITH_ZONE.test(s)) return null;
    var ms = Date.parse(s);
    if (!isFinite(ms) || ms < 0) return null;
    return { startMs: ms, endMs: dateOnly ? ms + 86400000 - 1 : ms };
  }

  function publicationValue(item) {
    return item.pubDate || item.published || item.dateAdded || null;
  }

  // Why a record is or is not live. `live` is true only for reason 'LIVE'.
  function classifyRecord(item, nowMs) {
    var now = typeof nowMs === 'number' && isFinite(nowMs) ? nowMs : Date.now();
    var tol = LIVE_WINDOWS.futureToleranceMinutes * 60000;
    var out = function (reason, ingestedMs, publishedMs) {
      return { live: reason === 'LIVE', reason: reason, ingestedMs: ingestedMs, publishedMs: publishedMs };
    };
    if (!item || typeof item !== 'object' || Array.isArray(item)) return out('INVALID_RECORD', null, null);
    if (item._addedAt === undefined || item._addedAt === null || item._addedAt === '') return out('NO_INGEST_TIME', null, null);
    var added = parseWhen(item._addedAt, false);
    if (!added) return out('INVALID_TIMESTAMP', null, null);
    var pubRaw = publicationValue(item);
    if (!pubRaw) return out('NO_PUBLICATION_DATE', added.startMs, null);
    var pub = parseWhen(pubRaw, true);
    if (!pub) return out('INVALID_TIMESTAMP', added.startMs, null);
    if (added.startMs - now > tol || pub.startMs - now > tol) return out('FUTURE_TIMESTAMP', added.startMs, pub.startMs);
    if (now - added.startMs > LIVE_WINDOWS.ingestMaxHours * 3600000) return out('NOT_RECENTLY_INGESTED', added.startMs, pub.startMs);
    if (now - pub.endMs > LIVE_WINDOWS.publicationMaxHours * 3600000) return out('PUBLISHED_BEFORE_WINDOW', added.startMs, pub.startMs);
    return out('LIVE', added.startMs, pub.startMs);
  }

  function isLiveRecord(item, nowMs) { return classifyRecord(item, nowMs).live; }

  // May ANY record be shown as live under this pipeline classification? Only a HEALTHY pipeline, or a
  // DEGRADED one whose delay is MEASURED (a numeric age within the stale limit backed by a valid,
  // non-future timestamp). A DEGRADED result can also mean "timestamp missing / invalid / in the
  // future", which is the absence of evidence and must withhold every record. Every list that
  // shows records (homepage triage, SOC desk) applies this same rule to its classifyFeed() result.
  function pipelineAllowsLive(classification, nowMs) {
    var now = typeof nowMs === 'number' && isFinite(nowMs) ? nowMs : Date.now();
    var c = classification;
    if (!c || (c.state !== STATES.HEALTHY && c.state !== STATES.DEGRADED)) return false;
    var age = c.ageMinutes;
    if (typeof age !== 'number' || !isFinite(age) || age < 0 || age > THRESHOLDS.staleAfterMinutes) return false;
    var ts = typeof c.timestamp === 'string' ? Date.parse(c.timestamp) : NaN;
    if (!isFinite(ts) || ts - now > THRESHOLDS.futureToleranceMinutes * 60000 ||
        now - ts > THRESHOLDS.staleAfterMinutes * 60000) return false;
    return true;
  }

  // → {items, windowHours, considered, excluded:{REASON:count}}. Newest ingestion first,
  // then priority, then source order. The caller applies its own display cap.
  function selectLiveRecords(rawItems, nowMs) {
    var now = typeof nowMs === 'number' && isFinite(nowMs) ? nowMs : Date.now();
    var list = Array.isArray(rawItems) ? rawItems : [];
    var excluded = {};
    var live = [];
    list.forEach(function (item, index) {
      var c = classifyRecord(item, now);
      if (c.live) { live.push({ item: item, time: c.ingestedMs, priority: Number(item.priority) || 0, index: index }); }
      else excluded[c.reason] = (excluded[c.reason] || 0) + 1;
    });
    live.sort(function (a, b) { return b.time - a.time || b.priority - a.priority || a.index - b.index; });
    return {
      items: live.map(function (x) { return x.item; }),
      windowHours: { ingest: LIVE_WINDOWS.ingestMaxHours, publication: LIVE_WINDOWS.publicationMaxHours },
      considered: list.length,
      excluded: excluded,
    };
  }

  // fetch() with a hard deadline. Rejects with an Error whose message is
  // 'timeout', 'http <status>' or the underlying network/parse error.
  function fetchJson(url, options) {
    var opts = options || {};
    var fetchImpl = opts.fetchImpl || (typeof fetch === 'function' ? fetch : null);
    var timeoutMs = opts.timeoutMs || THRESHOLDS.fetchTimeoutMs;
    if (!fetchImpl) return Promise.reject(new Error('fetch unavailable'));
    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = null;
    var deadline = new Promise(function (_, reject) {
      timer = setTimeout(function () {
        if (controller) { try { controller.abort(); } catch (e) { /* ignore */ } }
        reject(new Error('timeout'));
      }, timeoutMs);
    });
    var request = fetchImpl(url, {
      cache: 'no-store', headers: { Accept: 'application/json' },
      signal: controller ? controller.signal : undefined,
    }).then(function (r) {
      if (!r || !r.ok) throw new Error('http ' + (r ? r.status : 'error'));
      return r.json();
    });
    return Promise.race([request, deadline]).then(
      function (v) { clearTimeout(timer); return v; },
      function (e) { clearTimeout(timer); throw e; }
    );
  }

  return {
    THRESHOLDS: THRESHOLDS, STATES: STATES,
    feedTimestamp: feedTimestamp, formatAge: formatAge,
    classifyFeed: classifyFeed, toneFor: toneFor, badgeFor: badgeFor, fetchJson: fetchJson,
    LIVE_WINDOWS: LIVE_WINDOWS, classifyRecord: classifyRecord, isLiveRecord: isLiveRecord,
    pipelineAllowsLive: pipelineAllowsLive, selectLiveRecords: selectLiveRecords,
  };
});
