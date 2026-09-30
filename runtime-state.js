/* SENTINEL APEX — public runtime state model (single source for customer pages).
 *
 * States are derived only from what the browser actually observed:
 *   CHECKING     a request is in flight (initial markup state)
 *   HEALTHY      feed reachable; pipeline timestamp within the monitor's warn window
 *   DEGRADED     feed reachable but freshness is behind cadence or not provable
 *   STALE        feed reachable; pipeline timestamp older than the monitor's stale window
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

  function feedTimestamp(feed) {
    if (!feed || typeof feed !== 'object') return null;
    var meta = feed.metadata || {};
    // Pipeline completion first: it is what the CI monitor measures.
    return meta.lastPipelineRun || meta.generated || feed.generatedAt || feed.lastUpdated || meta.generatedAt || null;
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
        reason: 'Feed reachable; pipeline timestamp missing or invalid, so freshness is not established.' };
    }
    var iso = new Date(ms).toISOString();
    if (ms - nowMs > THRESHOLDS.futureToleranceMinutes * 60000) {
      return { state: STATES.DEGRADED, reachable: true, ageMinutes: null, timestamp: iso,
        reason: 'Feed reachable; pipeline timestamp is in the future, so freshness is not established.' };
    }
    var age = Math.max(0, Math.floor((nowMs - ms) / 60000));
    if (age <= THRESHOLDS.healthyMaxMinutes) {
      return { state: STATES.HEALTHY, reachable: true, ageMinutes: age, timestamp: iso,
        reason: 'Pipeline completed ' + formatAge(age) + ' ago (' + iso + ').' };
    }
    if (age <= THRESHOLDS.staleAfterMinutes) {
      return { state: STATES.DEGRADED, reachable: true, ageMinutes: age, timestamp: iso,
        reason: 'Pipeline last completed ' + formatAge(age) + ' ago; behind its scheduled cadence.' };
    }
    return { state: STATES.STALE, reachable: true, ageMinutes: age, timestamp: iso,
      reason: 'Pipeline last completed ' + formatAge(age) + ' ago; intelligence may be out of date.' };
  }

  function toneFor(state) {
    return Object.prototype.hasOwnProperty.call(TONE, state) ? TONE[state] : 'warn';
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
    classifyFeed: classifyFeed, toneFor: toneFor, fetchJson: fetchJson,
  };
});
