/* SENTINEL APEX SOC pricing — source-provenance trust strip.
 * Read-only; uses the existing first-party feed request instead of unverifiable
 * local fallback metrics. Never asserts uptime, latency or payment success.
 */
(function(root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SocPricingEvidence = api;
  if (root && root.document) {
    if (root.document.readyState === 'loading') {
      root.document.addEventListener('DOMContentLoaded', api.boot, { once: true });
    } else api.boot();
  }
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  function notVerified(state, message) {
    return { state: state, published: null, generatedAt: null, message: message };
  }

  function assess(feed, runtime, nowMs) {
    if (!runtime || typeof runtime.classifyFeed !== 'function') {
      return notVerified('UNAVAILABLE', 'Freshness verifier unavailable. Do not treat the feed as live.');
    }
    if (!feed || typeof feed !== 'object' ||
        !Number.isSafeInteger(feed.totalPublished) || feed.totalPublished < 1 ||
        typeof feed.generatedAt !== 'string' || !feed.metadata ||
        typeof feed.metadata.generated !== 'string' ||
        feed.generatedAt !== feed.metadata.generated ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(feed.generatedAt) ||
        !Number.isFinite(Date.parse(feed.generatedAt))) {
      return notVerified('DEGRADED', 'First-party feed responded, but its genuine report count or publication timestamp cannot be verified.');
    }
    // Deliberately pass ONLY genuine generatedAt. lastPipelineRun is a
    // heartbeat and must never be substituted for publication freshness.
    var result = runtime.classifyFeed({
      ok: true, feed: { generatedAt: feed.generatedAt },
      nowMs: typeof nowMs === 'number' ? nowMs : Date.now()
    });
    if (result.state === 'HEALTHY') {
      return {state: result.state, published: feed.totalPublished,
        generatedAt: result.timestamp,
        message: 'Last served snapshot is within the 90-minute freshness window. Counts describe published reports, not unique threats or verified customer detections.'};
    }
    if (result.state === 'DEGRADED' || result.state === 'STALE') {
      return {state: result.state, published: feed.totalPublished,
        generatedAt: result.timestamp,
        message: 'First-party intelligence snapshot is ' + result.state.toLowerCase() +
          '. Counts describe historical published reports, not current live coverage. Review service evidence before relying on freshness.'};
    }
    return notVerified('UNAVAILABLE', 'Feed publication freshness could not be established.');
  }

  function render(result, doc) {
    if (!doc || !result) return;
    var count = doc.getElementById('stat-threats');
    var generated = doc.getElementById('stat-cves');
    var state = doc.getElementById('pricing-feed-status');
    var note = doc.getElementById('pricing-feed-message');
    var wrap = doc.getElementById('pricing-evidence');
    if (!(count && generated && state && note && wrap)) return;
    count.textContent = result.published === null ? '—' : result.published.toLocaleString('en-US');
    generated.textContent = result.generatedAt ? result.generatedAt.slice(0, 16).replace('T', ' ') : '—';
    state.textContent = result.state;
    state.setAttribute('data-state', result.state);
    wrap.setAttribute('data-state', result.state);
    // textContent prevents untrusted feed content becoming HTML.
    note.textContent = result.message;
  }

  function boot() {
    var doc = typeof document !== 'undefined' ? document : null;
    if (!doc || !doc.getElementById('pricing-evidence')) return;
    var runtime = typeof window !== 'undefined' ? window.SentinelRuntimeState : null;
    if (!runtime || typeof runtime.fetchJson !== 'function') {
      render(notVerified('UNAVAILABLE', 'Unable to verify intelligence freshness in this browser.'), doc);
      return;
    }
    runtime.fetchJson('/live-intel.json', { timeoutMs: 8000 }).then(function (feed) {
      render(assess(feed, runtime, Date.now()), doc);
    }).catch(function () {
      render(notVerified('UNAVAILABLE', 'The first-party intelligence feed could not be verified. Check service evidence before relying on live coverage.'), doc);
    });
  }

  return { assess: assess, render: render, boot: boot };
});
