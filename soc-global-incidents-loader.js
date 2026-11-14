/* SENTINEL APEX SOC — GCII fail-closed, read-only session freshness.
 * A successful initial fetch is not perpetual authorization to display incident
 * cards. Re-evaluate the existing verified snapshot locally; never poll APIs.
 */
(function () {
  'use strict';
  const container = document.getElementById('soc-gcii-feed');
  if (!container) return;
  const incidents = window.CDBGlobalIncidents;
  const RECHECK_MS = 5000;
  let snapshot = null;
  let signature = null;
  let expiryTimer = null;

  function unavailable() {
    container.replaceChildren();
    const p = document.createElement('p');
    p.textContent = 'Global incident feed unavailable or invalid. Verified coverage cannot be asserted.';
    container.appendChild(p);
  }
  function stopExpiryTimer() {
    if (expiryTimer !== null) {
      window.clearTimeout(expiryTimer);
      expiryTimer = null;
    }
  }
  function invalidate() {
    stopExpiryTimer();
    snapshot = null;
    signature = null;
    unavailable();
  }
  // Derive a bounded fingerprint from the renderer's same incident-selection
  // authority. This is an ephemeral UI revision marker, not a crypto signature.
  function currentSignature(feed, nowMs) {
    if (!incidents || typeof incidents.selectFreshIncidents !== 'function') return null;
    const selected = incidents.selectFreshIncidents(feed, nowMs);
    if (!Array.isArray(selected)) return null;
    return JSON.stringify(selected.map(item => [item.id, item.updated_utc]));
  }
  function reviewSnapshot() {
    if (!snapshot) return;
    if (container.isConnected === false) { stopExpiryTimer(); snapshot = null; return; }
    try {
      const next = currentSignature(snapshot, Date.now());
      if (next === null) {
        // An expired or invalid snapshot must never become live again without
        // a new verified network retrieval. Render the safe stale indicator.
        const expired = snapshot;
        stopExpiryTimer();
        snapshot = null;
        signature = null;
        if (!incidents.render(container, expired)) unavailable();
        return;
      }
      if (next !== signature) {
        if (!incidents.render(container, snapshot)) {
          invalidate();
          return;
        }
        signature = next;
      }
    } catch (_) {
      invalidate();
    }
  }
  function scheduleExpiryCheck() {
    stopExpiryTimer();
    if (!snapshot) return;
    expiryTimer = window.setTimeout(function () {
      expiryTimer = null;
      reviewSnapshot();
      if (snapshot) scheduleExpiryCheck();
    }, RECHECK_MS);
  }
  function onResume() { if (!document.hidden) reviewSnapshot(); }
  if (!incidents || typeof incidents.render !== 'function' ||
      typeof incidents.selectFreshIncidents !== 'function') {
    unavailable();
    return;
  }

  document.addEventListener('visibilitychange', onResume);
  window.addEventListener('focus', reviewSnapshot);
  window.addEventListener('pagehide', function () {
    stopExpiryTimer();
    snapshot = null;
    signature = null;
  });

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 6000);
  fetch('/api/v1/global-incidents/feed.json', {
    method: 'GET', credentials: 'omit', cache: 'no-store',
    headers: { Accept: 'application/json' }, signal: controller.signal
  }).then(response => {
    if (!response.ok || !(response.headers.get('content-type') || '').includes('application/json')) throw Error('invalid response');
    const length = Number(response.headers.get('content-length') || 0);
    if (length > 1048576) throw Error('too large');
    return response.text();
  }).then(body => {
    if (body.length > 1048576) throw Error('too large');
    const feed = JSON.parse(body);
    const current = currentSignature(feed, Date.now());
    // The renderer itself supplies the user-facing unavailable/stale state.
    if (!incidents.render(container, feed)) throw Error('invalid feed');
    if (current === null) return; // Never retain or later resurrect an invalid/stale feed.
    snapshot = feed;
    signature = current;
    scheduleExpiryCheck();
  }).catch(invalidate).finally(() => window.clearTimeout(timeout));
})();
