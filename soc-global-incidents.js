/* SENTINEL APEX SOC — GCII v1 read-only, fail-closed consumer.
 * Explicitly invoke CDBGlobalIncidents.render(container, feed) with a parsed JSON feed.
 * Never inject feed text as HTML. */
(function (global) {
  'use strict';
  var STATES = ['investigating', 'confirmed', 'disputed', 'resolved'];
  var SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'];
  function validUrl(url) {
    try {
      var u = new URL(url);
      return u.protocol === 'https:' && !u.username && !u.password &&
        (u.port === '' || u.port === '443') && u.hostname.indexOf('.') > 0 &&
        !/(^localhost$|\.local$|\.internal$)/i.test(u.hostname);
    } catch (_) { return false; }
  }
  function validDate(value) {
    return typeof value === 'string' && /(Z|[+-]\d\d:\d\d)$/.test(value) &&
      Number.isFinite(Date.parse(value));
  }
  function validate(feed) {
    if (!feed || feed.schema !== 'cdb.global-incidents.v1' ||
        !validDate(feed.generated_at_utc) || !Array.isArray(feed.incidents) ||
        feed.incidents.length > 500 || !/^[a-f0-9]{64}$/.test(feed.sha256 || '')) return false;
    var ids = new Set();
    return feed.incidents.every(function (item) {
      if (!item || typeof item.id !== 'string' || !item.id || ids.has(item.id) ||
          typeof item.title !== 'string' || !item.title ||
          !STATES.includes(item.status) || !SEVERITIES.includes(item.severity) ||
          !['low','medium','high'].includes(item.confidence) ||
          !validDate(item.updated_utc) || !validDate(item.first_seen_utc) ||
          !Array.isArray(item.sources) || item.sources.length < 1 || item.sources.length > 20 ||
          !Array.isArray(item.claims) || item.claims.length < 1 || item.claims.length > 100) return false;
      ids.add(item.id);
      var urls = new Set();
      if (!item.sources.every(function (s) {
        if (!s || !validUrl(s.url) || typeof s.publisher !== 'string' ||
            !s.publisher || !validDate(s.published_at_utc) || !validDate(s.retrieved_at_utc) ||
            urls.has(s.url)) return false;
        urls.add(s.url); return true;
      })) return false;
      if (!item.claims.every(function (c) {
        return c && typeof c.text === 'string' && c.text.length > 0 &&
          ['reported','corroborated','confirmed','disputed'].includes(c.verification_state) &&
          Array.isArray(c.source_urls) && c.source_urls.length > 0 &&
          c.source_urls.every(function (url) { return urls.has(url); });
      })) return false;
      return item.status !== 'confirmed' ||
        item.claims.some(function (c) { return c.verification_state === 'confirmed'; });
    });
  }
  // Expose only incident records with a genuine updated timestamp in the
  // last 24h, and only when the incident-feed publication is <=2h old.
  // Null means feed freshness cannot be certified; [] means no recent records.
  function selectFreshIncidents(feed, nowMs) {
    if (!validate(feed)) return null;
    var now = typeof nowMs === 'number' && Number.isFinite(nowMs) ? nowMs : Date.now();
    var generated = Date.parse(feed.generated_at_utc);
    if (generated > now + 300000 || now - generated > 7200000) return null;
    return feed.incidents.filter(function (item) {
      var updated = Date.parse(item.updated_utc);
      var firstSeen = Date.parse(item.first_seen_utc);
      return updated <= now && updated >= now - 86400000 &&
        firstSeen <= updated && firstSeen <= now;
    }).sort(function (a, b) {
      return Date.parse(b.updated_utc) - Date.parse(a.updated_utc);
    }).slice(0, 20);
  }
  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text;
    return node;
  }
  function render(container, feed) {
    if (!container || typeof container.replaceChildren !== 'function') return false;
    var fragment = document.createDocumentFragment();
    fragment.appendChild(el('h2', 'Global Critical Incidents'));
    if (!validate(feed)) {
      fragment.appendChild(el('p', 'Incident intelligence unavailable or invalid — no verified coverage can be asserted.', 'soc-gcii-unavailable'));
      container.replaceChildren(fragment);
      return false;
    }
    var current = selectFreshIncidents(feed);
    if (current === null) {
      fragment.appendChild(el('p', 'Incident feed stale or clock unverified. Historical incident cards are withheld until a fresh published feed is verified.', 'soc-gcii-stale'));
      container.replaceChildren(fragment);
      return true; // A safe unavailable state was rendered; the loader need not overwrite it.
    }
    fragment.appendChild(el('p', 'Feed generated: ' + feed.generated_at_utc + ' · ' + current.length + ' recently updated records (24h)'));
    if (!current.length) fragment.appendChild(el('p', 'No verified incident updates in the last 24 hours; this does not imply zero global incidents.'));
    current.forEach(function (item) {
      var card = el('article', '', 'soc-gcii-card');
      card.appendChild(el('h3', item.title));
      card.appendChild(el('p', item.severity.toUpperCase() + ' · ' + item.status + ' · confidence: ' + item.confidence));
      card.appendChild(el('p', 'Updated: ' + item.updated_utc));
      item.claims.forEach(function (claim) {
        card.appendChild(el('p', claim.verification_state + ': ' + claim.text));
      });
      var list = document.createElement('ul');
      item.sources.forEach(function (source) {
        var li = document.createElement('li'), a = el('a', source.publisher);
        a.href = source.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
        li.appendChild(a); list.appendChild(li);
      });
      card.appendChild(list); fragment.appendChild(card);
    });
    container.replaceChildren(fragment);
    return true;
  }
  global.CDBGlobalIncidents = Object.freeze({validate:validate, selectFreshIncidents:selectFreshIncidents, render:render});
})(window);
