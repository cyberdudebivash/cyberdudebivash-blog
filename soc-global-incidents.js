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
    var age = Date.now() - Date.parse(feed.generated_at_utc);
    if (age < -300000 || age > 7200000) {
      fragment.appendChild(el('p', 'Incident feed is stale or has an invalid clock. Last-known data shown; freshness not verified.', 'soc-gcii-stale'));
    }
    fragment.appendChild(el('p', 'Feed generated: ' + feed.generated_at_utc + ' · ' + feed.incidents.length + ' records'));
    if (!feed.incidents.length) fragment.appendChild(el('p', 'No verified incidents in this feed; this does not imply zero global incidents.'));
    feed.incidents.forEach(function (item) {
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
  global.CDBGlobalIncidents = Object.freeze({validate:validate, render:render});
})(window);
