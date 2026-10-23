/* SENTINEL APEX SOC — customer-safe, read-only intelligence desk.
 * Renders a bounded first-party public feed; never represents feed records as
 * customer alerts, confirmed incidents, or live managed SOC coverage.
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root && root.document) {
    root.SocIntelligenceDesk = api;
    if (root.document.readyState === 'loading') {
      root.document.addEventListener('DOMContentLoaded', function () { api.boot(root); }, { once: true });
    } else api.boot(root);
  }
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';
  var ENDPOINT = '/live-intel.json';
  var ALLOWED_SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  var LIMIT = 12;

  function string(value, fallback) {
    return typeof value === 'string' && value.trim() ? value.trim().slice(0, 300) : fallback;
  }
  function safeRecordHref(raw) {
    if (typeof raw !== 'string' || raw.length > 512) return null;
    try {
      var u = new URL(raw, 'https://soc.cyberdudebivash.in');
      if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) return null;
      if (!['soc.cyberdudebivash.in', 'blog.cyberdudebivash.in'].includes(u.hostname)) return null;
      if (!/^\/posts\/[a-z0-9._-]+\.html$/i.test(u.pathname)) return null;
      return u.pathname;
    } catch (e) { return null; }
  }
  function normalizeRecords(feed) {
    if (!feed || !Array.isArray(feed.items)) return null;
    return feed.items.slice(0, 100).filter(function (item) {
      return item && typeof item === 'object' && !Array.isArray(item) &&
        typeof item.title === 'string' && item.title.trim();
    }).map(function (item) {
      var severity = string(item.threatLevel || item.threat_level, 'UNASSESSED').toUpperCase();
      if (ALLOWED_SEVERITY.indexOf(severity) === -1) severity = 'UNASSESSED';
      return {
        id: string(item.id, 'ID NOT SUPPLIED'),
        title: string(item.title, 'Untitled report'),
        severity: severity,
        source: string(item.source, 'SOURCE NOT SUPPLIED'),
        exploited: item.exploited === true,
        href: safeRecordHref(item.link),
        date: string(item.pubDate || item.first_seen, 'DATE NOT SUPPLIED')
      };
    });
  }
  function filterRecords(records, query, severity, exploitedOnly) {
    var q = String(query || '').trim().toLocaleLowerCase().slice(0, 120);
    return records.filter(function (item) {
      return (severity === 'all' || item.severity === severity) &&
        (!exploitedOnly || item.exploited) &&
        (!q || (item.id + ' ' + item.title + ' ' + item.source).toLocaleLowerCase().includes(q));
    });
  }
  function metrics(records) {
    return {
      records: records.length,
      exploited: records.filter(function (x) { return x.exploited; }).length,
      sources: new Set(records.map(function (x) { return x.source.toLowerCase(); })
        .filter(function (x) { return x !== 'source not supplied'; })).size
    };
  }

  function csvCell(value) {
    var v = String(value == null ? '' : value).replace(/[\u0000-\u001f]/g, ' ').slice(0, 400);
    if (/^\s*[=+\-@]/.test(v)) v = "'" + v;
    return '"' + v.replace(/"/g, '""') + '"';
  }
  function buildCsv(records) {
    var header = ['ID', 'Title', 'Feed severity', 'Feed source', 'Exploitation flagged', 'Record date', 'Report URL'];
    var rows = records.slice(0, 100).map(function (record) {
      return [record.id, record.title, record.severity, record.source,
        record.exploited ? 'Yes (feed-reported)' : 'No', record.date,
        record.href ? 'https://soc.cyberdudebivash.in' + record.href : 'Not verified'];
    });
    return [header].concat(rows).map(function (row) {
      return row.map(csvCell).join(',');
    }).join('\r\n') + '\r\n';
  }

  function text(root, selector, value) {
    var el = root.querySelector(selector);
    if (el) el.textContent = String(value);
  }
  function make(document, tag, className, value) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    if (value !== undefined) el.textContent = String(value);
    return el;
  }
  function card(document, item) {
    var li = make(document, 'li', 'soc-desk__record');
    var head = make(document, 'div', 'soc-desk__record-head');
    var sev = make(document, 'span', 'soc-desk__severity', item.severity);
    sev.dataset.severity = item.severity;
    head.append(sev, make(document, 'span', 'soc-desk__record-id', item.id));
    li.append(head, make(document, 'h3', 'soc-desk__record-title', item.title));
    var meta = make(document, 'p', 'soc-desk__record-meta');
    meta.append(make(document, 'span', '', 'Source: ' + item.source));
    meta.append(make(document, 'span', '', 'Dated: ' + item.date));
    if (item.exploited) meta.append(make(document, 'span', 'soc-desk__exploited', 'Reported exploitation'));
    li.append(meta);
    if (item.href) {
      var link = make(document, 'a', 'soc-desk__record-link', 'Read source-linked report');
      link.href = item.href;
      li.append(link);
    } else {
      li.append(make(document, 'span', 'soc-desk__unlinked', 'Direct report link not verified'));
    }
    return li;
  }
  function boot(root) {
    var document = root.document;
    var shell = document.getElementById('soc-intelligence-desk');
    if (!shell || shell.dataset.initialized) return;
    shell.dataset.initialized = 'true';
    var RS = root.SentinelRuntimeState;
    var list = shell.querySelector('[data-desk-records]');
    var search = shell.querySelector('[data-desk-search]');
    var severity = shell.querySelector('[data-desk-severity]');
    var exploited = shell.querySelector('[data-desk-exploited]');
    var refresh = shell.querySelector('[data-desk-refresh]');
    var exportButton = shell.querySelector('[data-desk-export]');
    if (!list || !search || !severity || !exploited || !refresh) return;
    var records = [];
    function show() {
      var subset = filterRecords(records, search.value, severity.value, exploited.checked);
      var frag = document.createDocumentFragment();
      subset.slice(0, LIMIT).forEach(function (item) { frag.append(card(document, item)); });
      list.replaceChildren(frag);
      text(shell, '[data-desk-count]', String(subset.length));
      text(shell, '[data-desk-visible]', 'Showing ' + Math.min(LIMIT, subset.length) + ' of ' + subset.length + ' matching feed records.');
      if (exportButton) exportButton.disabled = subset.length === 0;
      var empty = shell.querySelector('[data-desk-empty]');
      if (empty) empty.hidden = subset.length > 0;
    }
    function setStatus(state, detail) {
      var indicator = shell.querySelector('[data-desk-state]');
      if (indicator) { indicator.dataset.state = state; indicator.textContent = state; }
      text(shell, '[data-desk-state-summary]', state);
      text(shell, '[data-desk-status-detail]', detail);
    }
    function fetchFeed() {
      refresh.disabled = true;
      setStatus('CHECKING', 'Checking the first-party public CTI snapshot. No customer telemetry is requested.');
      return (RS && typeof RS.fetchJson === 'function'
        ? RS.fetchJson(ENDPOINT, { timeoutMs: 8000 })
        : Promise.reject(new Error('Freshness verifier unavailable')))
        .then(function (feed) {
          var parsed = normalizeRecords(feed);
          if (!parsed) throw new Error('Invalid feed contract');
          var cls = RS.classifyFeed({ ok: true, feed: feed });
          records = parsed;
          var summary = metrics(records);
          text(shell, '[data-desk-sample]', String(summary.records));
          text(shell, '[data-desk-exploited-count]', String(summary.exploited));
          text(shell, '[data-desk-sources]', String(summary.sources));
          setStatus(cls.state, cls.reason);
          text(shell, '[data-desk-published]', cls.timestamp
            ? 'Feed timestamp: ' + cls.timestamp.replace('T', ' ').slice(0, 19) + ' UTC'
            : 'Feed timestamp not established');
          show();
        })
        .catch(function (error) {
          records = [];
          text(shell, '[data-desk-sample]', '—');
          text(shell, '[data-desk-exploited-count]', '—');
          text(shell, '[data-desk-sources]', '—');
          text(shell, '[data-desk-published]', 'No validated feed timestamp');
          setStatus('UNAVAILABLE', 'Public CTI snapshot unavailable (' +
            (error && error.message === 'timeout' ? 'request timeout' : 'retrieval/validation failed') +
            '). This does not indicate customer incident status.');
          show();
        })
        .finally(function () { refresh.disabled = false; });
    }
    search.addEventListener('input', show);
    severity.addEventListener('change', show);
    exploited.addEventListener('change', show);
    refresh.addEventListener('click', fetchFeed);
    if (exportButton) exportButton.addEventListener('click', function () {
      var subset = filterRecords(records, search.value, severity.value, exploited.checked);
      if (!subset.length) return;
      var blob = new Blob([buildCsv(subset)], { type: 'text/csv;charset=utf-8' });
      var href = URL.createObjectURL(blob);
      try {
        var a = document.createElement('a');
        a.href = href; a.download = 'sentinel-apex-soc-public-cti.csv';
        a.hidden = true;
        document.body.appendChild(a);
        a.click(); a.remove();
      } finally { URL.revokeObjectURL(href); }
    });
    show();
    fetchFeed();
  }
  return { ENDPOINT: ENDPOINT, LIMIT: LIMIT, safeRecordHref: safeRecordHref,
    normalizeRecords: normalizeRecords, filterRecords: filterRecords, metrics: metrics,
    csvCell: csvCell, buildCsv: buildCsv, boot: boot };
});
