// Run: node --test tests/soc-gcii-session-expiry.test.cjs
// Zero network, no Cloudflare credentials, no production writes.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const consumer = fs.readFileSync(path.join(root, 'soc-global-incidents.js'), 'utf8');
const loader = fs.readFileSync(path.join(root, 'soc-global-incidents-loader.js'), 'utf8');
const MINUTE = 60000;
const HOUR = 60 * MINUTE;

function fixture(now, options = {}) {
  const iso = n => new Date(n).toISOString();
  const generated = options.generatedAt ?? now - 30 * MINUTE;
  const updated = options.updatedAt ?? now - (24 * HOUR - MINUTE);
  const firstSeen = options.firstSeen ?? updated - 10 * MINUTE;
  const url = 'https://example.org/advisory';
  return {
    schema: 'cdb.global-incidents.v1',
    generated_at_utc: iso(generated),
    sha256: 'a'.repeat(64),
    incidents: [{
      id: 'evidence-1', title: 'Source-linked incident update',
      first_seen_utc: iso(firstSeen), updated_utc: iso(updated),
      status: 'confirmed', severity: 'high', confidence: 'medium',
      sources: [{url, publisher: 'Example CERT',
        published_at_utc: iso(updated), retrieved_at_utc: iso(updated)}],
      claims: [{text: 'Source-backed report', verification_state: 'confirmed', source_urls: [url]}]
    }]
  };
}

function fakeElement(tagName = 'div') {
  return {
    tagName, className: '', textContent: '', children: [], isConnected: true,
    appendChild(node) { this.children.push(node); return node; },
    replaceChildren(...nodes) {
      this.children = nodes.flatMap(node =>
        node && node.tagName === '#fragment' ? node.children.slice() : [node]);
    },
  };
}
function descendants(node) {
  return [node, ...(node.children || []).flatMap(descendants)];
}
async function setup({ ageMinutes = 30, corrupt = false, deferResponse = false } = {}) {
  let now = Date.parse('2026-11-14T12:00:00Z');
  const container = fakeElement('section');
  const documentListeners = {};
  const windowListeners = {};
  const timers = new Map();
  let timerId = 0;
  let requests = 0;
  let renders = 0;
  let releaseResponse = null;
  const payload = fixture(now, {generatedAt: now - ageMinutes * MINUTE});
  if (corrupt) payload.schema = 'unexpected-schema';
  class Clock extends Date { static now() { return now; } }
  const setTimeout = (fn, delay) => {
    const id = ++timerId;
    timers.set(id, {fn, delay});
    return id;
  };
  const clearTimeout = id => { timers.delete(id); };
  const document = {
    hidden: false,
    getElementById: id => id === 'soc-gcii-feed' ? container : null,
    createElement: tag => fakeElement(tag),
    createDocumentFragment: () => fakeElement('#fragment'),
    addEventListener: (event, fn) => { documentListeners[event] = fn; },
  };
  const window = {
    addEventListener: (event, fn) => { windowListeners[event] = fn; },
    setTimeout, clearTimeout,
  };
  const fetch = (url, options) => {
    requests++;
    assert.equal(url, '/api/v1/global-incidents/feed.json');
    assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.cache, 'no-store');
    const response = {
      ok: true,
      headers: {get(name) {
        return name === 'content-type' ? 'application/json' : null;
      }},
      text: async () => JSON.stringify(payload),
    };
    if (deferResponse) return new Promise(resolve => { releaseResponse = () => resolve(response); });
    return Promise.resolve(response);
  };
  const context = vm.createContext({
    window, document, Date: Clock, URL, Set, Number, Object,
    AbortController, fetch, setTimeout, clearTimeout,
  });
  vm.runInContext(consumer, context, {filename:'soc-global-incidents.js'});
  const render = window.CDBGlobalIncidents.render;
  window.CDBGlobalIncidents = Object.freeze({
    ...window.CDBGlobalIncidents,
    render(...args) { renders++; return render(...args); },
  });
  vm.runInContext(loader, context, {filename:'soc-global-incidents-loader.js'});
  for (let i = 0; i < 12; i++) await Promise.resolve();
  const status = () => descendants(container).map(n => n.textContent || '').join(' | ');
  const cards = () => descendants(container).filter(n => n.className === 'soc-gcii-card');
  const runExpiry = () => {
    const timer = Array.from(timers.entries()).find(([, t]) => t.delay === 5000);
    assert.ok(timer, 'one local freshness check must be scheduled');
    timers.delete(timer[0]);
    timer[1].fn();
  };
  return {
    container, status, cards, runExpiry, payload, document, documentListeners,
    windowListeners, timers, get requests() { return requests; },
    get renders() { return renders; },
    advance(ms) { now += ms; },
    releaseResponse() { if (releaseResponse) releaseResponse(); },
  };
}

test('fresh incident ages out within the open browser tab without any network polling', async () => {
  const h = await setup();
  assert.equal(h.requests, 1);
  assert.equal(h.cards().length, 1, 'initial verified incident is visible');
  h.advance(2 * MINUTE);
  h.runExpiry();
  assert.equal(h.cards().length, 0, 'incident older than 24h is withheld');
  assert.match(h.status(), /No verified incident updates in the last 24 hours/);
  assert.equal(h.requests, 1, 'local timer never performs another fetch');
});

test('unchanged snapshot is not needlessly rerendered or queried', async () => {
  const h = await setup();
  const renders = h.renders;
  h.advance(5000);
  h.runExpiry();
  assert.equal(h.cards().length, 1);
  assert.equal(h.renders, renders, 'no DOM churn while incident selection remains unchanged');
  assert.equal(h.requests, 1);
});

test('two-hour feed expiry removes all incident cards and never resurrects stale snapshot', async () => {
  const h = await setup();
  h.advance(92 * MINUTE); // generated 30min before load => >2h
  h.runExpiry();
  assert.equal(h.cards().length, 0);
  assert.match(h.status(), /Incident feed stale or clock unverified/);
  assert.equal(Array.from(h.timers.values()).filter(t => t.delay === 5000).length, 0);
  h.advance(60 * MINUTE);
  h.documentListeners.visibilitychange();
  assert.equal(h.cards().length, 0);
  assert.equal(h.requests, 1);
});

test('background-tab resume immediately hides expired cards, with no fetch', async () => {
  const h = await setup();
  h.advance(92 * MINUTE);
  h.documentListeners.visibilitychange();
  assert.equal(h.cards().length, 0);
  assert.match(h.status(), /Incident feed stale/);
  assert.equal(h.requests, 1);
});

test('invalid and already-stale first responses fail closed without retained timers', async () => {
  for (const options of [{corrupt:true}, {ageMinutes:181}]) {
    const h = await setup(options);
    assert.equal(h.cards().length, 0);
    assert.equal(Array.from(h.timers.values()).filter(t => t.delay === 5000).length, 0);
    assert.equal(h.requests, 1);
  }
});

test('pagehide clears cards and cancels local rechecks before bfcache restores the page', async () => {
  const h = await setup();
  assert.equal(h.cards().length, 1);
  h.windowListeners.pagehide();
  assert.equal(h.cards().length, 0, 'bfcache must not restore live-looking incident cards');
  assert.match(h.status(), /Verified coverage cannot be asserted/);
  assert.equal(Array.from(h.timers.values()).filter(t => t.delay === 5000).length, 0);
  assert.equal(h.requests, 1);
});

test('fetch resolving after pagehide cannot resurrect incident cards or schedule new timers', async () => {
  const h = await setup({deferResponse:true});
  assert.equal(h.requests, 1);
  h.windowListeners.pagehide();
  h.releaseResponse();
  for (let i=0;i<12;i++) await Promise.resolve();
  assert.equal(h.cards().length, 0);
  assert.match(h.status(), /Verified coverage cannot be asserted/);
  assert.equal(Array.from(h.timers.values()).filter(t => t.delay === 5000).length, 0);
  assert.equal(h.requests, 1);
});

test('versioned GCII asset and all release gate scripts include the session-expiry regression suite', () => {
  const html = fs.readFileSync(path.join(root, 'soc.html'), 'utf8');
  assert.match(html, /src="\/soc-global-incidents\.js\?v=20261112-fresh-only1"/);
  assert.match(html, /src="\/soc-global-incidents-loader\.js\?v=20261114-gcii-expiry1"/);
  const scripts = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts;
  for (const key of ['test:ci', 'check:cloudflare', 'test:soc-frontend']) {
    assert.match(scripts[key], /tests\/soc-gcii-session-expiry\.test\.cjs/, key);
  }
});
