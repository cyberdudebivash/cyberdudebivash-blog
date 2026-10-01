'use strict';

// Real-handler tests for the evidence-only IOC feed on /api/v1/intel:
// action=iocs (entitlements, filters, STIX), and the graph/search/ioc-detail
// pseudo-IOC cleanup. Only authenticate() is stubbed; data is the committed
// production feed and graph.

jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn() };
});

const { authenticate } = require('../../_lib/middleware');
const handler = require('../intel');
const intel = require('../../_lib/intel');
const { getFeed } = require('../../_lib/ioc-engine/feed');

const NEGATIVE_VALUES = ['github.com', 'microsoft.com', '169.254.169.254', '127.0.0.1', 'localhost', 'cve-2026-12345', 'abcdef1234567890abcdef1234567890abcdef12'];

function req(query) { return { method: 'GET', query, headers: {}, url: '/api/v1/intel' }; }
function res() {
  const r = { statusCode: null, body: null, headers: {} };
  r.setHeader = jest.fn((k, v) => { r.headers[k] = v; });
  r.status = jest.fn(s => { r.statusCode = s; return r; });
  r.json = jest.fn(b => { r.body = b; return r; });
  r.send = jest.fn(b => { r.body = b; return r; });
  r.end = jest.fn(() => r);
  return r;
}
function asTier(tier) {
  authenticate.mockReset();
  authenticate.mockResolvedValue({ tier, userId: `u-${tier}`, email: `${tier}@example.com`, keyHash: 'h', requestsUsed: 1, requestsLimit: 999999 });
}
async function call(tier, query) {
  asTier(tier);
  const r = res();
  await handler(req(query), r);
  return r;
}

describe('action=iocs — entitlements through the canonical tier module', () => {
  test.each(['free', 'starter'])('%s: 403', async tier => {
    expect((await call(tier, { action: 'iocs' })).statusCode).toBe(403);
  });

  test.each(['pro', 'team', 'enterprise'])('%s: evidence-backed indicators with provenance and feed_status', async tier => {
    const r = await call(tier, { action: 'iocs', limit: '20' });
    expect(r.statusCode).toBe(200);
    expect(r.body.iocs.length).toBe(Math.min(20, getFeed().items.length));
    for (const i of r.body.iocs) {
      expect(i.observations.length).toBeGreaterThan(0);
      expect(i.source_url).toMatch(/^https:\/\/[a-z]+\.abuse\.ch\//);
    }
    expect(r.body.feed_status).toMatchObject({ status: expect.stringMatching(/^(healthy|degraded|unavailable)$/), indicator_count: getFeed().items.length });
    expect(r.body.pagination.total).toBe(getFeed().items.length);
  });

  test('STIX 2.1 for Team and Enterprise; Pro gets JSON plus an upgrade note, never a bundle', async () => {
    for (const tier of ['team', 'enterprise']) {
      const r = await call(tier, { action: 'iocs', limit: '5', format: 'stix' });
      expect(r.body.stix.type).toBe('bundle');
      const inds = r.body.stix.objects.filter(o => o.type === 'indicator');
      expect(inds).toHaveLength(r.body.iocs.length);
      expect(inds.map(o => o.id)).toEqual(r.body.iocs.map(i => i.stix_id));
      for (const o of inds) expect(o.pattern).not.toMatch(/file:value|artifact:/);
    }
    const pro = await call('pro', { action: 'iocs', limit: '5', format: 'stix' });
    expect(pro.body.stix).toBeNull();
    expect(pro.body.stix_note).toMatch(/Team and Enterprise/);
  });

  test('filters and validation errors', async () => {
    const urls = await call('pro', { action: 'iocs', type: 'url', limit: '200' });
    expect(urls.body.iocs.every(i => i.type === 'url')).toBe(true);
    const high = await call('pro', { action: 'iocs', confidence: 'HIGH', limit: '200' });
    expect(high.body.iocs.every(i => ['HIGH', 'VERY_HIGH'].includes(i.confidence))).toBe(true);
    expect((await call('pro', { action: 'iocs', limit: '5000' })).body.pagination.limit).toBe(200);
    const bad = await call('pro', { action: 'iocs', type: 'email' });
    expect(bad.statusCode).toBe(400);
    expect(bad.body.error.code || bad.body.error).toBeTruthy();
  });

  test('negative controls never appear in any served page', async () => {
    const r = await call('enterprise', { action: 'iocs', limit: '200', page: '1' });
    const all = [];
    for (let p = 1; p <= r.body.pagination.total_pages; p++) {
      all.push(...(await call('enterprise', { action: 'iocs', limit: '200', page: String(p) })).body.iocs.map(i => i.value.toLowerCase()));
    }
    expect(all.length).toBe(getFeed().items.length);
    for (const v of NEGATIVE_VALUES) expect(all).not.toContain(v);
  });
});

describe('graph / search / ioc detail — legacy pseudo-IOCs removed by provenance', () => {
  test('served graph has only evidence-backed IOC nodes; the persisted graph still holds the legacy ones', () => {
    const persisted = require('../../_lib/threat-graph').loadGraph();
    const legacy = Object.values(persisted.nodes).filter(n => n.type === 'IOC' && !(n.attributes && n.attributes.provenance));
    expect(legacy.length).toBeGreaterThan(0); // regression fixture: real legacy nodes exist on disk
    const served = Object.values(intel.loadGraph().nodes).filter(n => n.type === 'IOC');
    expect(served.every(n => n.attributes.provenance && n.attributes.provenance.source_url)).toBe(true);
    for (const v of NEGATIVE_VALUES) expect(served.map(n => String(n.name).toLowerCase())).not.toContain(v);
  });

  test('unified search IOC results are evidence-backed only', async () => {
    for (const q of ['github.com', '169.254.169.254', 'microsoft.com', 'cve.org']) {
      const r = await call('enterprise', { action: 'unified-search', q, type: 'ioc', limit: '50' });
      const names = (r.body.results || []).map(d => String(d.name).toLowerCase());
      expect(names).not.toContain(q);
    }
    const sample = getFeed().items[0];
    const hit = await call('enterprise', { action: 'unified-search', q: sample.value, type: 'ioc', limit: '5' });
    expect(hit.body.results.map(d => d.id)).toContain(sample.id);
  });

  test('legacy pseudo-IOC ids 404 on action=ioc; feed ids resolve with provenance', async () => {
    expect((await call('pro', { action: 'ioc', id: 'ioc:ipv4:169.254.169.254' })).statusCode).toBe(404);
    expect((await call('pro', { action: 'ioc', id: 'ioc:domain:github.com' })).statusCode).toBe(404);
    const sample = getFeed().items[0];
    const r = await call('pro', { action: 'ioc', id: sample.id });
    expect(r.statusCode).toBe(200);
    expect(JSON.stringify(r.body)).toContain(sample.source_url);
  });
});
