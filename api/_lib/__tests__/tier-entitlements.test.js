'use strict';

// Regression suite for the Sentinel Team entitlement defect: every paid
// capability gate hand-wrote `tier === 'pro' || tier === 'enterprise'`, so
// the Team plan (priced above Pro; advertised with IOC access, STIX 2.1
// export and SIEM export) received free-tier data and 403s. These tests run
// the real handlers/libraries against committed production data with only
// authenticate() stubbed to a controlled tier.

jest.mock('../middleware', () => {
  const actual = jest.requireActual('../middleware');
  return { ...actual, authenticate: jest.fn() };
});

const fs = require('fs');
const path = require('path');
const { authenticate } = require('../middleware');
const middleware = jest.requireActual('../middleware');
const entitlements = require('../tier-entitlements');
const intel = require('../intel');
const threatGraph = require('../threat-graph');
const enrichment = require('../enrichment-pipeline');
const siem = require('../siem-connector-store');
const intelHandler = require('../../v1/intel');
const iocSearchHandler = require('../../v1/ioc/search');
const { PLANS } = require('../payment-utils');

function mockReq(query = {}) {
  return { method: 'GET', query, headers: {}, url: '/api/v1/intel' };
}
function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.send = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
function asTier(tier) {
  authenticate.mockReset();
  authenticate.mockResolvedValue({ tier, userId: `u-${tier}`, email: `${tier}@example.com`, keyHash: 'h', requestsUsed: 1, requestsLimit: 999999 });
}

describe('canonical tier module', () => {
  test('ordering matches the published price ladder (Team is priced above Pro)', () => {
    expect(entitlements.TIERS).toEqual(['free', 'starter', 'pro', 'team', 'enterprise']);
    expect(PLANS.team.amount).toBeGreaterThan(PLANS.pro.amount);
    expect(PLANS.enterprise.amount).toBeGreaterThan(PLANS.team.amount);
  });

  test('middleware keeps re-exporting the same canonical TIERS (backward compatible)', () => {
    expect(middleware.TIERS).toBe(entitlements.TIERS);
  });

  test('tierAtLeast: paid ladder semantics, unknown caller tiers fail closed', () => {
    expect(entitlements.tierAtLeast('team', 'pro')).toBe(true);
    expect(entitlements.tierAtLeast('enterprise', 'team')).toBe(true);
    expect(entitlements.tierAtLeast('pro', 'team')).toBe(false);
    expect(entitlements.tierAtLeast('starter', 'pro')).toBe(false);
    expect(entitlements.tierAtLeast(undefined, 'pro')).toBe(false);
    expect(entitlements.tierAtLeast('PRO', 'pro')).toBe(false);
    expect(() => entitlements.tierAtLeast('pro', 'platinum')).toThrow(/unknown minimum tier/);
  });

  test('dataProfile: Team gets the Pro profile, never Enterprise-only fields, unknown -> free', () => {
    expect(entitlements.dataProfile('team')).toBe('pro');
    expect(entitlements.dataProfile('enterprise')).toBe('enterprise');
    expect(entitlements.dataProfile('starter')).toBe('free');
    expect(entitlements.dataProfile('bogus')).toBe('free');
    expect(entitlements.dataProfile('__proto__')).toBe('free');
  });
});

describe('Team receives at least Pro data from the intel library', () => {
  test('getIntel: Team is served the Pro response shape, not the truncated free shape', () => {
    // attestItem() stamps verified_at with the wall clock; pin it so the
    // comparison is about entitlement shape, not millisecond jitter.
    jest.useFakeTimers({ now: new Date('2026-09-30T00:00:00Z') });
    const team = intel.getIntel('live', 'team', { limit: '5' });
    const pro = intel.getIntel('live', 'pro', { limit: '5' });
    const free = intel.getIntel('live', 'free', { limit: '5' });
    expect(team.items.length).toBeGreaterThan(0);
    expect(team.items).toEqual(pro.items);
    expect(team.items).not.toEqual(free.items);
    expect(team.tier_info).toMatchObject({ full_access: true, ioc_access: true, detection_rules: true, realtime_feed: false });
    jest.useRealTimers();
  });

  test('applyTierFilter never gives Team the free-tier upgrade-teaser description', () => {
    const [item] = intel.applyTierFilter([{ id: 'X-1', title: 't', description: 'd'.repeat(400) }], 'team');
    expect(item.description).toBe('d'.repeat(400));
    const [freeItem] = intel.applyTierFilter([{ id: 'X-1', title: 't', description: 'd'.repeat(400) }], 'free');
    expect(freeItem.description).toMatch(/Upgrade to Pro/);
  });

  test('threat graph node budget: Team >= Pro, starter unchanged', () => {
    const graph = { nodes: Object.fromEntries(Array.from({ length: 400 }, (_, i) => [`n${i}`, { id: `n${i}`, type: 'CVE', attributes: { priority_score: 90 } }])), edges: [] };
    expect(threatGraph.getGraphForTier(graph, 'team').tier_info.node_limit).toBe(300);
    expect(threatGraph.getGraphForTier(graph, 'pro').tier_info.node_limit).toBe(300);
    expect(threatGraph.getGraphForTier(graph, 'starter').tier_info.node_limit).toBe(60);
  });

  test('enrichment tier gating uses the Pro filter for Team', () => {
    const item = { id: 'X', actor_attribution: { primary_actor: 'A', signals: ['s'] }, data_confidence: { score: 80, tier: 'HIGH' } };
    expect(enrichment.applyTierGating([item], 'team')).toEqual(enrichment.applyTierGating([item], 'pro'));
    expect(enrichment.applyTierGating([item], 'team')).not.toEqual(enrichment.applyTierGating([item], 'free'));
  });

  test('SIEM connector entitlements: Team can connect a live SIEM (advertised SIEM export)', () => {
    expect(siem.getSiemConnectorEntitlements('team').live_connectors).toEqual({ enabled: true, max: 5 });
    expect(siem.getSiemConnectorEntitlements('starter').live_connectors).toEqual({ enabled: false, max: 0 });
  });
});

describe('Team is not refused capabilities that Pro receives (real handlers)', () => {
  test('action=iocs: Team 200, starter 403', async () => {
    asTier('team');
    let res = mockRes();
    await intelHandler(mockReq({ action: 'iocs', limit: '5' }), res);
    expect(res.statusCode).not.toBe(403);
    expect(res.body && res.body.error).toBeFalsy();

    asTier('starter');
    res = mockRes();
    await intelHandler(mockReq({ action: 'iocs', limit: '5' }), res);
    expect(res.statusCode).toBe(403);
  });

  test('action=iocs&format=stix: STIX 2.1 bundle is delivered to Team (sold feature) but not Pro', async () => {
    asTier('team');
    let res = mockRes();
    await intelHandler(mockReq({ action: 'iocs', limit: '5', format: 'stix' }), res);
    const teamBody = res.body;
    expect(teamBody.stix).toBeTruthy();
    expect(teamBody.stix.type).toBe('bundle');

    asTier('pro');
    res = mockRes();
    await intelHandler(mockReq({ action: 'iocs', limit: '5', format: 'stix' }), res);
    expect(res.body.stix).toBeNull();
  });

  test('legacy /api/v1/ioc/search: Team is not TIER_RESTRICTED', async () => {
    asTier('team');
    const res = mockRes();
    await iocSearchHandler({ method: 'GET', query: { q: 'example' }, headers: {}, url: '/api/v1/ioc/search' }, res);
    expect(res.statusCode).not.toBe(403);
  });
});

describe('recurrence guard', () => {
  // A new hand-written `pro || enterprise` literal would silently re-exclude
  // Team. Paid-capability gates must use tier-entitlements instead.
  const apiRoot = path.join(__dirname, '..', '..');
  function walk(dir, out = []) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name === '__tests__' || e.name === 'node_modules' || e.name === 'intel' || e.name === 'tier-entitlements.js') continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p, out);
      else if (e.name.endsWith('.js')) out.push(p);
    }
    return out;
  }

  test('no API module gates on the literal pair pro/enterprise', () => {
    const pattern = /tier\s*===\s*'pro'\s*\|\|\s*[\w.]*tier\s*===\s*'enterprise'|tier\s*!==\s*'pro'\s*&&\s*[\w.]*tier\s*!==\s*'enterprise'/;
    const offenders = walk(apiRoot).filter(f => pattern.test(fs.readFileSync(f, 'utf8')));
    expect(offenders.map(f => path.relative(apiRoot, f))).toEqual([]);
  });
});
