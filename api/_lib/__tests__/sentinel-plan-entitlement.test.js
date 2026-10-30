'use strict';

const plan = require('../sentinel-plan-entitlement');

describe('canonical Sentinel APEX upgrade URL', () => {
  test('points at the Sentinel APEX platform with plan=pro and campaign UTMs', () => {
    const u = new URL(plan.premiumUpgradeUrl({ content: 'sentinel-apex-vuln-cve-2025-62593-ray-v3' }));
    expect(`${u.origin}${u.pathname}`).toBe('https://intel.cyberdudebivash.com/upgrade.html');
    expect(Object.fromEntries(u.searchParams)).toEqual({
      plan: 'pro', utm_source: 'intel-factory', utm_medium: 'premium-intelligence',
      utm_campaign: 'sentinel-apex-conversion', utm_content: 'sentinel-apex-vuln-cve-2025-62593-ray-v3',
    });
  });

  test('carries no customer identifier, whatever it is given', () => {
    const u = new URL(plan.premiumUpgradeUrl({ content: 'buyer@example.com cdb_pro_secret?x=1', source: 'https://evil.example/' }));
    expect([...u.searchParams.keys()].sort()).toEqual(['plan', 'utm_campaign', 'utm_content', 'utm_medium', 'utm_source']);
    expect(u.host).toBe('intel.cyberdudebivash.com');
    for (const v of u.searchParams.values()) expect(v).toMatch(/^[a-z0-9._-]+$/);
    expect(u.toString()).not.toContain('@');
  });
});

describe('tier eligibility fails closed', () => {
  test.each([['PRO', true], ['ENTERPRISE', true], ['MSSP', true], ['FREE', false], ['pro', false], ['Pro', false], ['PLATINUM', false], ['', false], [undefined, false], [null, false]])('gateway tier %p -> %p', (tier, eligible) => {
    expect(plan.isEligibleSentinelTier(tier)).toBe(eligible);
  });
  test.each([['pro', true], ['team', true], ['enterprise', true], ['free', false], ['starter', false], ['Pro', false], ['', false], [undefined, false]])('blog tier %p -> %p', (tier, eligible) => {
    expect(plan.isEligibleBlogTier(tier)).toBe(eligible);
  });
  test('only cdb_ keys and JWTs are treated as Sentinel APEX platform credentials', () => {
    expect(plan.isSentinelPlatformCredential('cdb_pro_x')).toBe(true);
    expect(plan.isSentinelPlatformCredential('aaa.bbb.ccc')).toBe(true);
    expect(plan.isSentinelPlatformCredential('sentinel_abc')).toBe(false);
    expect(plan.isSentinelPlatformCredential('')).toBe(false);
  });
});

describe('gateway subscription authority — negative controls', () => {
  afterEach(() => plan.setSentinelGatewayBinding(null));

  test('missing binding refuses access instead of treating paid tier as trusted', async () => {
    plan.setSentinelGatewayBinding(null);
    await expect(plan.resolveSentinelPlatformCredential('cdb_pro_test_key'))
      .rejects.toMatchObject({ code: 'ENTITLEMENT_SERVICE_UNAVAILABLE' });
  });

  test.each([
    [{ valid: false, tier: 'PRO' }, false],
    [{ valid: true, tier: 'FREE' }, false],
    [{ valid: true, tier: 'pro' }, false],
    [{ valid: true, tier: 'MSSP' }, true],
    [{ valid: true, tier: 'ENTERPRISE' }, true],
  ])('only verified exact gateway tiers grant premium access: %p', async (payload, allowed) => {
    const gateway = { fetch: jest.fn(async () => ({ ok: true, json: async () => payload })) };
    plan.setSentinelGatewayBinding(gateway);
    const result = await plan.resolveSentinelPlatformCredential('cdb_pro_test_key');
    expect(result.planEligible).toBe(allowed);
    expect(result.valid).toBe(payload.valid);
    expect(gateway.fetch).toHaveBeenCalledTimes(1);
  });

  test('gateway outage fails closed', async () => {
    plan.setSentinelGatewayBinding({ fetch: async () => { throw new Error('offline'); } });
    await expect(plan.resolveSentinelPlatformCredential('cdb_pro_test_key'))
      .rejects.toMatchObject({ code: 'ENTITLEMENT_SERVICE_UNAVAILABLE' });
  });

  test('gateway request uses header credential, never a query parameter', async () => {
    const fetch = jest.fn(async () => ({ ok: true, json: async () => ({ valid: true, tier: 'PRO' }) }));
    plan.setSentinelGatewayBinding({ fetch });
    await plan.resolveSentinelPlatformCredential('cdb_pro_test_key');
    const [url, opts] = fetch.mock.calls[0];
    expect(new URL(url).searchParams.has('api_key')).toBe(false);
    expect(opts.headers['X-API-Key']).toBe('cdb_pro_test_key');
  });
});
