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
