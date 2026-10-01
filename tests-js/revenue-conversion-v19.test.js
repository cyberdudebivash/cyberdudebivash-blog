'use strict';

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const revenue = require('../revenue-conversion-v19.js');
const middleware = require('../api/_lib/middleware.js');
const assets = require('../scripts/build-cloudflare-assets.js');

describe('P0 Revenue Conversion v19', () => {
  test('only canonical paid tiers may enter direct checkout', () => {
    assert.equal(revenue.sanitizePlan('starter'), 'starter');
    assert.equal(revenue.sanitizePlan('PRO'), 'pro');
    assert.equal(revenue.sanitizePlan('team'), 'team');
    assert.equal(revenue.sanitizePlan('enterprise'), 'enterprise');
    assert.equal(revenue.sanitizePlan('free'), null);
    assert.equal(revenue.sanitizePlan('admin'), null);
  });

  test('campaign attribution is bounded to non-sensitive tokens', () => {
    const a = revenue.parseAttribution('?utm_source=sentinel apex report&utm_medium=cti/dossier&utm_campaign=x%20y&utm_content=pro<script>');
    assert.deepEqual(a, {
      source: 'sentinel_apex_report',
      medium: 'cti_dossier',
      campaign: 'x_y',
      content: 'pro_script_',
    });
    const payload = revenue.eventPayload('pro', a, { step: 2 });
    assert.equal(payload.plan, 'pro');
    assert.equal(payload.revenue_surface, 'buy_v19');
    assert.equal(Object.prototype.hasOwnProperty.call(payload, 'email'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(payload, 'api_key'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(payload, 'payment_id'), false);
  });

  test('API quota exhaustion recommends exactly one next paid tier', () => {
    assert.equal(middleware.nextPaidTier('free'), 'starter');
    assert.equal(middleware.nextPaidTier('starter'), 'pro');
    assert.equal(middleware.nextPaidTier('pro'), 'team');
    assert.equal(middleware.nextPaidTier('team'), 'enterprise');
    assert.equal(middleware.nextPaidTier('enterprise'), null);
  });

  test('API upgrade URL goes straight to the Sentinel APEX platform checkout with measurable attribution', () => {
    const url = new URL(middleware.upgradeCheckoutUrl('starter'));
    assert.equal(url.origin + url.pathname, 'https://intel.cyberdudebivash.com/upgrade.html');
    assert.equal(url.searchParams.get('plan'), 'pro');
    assert.equal(url.searchParams.get('utm_source'), 'api_rate_limit');
    assert.equal(url.searchParams.get('utm_medium'), 'api');
    assert.equal(url.searchParams.get('utm_campaign'), 'p0_revenue_conversion_v19');
    assert.equal(new URL(middleware.upgradeCheckoutUrl('free')).searchParams.get('plan'), 'pro');
    assert.equal(new URL(middleware.upgradeCheckoutUrl('pro')).searchParams.get('plan'), 'enterprise');
    assert.equal(new URL(middleware.upgradeCheckoutUrl('team')).searchParams.get('plan'), 'enterprise');
    assert.equal(middleware.upgradeCheckoutUrl('enterprise'), null);
  });

  test('Cloudflare bundle explicitly publishes both v19 checkout assets', () => {
    assert.ok(assets.PUBLIC_ROOT_FILES.includes('buy.html'));
    assert.ok(assets.PUBLIC_ROOT_FILES.includes('revenue-conversion-v19.js'));
  });

  test('buy page forwards old checkout links to the platform checkout and excludes overlay engines', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'buy.html'), 'utf8');
    assert.ok(html.includes('/intel-plans.js'));
    assert.ok(html.includes('IntelCheckout.go(plan'));
    assert.ok(html.includes('href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro'));
    assert.ok(html.includes('G-XTGLNMNNC7'));
    assert.equal(html.includes('/payment-flow.js'), false);
    assert.equal(html.includes('/conversion-engine.js'), false);
    assert.equal(html.includes('/monetization.js'), false);
  });

  test('revenue controller source never handles customer identity or payment credentials', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'revenue-conversion-v19.js'), 'utf8');
    assert.doesNotMatch(source, /razorpay_payment_id/);
    assert.doesNotMatch(source, /razorpay_signature/);
    assert.doesNotMatch(source, /api[_-]?key/i);
    assert.doesNotMatch(source, /\bemail\s*:/i);
  });
});
