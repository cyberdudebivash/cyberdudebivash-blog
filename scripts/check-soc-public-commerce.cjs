#!/usr/bin/env node
'use strict';

/**
 * P0 read-only customer-commerce smoke check. Current plans are sold solely
 * on intel.cyberdudebivash.com; legacy blog plan amounts are NOT sales prices.
 * No payment requests, login, secrets, customer data, or mutation are used.
 * A PASS verifies PUBLIC CONTRACT/CTA INTEGRITY, NOT payment collection.
 */
const { TextDecoder } = require('node:util');

const BASE = 'https://intel.cyberdudebivash.com';
const URLS = Object.freeze({
  legacyPlans: 'https://blog.cyberdudebivash.in/api/v1/billing?action=plans',
  canonicalPricing: `${BASE}/api/pricing`,
  socPricing: 'https://soc.cyberdudebivash.in/pricing.html',
  blogPricing: 'https://blog.cyberdudebivash.in/pricing.html',
  upgrade: `${BASE}/upgrade.html?plan=pro`,
});
const PUBLISHED = Object.freeze({
  PRO: Object.freeze({monthly:410000,annual:4100000,usd_monthly:49,usd_annual:490}),
  ENTERPRISE: Object.freeze({monthly:4160000,annual:41600000,usd_monthly:499,usd_annual:4990}),
  MSSP: Object.freeze({monthly:8330000,annual:83300000,usd_monthly:999,usd_annual:9990}),
});
const MAX_JSON = 64 * 1024;
const MAX_HTML = 384 * 1024;
const MAX_TIMEOUT_MS = 15000;

function isCheckoutUrl(value) {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.origin === BASE && url.pathname === '/upgrade.html' &&
      !url.username && !url.password && !url.hash &&
      url.searchParams.get('utm_source') === 'blog' &&
      !url.searchParams.has('plan');
  } catch { return false; }
}

function assessLegacyPlans(d) {
  return !!(d && d.success === true && d.on_sale === false &&
    isCheckoutUrl(d.checkout_url) &&
    d.plans && d.plans.pro && d.plans.pro.currency === 'INR' &&
    d.plans.pro.amount === 1499);
}

function assessCanonicalPricing(d) {
  if (!d || d.currency !== 'INR' || d.unit !== 'paise' ||
    !d.tiers || typeof d.tiers !== 'object' ||
    !d.checkout || !d.checkout.razorpay ||
    d.checkout.razorpay.role !== 'primary' ||
    d.checkout.razorpay.currency !== 'INR') return false;
  return Object.entries(PUBLISHED).every(([name,expected]) => {
    const tier = d.tiers[name];
    return tier && Object.entries(expected).every(([key,value]) =>
      Number.isSafeInteger(tier[key]) && tier[key] === value);
  });
}

function assessPricingPage(html) {
  if (typeof html !== 'string' || html.length < 1000 ||
    /create-razorpay-order|checkout\.razorpay\.com|PaymentFlow\.payInstant/i.test(html)) return false;
  for (const plan of ['pro','enterprise','mssp']) {
    if (!html.includes(`data-intel-plan="${plan}"`) ||
        !html.includes(`data-intel-price="${plan.toUpperCase()}"`) ||
        !html.includes(`https://intel.cyberdudebivash.com/upgrade.html?plan=${plan}`)) return false;
  }
  // A legitimate new PRO Defense price is $49/month; only the retired
  // "SOC Pro" association is prohibited, never a blanket $49 ban.
  if (/SOC Pro[\s\S]{0,40}(?:\$49\s*\/(?:mo|month)|₹\s?4,099)|(?:\$49\s*\/(?:mo|month)|₹\s?4,099)[\s\S]{0,40}SOC Pro/i.test(html)) return false;
  return true;
}

function assessUpgrade(html) {
  return typeof html === 'string' && html.length >= 1000 &&
    /(?:Secure checkout|Choose a plan and subscribe)/i.test(html) &&
    /Razorpay/i.test(html);
}

async function boundedRead(response, format, limit) {
  if (!response || response.status !== 200) throw Error('HTTP_NOT_200');
  const type = (response.headers?.get('content-type') || '').toLowerCase();
  if (format === 'json' ? !/(?:application\/json|\+json)/.test(type) : !type.includes('text/html'))
    throw Error('WRONG_CONTENT_TYPE');
  if (!response.body || typeof response.body.getReader !== 'function') throw Error('BODY_MISSING');
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) throw Error('BODY_TOO_LARGE');
      chunks.push(value);
    }
  } catch (err) {
    await reader.cancel().catch(() => {});
    throw err;
  }
  if (bytes === 0) throw Error('BODY_EMPTY');
  const raw = Buffer.concat(chunks.map(c => Buffer.from(c)), bytes);
  const txt = new TextDecoder('utf-8', {fatal:true}).decode(raw);
  return format === 'json' ? JSON.parse(txt) : txt;
}

async function monitor({fetchImpl=globalThis.fetch,timeoutMs=MAX_TIMEOUT_MS}={}) {
  if (typeof fetchImpl !== 'function') return {status:'FAIL',codes:['FETCH_UNAVAILABLE']};
  const cases = [
    ['legacyPlans','json',MAX_JSON,assessLegacyPlans],
    ['canonicalPricing','json',MAX_JSON,assessCanonicalPricing],
    ['socPricing','html',MAX_HTML,assessPricingPage],
    ['blogPricing','html',MAX_HTML,assessPricingPage],
    ['upgrade','html',MAX_HTML,assessUpgrade],
  ];
  const codes=[];
  for (const [name,format,limit,assess] of cases) {
    try {
      const response = await fetchImpl(URLS[name],{
        method:'GET',credentials:'omit',redirect:'error',
        headers:{'Accept':format==='json'?'application/json':'text/html'},
        signal:AbortSignal.timeout(timeoutMs),
      });
      const data = await boundedRead(response,format,limit);
      if (!assess(data)) codes.push(`${name.toUpperCase()}_CONTRACT_INVALID`);
    } catch (_) {
      // No remote body, URL query, token, stack or customer detail in CI log.
      codes.push(`${name.toUpperCase()}_UNAVAILABLE_OR_INVALID`);
    }
  }
  return {status:codes.length?'FAIL':'PASS',codes,
    detail:'PUBLIC_COMMERCE_CONTRACT_ONLY_NOT_PAYMENT_OR_MANAGED_SOC_CERTIFICATION'};
}

if (require.main === module) {
  monitor().then(result => {
    console.log(JSON.stringify(result));
    if (result.status !== 'PASS') process.exitCode=2;
  }).catch(() => {
    console.error('HOLD: PUBLIC_COMMERCE_MONITOR_ERROR');
    process.exitCode=2;
  });
}
module.exports={URLS,PUBLISHED,isCheckoutUrl,assessLegacyPlans,
  assessCanonicalPricing,assessPricingPage,assessUpgrade,boundedRead,monitor};
