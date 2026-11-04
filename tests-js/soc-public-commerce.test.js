'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {URLS,PUBLISHED,assessLegacyPlans,assessCanonicalPricing,
  assessPricingPage,assessUpgrade,boundedRead,monitor} =
  require('../scripts/check-soc-public-commerce.cjs');

const plans = () => ({success:true,on_sale:false,
  checkout_url:'https://intel.cyberdudebivash.com/upgrade.html?utm_source=blog&utm_medium=api&utm_campaign=plan-checkout',
  plans:{pro:{currency:'INR',amount:1499}}});
const pricing = () => ({currency:'INR',unit:'paise',
  tiers:structuredClone(PUBLISHED),checkout:{razorpay:{role:'primary',currency:'INR'}}});
const page = () => '<html>'+('pricing '.repeat(160))+
  ['pro','enterprise','mssp'].map(p=>`<a data-intel-plan="${p}" href="https://intel.cyberdudebivash.com/upgrade.html?plan=${p}&amp;utm_source=blog">Buy</a><span data-intel-price="${p.toUpperCase()}">See price</span>`).join('')+'</html>';
const upgrade = () => '<html>'+('Secure checkout Razorpay Choose a plan and subscribe '.repeat(30))+'</html>';
const response = (value,format='json') => new Response(format==='json'?JSON.stringify(value):value,
  {status:200,headers:{'content-type':format==='json'?'application/json; charset=utf-8':'text/html; charset=utf-8'}});
const fixtures = {legacyPlans:response(plans()),canonicalPricing:response(pricing()),
  socPricing:response(page(),'html'),blogPricing:response(page(),'html'),upgrade:response(upgrade(),'html')};
function fakeFetch(replace={}) { return async url => {
  const name=Object.keys(URLS).find(k=>URLS[k]===url);
  return replace[name] || fixtures[name].clone();
}; }

test('independent live commerce gate accepts valid, distinct old/new pricing contracts',async()=>{
  assert.equal((await monitor({fetchImpl:fakeFetch()})).status,'PASS');
});
test('retired checkout must remain off-sale and linked only to approved platform',()=>{
  assert.equal(assessLegacyPlans(plans()),true);
  for(const mutate of [d=>d.on_sale=true,d=>d.checkout_url='https://attacker.example/upgrade.html',
    d=>d.checkout_url='http://intel.cyberdudebivash.com/upgrade.html',
    d=>d.checkout_url+='&plan=enterprise',d=>d.plans.pro.amount=4100]){
    const d=plans();mutate(d);assert.equal(assessLegacyPlans(d),false);
  }
});
test('active platform prices and currency are pinned to the observed commercial contract',()=>{
  assert.equal(assessCanonicalPricing(pricing()),true);
  for(const mutate of [d=>d.tiers.PRO.monthly=149900,d=>d.tiers.ENTERPRISE.usd_monthly=49,
    d=>d.tiers.MSSP.annual=1,d=>d.unit='rupees',
    d=>d.checkout.razorpay.role='secondary']){
    const d=pricing();mutate(d);assert.equal(assessCanonicalPricing(d),false);
  }
});
test('both public pricing pages must link PRO, Enterprise and MSSP to the canonical checkout',()=>{
  assert.equal(assessPricingPage(page()),true);
  assert.equal(assessPricingPage(page().replace('data-intel-plan="mssp"','data-intel-plan="fake"')),false);
  assert.equal(assessPricingPage(page()+'<p>SOC Pro — $49/mo</p>'),false);
  assert.equal(assessPricingPage(page().replace('https://intel.cyberdudebivash.com/upgrade.html?plan=pro','https://invalid.example')),false);
});
test('published checkout GET requires substantive page, not HTML error page',()=>{
  assert.equal(assessUpgrade(upgrade()),true);
  assert.equal(assessUpgrade('<html><body>error</body></html>'),false);
});
test('bounded reader refuses HTML masquerading as JSON and oversized bodies',async()=>{
  await assert.rejects(()=>boundedRead(response('{}','html'),'json',1024),/WRONG_CONTENT_TYPE/);
  await assert.rejects(()=>boundedRead(response('a'.repeat(2048),'html'),'html',1000),/BODY_TOO_LARGE/);
});
test('independent signal reports a broken platform price even if intel freshness is unrelated',async()=>{
  const d=pricing();d.tiers.PRO.monthly=999;
  const result=await monitor({fetchImpl:fakeFetch({canonicalPricing:response(d)})});
  assert.deepEqual(result.codes,['CANONICALPRICING_CONTRACT_INVALID']);
});
test('endpoint failures never get recorded as a passing commerce check',async()=>{
  const result=await monitor({fetchImpl:async(url)=>{
    if(url===URLS.upgrade)throw Error('offline');
    return fakeFetch()(url);
  }});
  assert.deepEqual(result.codes,['UPGRADE_UNAVAILABLE_OR_INVALID']);
});
