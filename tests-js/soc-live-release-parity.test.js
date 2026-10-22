'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {ROUTES,assess,compareBuildLive,localAssetPath}=require('../scripts/soc-live-release-parity.cjs');

function fixture(spec){
  const standard=['<!doctype html><html><head><title>SENTINEL APEX SOC</title>'];
  if(spec.path==='/soc-readiness-assessment.html'){
    standard.push('<link rel="canonical" href="https://blog.cyberdudebivash.in/soc-readiness-assessment.html">');
  }
  standard.push('</head><body><main>');
  for(const marker of spec.markers)standard.push('<span>'+marker+'</span>');
  if(spec.path==='/soc-readiness-assessment.html'){
    standard.push('<a href="mailto:contact@cyberdudebivash.in?subject=SENTINEL%20APEX">Request a Scoped Proposal</a>');
    standard.push('<p>not an active 24/7 monitoring service</p>');
  }
  return standard.join('')+'</main></body></html>';
}
const response=(body,status=200,type='text/html; charset=utf-8')=>({body,status,type});
test('positive: every required SOC/CTI and legal route has a strict marker contract',()=>{
  assert.equal(ROUTES.length,8);
  assert.ok(ROUTES.some(x=>x.path==='/soc-readiness-assessment.html'));
  assert.ok(ROUTES.some(x=>x.path==='/terms.html'));
  for(const spec of ROUTES){
    assert.deepEqual(assess(spec,response(fixture(spec))),[],spec.path);
    const r=compareBuildLive(spec,fixture(spec),response(fixture(spec)));
    assert.equal(r.ok,true,spec.path);
    assert.match(r.localSha,/^[a-f0-9]{64}$/);
    assert.equal(r.localSha,r.liveSha);
  }
});
test('negative: HTTP 404 and HTML-like error bodies never pass',()=>{
  const spec=ROUTES.find(x=>x.path==='/soc-readiness-assessment.html');
  assert.ok(assess(spec,response(fixture(spec),404)).includes('HTTP_NOT_200'));
  assert.ok(assess(spec,response('<title>404 Not Found</title>')).includes('SOFT_404'));
});
test('negative: wrong content type and empty bodies fail closed',()=>{
  const spec=ROUTES[0];
  assert.ok(assess(spec,response(fixture(spec),200,'application/json')).includes('NOT_HTML'));
  assert.ok(assess(spec,response('')).includes('BODY_EMPTY_OR_OVERSIZE'));
});
test('negative: legal pages containing obsolete incorporated identity fail',()=>{
  for(const spec of ROUTES.filter(x=>x.legal)){
    const bad=fixture(spec)+'<footer>CyberDudeBivash Pvt. Ltd.</footer>';
    assert.ok(assess(spec,response(bad)).includes('FALSE_INCORPORATION_CLAIM'));
  }
});
test('negative: old private-limited JSON-LD organization rejected',()=>{
  const spec=ROUTES.find(x=>x.path==='/contact.html');
  assert.ok(assess(spec,response(fixture(spec)+'<script type="application/ld+json">{"name":"CYBERDUDEBIVASH PRIVATE LIMITED"}</script>')).includes('FALSE_INCORPORATION_CLAIM'));
});
test('negative: homepage rejects obsolete proprietor incorporation and Corporation schema',()=>{
  const spec=ROUTES.find(x=>x.path==='/');
  const baseline=fixture(spec);
  assert.ok(assess(spec,response(baseline+'<footer>CyberDudeBivash Pvt. Ltd.</footer>'))
    .includes('FALSE_INCORPORATION_CLAIM'));
  assert.ok(assess(spec,response(baseline+'<script type="application/ld+json">{"@type":"Corporation"}</script>'))
    .includes('INCORPORATED_STRUCTURED_IDENTITY'));
});
test('negative: PAN property on homepage fails without logging its value',()=>{
  const spec=ROUTES.find(x=>x.path==='/');
  const bad=fixture(spec)+'<script type="application/ld+json">{"propertyID":"PAN","value":"REDACTED"}</script>';
  assert.ok(assess(spec,response(bad)).includes('PERSONAL_PAN_METADATA'));
});
test('negative: missing enterprise inquiry link and missing 24/7 disclaimer fail',()=>{
  const spec=ROUTES.find(x=>x.path==='/soc-readiness-assessment.html');
  const original=fixture(spec);
  assert.ok(assess(spec,response(original.replace('mailto:contact@cyberdudebivash.in?subject=','mailto:other.invalid?subject='))).includes('ENQUIRY_LINK_MISSING'));
  assert.ok(assess(spec,response(original.replace('not an active 24/7 monitoring service','real-time SOC service is running'))).includes('SERVICE_BOUNDARY_MISSING'));
});
test('negative: customer checkout links or wrong canonical block the assessment offer',()=>{
  const spec=ROUTES.find(x=>x.path==='/soc-readiness-assessment.html');
  assert.ok(assess(spec,response(fixture(spec)+'<a href="/checkout">Pay now</a>')).includes('FALSE_CHECKOUT'));
  assert.ok(assess(spec,response(fixture(spec).replace('rel="canonical"','rel="something-else"'))).includes('CANONICAL_INCORRECT'));
});
test('negative: exact build-vs-live mismatch blocks even when generic markers match',()=>{
  const spec=ROUTES[0];
  const built=fixture(spec);
  const live=built.replace('</body>','<aside>stale extra UI</aside></body>');
  const r=compareBuildLive(spec,built,response(live));
  assert.equal(r.ok,false);
  assert.ok(r.codes.includes('BUILD_VS_LIVE_BYTES_DIFFER'));
});
test('negative: unsafe local asset path cannot be resolved',()=>{
  assert.throws(()=>localAssetPath('dist-public','/../private-secret.html'),/ASSET_PATH_INVALID/);
  assert.match(localAssetPath('dist-public','/soc-readiness-assessment.html'),/soc-readiness-assessment\.html$/);
});
