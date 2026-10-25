'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {ORIGIN,ROUTES,assess,compareBuildLive,localAssetPath}=require('../scripts/soc-live-release-parity.cjs');

function fixture(spec){
  const standard=['<!doctype html><html><head><title>SENTINEL APEX SOC</title>'];
  standard.push('<link rel="canonical" href="'+ORIGIN+spec.path+'">');
  standard.push('<meta property="og:url" content="'+ORIGIN+spec.path+'">');
  standard.push('</head><body><main>');
  for(const marker of spec.markers)standard.push('<span>'+marker+'</span>');
  if(spec.path==='/soc-readiness-assessment.html'){
    standard.push('<a href="mailto:contact@cyberdudebivash.in?subject=SENTINEL%20APEX">Request a Scoped Proposal</a>');
    standard.push('<p>not an active 24/7 monitoring service</p>');
  }
  return standard.join('')+'</main></body></html>';
}
const response=(body,status=200,type='text/html; charset=utf-8')=>({body,status,type});
test('P0 parity must probe SOC hostname, never legacy CTI origin',()=>{
  assert.equal(ORIGIN,'https://soc.cyberdudebivash.in');
  assert.equal(ROUTES.length,8);
});
test('P0 every release route rejects legacy, absent or duplicated head SEO identity',()=>{
  for(const spec of ROUTES){
    const original=fixture(spec);
    const stale=original.replace(
      '<link rel="canonical" href="'+ORIGIN+spec.path+'">',
      '<link rel="canonical" href="https://blog.cyberdudebivash.in'+spec.path+'">'
    ).replace(
      '<meta property="og:url" content="'+ORIGIN+spec.path+'">',
      '<meta property="og:url" content="https://blog.cyberdudebivash.in'+spec.path+'">'
    );
    const errors=assess(spec,response(stale));
    assert.ok(errors.includes('CANONICAL_INCORRECT'),spec.path);
    assert.ok(errors.includes('OG_URL_INCORRECT'),spec.path);
    const duplicate=original.replace('</head>','<link rel="canonical" href="'+ORIGIN+spec.path+'"></head>');
    assert.ok(assess(spec,response(duplicate)).includes('CANONICAL_INCORRECT'),spec.path);
    const bodyOnly=original.replace('<meta property="og:url" content="'+ORIGIN+spec.path+'">','')
      .replace('</body>','<meta property="og:url" content="'+ORIGIN+spec.path+'"></body>');
    assert.ok(assess(spec,response(bodyOnly)).includes('OG_URL_INCORRECT'),spec.path);
    const missingHead=original.replace('<head>','<div>').replace('</head>','</div>');
    assert.ok(assess(spec,response(missingHead)).includes('DOCUMENT_HEAD_MISSING_OR_AMBIGUOUS'),spec.path);
  }
});
test('negative: inert canonical and Open Graph tags in comments or scripts cannot certify identity',()=>{
  for(const spec of ROUTES){
    const original=fixture(spec);
    const canonical='<link rel="canonical" href="'+ORIGIN+spec.path+'">';
    const og='<meta property="og:url" content="'+ORIGIN+spec.path+'">';
    for(const wrap of [tag=>'<!-- '+tag+' -->',tag=>'<script type="text/plain">'+tag+'</script>']){
      const inert=original.replace(canonical,wrap(canonical)).replace(og,wrap(og));
      const errors=assess(spec,response(inert));
      assert.ok(errors.includes('CANONICAL_INCORRECT'),spec.path);
      assert.ok(errors.includes('OG_URL_INCORRECT'),spec.path);
    }
  }
});
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
test('negative: live parity blocks obsolete visible SOC legal host and service claims',()=>{
  const about=ROUTES.find(x=>x.path==='/about.html');
  const terms=ROUTES.find(x=>x.path==='/terms.html');
  const obsoleteAbout=fixture(about).replace('</main>',
    '<p>We monitor official vulnerability authorities around the clock.</p>'+
    '<p>X/Twitter: @cdbsentinelapex</p></main>');
  const aboutErrors=assess(about,response(obsoleteAbout));
  assert.ok(aboutErrors.includes('UNVERIFIED_CONTINUOUS_MONITORING_COPY'));
  assert.ok(aboutErrors.includes('RETIRED_SOCIAL_IDENTITY'));
  const obsoleteTerms=fixture(terms).replace('</main>',
    '<p>Effective date: 5 July 2026 · blog.cyberdudebivash.in</p></main>');
  assert.ok(assess(terms,response(obsoleteTerms)).includes('LEGACY_VISIBLE_LEGAL_HOST'));
});
test('negative control: hidden scripts and comments do not count as visible legal copy',()=>{
  const about=ROUTES.find(x=>x.path==='/about.html');
  const terms=ROUTES.find(x=>x.path==='/terms.html');
  const hiddenAbout=fixture(about).replace('</main>',
    '<!-- We monitor around the clock. X/Twitter: @cdbsentinelapex -->'+
    '<script>const legacy="We monitor around the clock. X/Twitter: @cdbsentinelapex";</script></main>');
  assert.deepEqual(assess(about,response(hiddenAbout)),[]);
  const hiddenTerms=fixture(terms).replace('</main>',
    '<script>const oldHost="blog.cyberdudebivash.in";</script></main>');
  assert.deepEqual(assess(terms,response(hiddenTerms)),[]);
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
test('negative: head-only and empty-body pages cannot establish legal or service parity',()=>{
  for(const spec of ROUTES){
    const headOnly=fixture(spec).replace(/<body>[\s\S]*?<\/body>/,'');
    assert.ok(assess(spec,response(headOnly)).includes('VISIBLE_BODY_MISSING'),spec.path);
    const emptyBody=fixture(spec).replace(/<body>[\s\S]*?<\/body>/,'<body></body>');
    assert.ok(assess(spec,response(emptyBody)).includes('VISIBLE_BODY_MISSING'),spec.path);
  }
});
test('negative: hidden service-boundary text and non-actionable enquiry cannot pass',()=>{
  const spec=ROUTES.find(x=>x.path==='/soc-readiness-assessment.html');
  const valid=fixture(spec);
  const scriptBoundary=valid.replace('<p>not an active 24/7 monitoring service</p>',
    '<script>const notice="not an active 24/7 monitoring service";</script>');
  assert.ok(assess(spec,response(scriptBoundary)).includes('SERVICE_BOUNDARY_MISSING'));
  const mailto='<a href="mailto:contact@cyberdudebivash.in?subject=SENTINEL%20APEX">Request a Scoped Proposal</a>';
  const scriptOnly=valid.replace(mailto,
    '<script>const link="mailto:contact@cyberdudebivash.in?subject=SENTINEL%20APEX";</script>');
  assert.ok(assess(spec,response(scriptOnly)).includes('ENQUIRY_LINK_MISSING'));
  const hidden=valid.replace(mailto,
    '<a hidden href="mailto:contact@cyberdudebivash.in?subject=SENTINEL%20APEX">Request a Scoped Proposal</a>');
  assert.ok(assess(spec,response(hidden)).includes('ENQUIRY_LINK_MISSING'));
  const ariaHidden=valid.replace(mailto,
    '<a aria-hidden="true" href="mailto:contact@cyberdudebivash.in?subject=SENTINEL%20APEX">Request a Scoped Proposal</a>');
  assert.ok(assess(spec,response(ariaHidden)).includes('ENQUIRY_LINK_MISSING'));
  assert.deepEqual(assess(spec,response(valid)),[]);
});
test('negative: inherited hidden ancestors cannot certify the only boundary or proposal CTA',()=>{
  const spec=ROUTES.find(x=>x.path==='/soc-readiness-assessment.html');
  const valid=fixture(spec);
  const boundary='<p>not an active 24/7 monitoring service</p>';
  const cta='<a href="mailto:contact@cyberdudebivash.in?subject=SENTINEL%20APEX">Request a Scoped Proposal</a>';
  for(const attribute of ['hidden','inert','aria-hidden="true"','aria-hidden=true',
    'style="display:none"','style="visibility: hidden"','style=display:none']){
    const wrap=html=>'<section '+attribute+'><div>'+html+'</div></section>';
    const boundaryHidden=valid.replace(boundary,wrap(boundary));
    const ctaHidden=valid.replace(cta,wrap(cta));
    const bothHidden=valid.replace(boundary,'').replace(cta,wrap(boundary+cta));
    assert.ok(assess(spec,response(boundaryHidden)).includes('SERVICE_BOUNDARY_MISSING'),attribute);
    assert.ok(assess(spec,response(ctaHidden)).includes('ENQUIRY_LINK_MISSING'),attribute);
    const errors=assess(spec,response(bothHidden));
    assert.ok(errors.includes('SERVICE_BOUNDARY_MISSING'),attribute);
    assert.ok(errors.includes('ENQUIRY_LINK_MISSING'),attribute);
  }
  const visibleWithHiddenDecoy=valid.replace('</main>',
    '<section hidden><p>not an active 24/7 monitoring service</p></section></main>');
  assert.deepEqual(assess(spec,response(visibleWithHiddenDecoy)),[]);
});
test('negative control: obsolete About and Terms copy inside hidden ancestors is not visible',()=>{
  const about=ROUTES.find(x=>x.path==='/about.html');
  const terms=ROUTES.find(x=>x.path==='/terms.html');
  const hiddenAbout=fixture(about).replace('</main>',
    '<section aria-hidden="true"><p>We monitor around the clock. X/Twitter: @cdbsentinelapex</p></section></main>');
  const hiddenTerms=fixture(terms).replace('</main>',
    '<section style="display:none"><p>blog.cyberdudebivash.in</p></section></main>');
  assert.deepEqual(assess(about,response(hiddenAbout)),[]);
  assert.deepEqual(assess(terms,response(hiddenTerms)),[]);
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

test('negative: required SOC and legal identity markers must be customer-visible',()=>{
  for(const spec of ROUTES){
    // Assessment email identity is separately validated as an actionable CTA.
    // Use its SOC Readiness marker, which has no duplicate visible anchor.
    const marker=spec.path==='/soc-readiness-assessment.html'?'SOC Readiness':spec.markers[0];
    const original=fixture(spec);
    const span='<span>'+marker+'</span>';
    assert.ok(original.includes(span),spec.path);
    for(const wrap of [
      html=>'<section hidden>'+html+'</section>',
      html=>'<section inert>'+html+'</section>',
      html=>'<section aria-hidden="true">'+html+'</section>',
      html=>'<section style="display:none">'+html+'</section>',
      html=>'<script type="text/plain">'+html+'</script>'
    ]){
      const decoy=original.replace(span,wrap(span));
      const errors=assess(spec,response(decoy));
      assert.ok(errors.includes('REQUIRED_VISIBLE_MARKER_MISSING'),spec.path+' '+wrap(span));
    }
  }
});
