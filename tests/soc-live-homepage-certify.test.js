'use strict';

const fs=require('node:fs');
const path=require('node:path');
const {
  ENDPOINTS,inspectResponseBody,certifyLiveHomepage,
}=require('../scripts/soc-live-homepage-certify');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');

function response(body=html,{status=200,type='text/html; charset=UTF-8',contentLength}={}) {
  return new Response(body,{
    status,
    headers:{
      'content-type':type,
      ...(contentLength===undefined?{}:{'content-length':String(contentLength)}),
    },
  });
}
function source() {
  return jest.fn(async()=>response());
}

describe('SOC public homepage canary — read-only fail-closed edge checks',()=>{
  test('source-correct current homepage passes structure and truthful metadata',()=>{
    const r=inspectResponseBody(html);
    expect(r.status).toBe('PASS');
    expect(r.count.mainOpen).toBe(1);
    expect(r.count.reportIds).toBe(1);
    expect(r.count.enterpriseCtas).toBe(1);
    expect(r.title).toMatch(/Threat Intelligence & SOC Readiness/i);
    expect(r.contentSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(r.limitations).toContain('not a deployment SHA attestation');
  });
  test('approved release asset parity requires exact approved HTML bytes, not merely valid structure',()=>{
    const approved=inspectResponseBody(html,{expectedHtml:html});
    expect(approved).toMatchObject({
      status:'PASS',reason:'APPROVED_HOMEPAGE_ASSET_MATCH',approvedAssetParity:true,
    });
    expect(approved.expectedContentSha256).toBe(approved.contentSha256);
    const structurallyValidButOld=html.replace(
      '<!-- Historical static cards removed',
      '<!-- Previous homepage revision marker --><!-- Historical static cards removed',
    );
    expect(inspectResponseBody(structurallyValidButOld).status).toBe('PASS');
    expect(inspectResponseBody(structurallyValidButOld,{expectedHtml:html}))
      .toMatchObject({
        status:'FAIL',reason:'PUBLIC_HOMEPAGE_ASSET_SHA256_MISMATCH',
        approvedAssetParity:false,
      });
    expect(inspectResponseBody(html,{expectedHtml:''}))
      .toMatchObject({status:'FAIL',reason:'APPROVED_HOMEPAGE_ASSET_INVALID'});
  });

  test('old static featured reports are rejected even without auto-generated markers',()=>{
    const old=html.replace('<!-- Historical static cards removed',
      '<article class="post-card"><h3>Historical report presented as current</h3></article><!-- Historical static cards removed');
    expect(inspectResponseBody(old))
      .toMatchObject({status:'FAIL',reason:'HOMEPAGE_INTEGRITY_FAILED'});
    const heading=html.replace('<!-- Historical static cards removed',
      '<h2>Featured Reports</h2><!-- Historical static cards removed');
    expect(inspectResponseBody(heading).status).toBe('FAIL');
  });

  test('approved SOC edge canary fails on a structurally valid stale asset and does no writes',async()=>{
    const modified=html.replace('<!-- Historical static cards removed',
      '<!-- Older edge content --><!-- Historical static cards removed');
    const fetcher=jest.fn(async()=>response(modified));
    const out=await certifyLiveHomepage({target:'soc',expectedHtml:html,fetcher});
    expect(out).toMatchObject({
      status:'FAIL',reason:'PUBLIC_HOMEPAGE_ASSET_SHA256_MISMATCH',
      approvedAssetParity:false,
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][1].method).toBe('GET');
  });

  test('rejects duplicated main / reports ID and the old SOC2+CTI title',()=>{
    const broken=html.replace('<!-- MAIN -->','<!-- MAIN --><!-- MAIN -->');
    expect(inspectResponseBody(broken)).toMatchObject({status:'FAIL',reason:'HOMEPAGE_INTEGRITY_FAILED'});
    const legacy=html.replace(/<title>[^<]*<\/title>/i,
      '<title>SENTINEL APEX SOC 2 & CTI PLATFORM</title>');
    expect(inspectResponseBody(legacy).status).toBe('FAIL');
  });
  test('rejects orphaned threat-card excerpt and preserves page source confidentiality',()=>{
    const bad=html.replace('<!-- Historical static cards removed',
      ') in the ClassDefinition UID validation regex\n<!-- Historical static cards removed');
    const r=inspectResponseBody(bad);
    expect(r.status).toBe('FAIL');
    expect(JSON.stringify(r)).not.toContain('ClassDefinition UID');
  });
  test('fetch is restricted to approved public domains without redirects or caching',async()=>{
    const fetcher=source();
    const out=await certifyLiveHomepage({fetcher});
    expect(out.status).toBe('PASS');
    const [url,opts]=fetcher.mock.calls[0];
    expect(url).toBe(ENDPOINTS.blog);
    expect(opts.method).toBe('GET');
    expect(opts.cache).toBe('no-store');
    expect(opts.redirect).toBe('manual');
    expect(opts.headers.Accept).toBe('text/html');
  });
  test('SOC endpoint uses only fixed SOC host and does not treat unexpected content as success',async()=>{
    const fetcher=source();
    expect((await certifyLiveHomepage({target:'soc',fetcher})).status).toBe('PASS');
    expect(fetcher.mock.calls[0][0]).toBe(ENDPOINTS.soc);
    await expect(certifyLiveHomepage({target:'https://evil.example',fetcher}))
      .rejects.toThrow('APPROVED_ENDPOINT_REQUIRED');
  });
  test('HTTP redirect, 403 and 404 are failures; HTTP 429 is inconclusive transport',async()=>{
    for(const status of [301,403,404,503]){
      const res=await certifyLiveHomepage({fetcher:async()=>response('NO',{status})});
      expect(res).toMatchObject({status:'FAIL',reason:'HTTP_STATUS_UNEXPECTED'});
    }
    const limited=await certifyLiveHomepage({fetcher:async()=>response('NO',{status:429})});
    expect(limited).toMatchObject({status:'INCONCLUSIVE',reason:'EDGE_RATE_LIMITED'});
  });
  test('non-HTML responses do not count as a successful release',async()=>{
    const out=await certifyLiveHomepage({
      fetcher:async()=>response(JSON.stringify({status:'ok'}),{type:'application/json'}),
    });
    expect(out).toMatchObject({status:'FAIL',reason:'NOT_HTML'});
  });
  test('large content-length and malformed stream are inconclusive, not success',async()=>{
    const out=await certifyLiveHomepage({
      fetcher:async()=>response(html,{contentLength:4*1024*1024}),
    });
    expect(out).toMatchObject({status:'INCONCLUSIVE',reason:'EDGE_READ_FAILED'});
  });
  test('network outages return inconclusive without inventing live page status',async()=>{
    const fetcher=jest.fn(async()=>{throw Error('ECONNREFUSED secret details');});
    const out=await certifyLiveHomepage({fetcher});
    expect(out).toMatchObject({status:'INCONCLUSIVE',reason:'EDGE_READ_FAILED'});
    expect(JSON.stringify(out)).not.toContain('ECONNREFUSED');
  });
  test('mutation paths and external host controls do not exist',()=>{
    const content=fs.readFileSync(path.join(__dirname,'..','scripts','soc-live-homepage-certify.js'),'utf8');
    expect(content).not.toContain("method:'POST'");
    expect(content).not.toContain('wrangler deploy');
    expect(content).not.toContain('ALTER TABLE');
  });
});
