#!/usr/bin/env node
'use strict';

/**
 * SOC P0 bounded public read-only acceptance probe.
 * Operator initiated only: no cron/CI live requests, auth, POSTs, D1, R2,
 * billing, provider alerts, retries or external third-party URLs.
 * This is NOT a customer entitlement/tenant or Blogger publication receipt.
 */
const ORIGIN = 'https://soc.cyberdudebivash.in';
const MAX_BYTES = 300000;
const FRESH_MAX_MS = 4 * 60 * 60 * 1000;
const CROSS_FEED_MAX_MS = 15 * 60 * 1000;
const SPECS = Object.freeze([
  { path:'/soc.html', kind:'soc_page' },
  { path:'/workbench.html', kind:'workbench_page' },
  { path:'/api/v1/workbench/dashboard', kind:'anonymous_dashboard' },
  { path:'/api/v1/intel?action=stats', kind:'public_stats' },
  { path:'/live-intel.json', kind:'public_feed' },
]);

const json = body => {
  try { return JSON.parse(body); } catch (_) { return null; }
};
const safeTimestamp = v => {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(v))
    return NaN;
  return Date.parse(v);
};
function inspectHeadIdentity(html, route) {
  const heads = html.match(/<head\b[^>]*>[\s\S]*?<\/head\s*>/gi) || [];
  const bodyPos = html.search(/<body\b/i);
  const head = heads.length === 1 && (bodyPos < 0 || html.indexOf(heads[0]) < bodyPos) ? heads[0] : '';
  const links = head.match(/<link\b[^>]*>/gi) || [];
  const metas = head.match(/<meta\b[^>]*>/gi) || [];
  const canonical = links.filter(t => /\brel=["']canonical["']/i.test(t));
  const og = metas.filter(t => /\bproperty=["']og:url["']/i.test(t));
  return Boolean(head) && canonical.length === 1 && og.length === 1 &&
    canonical[0].includes('href="' + ORIGIN + route + '"') &&
    og[0].includes('content="' + ORIGIN + route + '"');
}
function evaluate(responses, nowMs = Date.now()) {
  const failures=[];
  const fail=(label,code)=>failures.push(label + ':' + code);
  const byKind={};
  for(const spec of SPECS) {
    const r=responses?.[spec.kind];
    if(!r || !Number.isSafeInteger(r.status) || typeof r.type!=='string' || typeof r.body!=='string' ||
       Buffer.byteLength(r.body,'utf8')>MAX_BYTES) {
      fail(spec.kind,'RESPONSE_MISSING_OR_INVALID'); continue;
    }
    byKind[spec.kind]=r;
    if(spec.kind === 'anonymous_dashboard') {
      if(r.status !== 401) fail(spec.kind,'ANONYMOUS_ACCESS_NOT_DENIED');
      if(!/^application\/json(?:;|$)/i.test(r.type)) fail(spec.kind,'NOT_JSON');
      if(!/no-store/i.test(r.cacheControl||'')) fail(spec.kind,'CACHE_CONTROL_MISSING');
      if(r.allowOrigin==='*') fail(spec.kind,'CORS_WILDCARD');
      if(json(r.body)?.error?.code !== 'UNAUTHORIZED') fail(spec.kind,'UNAUTHORIZED_CONTRACT_MISSING');
    } else {
      if(r.status !== 200) { fail(spec.kind,'HTTP_NOT_200'); continue; }
      if(spec.kind.endsWith('_page')) {
        if(!/^text\/html(?:;|$)/i.test(r.type)) fail(spec.kind,'NOT_HTML');
        if(spec.kind==='soc_page') {
          if(!inspectHeadIdentity(r.body,'/soc.html')) fail(spec.kind,'SOC_CANONICAL_OR_OG_MISMATCH');
          if(!r.body.includes('SENTINEL APEX SOC')) fail(spec.kind,'BRAND_MARKER_MISSING');
        } else {
          if(!/name=["']robots["'][^>]*content=["']noindex/i.test(r.body)) fail(spec.kind,'WORKBENCH_NOT_NOINDEX');
          if(!r.body.includes('X-Analyst-Key')) fail(spec.kind,'ANALYST_AUTH_BOUNDARY_MISSING');
        }
      } else if(!/^application\/json(?:;|$)/i.test(r.type)) fail(spec.kind,'NOT_JSON');
    }
  }
  const stats=json(byKind.public_stats?.body||'');
  const feed=json(byKind.public_feed?.body||'');
  if(!stats || stats.success !== true || !Number.isSafeInteger(stats.stats?.total_published) ||
      !Number.isSafeInteger(stats.stats?.live_intel_count)) fail('public_stats','CONTRACT_INVALID');
  if(!feed || !Array.isArray(feed.items) || !Number.isSafeInteger(feed.totalPublished))
    fail('public_feed','CONTRACT_INVALID');
  if(stats && feed && stats.stats?.total_published !== feed.totalPublished)
    fail('public_feed','STATS_FEED_COUNT_DRIFT');
  for(const [key,value] of [
    ['public_stats',stats?.stats?.last_run],
    ['public_feed',feed?.generatedAt],
  ]) {
    const at=safeTimestamp(value),age=nowMs-at;
    if(!Number.isFinite(at) || age < -5*60*1000) fail(key,'TIMESTAMP_INVALID_OR_FUTURE');
    else if(age > FRESH_MAX_MS) fail(key,'DATA_STALE');
  }
  const ts=safeTimestamp(stats?.stats?.last_run);
  const tf=safeTimestamp(feed?.generatedAt);
  if(Number.isFinite(ts) && Number.isFinite(tf) && Math.abs(ts-tf)>CROSS_FEED_MAX_MS)
    fail('cross_layer','STATS_FEED_TIMESTAMP_DRIFT');
  return { status:failures.length?'HOLD':'SOURCE_PUBLIC_READONLY_PASS', failed:failures.length,
    codes:[...new Set(failures)].sort(),checked:SPECS.map(s=>s.path),
    warning:'No customer login, tenant A/B, D1/R2 writes, signed contracts or provider receipt was tested' };
}
async function boundedGet(spec) {
  const url=new URL(spec.path,ORIGIN);
  if(url.origin!==ORIGIN)throw Error('ORIGIN_POLICY_DENIED');
  const response=await fetch(url,{method:'GET',redirect:'manual',
    headers:{Accept:spec.kind.endsWith('_page')?'text/html':'application/json','Cache-Control':'no-cache'},
    signal:AbortSignal.timeout(9000)});
  const reader=response.body?.getReader();
  if(!reader)throw Error('EMPTY_BODY');
  const chunks=[];let n=0;
  try {
    for(;;) {
      const {done,value}=await reader.read();if(done)break;
      n+=value.byteLength;
      if(n>MAX_BYTES) {await reader.cancel();throw Error('BODY_LIMIT');}
      chunks.push(Buffer.from(value));
    }
  } finally {reader.releaseLock();}
  return {status:response.status,type:response.headers.get('content-type')||'',
    cacheControl:response.headers.get('cache-control')||'',
    allowOrigin:response.headers.get('access-control-allow-origin')||'',
    body:Buffer.concat(chunks).toString('utf8')};
}
async function run() {
  const answers={};
  // Maximum five same-origin GET requests, sequentially, with no retries.
  for(const spec of SPECS) answers[spec.kind]=await boundedGet(spec);
  return evaluate(answers);
}
if(require.main===module){
  if(process.argv.length!==3 || process.argv[2]!=='--live') {
    console.error('Usage: node scripts/soc-public-integration-gate.cjs --live (operator-only read-only GETs)');
    process.exitCode=2;
  } else run().then(out=>{
    console.log(JSON.stringify(out));if(out.status==='HOLD')process.exitCode=1;
  }).catch(()=>{
    // Do not print URLs with future query secrets, payloads, error internals.
    console.error('HOLD SOC_PUBLIC_READONLY_PROBE_FAILED');
    process.exitCode=1;
  });
}
module.exports={ORIGIN,SPECS,MAX_BYTES,evaluate,inspectHeadIdentity};
