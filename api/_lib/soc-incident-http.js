'use strict';

/**
 * SENTINEL APEX SOC — SOURCE-ONLY, UNWIRED incident HTTP adapter.
 *
 * No entry in workers/lib/route-table.js or router.js, and enabled=false by
 * default. Even a caller with a valid bearer token receives 404 while off.
 *
 * Production wiring, allowed host, complete authentication, identity session
 * provisioning, D1 migrations and a protection/rate-limit layer are separate
 * operator-certified release steps. No bearer tokens or PII are logged.
 */
const MAX_BYTES = 8192;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const INCIDENT_ROUTE = new RegExp(
  '^/api/v1/soc/tenants/([a-z0-9_-]{3,64})/incidents(?:/(inc_' + UUID + '))?/?$'
);
const ALLOWED = new Set(['GET','POST','PATCH']);
const PAID_TIERS = new Set(['PRO','ENTERPRISE','MSSP']);
// A shared Threat Intel subscription grants no customer incident capability
// by itself. SOC incident operations require an independent, operator-approved
// feature grant bound to the same canonical subscription and tenant.
const SOC_PRODUCT = 'SENTINEL_APEX_SOC';
const SOC_CAPABILITY = Object.freeze({
  GET: 'soc.incidents.read',
  POST: 'soc.incidents.write',
  PATCH: 'soc.incidents.write',
});
const ERROR_STATUSES = new Set([400,401,403,404,409,413,429,503]);
const HEADERS = {
  'Content-Type':'application/json; charset=utf-8',
  'Cache-Control':'no-store, no-cache, must-revalidate',
  'Pragma':'no-cache',
  'Vary':'Authorization',
  'X-Content-Type-Options':'nosniff',
  'X-Frame-Options':'DENY',
  'Referrer-Policy':'no-referrer',
  'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",
};
function reply(status, json) {
  return new Response(JSON.stringify(json),{status,headers:HEADERS});
}
function error(status, code) {
  return reply(status,{success:false,error:{code}});
}
function invalid(code) {
  const e=new Error(code);
  e.code=code;e.status=400;
  throw e;
}
async function parseSmallJson(request) {
  const length=request.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length)>MAX_BYTES)) {
    const e=new Error('PAYLOAD_TOO_LARGE');e.status=413;e.code='PAYLOAD_TOO_LARGE';throw e;
  }
  if (request.headers.get('content-type')?.toLowerCase().split(';',1)[0].trim() !== 'application/json') {
    invalid('JSON_CONTENT_TYPE_REQUIRED');
  }
  const reader=request.body?.getReader();
  if (!reader) invalid('JSON_BODY_REQUIRED');
  let total=0;
  const chunks=[];
  try {
    while(true) {
      const next=await reader.read();
      if (next.done) break;
      total+=next.value.byteLength;
      if (total>MAX_BYTES) {
        await reader.cancel();
        const e=new Error('PAYLOAD_TOO_LARGE');e.status=413;e.code='PAYLOAD_TOO_LARGE';throw e;
      }
      chunks.push(next.value);
    }
  } finally { reader.releaseLock(); }
  if (total===0) invalid('JSON_BODY_REQUIRED');
  const body=new Uint8Array(total);
  let offset=0;
  for(const chunk of chunks){body.set(chunk,offset);offset+=chunk.byteLength;}
  let result;
  try {result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));}
  catch(_) {invalid('INVALID_JSON');}
  if (!result || typeof result!=='object' || Array.isArray(result)) invalid('INVALID_JSON_OBJECT');
  return result;
}

function createSocIncidentHttpHandler({service,approvedOrigin,enabled=false,authorizeCommercialAccess}={}) {
  if (!service || ['get','list','create','update'].some(k=>typeof service[k]!=='function')) {
    throw new Error('VERIFIED_SOC_SERVICE_REQUIRED');
  }
  if (typeof approvedOrigin!=='string' || !/^https:\/\/[a-z0-9.-]+$/.test(approvedOrigin) ||
      approvedOrigin !== 'https://soc.cyberdudebivash.in') {
    throw new Error('APPROVED_SOC_ORIGIN_REQUIRED');
  }

  // Customer data requires an independently implemented, server-trusted
  // billing-to-tenant authorization authority. No browser or JWT tier claim
  // can replace it; this remains SOURCE ONLY and unregistered.
  if (enabled === true && typeof authorizeCommercialAccess !== 'function') {
    throw new Error('SOC_ENTITLEMENT_AUTHORITY_REQUIRED');
  }

  return async function handle(request) {
    // Authentication is NOT an activation switch. Explicit, independently
    // authorized operator configuration is required before any request is served.
    if (enabled !== true) return error(404,'NOT_FOUND');
    if (!(request instanceof Request)) return error(400,'INVALID_REQUEST');
    const url=new URL(request.url);
    if (url.origin!==approvedOrigin) return error(404,'NOT_FOUND');
    const origin=request.headers.get('origin');
    if (origin && origin!==approvedOrigin) return error(403,'CROSS_ORIGIN_DENIED');
    if (!ALLOWED.has(request.method)) return error(405,'METHOD_NOT_ALLOWED');
    const route=url.pathname.match(INCIDENT_ROUTE);
    if (!route) return error(404,'NOT_FOUND');
    const tenantId=route[1], id=route[2];
    if ((request.method==='POST' && id) ||
        (request.method==='PATCH' && !id) ||
        (request.method==='GET' && url.searchParams.has('token'))) {
      return error(400,'INVALID_ROUTE');
    }

    const authorization=request.headers.get('authorization')||'';
    const match=authorization.match(/^Bearer ([A-Za-z0-9_.-]{20,8192})$/);
    if (!match || request.headers.has('cookie')) return error(401,'BEARER_TOKEN_REQUIRED');
    const accessToken=match[1];
    try {
      // Commercial access is separate from OIDC identity + D1 membership.
      // Both are mandatory: the service performs its own tenant/role checks.
      // The injected authority must verify subscription ownership using
      // server-trusted records, not accept a browser-provided tier or tenant.
      let entitlement;
      try {
        entitlement=await authorizeCommercialAccess({
          accessToken, tenantId, capability: SOC_CAPABILITY[request.method],
        });
      } catch (_) { return error(503,'ENTITLEMENT_SERVICE_UNAVAILABLE'); }
      // Fail closed on incomplete/foreign commercial grants. The authority
      // must verify an ACTIVE subscription and an independently enabled SOC
      // product permission for this exact operation. Never infer either from
      // the common PRO/ENTERPRISE/MSSP plan labels alone.
      if (!entitlement || typeof entitlement!=='object' ||
          entitlement.verified!==true || entitlement.allowed!==true ||
          entitlement.tenantId!==tenantId || !PAID_TIERS.has(entitlement.tier) ||
          entitlement.product!==SOC_PRODUCT ||
          entitlement.subscriptionStatus!=='active' ||
          !Array.isArray(entitlement.capabilities) ||
          entitlement.capabilities.length>32 ||
          !entitlement.capabilities.includes(SOC_CAPABILITY[request.method])) {
        return error(403,'SUBSCRIPTION_REQUIRED');
      }
      if (request.method==='GET') {
        if (id) {
          if (url.search) invalid('UNEXPECTED_QUERY');
          return reply(200,{success:true,data:await service.get({accessToken,tenantId,id})});
        }
        const fields=[...url.searchParams.keys()];
        if (fields.some(key=>key!=='state' && key!=='limit') ||
            fields.length!==new Set(fields).size) invalid('UNEXPECTED_QUERY');
        const limit=url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : 30;
        const state=url.searchParams.has('state') ? url.searchParams.get('state') : undefined;
        if (!Number.isSafeInteger(limit) || limit<1 || limit>50) invalid('INVALID_LIMIT');
        return reply(200,{success:true,data:await service.list({accessToken,tenantId,state,limit})});
      }
      if (url.search) invalid('UNEXPECTED_QUERY');
      const rid=request.headers.get('idempotency-key');
      if (typeof rid!=='string' || !/^[A-Za-z0-9_.:-]{16,128}$/.test(rid)) {
        invalid('IDEMPOTENCY_KEY_REQUIRED');
      }
      if (request.method==='POST') {
        const body=await parseSmallJson(request);
        return reply(201,{success:true,data:await service.create({
          accessToken,tenantId,requestId:rid,input:body,
        })});
      }
      const ifMatch=request.headers.get('if-match')||'';
      if (!/^"[1-9][0-9]{0,14}"$/.test(ifMatch)) invalid('IF_MATCH_VERSION_REQUIRED');
      const expectedVersion=Number(ifMatch.slice(1,-1));
      if (!Number.isSafeInteger(expectedVersion)) invalid('IF_MATCH_VERSION_REQUIRED');
      const body=await parseSmallJson(request);
      return reply(200,{success:true,data:await service.update({
        accessToken,tenantId,id,expectedVersion,requestId:rid,changes:body,
      })});
    } catch(e) {
      const status=ERROR_STATUSES.has(e?.status)?e.status:500;
      const code=status===500 ? 'INTERNAL_ERROR' :
        (/^[A-Z_]+$/.test(e?.code||'') ? e.code : 'REQUEST_REJECTED');
      return error(status,code);
    }
  };
}

module.exports = {createSocIncidentHttpHandler};
