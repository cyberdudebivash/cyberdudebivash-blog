'use strict';

const {createSocIncidentHttpHandler} = require('../soc-incident-http');
const ORIGIN='https://soc.cyberdudebivash.in';
const API=ORIGIN+'/api/v1/soc/tenants/acme/incidents';
const ID='inc_00000000-0000-4000-8000-000000000001';
const TOKEN='a'.repeat(128)+'.'+'b'.repeat(128)+'.'+'c'.repeat(128);
const R='request-1234567890123456';
const auth={'Authorization':'Bearer '+TOKEN};

function fixture(enabled=true) {
  const service={
    list:jest.fn(async()=>[{incidentId:ID,version:2}]),
    get:jest.fn(async()=>({incidentId:ID,version:2})),
    create:jest.fn(async()=>({incidentId:ID,version:1})),
    update:jest.fn(async()=>({incidentId:ID,version:3})),
  };
  const entitlement=jest.fn(async ({tenantId}) => ({
    verified:true,allowed:true,tenantId,tier:'PRO',
    product:'SENTINEL_APEX_SOC',subscriptionStatus:'active',
    capabilities:['soc.incidents.read','soc.incidents.write'],
  }));
  return {
    service,entitlement,
    handle:createSocIncidentHttpHandler({
      service,approvedOrigin:ORIGIN,enabled,authorizeCommercialAccess:entitlement,
    }),
  };
}
async function json(response) {return response.json();}
function request(url=API,init={}) {
  return new Request(url,{...init,headers:{...auth,...(init.headers||{})}});
}
function write(method, url=API, body={title:'Pilot signal',severity:'HIGH'}, headers={}) {
  return request(url,{
    method,headers:{'Content-Type':'application/json','Idempotency-Key':R,...headers},
    body:JSON.stringify(body),
  });
}

test('construction requires a real service and approved SOC-only origin',() => {
  expect(()=>createSocIncidentHttpHandler({service:{},approvedOrigin:ORIGIN}))
    .toThrow('VERIFIED_SOC_SERVICE_REQUIRED');
  expect(()=>createSocIncidentHttpHandler({service:fixture().service,approvedOrigin:'https://blog.cyberdudebivash.in'}))
    .toThrow('APPROVED_SOC_ORIGIN_REQUIRED');
});

test('no route is enabled by default even with a valid-looking token',async() => {
  const {service,handle}=fixture(false);
  const res=await handle(request());
  expect(res.status).toBe(404);
  expect((await json(res)).error.code).toBe('NOT_FOUND');
  expect(service.list).not.toHaveBeenCalled();
});

test('wrong-host and cross-origin browsers cannot use SOC handler',async() => {
  const {handle,service}=fixture();
  expect((await handle(request('https://blog.cyberdudebivash.in/api/v1/soc/tenants/acme/incidents'))).status).toBe(404);
  const response=await handle(request(API,{headers:{Origin:'https://evil.example'}}));
  expect(response.status).toBe(403);
  expect(response.headers.has('access-control-allow-origin')).toBe(false);
  expect(service.list).not.toHaveBeenCalled();
});

test('preflight is not cross-origin authorized and remains non-cacheable',async() => {
  const {handle}=fixture();
  const res=await handle(request(API,{method:'OPTIONS',headers:{Origin:'https://evil.example'}}));
  expect(res.status).toBe(403);
  expect(res.headers.has('access-control-allow-origin')).toBe(false);
  expect(res.headers.get('cache-control')).toContain('no-store');
  expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
});

test('missing bearer and cookie credentials both denied without calling service',async() => {
  const {handle,service}=fixture();
  const r=new Request(API);
  const res=await handle(r);
  expect(res.status).toBe(401);
  const cookie=await handle(request(API,{headers:{Cookie:'session=attacker'}}));
  expect(cookie.status).toBe(401);
  expect(service.list).not.toHaveBeenCalled();
});

test('tenant list is bounded and supplied only through the service identity check',async() => {
  const {handle,service}=fixture();
  const res=await handle(request(API+'?state=TRIAGE&limit=10'));
  expect(res.status).toBe(200);
  expect(service.list).toHaveBeenCalledWith({accessToken:TOKEN,tenantId:'acme',state:'TRIAGE',limit:10});
  expect(res.headers.has('access-control-allow-origin')).toBe(false);
  expect(res.headers.get('vary')).toContain('Authorization');
  expect((await json(res)).data).toEqual([{incidentId:ID,version:2}]);
});

test('GET individual incident dispatches with tenant-bound id',async() => {
  const {handle,service}=fixture();
  const res=await handle(request(API+'/'+ID));
  expect(res.status).toBe(200);
  expect(service.get).toHaveBeenCalledWith({accessToken:TOKEN,tenantId:'acme',id:ID});
});

test('rejects unexpected query and duplicate query parameters',async() => {
  const {handle,service}=fixture();
  for(const url of [API+'?token=leak',API+'?sort=global',API+'?limit=2&limit=3',API+'?limit=10000']) {
    const res=await handle(request(url));
    expect(res.status).toBe(400);
  }
  expect(service.list).not.toHaveBeenCalled();
});

test('POST requires JSON and idempotency key; creates only with allowed data',async() => {
  const {handle,service}=fixture();
  const success=await handle(write('POST'));
  expect(success.status).toBe(201);
  expect(service.create).toHaveBeenCalledWith({
    accessToken:TOKEN,tenantId:'acme',requestId:R,input:{title:'Pilot signal',severity:'HIGH'},
  });
  const missing=await handle(write('POST',API,{title:'Test'},{'Idempotency-Key':'bad'}));
  expect(missing.status).toBe(400);
  const wrongType=await handle(request(API,{method:'POST',headers:{'Idempotency-Key':R,'Content-Type':'text/plain'},body:'{}'}));
  expect(wrongType.status).toBe(400);
});

test('PATCH requires an incident ID, valid ETag version and idempotency key',async() => {
  const {handle,service}=fixture();
  const res=await handle(write('PATCH',API+'/'+ID,{state:'INVESTIGATING'},{'If-Match':'"2"'}));
  expect(res.status).toBe(200);
  expect(service.update).toHaveBeenCalledWith({
    accessToken:TOKEN,tenantId:'acme',id:ID,expectedVersion:2,requestId:R,
    changes:{state:'INVESTIGATING'},
  });
  expect((await handle(write('PATCH',API,{state:'INVESTIGATING'},{'If-Match':'"2"'}))).status).toBe(400);
  expect((await handle(write('PATCH',API+'/'+ID,{state:'INVESTIGATING'}))).status).toBe(400);
});

test('invalid JSON and unsupported methods are rejected, without service calls',async() => {
  const {handle,service}=fixture();
  const res=await handle(request(API,{method:'POST',headers:{'Content-Type':'application/json','Idempotency-Key':R},body:'{"x":'}));
  expect(res.status).toBe(400);
  expect((await handle(request(API,{method:'DELETE'}))).status).toBe(405);
  expect(service.create).not.toHaveBeenCalled();
});

test('overly large JSON fails before allocation or service operation',async() => {
  const {handle,service}=fixture();
  const body=JSON.stringify({title:'x'.repeat(9000)});
  const res=await handle(write('POST',API,{title:'x'.repeat(9000)}));
  expect(res.status).toBe(413);
  expect(body.length).toBeGreaterThan(8192);
  expect(service.create).not.toHaveBeenCalled();
});

test('database error messages are not sent to the client',async() => {
  const {handle,service}=fixture();
  service.get.mockRejectedValue(new Error('D1 credentials: NEVER_LEAK'));
  const res=await handle(request(API+'/'+ID));
  expect(res.status).toBe(500);
  expect(JSON.stringify(await json(res))).not.toContain('NEVER_LEAK');
});

test.each([undefined, false, 'false', 'true', 0, 1, null, {}])(
  'SOC incident HTTP rejects non-boolean or disabled activation value %p', async enabled => {
    const service = fixture().service;
    const handler = createSocIncidentHttpHandler({service,approvedOrigin:ORIGIN,enabled});
    const res = await handler(request());
    expect(res.status).toBe(404);
    expect((await res.json()).error.code).toBe('NOT_FOUND');
    expect(service.list).not.toHaveBeenCalled();
  }
);

test('customer SOC adapter refuses activation without a trusted commercial authority', () => {
  const service=fixture().service;
  expect(() => createSocIncidentHttpHandler({service,approvedOrigin:ORIGIN,enabled:true}))
    .toThrow('SOC_ENTITLEMENT_AUTHORITY_REQUIRED');
});

test.each([
  [{verified:true,allowed:true,tenantId:'acme',tier:'FREE'},403],
  [{verified:true,allowed:true,tenantId:'acme',tier:'pro'},403],
  [{verified:true,allowed:true,tenantId:'acme',tier:'UNKNOWN'},403],
  [{verified:true,allowed:true,tenantId:'contoso',tier:'PRO'},403],
  [{verified:false,allowed:true,tenantId:'acme',tier:'PRO'},403],
  [{verified:true,allowed:false,tenantId:'acme',tier:'PRO'},403],
  [true,403],
  [null,403],
])('refuses untrusted or nonpremium commercial entitlement: %p', async (verdict,status) => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockResolvedValue(verdict);
  const res=await handle(request());
  expect(res.status).toBe(status);
  expect((await res.json()).error.code).toBe('SUBSCRIPTION_REQUIRED');
  expect(service.list).not.toHaveBeenCalled();
});

test('commercial entitlement authority outage fails closed without incident access',async () => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockRejectedValue(new Error('private billing data unavailable'));
  const res=await handle(request());
  expect(res.status).toBe(503);
  const body=await res.json();
  expect(body.error.code).toBe('ENTITLEMENT_SERVICE_UNAVAILABLE');
  expect(JSON.stringify(body)).not.toContain('private billing data');
  expect(service.list).not.toHaveBeenCalled();
});

test.each(['PRO','ENTERPRISE','MSSP'])('verified %s entitlement permits tenant-bound service authorization',async tier => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockResolvedValue({
    verified:true,allowed:true,tenantId:'acme',tier,
    product:'SENTINEL_APEX_SOC',subscriptionStatus:'active',
    capabilities:['soc.incidents.read','soc.incidents.write'],
  });
  const res=await handle(request());
  expect(res.status).toBe(200);
  expect(service.list).toHaveBeenCalledTimes(1);
  expect(entitlement).toHaveBeenCalledWith({
    accessToken:TOKEN,tenantId:'acme',capability:'soc.incidents.read',
  });
});


const verifiedGrant=(capabilities=['soc.incidents.read','soc.incidents.write'])=>({
  verified:true,allowed:true,tenantId:'acme',tier:'PRO',
  product:'SENTINEL_APEX_SOC',subscriptionStatus:'active',capabilities,
});

test.each([
  [{...verifiedGrant(),product:'SENTINEL_APEX_THREAT_INTEL'},'wrong product'],
  [{...verifiedGrant(),product:undefined},'missing product'],
  [{...verifiedGrant(),subscriptionStatus:'past_due'},'past due without approved SOC grace'],
  [{...verifiedGrant(),subscriptionStatus:'cancelled'},'cancelled'],
  [{...verifiedGrant(),subscriptionStatus:'refunded'},'refunded'],
  [{...verifiedGrant(),subscriptionStatus:'expired'},'expired'],
  [{...verifiedGrant(),subscriptionStatus:'ACTIVE'},'mis-cased status'],
  [{...verifiedGrant(),capabilities:[]},'missing scope'],
  [{...verifiedGrant(),capabilities:['intel.premium.read']},'intel-only scope'],
  [{...verifiedGrant(),capabilities:'soc.incidents.read'},'untrusted scope string'],
  [{...verifiedGrant(),capabilities:Array(33).fill('soc.incidents.read')},'oversize scope claims'],
  [{...verifiedGrant(),tier:'FREE'},'free despite explicit feature'],
  [{...verifiedGrant(),tenantId:'contoso'},'wrong tenant'],
])('paid plan does not enable SOC incident access: %s (%s)',async (verdict) => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockResolvedValue(verdict);
  const res=await handle(request());
  expect(res.status).toBe(403);
  expect((await res.json()).error.code).toBe('SUBSCRIPTION_REQUIRED');
  expect(service.list).not.toHaveBeenCalled();
});

test('read-only explicit SOC grant permits reads but never mutations',async () => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockResolvedValue(verifiedGrant(['soc.incidents.read']));
  const read=await handle(request());
  expect(read.status).toBe(200);
  const writeResponse=await handle(write('POST'));
  expect(writeResponse.status).toBe(403);
  expect(service.create).not.toHaveBeenCalled();
  expect(entitlement).toHaveBeenNthCalledWith(2,{
    accessToken:TOKEN,tenantId:'acme',capability:'soc.incidents.write',
  });
});

test('write-only explicit SOC grant cannot read tenant incidents',async () => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockResolvedValue(verifiedGrant(['soc.incidents.write']));
  expect((await handle(request())).status).toBe(403);
  expect(service.list).not.toHaveBeenCalled();
});

test('approved SOC write scope and active shared subscription allow service RBAC to run',async () => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockResolvedValue(verifiedGrant(['soc.incidents.write']));
  const created=await handle(write('POST'));
  expect(created.status).toBe(201);
  expect(service.create).toHaveBeenCalledTimes(1);
  expect(entitlement).toHaveBeenCalledWith({
    accessToken:TOKEN,tenantId:'acme',capability:'soc.incidents.write',
  });
});

test('malformed entitlement authority result fails closed on mutation',async () => {
  const {handle,service,entitlement}=fixture();
  entitlement.mockResolvedValue({verified:true,allowed:true,tenantId:'acme',tier:'MSSP'});
  const res=await handle(write('PATCH',API+'/'+ID,{state:'INVESTIGATING'},{'If-Match':'"2"'}));
  expect(res.status).toBe(403);
  expect(service.update).not.toHaveBeenCalled();
});
