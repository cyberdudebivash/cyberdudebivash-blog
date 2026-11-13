'use strict';

// Tests the real public route, not only a helper. Synthetic clock prevents
// today's moving wall-clock from invalidating an immutable source fixture.
jest.mock('../../_lib/security',()=>({
  guardRequest:jest.fn(async()=>true),
  globalIpRateLimit:jest.fn(async()=>true),
  applySecurityHeaders:jest.fn()
}));
jest.mock('../../_lib/middleware',()=>({
  authenticate:jest.fn(),
  successResponse:jest.fn(),
  corsHeaders:jest.fn(()=>({})),
  apiError:jest.fn((res,status,code,message)=>res.status(status).json({
    success:false,error:{code,message}
  }))
}));
jest.mock('../../_lib/intel',()=>({
  getPlatformStats:jest.fn(()=>({
    total_published:7466,live_intel_count:150,critical_threats:39
  })),
  getIntel:jest.fn(()=>{throw new Error('Enterprise loader must not serve public dashboard');})
}));

const handler=require('../intel');
const feed=require('../../../live-intel.json');
const RS=require('../../../runtime-state.js');
const {assessPublicIntel}=require('../../_lib/public-intel-freshness');
const {getPlatformStats,getIntel}=require('../../_lib/intel');

const SOURCE=Date.parse(RS.feedTimestamp(feed));
function req(action,method='GET',extra={}){
  return {method,query:{action,...extra},url:'/api/v1/intel',headers:{}};
}
function response(){
  const res={statusCode:0,body:null,headers:{}};
  res.setHeader=jest.fn((k,v)=>{res.headers[k.toLowerCase()]=v;return res;});
  res.status=jest.fn(n=>{res.statusCode=n;return res;});
  res.json=jest.fn(v=>{res.body=v;return res;});
  res.end=jest.fn(()=>res);
  return res;
}
beforeEach(()=>{
  jest.useFakeTimers();
  jest.setSystemTime(SOURCE+60*60000);
  jest.clearAllMocks();
});
afterEach(()=>jest.useRealTimers());

test('API action=dashboard returns only individually source-verified and ingested reports',async()=>{
  const res=response();
  await handler(req('dashboard'),res);
  expect(res.statusCode).toBe(200);
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.body.meta.contract).toBe('cdb.dashboard-feed.v1');
  expect(res.body.meta.source_timestamp).toBe(new Date(SOURCE).toISOString());
  expect(['HEALTHY','DEGRADED']).toContain(res.body.meta.freshness_state);
  expect(Array.isArray(res.body.data.items)).toBe(true);
  expect(res.body.data.items.length).toBeGreaterThan(0);
  const now=Date.now();
  for(const item of res.body.data.items){
    expect(item).toHaveProperty('first_ingested');
    expect(item).toHaveProperty('published');
    expect(RS.isLiveRecord({_addedAt:item.first_ingested,pubDate:item.published},now)).toBe(true);
    for(const field of ['iocs','explanation','scoring','actor_attribution','api_key','customer_id']){
      expect(item).not.toHaveProperty(field);
    }
  }
  expect(getIntel).not.toHaveBeenCalled();
});

test.each(['intel','breaking','malware','ai_security'])('API dashboard section=%s remains bounded and truth-filtered',async(section)=>{
  const res=response();
  await handler(req('dashboard','GET',{section,limit:'3'}),res);
  expect(res.statusCode).toBe(200);
  expect(res.body.data.section).toBe(section);
  expect(res.body.data.items.length).toBeLessThanOrEqual(3);
});

test('P0 a stale Worker does not reissue old records from a freshly requested dashboard API URL',async()=>{
  jest.setSystemTime(SOURCE+4*3600000);
  const res=response();
  await handler(req('dashboard'),res);
  expect(res.statusCode).toBe(503);
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.body.success).toBe(false);
  expect(res.body.error.code).toBe('DASHBOARD_FEED_UNAVAILABLE');
  expect(res.body.data).toBeUndefined();
});

test('P0 stats endpoint withholds stale counts rather than presenting a current request timestamp as fresh',async()=>{
  jest.setSystemTime(SOURCE+4*3600000);
  const res=response();
  await handler(req('stats'),res);
  expect(res.statusCode).toBe(503);
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.body.error.code).toBe('PUBLIC_INTELLIGENCE_STALE');
  expect(res.body.stats).toBeUndefined();
  expect(getPlatformStats).not.toHaveBeenCalled();
});

test('Verified stats preserve historical volume truth with explicitly separate source timestamp',async()=>{
  const res=response();
  await handler(req('stats'),res);
  expect(res.statusCode).toBe(200);
  expect(res.headers['cache-control']).toBe('no-store');
  // Preserve historical-mock divergence as source publications advance;
  // the public API must report the authoritative cumulative source count.
  expect(feed.totalPublished).toBeGreaterThan(7466);
  expect(res.body.stats.total_published).toBe(feed.totalPublished);
  expect(res.body.stats.metrics_scope).toBe('CURRENT_EVIDENCED_WINDOW');
  const current=assessPublicIntel(feed,Date.now()).items;
  expect(res.body.stats.live_intel_count).toBe(current.length);
  expect(res.body.stats.live_intel_count).toBeLessThan(150);
  expect(res.body.stats.critical_threats).toBe(current.filter(i=>
    Number(i.cvss)>=9).length);
  expect(res.body.stats.cisa_kev_count).toBe(current.filter(i=>
    i.cisaKev===true||i.cisa_kev===true).length);
  expect(res.body.meta.source_timestamp).toBe(new Date(SOURCE).toISOString());
  expect(res.body.meta.timestamp).not.toBe(res.body.meta.source_timestamp);
});

test.each(['stats','dashboard'])('P0 public %s route refuses POST without processing data',async(action)=>{
  const res=response();
  await handler(req(action,'POST'),res);
  expect(res.statusCode).toBe(405);
  expect(getPlatformStats).not.toHaveBeenCalled();
  expect(getIntel).not.toHaveBeenCalled();
});
