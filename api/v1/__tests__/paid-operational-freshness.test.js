'use strict';
const SOURCE='2026-11-13T18:30:00.000Z', REPORT='2026-11-13T18:25:00.000Z';

jest.mock('../../../live-intel.json',()=>({
  generatedAt:'2026-11-13T18:30:00.000Z',
  metadata:{lastPipelineRun:'2026-11-13T18:31:00.000Z',
    lastReportGeneratedAt:'2026-11-13T18:25:00.000Z'},
  items:[
    {id:'FRESH-CVE',_addedAt:'2026-11-13T18:00:00.000Z',
      pubDate:'2026-11-13T17:59:00.000Z'},
    {id:'OLD-CVE',_addedAt:'2026-10-01T18:00:00.000Z',
      pubDate:'2026-10-01T17:59:00.000Z'}
  ]
}));
jest.mock('../../_lib/security',()=>({
  guardRequest:jest.fn(async()=>true),globalIpRateLimit:jest.fn(async()=>true),
  applySecurityHeaders:jest.fn()
}));
jest.mock('../../_lib/middleware',()=>({
  authenticate:jest.fn(async()=>({tier:'pro',userId:'paid-test',
    requestsUsed:1,requestsLimit:100})),
  corsHeaders:jest.fn(()=>({})),
  apiError:jest.fn((res,status,code,message)=>res.status(status).json({
    success:false,error:{code,message}})),
  successResponse:jest.fn((res,data,meta)=>res.status(200).json({
    success:true,data,meta}))
}));
jest.mock('../../_lib/intel',()=>({
  getIntel:jest.fn(),getPlatformStats:jest.fn()
}));
const {getIntel}=require('../../_lib/intel');
const handler=require('../intel');
function req(action) {
  return {method:'GET',query:{action,limit:'1'},url:'/api/v1/intel',headers:{}};
}
function response(){
  const res={statusCode:0,headers:{},body:null};
  res.setHeader=(name,value)=>{res.headers[name.toLowerCase()]=value;return res;};
  res.status=value=>{res.statusCode=value;return res;};
  res.json=value=>{res.body=value;return res;};
  res.send=value=>{res.body=value;return res;};
  res.end=()=>res;
  return res;
}
const routeResult=stamp=>({
  intel_meta:{generated_at:stamp,total_published:7506},
  items:[{id:'FRESH-CVE'}],pagination:{page:1,limit:1,total:1,has_next:false},
  tier_info:{tier:'pro'}
});
beforeEach(()=>{
  jest.useFakeTimers().setSystemTime(new Date('2026-11-13T19:00:00.000Z'));
  getIntel.mockReset().mockImplementation((kind,tier,query,options)=>{
    expect(['live','topThreats','ransomware']).toContain(kind);
    expect(tier).toBe('pro');
    expect(options.allowedIds).toBeInstanceOf(Set);
    expect([...options.allowedIds]).toEqual(['FRESH-CVE']);
    return routeResult(SOURCE);
  });
});
afterEach(()=>jest.useRealTimers());

test.each(['live','top','ransomware'])('paid %s only returns source-verified records with no-store',async action=>{
  const res=response();
  await handler(req(action),res);
  expect(res.statusCode).toBe(200);
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.body.data.items).toEqual([{id:'FRESH-CVE'}]);
  expect(res.body.data.intel_meta).toMatchObject({
    report_generated_at:REPORT,
    source_generated_at:SOURCE,
    records_scope:'VERIFIED_RECENT_ONLY'
  });
});

test.each(['live','top','ransomware'])('paid %s returns 503 not archived content when source is stale',async action=>{
  jest.setSystemTime(new Date('2026-11-13T22:30:00.000Z'));
  const res=response();
  await handler(req(action),res);
  expect(res.statusCode).toBe(503);
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.body.error.code).toBe('OPERATIONAL_INTELLIGENCE_STALE');
  expect(res.body.data).toBeUndefined();
  expect(getIntel).not.toHaveBeenCalled();
});

test.each(['live','top','ransomware'])('paid %s refuses old S2N asset even if root report fresh',async action=>{
  getIntel.mockImplementation(()=>routeResult('2026-11-13T10:00:00.000Z'));
  const res=response();
  await handler(req(action),res);
  expect(res.statusCode).toBe(503);
  expect(res.body.error.code).toBe('OPERATIONAL_ASSET_GENERATION_DIVERGED');
  expect(res.headers['cache-control']).toBe('no-store');
});
