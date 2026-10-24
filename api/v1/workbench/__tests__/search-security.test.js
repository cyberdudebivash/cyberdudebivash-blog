'use strict';

jest.mock('../../../_lib/redis', () => ({
  zrevrange: jest.fn(async () => []),
  smembers: jest.fn(async () => []),
  hgetall: jest.fn(async () => []),
}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn(async () => ({ id: 'analyst-1' })) }));
jest.mock('../../../_lib/intelligence-manager', () => ({ IntelligenceManager: jest.fn(() => ({ getIntelligence: jest.fn() })) }));
jest.mock('../../../_lib/graph-engine', () => ({ GraphEngine: jest.fn(() => ({ getEntity: jest.fn() })) }));

const redis = require('../../../_lib/redis');
const { requireAnalyst } = require('../../../_lib/analyst-auth');
const handler = require('../search');

beforeEach(() => {
  jest.clearAllMocks();
  requireAnalyst.mockResolvedValue({id:'analyst-1',role:'analyst'});
  redis.zrevrange.mockResolvedValue([]);
  redis.hgetall.mockResolvedValue([]);
  redis.smembers.mockResolvedValue([]);
});

function mockReq(query = {}) {
  return { method: 'GET', query, headers: {}, url: '/api/v1/workbench/search' };
}

function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(code => { res.statusCode = code; return res; });
  res.json = jest.fn(body => { res.body = body; return res; });
  res.end = jest.fn(() => res);
  return res;
}

describe('Workbench search input bounds', () => {
  test('clamps arbitrarily large limit to 100', async () => {
    const res = mockRes();
    await handler(mockReq({ q: 'threat', limit: '999999999' }), res);
    expect(res.statusCode).toBe(200);
    expect(res.body.limit).toBe(100);
  });

  test('normalizes invalid/negative limits safely', async () => {
    expect(handler._test.parseLimit('not-a-number')).toBe(50);
    expect(handler._test.parseLimit('-10')).toBe(1);
    expect(handler._test.parseLimit('101')).toBe(100);
  });

  test('rejects a query longer than 200 characters', async () => {
    const res = mockRes();
    await handler(mockReq({ q: 'a'.repeat(201) }), res);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('QUERY_TOO_LONG');
  });

  test('rejects unknown search type instead of silently scanning all stores', async () => {
    const res = mockRes();
    await handler(mockReq({ q: 'threat', type: 'everything-forever' }), res);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_TYPE');
  });
});

describe('P0 internal SOC search isolation', () => {
  test('ordinary analyst type=all searches own assignment index only, excluding stale foreign owner',async()=>{
    redis.zrevrange.mockResolvedValue(['own','foreign','empty-owner']);
    redis.hgetall.mockImplementation(async key => ({
      'investigation:own':['id','own','assignee','analyst-1','title','Relevant threat'],
      'investigation:foreign':['id','foreign','assignee','analyst-2','title','Relevant private threat'],
      'investigation:empty-owner':['id','empty-owner','title','Relevant unowned threat'],
    }[key]||[]));
    const res=mockRes();
    await handler(mockReq({q:'threat',type:'all'}),res);
    expect(res.statusCode).toBe(200);
    expect(res.body.scope).toBe('self');
    expect(res.body.results.map(x=>x.id)).toEqual(['own']);
    expect(redis.zrevrange).toHaveBeenCalledWith('investigations:assigned:analyst-1',0,100);
    expect(redis.smembers).not.toHaveBeenCalled();
    expect(redis.zrevrange).not.toHaveBeenCalledWith('investigations:all',expect.anything(),expect.anything());
  });

  test('ordinary analyst cannot enumerate global intelligence, graph or evidence index',async()=>{
    for(const type of ['intelligence','entities','evidence']) {
      const res=mockRes();
      await handler(mockReq({q:'threat',type}),res);
      expect(res.statusCode).toBe(403);
      expect(res.body.error.code).toBe('SEARCH_SCOPE_FORBIDDEN');
    }
    expect(redis.smembers).not.toHaveBeenCalled();
    expect(redis.zrevrange).not.toHaveBeenCalled();
  });

  test('configured internal lead can search broader categories but still returns explicit scope',async()=>{
    requireAnalyst.mockResolvedValue({id:'lead',role:'lead_analyst'});
    const res=mockRes();
    await handler(mockReq({q:'threat',type:'entities'}),res);
    expect(res.statusCode).toBe(200);
    expect(res.body.scope).toBe('internal_lead');
    expect(redis.smembers).toHaveBeenCalledWith('graph:entities:all');
  });

  test('unknown or customer role does not inherit internal lead search privileges',async()=>{
    requireAnalyst.mockResolvedValue({id:'customer',role:'customer'});
    const denied=mockRes();
    await handler(mockReq({q:'threat',type:'evidence'}),denied);
    expect(denied.statusCode).toBe(403);
    expect(redis.zrevrange).not.toHaveBeenCalled();
    const limited=mockRes();
    await handler(mockReq({q:'threat',type:'all'}),limited);
    expect(limited.statusCode).toBe(200);
    expect(limited.body.scope).toBe('self');
  });

  test('backend errors do not disclose redis index names or expose record data',async()=>{
    redis.zrevrange.mockRejectedValueOnce(new Error('private Redis investigations:assigned:analyst-1'));
    const res=mockRes();
    await handler(mockReq({q:'threat',type:'investigations'}),res);
    expect(res.statusCode).toBe(503);
    expect(res.body.error.code).toBe('SEARCH_UNAVAILABLE');
    expect(JSON.stringify(res.body)).not.toMatch(/private Redis|investigations:assigned:/);
  });
});
