'use strict';
jest.mock('../../../_lib/redis', () => ({
  zrevrange: jest.fn(), hgetall: jest.fn(), zcard: jest.fn(), scard: jest.fn()
}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));
jest.mock('../../../_lib/investigation-manager', () => ({
  InvestigationManager: jest.fn().mockImplementation(() => ({}))
}));

const redis = require('../../../_lib/redis');
const { requireAnalyst } = require('../../../_lib/analyst-auth');
const dashboard = require('../dashboard');

function response() {
  return {
    headers: {}, statusCode: null, body: null,
    setHeader(k,v) { this.headers[k.toLowerCase()] = v; return this; },
    status(code) { this.statusCode = code; return this; },
    json(data) { this.body = data; return this; },
    end() { this.ended = true; return this; }
  };
}
function request(analyst) {
  return {method:'GET',query:analyst === undefined ? {} : {analyst},headers:{}};
}
function data(row) {
  return Object.entries(row).flatMap(([k,v])=>[k,v]);
}
beforeEach(()=>{
  jest.clearAllMocks();
  requireAnalyst.mockResolvedValue({id:'alice',role:'analyst'});
  redis.zrevrange.mockImplementation(async key => ({
    'investigations:assigned:alice':['own','stale-foreign'],
    'investigations:by:status:in_progress':['own','foreign'],
    'investigations:by:status:open':['foreign'],
    'investigations:by:status:pending_review':['foreign'],
    'investigations:all':['foreign']
  }[key] || []));
  redis.hgetall.mockImplementation(async key => ({
    'investigation:own':data({id:'own',title:'Owner A',assignee:'alice',status:'in_progress'}),
    'investigation:stale-foreign':data({id:'stale-foreign',title:'Reassigned to B',assignee:'bob',status:'open'}),
    'investigation:foreign':data({id:'foreign',title:'Customer B',assignee:'bob',status:'pending_review'})
  }[key] || []));
  redis.zcard.mockResolvedValue(22);
  redis.scard.mockResolvedValue(54);
});

test('P0 cross-analyst query is denied before any Redis list or count read',async()=>{
  const res=response();
  await dashboard(request('bob'),res);
  expect(res.statusCode).toBe(403);
  expect(res.body.error.code).toBe('ANALYST_SCOPE_FORBIDDEN');
  expect(redis.zrevrange).not.toHaveBeenCalled();
  expect(redis.zcard).not.toHaveBeenCalled();
  expect(res.headers['cache-control']).toContain('no-store');
  expect(res.headers['access-control-allow-origin']).toBeUndefined();
});

test('standard analyst sees only verified own assignments, not global queue or totals',async()=>{
  const res=response();
  await dashboard(request(),res);
  expect(res.statusCode).toBe(200);
  expect(res.body.analyst).toBe('alice');
  const d=res.body.dashboard;
  expect(d.scope).toBe('self');
  expect(d.myInvestigations.map(x=>x.id)).toEqual(['own']);
  expect(d.inProgress.map(x=>x.id)).toEqual(['own']);
  expect(d.open).toEqual([]);
  expect(d.pendingReview).toEqual([]);
  expect(d.recentlyUpdated).toEqual([]);
  expect(d.workbenchStats).toBeNull();
  expect(redis.zrevrange).not.toHaveBeenCalledWith('investigations:all',expect.anything(),expect.anything());
  expect(redis.zcard).not.toHaveBeenCalled();
  expect(redis.scard).not.toHaveBeenCalled();
});

test('a configured internal SOC lead can view shared queues but cannot impersonate',async()=>{
  requireAnalyst.mockResolvedValue({id:'alice',role:'lead_analyst'});
  const res=response();
  await dashboard(request(),res);
  expect(res.statusCode).toBe(200);
  expect(res.body.dashboard.scope).toBe('internal_lead');
  expect(res.body.dashboard.pendingReview[0].id).toBe('foreign');
  expect(res.body.dashboard.workbenchStats.totalInvestigations).toBe(22);
  const impersonation=response();
  await dashboard(request('bob'),impersonation);
  expect(impersonation.statusCode).toBe(403);
});

test('backend failures do not disclose Redis errors, keys or internal stack',async()=>{
  redis.zrevrange.mockRejectedValueOnce(new Error('redis internal private key investigations:assigned:alice'));
  const res=response();
  await dashboard(request(),res);
  expect(res.statusCode).toBe(503);
  expect(res.body.error.code).toBe('DASHBOARD_UNAVAILABLE');
  expect(JSON.stringify(res.body)).not.toMatch(/internal private|investigations:assigned:alice/i);
});

test('unverified role defaults to least-privilege, while missing auth remains denied',async()=>{
  requireAnalyst.mockResolvedValue({id:'alice',role:'customer'});
  const limited=response();
  await dashboard(request(),limited);
  expect(limited.statusCode).toBe(200);
  expect(limited.body.dashboard.scope).toBe('self');
  requireAnalyst.mockImplementation(async(req,res,fail)=>{fail(res,401,'UNAUTHORIZED','Denied');return null});
  const denied=response();
  await dashboard(request(),denied);
  expect(denied.statusCode).toBe(401);
  expect(redis.zcard).not.toHaveBeenCalled();
});
