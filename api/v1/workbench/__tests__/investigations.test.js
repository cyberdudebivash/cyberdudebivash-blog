'use strict';

// Route-handler tests for workbench/investigations.js. These exist to prove
// two things together: (1) the auth gate actually blocks unauthenticated
// requests, and (2) the routing fix described in request-path.js actually
// resolves real requests to the correct handler with the correct ID --
// specifically the bare-ID GET/PUT case, which previously compared
// pathParts[length-3] (always 'workbench' for this URL shape) against
// 'investigations' and could therefore never match.
//
// redis is mocked because every manager class here requires it at
// construction time (module load), even though none of these tests ever
// let a real method run far enough to call it -- every manager method under
// test is spied/mocked directly instead, so control never reaches `this.redis`.
jest.mock('../../../_lib/redis', () => ({}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { InvestigationManager } = require('../../../_lib/investigation-manager');
const { EvidenceManager } = require('../../../_lib/evidence-manager');
const { TimelineEngine } = require('../../../_lib/timeline-engine');
const { InvestigationGraph } = require('../../../_lib/investigation-graph');
const { AIAnalyst } = require('../../../_lib/ai-analyst');
const handler = require('../investigations');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/workbench/investigations' };
}

function mockRes() {
  const res = { headers: {}, statusCode: null, body: null };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}

beforeEach(() => {
  requireAnalyst.mockReset();
  requireAnalyst.mockResolvedValue(CALLER);
  // Every ID-based operation now checks the parent investigation's owner
  // before handing off to graph/evidence/AI managers.
  jest.spyOn(InvestigationManager.prototype, 'getInvestigation')
    .mockImplementation(async id => ({ id, assignee: CALLER.id, status: 'open' }));
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('unauthenticated requests never reach a manager method', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });
  const getInvSpy = jest.spyOn(InvestigationManager.prototype, 'getInvestigation');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'inv-123' }), res);

  expect(res.statusCode).toBe(401);
  expect(getInvSpy).not.toHaveBeenCalled();
});

test('POST /investigations creates with the authenticated caller as createdBy', async () => {
  const spy = jest.spyOn(InvestigationManager.prototype, 'createInvestigation')
    .mockResolvedValue({ id: 'inv-new', title: 'New Investigation' });

  const res = mockRes();
  await handler(mockReq('POST', { body: { title: 'New Investigation', description: 'desc' } }), res);

  expect(spy).toHaveBeenCalledWith('New Investigation', 'desc', 'MEDIUM', 'analyst-1', [], 'analyst-1');
  expect(res.statusCode).toBe(201);
  expect(res.body.investigation.id).toBe('inv-new');
});

test('GET /investigations lists with query filters', async () => {
  const spy = jest.spyOn(InvestigationManager.prototype, 'listInvestigations').mockResolvedValue([]);

  const res = mockRes();
  await handler(mockReq('GET', { query: { status: 'open' } }), res);

  expect(spy).toHaveBeenCalledWith({ assignee: 'analyst-1' }, 50);
});

test('GET /investigations/{id} (bare ID) resolves the real ID, not the literal "investigations"', async () => {
  const spy = jest.spyOn(InvestigationManager.prototype, 'getInvestigation')
    .mockResolvedValue({ id: 'inv-123', title: 'Bare ID fetch', assignee: 'analyst-1' });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'inv-123' }), res);

  expect(spy).toHaveBeenCalledWith('inv-123');
  expect(res.statusCode).toBe(200);
  expect(res.body.investigation.id).toBe('inv-123');
});

test('PUT /investigations/{id} (bare ID) resolves the real ID, not the literal "investigations"', async () => {
  const spy = jest.spyOn(InvestigationManager.prototype, 'updateInvestigation')
    .mockResolvedValue({ id: 'inv-123', title: 'Updated' });

  const res = mockRes();
  await handler(mockReq('PUT', { apexSubpath: 'inv-123', body: { title: 'Updated' } }), res);

  expect(spy).toHaveBeenCalledWith('inv-123', { title: 'Updated' });
});

test('POST /investigations/evidence sets createdBy to the caller, overriding any client-supplied value', async () => {
  const spy = jest.spyOn(EvidenceManager.prototype, 'addEvidence').mockResolvedValue({ id: 'ev-1' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'evidence',
    body: {
      investigationId: 'inv-123', type: 'file', title: 'Ev1', content: 'c',
      metadata: { createdBy: 'attacker-supplied' },
    },
  }), res);

  expect(spy).toHaveBeenCalledWith('inv-123', 'file', 'Ev1', 'c', { createdBy: 'analyst-1' });
  expect(res.statusCode).toBe(201);
});

test('GET /investigations/{id}/evidence lists evidence for that investigation', async () => {
  const spy = jest.spyOn(EvidenceManager.prototype, 'getInvestigationEvidence').mockResolvedValue([{ id: 'ev-1' }]);

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'inv-123/evidence' }), res);

  expect(spy).toHaveBeenCalledWith('inv-123', 100);
  expect(res.body.investigationId).toBe('inv-123');
});

test('GET /investigations/{id}/timeline routes to the timeline handler, not the bare-ID fallback', async () => {
  const timelineSpy = jest.spyOn(TimelineEngine.prototype, 'buildInvestigationTimeline').mockResolvedValue([]);
  const statsSpy = jest.spyOn(TimelineEngine.prototype, 'getTimelineStats').mockResolvedValue({ total: 0 });
  const getInvSpy = jest.spyOn(InvestigationManager.prototype, 'getInvestigation');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'inv-123/timeline' }), res);

  expect(timelineSpy).toHaveBeenCalledWith('inv-123');
  expect(statsSpy).toHaveBeenCalledWith('inv-123');
  expect(getInvSpy).toHaveBeenCalledWith('inv-123');
});

test('GET /investigations/{id}/graph builds the investigation graph', async () => {
  const spy = jest.spyOn(InvestigationGraph.prototype, 'buildInvestigationGraph')
    .mockResolvedValue({ nodes: [], edges: [] });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'inv-123/graph' }), res);

  expect(spy).toHaveBeenCalledWith('inv-123', 2);
});

test('GET /investigations/{id}/suggestions fans out to every AI analyst suggestion method', async () => {
  const related = jest.spyOn(AIAnalyst.prototype, 'suggestRelatedIntelligence').mockResolvedValue([]);
  const missing = jest.spyOn(AIAnalyst.prototype, 'suggestMissingEvidence').mockResolvedValue([]);
  const detection = jest.spyOn(AIAnalyst.prototype, 'suggestDetectionRules').mockResolvedValue([]);
  const iocs = jest.spyOn(AIAnalyst.prototype, 'prioritizeIOCs').mockResolvedValue([]);
  const completeness = jest.spyOn(AIAnalyst.prototype, 'scoreInvestigationCompleteness').mockResolvedValue({ score: 0 });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'inv-123/suggestions' }), res);

  [related, missing, detection, iocs, completeness].forEach(spy => expect(spy).toHaveBeenCalledWith('inv-123'));
  expect(res.body.suggestions.completeness).toEqual({ score: 0 });
});

test('GET /investigations/{id}/summary generates the executive summary', async () => {
  const spy = jest.spyOn(AIAnalyst.prototype, 'generateExecutiveSummary').mockResolvedValue({ text: 'summary' });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'inv-123/summary' }), res);

  expect(spy).toHaveBeenCalledWith('inv-123');
});

test('POST /investigations/{id}/link-intelligence links the given intelligence ID', async () => {
  const spy = jest.spyOn(InvestigationManager.prototype, 'linkIntelligence').mockResolvedValue({ linked: true });

  const res = mockRes();
  await handler(mockReq('POST', { apexSubpath: 'inv-123/link-intelligence', body: { intelligenceId: 'intel-1' } }), res);

  expect(spy).toHaveBeenCalledWith('inv-123', 'intel-1');
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('DELETE'), res);

  expect(res.statusCode).toBe(404);
});

test('P0 foreign owner cannot read detail, evidence, timeline, graph, suggestions or executive summary', async () => {
  jest.spyOn(InvestigationManager.prototype,'getInvestigation')
    .mockResolvedValue({id:'inv-foreign',assignee:'bob'});
  const graph=jest.spyOn(InvestigationGraph.prototype,'buildInvestigationGraph');
  const evidence=jest.spyOn(EvidenceManager.prototype,'getInvestigationEvidence');
  const ai=jest.spyOn(AIAnalyst.prototype,'generateExecutiveSummary');
  for(const subpath of ['inv-foreign','inv-foreign/evidence','inv-foreign/timeline',
    'inv-foreign/graph','inv-foreign/suggestions','inv-foreign/summary']) {
    const res=mockRes();
    await handler(mockReq('GET',{apexSubpath:subpath}),res);
    expect(res.statusCode).toBe(404);
    expect(res.body.error.message).toBe('Investigation not found');
  }
  expect(graph).not.toHaveBeenCalled();
  expect(evidence).not.toHaveBeenCalled();
  expect(ai).not.toHaveBeenCalled();
});
test('P0 foreign owner cannot mutate investigation, evidence or intelligence links',async()=>{
  jest.spyOn(InvestigationManager.prototype,'getInvestigation')
    .mockResolvedValue({id:'inv-foreign',assignee:'bob'});
  const update=jest.spyOn(InvestigationManager.prototype,'updateInvestigation');
  const link=jest.spyOn(InvestigationManager.prototype,'linkIntelligence');
  const evidence=jest.spyOn(EvidenceManager.prototype,'addEvidence');
  for(const [method,subpath,body] of [
    ['PUT','inv-foreign',{title:'malicious update'}],
    ['POST','inv-foreign/link-intelligence',{intelligenceId:'intel-1'}],
    ['POST','evidence',{investigationId:'inv-foreign',type:'file',title:'foreign evidence'}],
  ]){
    const res=mockRes();
    await handler(mockReq(method,{apexSubpath:subpath,body}),res);
    expect(res.statusCode).toBe(404);
  }
  expect(update).not.toHaveBeenCalled();
  expect(link).not.toHaveBeenCalled();
  expect(evidence).not.toHaveBeenCalled();
});
test('P0 ordinary analyst cannot choose another assignee during create or update',async()=>{
  const create=jest.spyOn(InvestigationManager.prototype,'createInvestigation');
  const update=jest.spyOn(InvestigationManager.prototype,'updateInvestigation');
  const createRes=mockRes();
  await handler(mockReq('POST',{body:{title:'X',assignee:'bob'}}),createRes);
  expect(createRes.statusCode).toBe(403);
  expect(create).not.toHaveBeenCalled();
  const updateRes=mockRes();
  await handler(mockReq('PUT',{apexSubpath:'inv-123',body:{assignee:'bob'}}),updateRes);
  expect(updateRes.statusCode).toBe(403);
  expect(update).not.toHaveBeenCalled();
});
test('P0 self-scoped lists never scan global status index and discard stale foreign assignments',async()=>{
  const spy=jest.spyOn(InvestigationManager.prototype,'listInvestigations').mockResolvedValue([
    {id:'own',assignee:'analyst-1',status:'open'},
    {id:'stale-foreign',assignee:'bob',status:'open'},
    {id:'closed',assignee:'analyst-1',status:'closed'},
  ]);
  const res=mockRes();
  await handler(mockReq('GET',{query:{status:'open',limit:'9999'}}),res);
  expect(spy).toHaveBeenCalledWith({assignee:'analyst-1'},50);
  expect(res.statusCode).toBe(200);
  expect(res.body.investigations.map(x=>x.id)).toEqual(['own']);
  expect(res.body.scope).toBe('self');
  const denied=mockRes();
  await handler(mockReq('GET',{query:{assignee:'bob'}}),denied);
  expect(denied.statusCode).toBe(403);
});
test('P0 lead role can inspect shared investigations but unknown analyst roles remain self-scoped',async()=>{
  jest.spyOn(InvestigationManager.prototype,'getInvestigation')
    .mockResolvedValue({id:'inv-foreign',assignee:'bob'});
  requireAnalyst.mockResolvedValue({id:'lead',role:'lead_analyst'});
  const allowed=mockRes();
  await handler(mockReq('GET',{apexSubpath:'inv-foreign'}),allowed);
  expect(allowed.statusCode).toBe(200);
  requireAnalyst.mockResolvedValue({id:'intern',role:'customer'});
  const denied=mockRes();
  await handler(mockReq('GET',{apexSubpath:'inv-foreign'}),denied);
  expect(denied.statusCode).toBe(404);
});
