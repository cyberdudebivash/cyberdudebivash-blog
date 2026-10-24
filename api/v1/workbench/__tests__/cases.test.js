'use strict';

// Route-handler tests for workbench/cases.js -- mirrors investigations.test.js:
// proves the auth gate blocks unauthenticated requests, proves the bare-ID
// GET fix (id === 'cases' && action, not the always-false pathParts[length-3]
// check it replaced), and proves the named sub-resource routes (notes,
// tasks, close) aren't shadowed by that bare-ID fallback and attribute
// authorship to the verified caller rather than any client-supplied field.
jest.mock('../../../_lib/redis', () => ({}));
jest.mock('../../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));

const { requireAnalyst } = require('../../../_lib/analyst-auth');
const { CaseManager } = require('../../../_lib/case-manager');
const { InvestigationManager } = require('../../../_lib/investigation-manager');
const handler = require('../cases');

const CALLER = { id: 'analyst-1', name: 'Analyst One', role: 'analyst' };

function mockReq(method, { apexSubpath, query = {}, body } = {}) {
  const q = { ...query };
  if (apexSubpath !== undefined) q.apexSubpath = apexSubpath;
  return { method, query: q, body, headers: {}, url: '/api/v1/workbench/cases' };
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
  jest.spyOn(CaseManager.prototype,'getCase')
    .mockImplementation(async id => ({id,investigationId:'inv-1'}));
  jest.spyOn(InvestigationManager.prototype,'getInvestigation')
    .mockImplementation(async id => ({id,assignee:'analyst-1'}));
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('unauthenticated requests never reach a manager method', async () => {
  requireAnalyst.mockImplementation(async (req, res, fail) => {
    fail(res, 401, 'UNAUTHORIZED', 'Invalid or missing analyst key');
    return null;
  });
  const spy = jest.spyOn(CaseManager.prototype, 'getCase');

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'case-123' }), res);

  expect(res.statusCode).toBe(401);
  expect(spy).not.toHaveBeenCalled();
});

test('POST /cases creates with the authenticated caller as createdBy', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'createCase').mockResolvedValue({ id: 'case-new' });

  const res = mockRes();
  await handler(mockReq('POST', { body: { investigationId: 'inv-1', title: 'New Case', description: 'd' } }), res);

  expect(spy).toHaveBeenCalledWith('inv-1', 'New Case', 'd', 'analyst-1');
  expect(res.statusCode).toBe(201);
});

test('GET /cases/{id} (bare ID) resolves the real ID, not the literal "cases"', async () => {
  const getSpy = jest.spyOn(CaseManager.prototype, 'getCase').mockResolvedValue({ id: 'case-123', investigationId: 'inv-1' });
  const summarySpy = jest.spyOn(CaseManager.prototype, 'getCaseSummary').mockResolvedValue({ notes: 0 });

  const res = mockRes();
  await handler(mockReq('GET', { apexSubpath: 'case-123' }), res);

  expect(getSpy).toHaveBeenCalledWith('case-123');
  expect(summarySpy).toHaveBeenCalledWith('case-123');
  expect(res.body.case.id).toBe('case-123');
});

test('POST /cases/{id}/notes attributes the note to the caller, not a client-supplied author', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'addNote').mockResolvedValue({ id: 'note-1' });
  const getSpy = jest.spyOn(CaseManager.prototype, 'getCase');

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'case-123/notes',
    body: { content: 'a note', author: 'attacker-supplied' },
  }), res);

  expect(spy).toHaveBeenCalledWith('case-123', 'a note', 'analyst-1');
  expect(getSpy).toHaveBeenCalledWith('case-123');
});

test('POST /cases/{id}/tasks adds a task with the given assignee and due date', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'addTask').mockResolvedValue({ id: 'task-1' });

  const res = mockRes();
  await handler(mockReq('POST', {
    apexSubpath: 'case-123/tasks',
    body: { description: 'do the thing', assignee: 'analyst-1', dueDate: '2026-09-01' },
  }), res);

  expect(spy).toHaveBeenCalledWith('case-123', 'do the thing', 'analyst-1', '2026-09-01');
});

test('PUT /cases/{id}/close closes the case with the given reason', async () => {
  const spy = jest.spyOn(CaseManager.prototype, 'closeCase').mockResolvedValue({ closed: true });

  const res = mockRes();
  await handler(mockReq('PUT', { apexSubpath: 'case-123/close', body: { closureReason: 'resolved' } }), res);

  expect(spy).toHaveBeenCalledWith('case-123', 'resolved');
});

test('unrecognized method/path combinations 404', async () => {
  const res = mockRes();
  await handler(mockReq('DELETE'), res);

  expect(res.statusCode).toBe(404);
});

test('P0 unauthorized case ID cannot read summary, write notes/tasks or close',async()=>{
  jest.spyOn(InvestigationManager.prototype,'getInvestigation')
    .mockResolvedValue({id:'inv-1',assignee:'bob'});
  const summary=jest.spyOn(CaseManager.prototype,'getCaseSummary');
  const addNote=jest.spyOn(CaseManager.prototype,'addNote');
  const addTask=jest.spyOn(CaseManager.prototype,'addTask');
  const close=jest.spyOn(CaseManager.prototype,'closeCase');
  const scenarios=[
    ['GET','case-123',undefined],
    ['POST','case-123/notes',{content:'unauthorized'}],
    ['POST','case-123/tasks',{description:'unauthorized'}],
    ['PUT','case-123/close',{closureReason:'unauthorized'}],
  ];
  for(const [method,apexSubpath,body] of scenarios){
    const res=mockRes();
    await handler(mockReq(method,{apexSubpath,body}),res);
    expect(res.statusCode).toBe(404);
    expect(res.body.error.message).toBe('Case not found');
  }
  [summary,addNote,addTask,close].forEach(fn=>expect(fn).not.toHaveBeenCalled());
});
test('P0 ordinary analyst cannot create a case on another investigation',async()=>{
  jest.spyOn(InvestigationManager.prototype,'getInvestigation')
    .mockResolvedValue({id:'inv-bob',assignee:'bob'});
  const spy=jest.spyOn(CaseManager.prototype,'createCase');
  const res=mockRes();
  await handler(mockReq('POST',{body:{investigationId:'inv-bob',title:'foreign case'}}),res);
  expect(res.statusCode).toBe(404);
  expect(spy).not.toHaveBeenCalled();
});
test('P0 owner cannot assign a case task to a different analyst without lead role',async()=>{
  const spy=jest.spyOn(CaseManager.prototype,'addTask');
  const res=mockRes();
  await handler(mockReq('POST',{apexSubpath:'case-123/tasks',
    body:{description:'Task',assignee:'bob'}}),res);
  expect(res.statusCode).toBe(403);
  expect(spy).not.toHaveBeenCalled();
});
test('P0 lead can access shared internal case but invalid/mismatched parent fails closed',async()=>{
  jest.spyOn(InvestigationManager.prototype,'getInvestigation')
    .mockResolvedValue({id:'inv-1',assignee:'bob'});
  requireAnalyst.mockResolvedValue({id:'lead',role:'soc_admin'});
  const summary=jest.spyOn(CaseManager.prototype,'getCaseSummary')
    .mockResolvedValue({notes:0});
  const allowed=mockRes();
  await handler(mockReq('GET',{apexSubpath:'case-123'}),allowed);
  expect(allowed.statusCode).toBe(200);
  expect(summary).toHaveBeenCalledWith('case-123');

  jest.spyOn(CaseManager.prototype,'getCase')
    .mockResolvedValue({id:'case-123',investigationId:'inv-not-matching'});
  const denied=mockRes();
  await handler(mockReq('GET',{apexSubpath:'case-123'}),denied);
  expect(denied.statusCode).toBe(404);
});
