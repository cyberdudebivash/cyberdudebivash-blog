'use strict';

const redis = require('../../_lib/redis');
const { InvestigationManager } = require('../../_lib/investigation-manager');
const { CaseManager } = require('../../_lib/case-manager');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const { resolvePathParts } = require('../../_lib/request-path');
const { isValidObjectId, canAccessInvestigation, canAssignInvestigation } = require('../../_lib/workbench-object-scope');

const MOUNT_PATH = '/api/v1/workbench/cases';

const investigationMgr = new InvestigationManager(redis);
const caseMgr = new CaseManager(redis, investigationMgr);

const CORS_HEADERS = {
  // Internal analyst APIs are same-origin only: deliberately do not emit Access-Control-Allow-Origin.
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Analyst-Key',
};

function ok(res, data, status = 200) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: true,
    meta: { timestamp: new Date().toISOString() },
    ...data,
  });
}

function fail(res, status, code, message) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: false,
    error: { code, message },
    meta: { timestamp: new Date().toISOString() },
  });
}

// Case-level authorization inherits from its parent investigation, never
// from the caller-provided case ID alone. All writes/reads pass this guard.
async function requireParentScope(res, caller, investigationId) {
  if (!isValidObjectId(investigationId)) {
    fail(res, 404, 'NOT_FOUND', 'Case not found'); return false;
  }
  try {
    const parent = await investigationMgr.getInvestigation(investigationId);
    if (!parent || parent.id !== investigationId ||
        !canAccessInvestigation(caller, parent)) {
      fail(res, 404, 'NOT_FOUND', 'Case not found'); return false;
    }
    return true;
  } catch (_) {
    fail(res, 503, 'WORKBENCH_UNAVAILABLE', 'Workbench temporarily unavailable');
    return false;
  }
}
async function requireCaseScope(res, caller, caseId) {
  if (!isValidObjectId(caseId)) {
    fail(res, 404, 'NOT_FOUND', 'Case not found'); return false;
  }
  try {
    const caseObj = await caseMgr.getCase(caseId);
    if (!caseObj || caseObj.id !== caseId ||
        !isValidObjectId(caseObj.investigationId)) {
      fail(res, 404, 'NOT_FOUND', 'Case not found'); return false;
    }
    return requireParentScope(res, caller, caseObj.investigationId);
  } catch (_) {
    fail(res, 503, 'WORKBENCH_UNAVAILABLE', 'Workbench temporarily unavailable');
    return false;
  }
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
    return res.status(200).end();
  }

  const caller = await requireAnalyst(req, res, fail);
  if (!caller) return;

  const pathParts = resolvePathParts(req, MOUNT_PATH);
  const action = pathParts[pathParts.length - 1];
  const id = pathParts[pathParts.length - 2];

  if (req.method === 'POST' && action === 'cases') {
    return handleCreateCase(req, res, caller);
  }

  // Named sub-resource actions checked before the bare-ID fallback below,
  // same discipline as investigations.js -- a plain `action && id` check
  // can't distinguish "the real ID" from "a known verb" on its own.
  if (req.method === 'POST' && pathParts.includes('notes') && id) {
    if (!await requireCaseScope(res, caller, id)) return;
    return handleAddNote(req, res, id, caller);
  }

  if (req.method === 'POST' && pathParts.includes('tasks') && id) {
    if (!await requireCaseScope(res, caller, id)) return;
    return handleAddTask(req, res, id, caller);
  }

  if (req.method === 'PUT' && action === 'close' && id) {
    if (!await requireCaseScope(res, caller, id)) return;
    return handleCloseCase(req, res, id);
  }

  // Bare /cases/{realId} -- id (segment before last) is the literal
  // 'cases' and action (last segment) is the real case ID for this exact
  // shape. Fixes the same pre-existing defect as investigations.js: the
  // old check compared pathParts[length-3] (always 'workbench' here, the
  // parent directory segment) against 'cases', which could never match.
  if (req.method === 'GET' && id === 'cases' && action) {
    if (!await requireCaseScope(res, caller, action)) return;
    return handleGetCase(req, res, action);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCreateCase(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, title, description } = body;
    if (!investigationId || !title) {
      return fail(res, 400, 'MISSING_FIELD', 'investigationId and title required');
    }
    if (!await requireParentScope(res, caller, investigationId)) return;

    const caseObj = await caseMgr.createCase(investigationId, title, description || '', caller.id);

    return ok(res, { case: caseObj }, 201);
  } catch (e) {
    return fail(res, 503, 'CREATE_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleGetCase(req, res, id) {
  try {
    const caseObj = await caseMgr.getCase(id);
    if (!caseObj) {
      return fail(res, 404, 'NOT_FOUND', `Case not found: ${id}`);
    }

    const summary = await caseMgr.getCaseSummary(id);

    return ok(res, { case: caseObj, summary });
  } catch (e) {
    return fail(res, 503, 'GET_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleAddNote(req, res, id, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { content } = body;
    if (!content) {
      return fail(res, 400, 'MISSING_CONTENT', 'content required');
    }

    // Author is the verified caller, never a client-supplied field --
    // otherwise any request could attribute a case note to any name it
    // chose to send.
    const note = await caseMgr.addNote(id, content, caller.id);

    return ok(res, { note }, 201);
  } catch (e) {
    return fail(res, 503, 'NOTE_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleAddTask(req, res, id, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { description, assignee, dueDate } = body;
    if (!description) {
      return fail(res, 400, 'MISSING_DESCRIPTION', 'description required');
    }
    if (assignee && !canAssignInvestigation(caller, assignee)) {
      return fail(res, 403, 'ASSIGNMENT_FORBIDDEN', 'Cannot assign a case task to another analyst');
    }

    const task = await caseMgr.addTask(id, description, assignee, dueDate);

    return ok(res, { task }, 201);
  } catch (e) {
    return fail(res, 503, 'TASK_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleCloseCase(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { closureReason } = body;
    const result = await caseMgr.closeCase(id, closureReason || 'No reason provided');

    return ok(res, result);
  } catch (e) {
    return fail(res, 503, 'CLOSE_FAILED', 'Workbench operation temporarily unavailable');
  }
}
