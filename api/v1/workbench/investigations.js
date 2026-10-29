'use strict';

const redis = require('../../_lib/redis');
const { IntelligenceManager } = require('../../_lib/intelligence-manager');
const { GraphEngine } = require('../../_lib/graph-engine');
const { GraphTraversal } = require('../../_lib/graph-traversal');
const { CorrelationEngine } = require('../../_lib/correlation-engine');
const { InvestigationManager } = require('../../_lib/investigation-manager');
const { CaseManager } = require('../../_lib/case-manager');
const { EvidenceManager } = require('../../_lib/evidence-manager');
const { TimelineEngine } = require('../../_lib/timeline-engine');
const { InvestigationGraph } = require('../../_lib/investigation-graph');
const { AIAnalyst } = require('../../_lib/ai-analyst');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const { resolvePathParts } = require('../../_lib/request-path');
const { isInternalLead, isValidObjectId, canAccessInvestigation, canAssignInvestigation } = require('../../_lib/workbench-object-scope');

const MOUNT_PATH = '/api/v1/workbench/investigations';

const manager = new IntelligenceManager(redis);
const graphEngine = new GraphEngine(redis, manager);
const traversal = new GraphTraversal(graphEngine);
const correlationEngine = new CorrelationEngine(graphEngine, traversal);
const investigationMgr = new InvestigationManager(redis, manager, graphEngine);
const caseMgr = new CaseManager(redis, investigationMgr);
const evidenceMgr = new EvidenceManager(redis, investigationMgr, graphEngine);
const timelineEngine = new TimelineEngine(redis, investigationMgr, manager);
const investigationGraph = new InvestigationGraph(redis, investigationMgr, graphEngine, traversal);
const aiAnalyst = new AIAnalyst(redis, investigationMgr, graphEngine, traversal, correlationEngine);

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

// The handler must not load evidence, AI suggestions, graphs or case-linked
// intelligence before checking the parent investigation's current owner.
async function requireInvestigationScope(res, caller, investigationId) {
  if (!isValidObjectId(investigationId)) {
    fail(res, 404, 'NOT_FOUND', 'Investigation not found');
    return false;
  }
  try {
    const investigation = await investigationMgr.getInvestigation(investigationId);
    if (!investigation || investigation.id !== investigationId ||
        !canAccessInvestigation(caller, investigation)) {
      fail(res, 404, 'NOT_FOUND', 'Investigation not found');
      return false;
    }
    return true;
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

  // Route-level object authorization covers every ID-based GET/POST/PUT
  // action. Missing and forbidden IDs produce the same non-disclosing 404.
  // POST evidence uses a body investigationId and is checked in its handler.
  let scopedId = null;
  if (req.method === 'GET' && action === 'evidence' && id) scopedId = id;
  else if (req.method === 'GET' &&
    ['timeline', 'graph', 'suggestions', 'summary'].includes(action) && id) scopedId = id;
  else if (req.method === 'POST' && action === 'link-intelligence' && id) scopedId = id;
  else if (id === 'investigations' && action &&
    ['GET', 'PUT'].includes(req.method)) scopedId = action;
  if (scopedId !== null && !await requireInvestigationScope(res, caller, scopedId)) return;

  // Investigation CRUD -- base path, no sub-segment
  if (req.method === 'POST' && action === 'investigations') {
    return handleCreateInvestigation(req, res, caller);
  }

  if (req.method === 'GET' && action === 'investigations') {
    return handleListInvestigations(req, res, caller);
  }

  // Named sub-resource actions (/investigations/{id}/{verb}) -- checked
  // BEFORE the bare-ID fallback below, since a bare `action && id` check
  // alone can't tell "the real ID" apart from "a known verb"; every one of
  // these must be resolved first or the bare-ID handler would shadow all
  // of them.
  if (req.method === 'POST' && pathParts.includes('evidence')) {
    return handleAddEvidence(req, res, caller);
  }

  if (req.method === 'GET' && pathParts.includes('evidence') && pathParts[pathParts.length - 2]) {
    const investigationId = pathParts[pathParts.length - 2];
    return handleGetInvestigationEvidence(req, res, investigationId);
  }

  if (req.method === 'GET' && action === 'timeline' && id) {
    return handleGetTimeline(req, res, id);
  }

  if (req.method === 'GET' && action === 'graph' && id) {
    return handleGetInvestigationGraph(req, res, id);
  }

  if (req.method === 'GET' && action === 'suggestions' && id) {
    return handleGetSuggestions(req, res, id);
  }

  if (req.method === 'GET' && action === 'summary' && id) {
    return handleGetExecutiveSummary(req, res, id);
  }

  if (req.method === 'POST' && action === 'link-intelligence' && id) {
    return handleLinkIntelligence(req, res, id);
  }

  // Bare /investigations/{realId} -- for this exact shape, `id` (the
  // segment right before the last) is always the literal 'investigations'
  // and `action` (the last segment) is the real investigation ID. Every
  // named verb above already returned if it matched, so reaching here
  // with id === 'investigations' unambiguously means "no verb, just an
  // ID" -- fixes a pre-existing defect where this used to check
  // pathParts[length-3] === 'investigations' (always false for this
  // shape: that position holds 'workbench', the parent directory segment,
  // not the resource name), so GET/PUT on a single investigation could
  // never actually be reached even once the missing-rewrite gap above is
  // fixed.
  if (req.method === 'GET' && id === 'investigations' && action) {
    return handleGetInvestigation(req, res, action);
  }

  if (req.method === 'PUT' && id === 'investigations' && action) {
    return handleUpdateInvestigation(req, res, action, caller);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCreateInvestigation(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { title, description, priority, assignee, linkedIntelligence } = body;
    if (!title) {
      return fail(res, 400, 'MISSING_TITLE', 'title required');
    }

    const effectiveAssignee = assignee || caller.id;
    if (!canAssignInvestigation(caller, effectiveAssignee)) {
      return fail(res, 403, 'ASSIGNMENT_FORBIDDEN', 'Cannot assign an investigation to another analyst');
    }
    const investigation = await investigationMgr.createInvestigation(
      title,
      description || '',
      priority || 'MEDIUM',
      effectiveAssignee,
      linkedIntelligence || [],
      caller.id
    );

    return ok(res, { investigation }, 201);
  } catch (e) {
    return fail(res, 503, 'CREATE_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleListInvestigations(req, res, caller) {
  const lead = isInternalLead(caller);
  if (!lead && req.query.assignee && req.query.assignee !== caller.id) {
    return fail(res, 403, 'ANALYST_SCOPE_FORBIDDEN', 'Cannot list another analyst\'s investigations');
  }
  try {
    // Force a caller-specific Redis index for normal analysts. Passing both
    // status and assignee to listInvestigations is unsafe: status takes
    // precedence and would silently trigger a global-index scan.
    const filters = lead ? {} : { assignee: caller.id };
    if (lead && req.query.status) filters.status = req.query.status;
    if (lead && req.query.assignee) filters.assignee = req.query.assignee;
    const parsedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isFinite(parsedLimit) ? Math.max(1, Math.min(50, parsedLimit)) : 50;
    const records = await investigationMgr.listInvestigations(filters, limit);
    const investigations = records.filter(investigation =>
      canAccessInvestigation(caller, investigation) &&
      (!req.query.status || investigation.status === req.query.status) &&
      (!req.query.assignee || investigation.assignee === req.query.assignee));
    return ok(res, { investigations, count: investigations.length,
      scope: lead ? 'internal_lead' : 'self' });
  } catch (_) {
    return fail(res, 503, 'LIST_UNAVAILABLE', 'Investigation list temporarily unavailable');
  }
}

async function handleGetInvestigation(req, res, id) {
  try {
    const investigation = await investigationMgr.getInvestigation(id);
    if (!investigation) {
      return fail(res, 404, 'NOT_FOUND', `Investigation not found: ${id}`);
    }

    return ok(res, { investigation });
  } catch (e) {
    return fail(res, 503, 'GET_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleUpdateInvestigation(req, res, id, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    // Ordinary analysts may update their own record but cannot transfer it
    // to another analyst; only explicitly configured internal leads can.
    if (Object.prototype.hasOwnProperty.call(body, 'assignee') &&
        !canAssignInvestigation(caller, body.assignee)) {
      return fail(res, 403, 'ASSIGNMENT_FORBIDDEN', 'Cannot reassign to another analyst');
    }
    // requireAnalyst already authenticated this internal caller above. Never
    // derive reassignment authority from a client-supplied body/role field.
    const investigation = await investigationMgr.updateInvestigation(id, body, caller);

    return ok(res, { investigation });
  } catch (e) {
    return fail(res, 503, 'UPDATE_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleAddEvidence(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, type, title, content, metadata } = body;
    if (!investigationId || !type || !title) {
      return fail(res, 400, 'MISSING_FIELD', 'investigationId, type, title required');
    }
    if (!await requireInvestigationScope(res, caller, investigationId)) return;

    // createdBy always the verified caller -- never a client-supplied
    // metadata field, otherwise any request could attribute evidence to
    // any name it chose to send.
    const evidence = await evidenceMgr.addEvidence(
      investigationId, type, title, content, { ...metadata, createdBy: caller.id }
    );

    return ok(res, { evidence }, 201);
  } catch (e) {
    return fail(res, 503, 'EVIDENCE_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleGetInvestigationEvidence(req, res, investigationId) {
  try {
    const limit = parseInt(req.query.limit || '100', 10);
    const evidence = await evidenceMgr.getInvestigationEvidence(investigationId, limit);

    return ok(res, {
      investigationId,
      evidence,
      count: evidence.length,
    });
  } catch (e) {
    return fail(res, 503, 'EVIDENCE_LIST_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleGetTimeline(req, res, id) {
  try {
    const timeline = await timelineEngine.buildInvestigationTimeline(id);
    const stats = await timelineEngine.getTimelineStats(id);

    return ok(res, {
      investigationId: id,
      timeline,
      stats,
    });
  } catch (e) {
    return fail(res, 503, 'TIMELINE_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleGetInvestigationGraph(req, res, id) {
  try {
    const maxDepth = parseInt(req.query.depth || '2', 10);
    const graphData = await investigationGraph.buildInvestigationGraph(id, maxDepth);

    return ok(res, graphData);
  } catch (e) {
    return fail(res, 503, 'GRAPH_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleGetSuggestions(req, res, id) {
  try {
    const [related, missing, detection, iocs, completeness] = await Promise.all([
      aiAnalyst.suggestRelatedIntelligence(id),
      aiAnalyst.suggestMissingEvidence(id),
      aiAnalyst.suggestDetectionRules(id),
      aiAnalyst.prioritizeIOCs(id),
      aiAnalyst.scoreInvestigationCompleteness(id),
    ]);

    return ok(res, {
      investigationId: id,
      suggestions: {
        relatedIntelligence: related,
        missingEvidence: missing,
        detectionRules: detection,
        prioritizedIOCs: iocs,
        completeness: completeness,
      },
    });
  } catch (e) {
    return fail(res, 503, 'SUGGESTIONS_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleGetExecutiveSummary(req, res, id) {
  try {
    const summary = await aiAnalyst.generateExecutiveSummary(id);

    return ok(res, { summary });
  } catch (e) {
    return fail(res, 503, 'SUMMARY_FAILED', 'Workbench operation temporarily unavailable');
  }
}

async function handleLinkIntelligence(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { intelligenceId } = body;
    if (!intelligenceId) {
      return fail(res, 400, 'MISSING_ID', 'intelligenceId required');
    }

    const result = await investigationMgr.linkIntelligence(id, intelligenceId);

    return ok(res, result);
  } catch (e) {
    return fail(res, 503, 'LINK_FAILED', 'Workbench operation temporarily unavailable');
  }
}
