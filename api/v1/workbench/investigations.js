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

  // Investigation CRUD -- base path, no sub-segment
  if (req.method === 'POST' && action === 'investigations') {
    return handleCreateInvestigation(req, res, caller);
  }

  if (req.method === 'GET' && action === 'investigations') {
    return handleListInvestigations(req, res);
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
    return handleUpdateInvestigation(req, res, action);
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

    const investigation = await investigationMgr.createInvestigation(
      title,
      description || '',
      priority || 'MEDIUM',
      assignee,
      linkedIntelligence || [],
      caller.id
    );

    return ok(res, { investigation }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleListInvestigations(req, res) {
  try {
    const filters = {};
    if (req.query.status) filters.status = req.query.status;
    if (req.query.assignee) filters.assignee = req.query.assignee;

    const limit = parseInt(req.query.limit || '50', 10);
    const investigations = await investigationMgr.listInvestigations(filters, limit);

    return ok(res, { investigations, count: investigations.length });
  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', e.message);
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
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleUpdateInvestigation(req, res, id) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const investigation = await investigationMgr.updateInvestigation(id, body);

    return ok(res, { investigation });
  } catch (e) {
    return fail(res, 500, 'UPDATE_FAILED', e.message);
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

    // createdBy always the verified caller -- never a client-supplied
    // metadata field, otherwise any request could attribute evidence to
    // any name it chose to send.
    const evidence = await evidenceMgr.addEvidence(
      investigationId, type, title, content, { ...metadata, createdBy: caller.id }
    );

    return ok(res, { evidence }, 201);
  } catch (e) {
    return fail(res, 500, 'EVIDENCE_FAILED', e.message);
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
    return fail(res, 500, 'EVIDENCE_LIST_FAILED', e.message);
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
    return fail(res, 500, 'TIMELINE_FAILED', e.message);
  }
}

async function handleGetInvestigationGraph(req, res, id) {
  try {
    const maxDepth = parseInt(req.query.depth || '2', 10);
    const graphData = await investigationGraph.buildInvestigationGraph(id, maxDepth);

    return ok(res, graphData);
  } catch (e) {
    return fail(res, 500, 'GRAPH_FAILED', e.message);
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
    return fail(res, 500, 'SUGGESTIONS_FAILED', e.message);
  }
}

async function handleGetExecutiveSummary(req, res, id) {
  try {
    const summary = await aiAnalyst.generateExecutiveSummary(id);

    return ok(res, { summary });
  } catch (e) {
    return fail(res, 500, 'SUMMARY_FAILED', e.message);
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
    return fail(res, 500, 'LINK_FAILED', e.message);
  }
}
