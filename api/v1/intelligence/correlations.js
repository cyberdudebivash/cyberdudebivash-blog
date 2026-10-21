'use strict';

const redis = require('../../_lib/redis');
const { IntelligenceManager } = require('../../_lib/intelligence-manager');
const { GraphEngine } = require('../../_lib/graph-engine');
const { GraphTraversal } = require('../../_lib/graph-traversal');
const { CorrelationEngine } = require('../../_lib/correlation-engine');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const { resolvePathParts } = require('../../_lib/request-path');

const MOUNT_PATH = '/api/v1/intelligence/correlations';

const manager = new IntelligenceManager(redis);
const graphEngine = new GraphEngine(redis, manager);
const traversal = new GraphTraversal(graphEngine);
const correlationEngine = new CorrelationEngine(graphEngine, traversal);

const CORS_HEADERS = {
  // Internal analyst APIs are same-origin only: deliberately do not emit Access-Control-Allow-Origin.
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

// CorrelationEngine (_lib/correlation-engine.js) implements a correlation API
// shaped around a whole pre-loaded investigation object (correlateThreatActors,
// correlateCampaigns, correlateMalware, correlateInfrastructure, correlateIOCs
// -- all `(investigation) => ...`), used by the report-generation pipeline.
// It has no constructor and does not store the graphEngine/traversal passed
// above, and it defines no entity-ID/graph-traversal-based correlation
// methods at all. The five handlers below were written against a different,
// never-implemented API (correlateThreatsActors, detectCampaigns,
// clusterMalwareVariants, clusterInfrastructure -- none of which exist on the
// class -- and a correlateIOCs(id) call that resolves to the real method but
// with the wrong argument shape, so it silently returns an empty array for
// any string id instead of throwing).
//
// Rather than let the now-reachable routes crash with an unhandled-looking
// TypeError, or silently return a fabricated-looking empty result that could
// be mistaken by a SOC analyst for "no correlations exist," every handler
// below returns an explicit, honest 501 until the real graph-based
// correlation capability is built on top of GraphTraversal. See the
// production certification doc for this round for the tracked follow-up.
function notImplemented(res, code) {
  return fail(res, 501, code, 'This correlation capability is not yet implemented. ' +
    'The underlying CorrelationEngine does not provide an entity-based graph ' +
    'correlation API. Tracked as a follow-up; not fabricated or estimated.');
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

  if (req.method === 'GET' && action === 'actors' && id) {
    return handleCorrelateActors(req, res, id);
  }

  if (req.method === 'GET' && action === 'campaigns' && id) {
    return handleDetectCampaigns(req, res, id);
  }

  if (req.method === 'GET' && action === 'malware-variants' && id) {
    return handleClusterMalware(req, res, id);
  }

  if (req.method === 'GET' && action === 'infrastructure' && id) {
    return handleClusterInfra(req, res, id);
  }

  if (req.method === 'GET' && action === 'iocs' && id) {
    return handleCorrelateIOCs(req, res, id);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCorrelateActors(req, res, id) {
  return notImplemented(res, 'CORRELATION_NOT_IMPLEMENTED');
}

async function handleDetectCampaigns(req, res, id) {
  return notImplemented(res, 'CAMPAIGN_DETECTION_NOT_IMPLEMENTED');
}

async function handleClusterMalware(req, res, id) {
  return notImplemented(res, 'MALWARE_CLUSTERING_NOT_IMPLEMENTED');
}

async function handleClusterInfra(req, res, id) {
  return notImplemented(res, 'INFRA_CLUSTERING_NOT_IMPLEMENTED');
}

async function handleCorrelateIOCs(req, res, id) {
  return notImplemented(res, 'IOC_CORRELATION_NOT_IMPLEMENTED');
}
