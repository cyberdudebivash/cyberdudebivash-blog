'use strict';

const redis = require('../../_lib/redis');
const { IntelligenceManager } = require('../../_lib/intelligence-manager');
const { GraphEngine } = require('../../_lib/graph-engine');
const { SimilarityEngine } = require('../../_lib/similarity-engine');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const { resolvePathParts } = require('../../_lib/request-path');

const MOUNT_PATH = '/api/v1/intelligence/similarity';

const manager = new IntelligenceManager(redis);
const graphEngine = new GraphEngine(redis, manager);
const similarityEngine = new SimilarityEngine(graphEngine);

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

  if (req.method === 'GET' && action === 'find' && id) {
    return handleFindSimilar(req, res, id);
  }

  if (req.method === 'GET' && action === 'ioc-matches' && id) {
    return handleFindIOCMatches(req, res, id);
  }

  if (req.method === 'GET' && action === 'duplicates') {
    return handleDetectDuplicates(req, res);
  }

  if (req.method === 'POST' && action === 'merge') {
    return handleMergeDuplicates(req, res, caller);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleFindSimilar(req, res, id) {
  try {
    const threshold = parseFloat(req.query.threshold || '0.7');
    const limit = parseInt(req.query.limit || '20', 10);

    const similar = await similarityEngine.findSimilarEntities(id, threshold, limit);

    return ok(res, {
      entityId: id,
      similar,
      count: similar.length,
    });
  } catch (e) {
    return fail(res, 500, 'SIMILARITY_FAILED', e.message);
  }
}

async function handleFindIOCMatches(req, res, id) {
  try {
    const matches = await similarityEngine.findIOCMatches(id);

    return ok(res, {
      iocId: id,
      matches,
    });
  } catch (e) {
    return fail(res, 500, 'IOC_MATCH_FAILED', e.message);
  }
}

async function handleDetectDuplicates(req, res) {
  try {
    const minSimilarity = parseFloat(req.query.minSimilarity || '0.9');
    const duplicates = await similarityEngine.detectDuplicates(minSimilarity);

    return ok(res, {
      duplicates,
      count: duplicates.length,
    });
  } catch (e) {
    return fail(res, 500, 'DUPLICATE_DETECTION_FAILED', e.message);
  }
}

async function handleMergeDuplicates(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { keepEntity, mergeEntity, reason } = body;
    if (!keepEntity || !mergeEntity) {
      return fail(res, 400, 'MISSING_FIELD', 'keepEntity and mergeEntity required');
    }

    const result = await similarityEngine.mergeDuplicates(
      keepEntity,
      mergeEntity,
      caller.id,
      reason || ''
    );

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'MERGE_FAILED', e.message);
  }
}
