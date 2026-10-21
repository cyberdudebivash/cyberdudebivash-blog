/**
 * SENTINEL APEX — Intelligence Publishing Pipeline API
 * Manages intelligence workflow from draft to publication.
 *
 * POST   /api/v1/intelligence/publish/submit — submit for review
 * POST   /api/v1/intelligence/publish/approve — approve for publication
 * POST   /api/v1/intelligence/publish/publish — publish to production
 * POST   /api/v1/intelligence/publish/retract — retract from production
 * GET    /api/v1/intelligence/publish/status/{id} — pipeline status
 * GET    /api/v1/intelligence/publish/pending — list items awaiting review
 * GET    /api/v1/intelligence/publish/published — list published intelligence
 */
'use strict';

const redis = require('../../_lib/redis');
const { PublishingPipeline } = require('../../_lib/publishing-pipeline');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const { resolvePathParts } = require('../../_lib/request-path');

const MOUNT_PATH = '/api/v1/intelligence/publish';

const pipeline = new PublishingPipeline(redis);

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

  // POST /api/v1/intelligence/publish/submit
  if (req.method === 'POST' && action === 'submit') {
    return handleSubmitReview(req, res, caller);
  }

  // POST /api/v1/intelligence/publish/approve
  if (req.method === 'POST' && action === 'approve') {
    return handleApprove(req, res, caller);
  }

  // POST /api/v1/intelligence/publish/publish
  if (req.method === 'POST' && action === 'publish') {
    return handlePublish(req, res, caller);
  }

  // POST /api/v1/intelligence/publish/retract
  if (req.method === 'POST' && action === 'retract') {
    return handleRetract(req, res, caller);
  }

  // GET /api/v1/intelligence/publish/status/{id} -- the literal 'status'
  // comes BEFORE the real ID in this URL, the reverse of every other named
  // route in this file, so `id` (pathParts[length-2]) holds the literal
  // 'status' and `action` (pathParts[length-1]) holds the real intelligence
  // ID -- not the other way around. Checking `action === 'status'` (as
  // every other route here correctly does for its own, differently-shaped
  // URL) could never match this shape, so this endpoint was unreachable
  // even after the routing-gap fix; fixed to check `id === 'status'` and
  // pass `action` (the real ID) through.
  if (req.method === 'GET' && id === 'status' && action) {
    return handleGetStatus(req, res, action);
  }

  // GET /api/v1/intelligence/publish/pending
  if (req.method === 'GET' && action === 'pending') {
    return handleGetPending(req, res);
  }

  // GET /api/v1/intelligence/publish/published
  if (req.method === 'GET' && action === 'published') {
    return handleGetPublished(req, res);
  }

  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleSubmitReview(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { intelligence_id, reason } = body;
    if (!intelligence_id) {
      return fail(res, 400, 'MISSING_ID', 'intelligence_id is required');
    }

    const result = await pipeline.submitForReview(
      intelligence_id,
      caller.id,
      reason || ''
    );

    return ok(res, {
      message: 'Intelligence submitted for review.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'SUBMISSION_FAILED', e.message);
  }
}

async function handleApprove(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { intelligence_id, reason, feedback } = body;
    if (!intelligence_id) {
      return fail(res, 400, 'MISSING_ID', 'intelligence_id is required');
    }

    const result = await pipeline.approveForPublication(
      intelligence_id,
      caller.id,
      reason || '',
      feedback || ''
    );

    return ok(res, {
      message: 'Intelligence approved for publication.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'APPROVAL_FAILED', e.message);
  }
}

async function handlePublish(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { intelligence_id, reason } = body;
    if (!intelligence_id) {
      return fail(res, 400, 'MISSING_ID', 'intelligence_id is required');
    }

    const result = await pipeline.publishToProduction(
      intelligence_id,
      caller.id,
      reason || ''
    );

    return ok(res, {
      message: 'Intelligence published to production.',
      intelligence: result,
    }, 201);

  } catch (e) {
    return fail(res, 500, 'PUBLICATION_FAILED', e.message);
  }
}

async function handleRetract(req, res, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { intelligence_id, reason } = body;
    if (!intelligence_id) {
      return fail(res, 400, 'MISSING_ID', 'intelligence_id is required');
    }

    const result = await pipeline.retractFromProduction(
      intelligence_id,
      caller.id,
      reason || ''
    );

    return ok(res, {
      message: 'Intelligence retracted from production.',
      intelligence: result,
    });

  } catch (e) {
    return fail(res, 500, 'RETRACTION_FAILED', e.message);
  }
}

async function handleGetStatus(req, res, id) {
  try {
    const status = await pipeline.getPipelineStatus(id);
    if (!status) {
      return fail(res, 404, 'NOT_FOUND', `Intelligence not found: ${id}`);
    }

    return ok(res, { status });

  } catch (e) {
    return fail(res, 500, 'STATUS_FAILED', e.message);
  }
}

async function handleGetPending(req, res) {
  try {
    // Get all intelligence in REVIEW status
    const pendingIds = await redis.zrange('intelligence:by:status:review', 0, -1);
    const pending = [];

    for (const id of pendingIds) {
      const status = await pipeline.getPipelineStatus(id);
      if (status) pending.push(status);
    }

    return ok(res, {
      pending,
      count: pending.length,
    });

  } catch (e) {
    return fail(res, 500, 'PENDING_FAILED', e.message);
  }
}

async function handleGetPublished(req, res) {
  try {
    // Get most recent published intelligence
    const limit = parseInt(req.query.limit || '50', 10);
    const publishedIds = await redis.zrevrange('intelligence:published:feed', 0, limit - 1);
    const published = [];

    for (const id of publishedIds) {
      const status = await pipeline.getPipelineStatus(id);
      if (status) published.push(status);
    }

    return ok(res, {
      published,
      count: published.length,
      limit,
    });

  } catch (e) {
    return fail(res, 500, 'PUBLISHED_FAILED', e.message);
  }
}
