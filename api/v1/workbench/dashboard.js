'use strict';

const redis = require('../../_lib/redis');
const { InvestigationManager } = require('../../_lib/investigation-manager');
const { requireAnalyst } = require('../../_lib/analyst-auth');

const investigationMgr = new InvestigationManager(redis);

const CORS_HEADERS = {
  // Internal analyst APIs are same-origin only: deliberately do not emit Access-Control-Allow-Origin.
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
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

  if (req.method !== 'GET') {
    return fail(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  }

  const caller = await requireAnalyst(req, res, fail);
  if (!caller) return;

  // Authentication does not authorize impersonating another analyst via
  // ?analyst=. Team-wide visibility requires an explicitly configured lead
  // role; customer/tenant authorizations are NOT inferred from this role.
  const analyst = caller.id;
  if (req.query?.analyst !== undefined && req.query.analyst !== analyst) {
    return fail(res, 403, 'ANALYST_SCOPE_FORBIDDEN', 'Dashboard is restricted to the authenticated analyst.');
  }
  const sharedQueues = caller.role === 'lead_analyst' || caller.role === 'soc_admin';
  try {
    const dashboard = await buildAnalystDashboard(analyst, { sharedQueues });
    return ok(res, { analyst, dashboard });
  } catch (_) {
    // Database internals, Redis errors and index names are never client data.
    return fail(res, 503, 'DASHBOARD_UNAVAILABLE', 'Dashboard temporarily unavailable.');
  }
};

async function buildAnalystDashboard(analyst, { sharedQueues = false } = {}) {
  const [assigned, open, inProgress, pending, recent, stats] = await Promise.all([
    getAssignedInvestigations(analyst),
    sharedQueues ? getOpenInvestigations() : Promise.resolve([]),
    getInProgressInvestigations(analyst),
    sharedQueues ? getPendingReview() : Promise.resolve([]),
    sharedQueues ? getRecentlyUpdated() : Promise.resolve([]),
    sharedQueues ? getWorkbenchStats() : Promise.resolve(null),
  ]);

  return {
    analyst,
    scope: sharedQueues ? 'internal_lead' : 'self',
    // Null is intentionally UNKNOWN/NOT_AUTHORIZED, not an invented zero.
    // The frontend must not present team totals as analyst-owned metrics.
    summary: {
      assignedCount: assigned.length,
      openCount: open.length,
      inProgressCount: inProgress.length,
      pendingReviewCount: pending.length,
    },
    myInvestigations: assigned,
    open,
    inProgress,
    pendingReview: pending,
    recentlyUpdated: recent,
    workbenchStats: stats,
    suggestedActions: generateSuggestedActions(assigned, open, pending),
    quickLinks: [
      { label: 'Create Investigation', url: '/api/v1/workbench/investigations' },
      { label: 'Search Intelligence', url: '/api/v1/workbench/search' },
      { label: 'View Graph', url: '/api/v1/intelligence/graph' },
      { label: 'My Cases', url: '/api/v1/workbench/cases' },
    ],
  };
}

async function getAssignedInvestigations(analyst) {
  const investIds = await redis.zrevrange(`investigations:assigned:${analyst}`, 0, 9);
  const investigations = [];

  for (const investId of investIds) {
    const investKey = `investigation:${investId}`;
    const data = await redis.hgetall(investKey);

    if (data && data.length > 0) {
      const invest = {};
      for (let i = 0; i < data.length; i += 2) {
        invest[data[i]] = data[i + 1];
      }
      if (invest.assignee === analyst) investigations.push(invest);
    }
  }

  return investigations;
}

async function getOpenInvestigations() {
  const investIds = await redis.zrevrange('investigations:by:status:open', 0, 4);
  const investigations = [];

  for (const investId of investIds) {
    const investKey = `investigation:${investId}`;
    const data = await redis.hgetall(investKey);

    if (data && data.length > 0) {
      const invest = {};
      for (let i = 0; i < data.length; i += 2) {
        invest[data[i]] = data[i + 1];
      }
      investigations.push(invest);
    }
  }

  return investigations;
}

async function getInProgressInvestigations(analyst) {
  const investIds = await redis.zrevrange('investigations:by:status:in_progress', 0, 9);
  const investigations = [];

  for (const investId of investIds) {
    const investKey = `investigation:${investId}`;
    const data = await redis.hgetall(investKey);

    if (data && data.length > 0) {
      const invest = {};
      for (let i = 0; i < data.length; i += 2) {
        invest[data[i]] = data[i + 1];
      }

      if (invest.assignee === analyst) {
        investigations.push(invest);
      }
    }
  }

  return investigations;
}

async function getPendingReview() {
  const investIds = await redis.zrevrange('investigations:by:status:pending_review', 0, 4);
  const investigations = [];

  for (const investId of investIds) {
    const investKey = `investigation:${investId}`;
    const data = await redis.hgetall(investKey);

    if (data && data.length > 0) {
      const invest = {};
      for (let i = 0; i < data.length; i += 2) {
        invest[data[i]] = data[i + 1];
      }
      investigations.push(invest);
    }
  }

  return investigations;
}

async function getRecentlyUpdated() {
  const investIds = await redis.zrevrange('investigations:all', 0, 9);
  const investigations = [];

  for (const investId of investIds) {
    const investKey = `investigation:${investId}`;
    const data = await redis.hgetall(investKey);

    if (data && data.length > 0) {
      const invest = {};
      for (let i = 0; i < data.length; i += 2) {
        invest[data[i]] = data[i + 1];
      }
      investigations.push(invest);
    }
  }

  return investigations;
}

async function getWorkbenchStats() {
  const [totalInvest, totalCases, totalEvidence, totalIntel] = await Promise.all([
    redis.zcard('investigations:all'),
    redis.zcard('cases:all'),
    redis.zcard('evidence:all'),
    redis.scard('graph:entities:all'),
  ]);

  return {
    totalInvestigations: totalInvest || 0,
    totalCases: totalCases || 0,
    totalEvidence: totalEvidence || 0,
    totalGraphEntities: totalIntel || 0,
  };
}

function generateSuggestedActions(assigned, open, pending) {
  const actions = [];

  if (open.length > 0) {
    actions.push({
      priority: 'high',
      action: `Claim ${open[0].title}`,
      type: 'claim',
      investigationId: open[0].id,
    });
  }

  if (pending.length > 0) {
    actions.push({
      priority: 'high',
      action: `Review ${pending[0].title}`,
      type: 'review',
      investigationId: pending[0].id,
    });
  }

  if (assigned.length > 0 && assigned.some(i => i.status === 'open')) {
    actions.push({
      priority: 'medium',
      action: 'Continue active investigation',
      type: 'continue',
      investigationId: assigned.find(i => i.status === 'open').id,
    });
  }

  return actions;
}
