'use strict';

const redis = require('../../_lib/redis');
const { IntelligenceManager } = require('../../_lib/intelligence-manager');
const { GraphEngine } = require('../../_lib/graph-engine');
const { requireAnalyst } = require('../../_lib/analyst-auth');

const manager = new IntelligenceManager(redis);
const graphEngine = new GraphEngine(redis, manager);

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const MAX_QUERY_LENGTH = 200;
const ALLOWED_TYPES = new Set(['all', 'investigations', 'intelligence', 'entities', 'evidence']);

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

function parseLimit(raw) {
  const n = Number.parseInt(raw || String(DEFAULT_LIMIT), 10);
  if (!Number.isFinite(n)) return DEFAULT_LIMIT;
  return Math.min(MAX_LIMIT, Math.max(1, n));
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

  const query = String(req.query.q || '').trim();
  const type = String(req.query.type || 'all').toLowerCase().trim();
  const limit = parseLimit(req.query.limit);

  if (query.length < 2) {
    return fail(res, 400, 'QUERY_TOO_SHORT', 'Query must be at least 2 characters');
  }
  if (query.length > MAX_QUERY_LENGTH) {
    return fail(res, 400, 'QUERY_TOO_LONG', `Query must not exceed ${MAX_QUERY_LENGTH} characters`);
  }
  if (!ALLOWED_TYPES.has(type)) {
    return fail(res, 400, 'INVALID_TYPE', `type must be one of: ${[...ALLOWED_TYPES].join(', ')}`);
  }

  try {
    const results = await performSearch(query, type, limit);
    return ok(res, {
      query,
      type,
      limit,
      results,
      resultCount: results.length,
    });
  } catch (e) {
    console.error('[WORKBENCH SEARCH] failed:', e && e.message ? e.message : 'unknown');
    return fail(res, 500, 'SEARCH_FAILED', 'Workbench search is temporarily unavailable.');
  }
};

async function performSearch(query, type, limit) {
  const results = [];
  const searchTerm = query.toLowerCase();

  if (type === 'all' || type === 'investigations') {
    const investigations = await searchInvestigations(searchTerm, limit);
    results.push(...investigations);
  }

  if (type === 'all' || type === 'intelligence') {
    const intelligence = await searchIntelligence(searchTerm, limit);
    results.push(...intelligence);
  }

  if (type === 'all' || type === 'entities') {
    const entities = await searchGraphEntities(searchTerm, limit);
    results.push(...entities);
  }

  if (type === 'all' || type === 'evidence') {
    const evidence = await searchEvidence(searchTerm, limit);
    results.push(...evidence);
  }

  return results.slice(0, limit);
}

async function searchInvestigations(query, limit) {
  const investigations = await redis.zrevrange('investigations:all', 0, Math.min(MAX_LIMIT, limit * 2));
  const results = [];

  for (const investId of investigations.slice(0, limit)) {
    const investKey = `investigation:${investId}`;
    const data = await redis.hgetall(investKey);

    if (!data || data.length === 0) continue;

    const invest = {};
    for (let i = 0; i < data.length; i += 2) {
      invest[data[i]] = data[i + 1];
    }

    if (
      (invest.title && invest.title.toLowerCase().includes(query)) ||
      (invest.description && invest.description.toLowerCase().includes(query))
    ) {
      results.push({
        type: 'investigation',
        id: investId,
        title: invest.title,
        description: invest.description,
        status: invest.status,
        createdAt: invest.createdAt,
      });
    }
  }

  return results;
}

async function searchIntelligence(query, limit) {
  const allIntelligence = await redis.smembers('graph:entities:all');
  const results = [];

  for (const intelId of allIntelligence.slice(0, Math.min(MAX_LIMIT * 2, limit * 2))) {
    try {
      const intel = await manager.getIntelligence(intelId);
      if (!intel) continue;

      if (
        (intel.title && intel.title.toLowerCase().includes(query)) ||
        (intel.description && intel.description.toLowerCase().includes(query))
      ) {
        results.push({
          type: 'intelligence',
          id: intelId,
          intelType: intel.type,
          title: intel.title,
          description: intel.description,
          status: intel.status,
          createdAt: intel.createdAt,
        });
        if (results.length >= limit) break;
      }
    } catch (_) {
      // Missing/stale internal record: skip without exposing storage errors.
    }
  }

  return results.slice(0, limit);
}

async function searchGraphEntities(query, limit) {
  const allEntities = await redis.smembers('graph:entities:all');
  const results = [];

  for (const entityId of allEntities.slice(0, Math.min(MAX_LIMIT * 2, limit * 2))) {
    try {
      const entity = await graphEngine.getEntity(entityId);
      if (!entity) continue;

      if (entity.name && entity.name.toLowerCase().includes(query)) {
        results.push({
          type: 'graph_entity',
          id: entityId,
          entityType: entity.type,
          name: entity.name,
          confidence: entity.confidence,
          createdAt: entity.createdAt,
        });
        if (results.length >= limit) break;
      }
    } catch (_) {
      // Missing/stale internal record: skip without exposing storage errors.
    }
  }

  return results.slice(0, limit);
}

async function searchEvidence(query, limit) {
  const allEvidence = await redis.zrevrange('evidence:all', 0, Math.min(MAX_LIMIT * 2, limit * 2));
  const results = [];

  for (const evidId of allEvidence) {
    try {
      const evidKey = `evidence:${evidId}`;
      const data = await redis.hgetall(evidKey);
      if (!data || data.length === 0) continue;

      const evid = {};
      for (let i = 0; i < data.length; i += 2) {
        evid[data[i]] = data[i + 1];
      }

      if (
        (evid.title && evid.title.toLowerCase().includes(query)) ||
        (evid.content && evid.content.toLowerCase().includes(query))
      ) {
        results.push({
          type: 'evidence',
          id: evidId,
          investigationId: evid.investigationId,
          evidenceType: evid.type,
          title: evid.title,
          createdAt: evid.createdAt,
        });
        if (results.length >= limit) break;
      }
    } catch (_) {
      // Missing/stale internal record: skip without exposing storage errors.
    }
  }

  return results.slice(0, limit);
}

module.exports._test = { parseLimit, performSearch, ALLOWED_TYPES, MAX_LIMIT, MAX_QUERY_LENGTH };
