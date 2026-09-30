/**
 * SENTINEL APEX — Watchlists & Intelligence Monitoring Feed
 * Single serverless function handling all watchlist customer endpoints,
 * matching the established api/v1/*.js router convention exactly
 * (guardRequest -> globalIpRateLimit -> authenticate() per handler ->
 * action= dispatch -> successResponse/apiError).
 *
 * Routing: /api/v1/watchlists?action={action}
 *
 *  action=list           GET   List the caller's watchlists
 *  action=create          POST  Create a watchlist. Body: {name, description?}
 *  action=get             GET   Single watchlist. ?id=
 *  action=update           POST  Update name/description/status. Body: {id, name?, description?, status?}
 *  action=delete            POST  Delete a watchlist. Body: {id}
 *  action=list-entities      GET   Entities tracked by a watchlist. ?id=
 *  action=add-entity          POST  Add a tracked entity. Body: {id, entity_type, entity_id}
 *  action=remove-entity        POST  Remove a tracked entity. Body: {id, entity_type, entity_id}
 *  action=feed               GET   Authenticated monitoring feed. ?limit=&cursor=
 *  action=entitlements         GET   The caller's current watchlist limits
 *
 * Every action requires authenticate() -- there is no unauthenticated
 * read path (unlike the pre-existing, deliberately-not-imitated
 * api/v1/customer/dashboard.js, which trusts a bare ?email= with no
 * credential; see the certification doc's reuse-before-build section).
 * Ownership is always re-derived from the authenticated caller's
 * userId, never from a client-supplied field.
 */
'use strict';

const sec = require('../_lib/security');
const { authenticate, successResponse, apiError } = require('../_lib/middleware');
const { parseBody } = require('../_lib/payment-utils');
const store = require('../_lib/watchlist-store');
const { tierAtLeast } = require('../_lib/tier-entitlements');
const { getEventsByIds } = require('../_lib/change-engine');

const VALID_ACTIONS = 'list, create, get, update, delete, list-entities, add-entity, remove-entity, feed, entitlements';

const FIELDS = {
  create:         ['name', 'description'],
  update:         ['id', 'name', 'description', 'status'],
  delete:         ['id'],
  'add-entity':    ['id', 'entity_type', 'entity_id'],
  'remove-entity': ['id', 'entity_type', 'entity_id'],
};

module.exports = async (req, res) => {
  const ok_guard = await sec.guardRequest(req, res, {
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    maxBodyBytes: 10240,
  });
  if (!ok_guard) return;

  if (!(await sec.globalIpRateLimit(req, res))) return;

  const action = String(req.query.action || '').toLowerCase().trim();
  if (!action) {
    return apiError(res, 400, 'MISSING_ACTION', `action parameter required. Valid: ${VALID_ACTIONS}.`);
  }

  switch (action) {
    case 'list':            return handleList(req, res);
    case 'create':           return handleCreate(req, res);
    case 'get':              return handleGet(req, res);
    case 'update':            return handleUpdate(req, res);
    case 'delete':             return handleDelete(req, res);
    case 'list-entities':       return handleListEntities(req, res);
    case 'add-entity':           return handleAddEntity(req, res);
    case 'remove-entity':         return handleRemoveEntity(req, res);
    case 'feed':                  return handleFeed(req, res);
    case 'entitlements':           return handleEntitlements(req, res);
    default:
      return apiError(res, 400, 'INVALID_ACTION', `Unknown action: "${action}". Valid: ${VALID_ACTIONS}`);
  }
};

/* ─── helpers ─────────────────────────────────────────────────── */

async function readValidatedBody(req, res, action) {
  if (req.method !== 'POST') {
    apiError(res, 405, 'METHOD_NOT_ALLOWED', `POST required for action=${action}`);
    return null;
  }
  let body;
  try {
    body = await parseBody(req);
  } catch (_) {
    apiError(res, 400, 'INVALID_BODY', 'Request body must be valid JSON.');
    return null;
  }
  const whitelistErr = sec.assertFieldWhitelist(body || {}, FIELDS[action] || []);
  if (whitelistErr) {
    apiError(res, 400, 'INVALID_FIELDS', whitelistErr);
    return null;
  }
  return body || {};
}

function mapStoreError(res, result) {
  const code = result.error;
  const status = code === 'NOT_FOUND' ? 404
    : code === 'LIMIT_REACHED' ? 429
    : code === 'UNSUPPORTED_ENTITY_TYPE' ? 400
    : 400;
  const message = result.message || (code === 'NOT_FOUND' ? 'Watchlist not found.' : 'Request could not be completed.');
  return apiError(res, status, code || 'BAD_REQUEST', message);
}

/* ─── GET ?action=list ─────────────────────────────────────────── */
async function handleList(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const watchlists = await store.listWatchlists(user.userId);
  return successResponse(res, { watchlists }, { count: watchlists.length });
}

/* ─── POST ?action=create ─────────────────────────────────────── */
async function handleCreate(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'create');
  if (body === null) return;

  const result = await store.createWatchlist({ ownerId: user.userId, name: body.name, description: body.description });
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { watchlist: result.watchlist });
}

/* ─── GET ?action=get&id= ─────────────────────────────────────── */
async function handleGet(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'id query parameter required.');

  const result = await store.getWatchlist(id, user.userId);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { watchlist: result.watchlist });
}

/* ─── POST ?action=update ─────────────────────────────────────── */
async function handleUpdate(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'update');
  if (body === null) return;
  const id = String(body.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'id required in body.');

  const result = await store.updateWatchlist(id, user.userId, {
    name: body.name, description: body.description, status: body.status,
  });
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { watchlist: result.watchlist });
}

/* ─── POST ?action=delete ─────────────────────────────────────── */
async function handleDelete(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'delete');
  if (body === null) return;
  const id = String(body.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'id required in body.');

  const result = await store.deleteWatchlist(id, user.userId);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { deleted: true, id });
}

/* ─── GET ?action=list-entities&id= ───────────────────────────── */
async function handleListEntities(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const id = String(req.query.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'id query parameter required.');

  const result = await store.listEntities(id, user.userId);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, { entities: result.entities }, { count: result.entities.length });
}

/* ─── POST ?action=add-entity ──────────────────────────────────── */
async function handleAddEntity(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'add-entity');
  if (body === null) return;
  const id = String(body.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'id required in body.');

  const result = await store.addEntity(id, user.userId, body.entity_type, body.entity_id);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, result);
}

/* ─── POST ?action=remove-entity ──────────────────────────────── */
async function handleRemoveEntity(req, res) {
  const user = await authenticate(req, res);
  if (!user) return;
  const body = await readValidatedBody(req, res, 'remove-entity');
  if (body === null) return;
  const id = String(body.id || '').trim();
  if (!id) return apiError(res, 400, 'MISSING_ID', 'id required in body.');

  const result = await store.removeEntity(id, user.userId, body.entity_type, body.entity_id);
  if (result.error) return mapStoreError(res, result);
  return successResponse(res, result);
}

/* ─── GET ?action=feed ─────────────────────────────────────────── */
async function handleFeed(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;

  const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 20, 100));
  const cursor = Math.max(0, parseInt(req.query.cursor, 10) || 0);

  const page = await store.getOwnerFeedPage(user.userId, { limit, cursor });
  const events = await getEventsByIds(page.eventIds);

  // Phase 12/29: relationship-carrying event types are pro/enterprise
  // gated at read time, matching intelligence-dossier.js's own
  // tier_info pattern exactly -- the underlying detection already ran on
  // full canonical state (Phase 68's "one global event" design), so
  // gating happens here, once, at delivery, not by re-running detection
  // per tier.
  const tierAllowsRelationships = tierAtLeast(user.tier, 'pro');
  const RELATIONSHIP_CHANGE_TYPES = new Set([
    'CVE_NEW_CAMPAIGN_ASSOCIATION', 'CVE_NEW_ACTOR_ASSOCIATION',
    'CAMPAIGN_NEW_ACTOR', 'CAMPAIGN_NEW_CVE',
  ]);
  const shaped = events.map(e => {
    if (!tierAllowsRelationships && RELATIONSHIP_CHANGE_TYPES.has(e.change_type)) {
      return { ...e, after: null, related: null, relationships_gated: true };
    }
    return e;
  });

  return successResponse(res, { events: shaped }, {
    total: page.total,
    next_cursor: page.nextCursor,
    limit,
  });
}

/* ─── GET ?action=entitlements ─────────────────────────────────── */
async function handleEntitlements(req, res) {
  if (req.method !== 'GET') return apiError(res, 405, 'METHOD_NOT_ALLOWED', 'GET required');
  const user = await authenticate(req, res);
  if (!user) return;
  const entitlements = store.getWatchlistEntitlements(user.tier);
  const watchlists = await store.listWatchlists(user.userId);
  return successResponse(res, {
    entitlements,
    usage: { watchlists_used: watchlists.length },
  });
}
