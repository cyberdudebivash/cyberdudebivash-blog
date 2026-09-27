'use strict';

/**
 * All Worker routing/dispatch logic, kept in plain CommonJS specifically
 * so it's requireable and unit-testable under plain Node (node:test)
 * without going through Wrangler/esbuild. workers/entry.js is a thin ESM
 * wrapper around handleFetch() below — Wrangler needs an ES module entry
 * (export default { fetch }) to recognize a Module Worker, but that
 * syntax can't be require()'d by Node directly, so the real logic lives
 * here instead of in the file Wrangler points main at.
 */

const { toNodeRequest, createNodeResponse } = require('./node-compat');
const { resolveRoute } = require('./route-table');
const { applyBaselineHeaders } = require('./security-headers');
const { setD1Binding: setHttpD1Binding } = require('../../api/_lib/d1');
const { setR2Binding } = require('../../api/_lib/premium-report-storage');

// Static require() map, not a dynamic require(computedPath) — esbuild
// must see each module reference at build time to bundle it; a
// runtime-computed string would silently fail to bundle. Keys must be
// exactly route-table.js's DIRECT_API_HANDLERS ∪ DYNAMIC_API_HANDLERS
// handler paths — enforced by router.test.js's parity check against
// route-table.js, not just by hand-matching here.
const HANDLER_MODULES = {
  'api/og': () => require('../../api/og'),
  'api/cron/dispatch-intel': () => require('../../api/cron/dispatch-intel'),
  'api/v1/admin': () => require('../../api/v1/admin'),
  'api/v1/analysis/assessments': () => require('../../api/v1/analysis/assessments'),
  'api/v1/analysis/findings': () => require('../../api/v1/analysis/findings'),
  'api/v1/auth': () => require('../../api/v1/auth'),
  'api/v1/billing': () => require('../../api/v1/billing'),
  'api/v1/billing/gumroad-webhook': () => require('../../api/v1/billing/gumroad-webhook'),
  'api/v1/billing/razorpay-webhook': () => require('../../api/v1/billing/razorpay-webhook'),
  'api/v1/connectors': () => require('../../api/v1/connectors'),
  'api/v1/customer/dashboard': () => require('../../api/v1/customer/dashboard'),
  'api/v1/customer/download': () => require('../../api/v1/customer/download'),
  'api/v1/defense-profile': () => require('../../api/v1/defense-profile'),
  'api/v1/deployments': () => require('../../api/v1/deployments'),
  'api/v1/detections/performance': () => require('../../api/v1/detections/performance'),
  'api/v1/detections/rules': () => require('../../api/v1/detections/rules'),
  'api/v1/detections/rules/[id]': () => require('../../api/v1/detections/rules/[id]'),
  'api/v1/hunts': () => require('../../api/v1/hunts'),
  'api/v1/intel': () => require('../../api/v1/intel'),
  'api/v1/intel/evidence/[id]': () => require('../../api/v1/intel/evidence/[id]'),
  'api/v1/premium-intelligence': () => require('../../api/v1/premium-intelligence'),
  'api/v1/watchlists': () => require('../../api/v1/watchlists'),
  'api/v1/notifications': () => require('../../api/v1/notifications'),
  'api/v1/intelligence/confidence': () => require('../../api/v1/intelligence/confidence'),
  'api/v1/intelligence/correlations': () => require('../../api/v1/intelligence/correlations'),
  'api/v1/intelligence/graph': () => require('../../api/v1/intelligence/graph'),
  'api/v1/intelligence/objects': () => require('../../api/v1/intelligence/objects'),
  'api/v1/intelligence/publish': () => require('../../api/v1/intelligence/publish'),
  'api/v1/intelligence/similarity': () => require('../../api/v1/intelligence/similarity'),
  'api/v1/ioc/[id]': () => require('../../api/v1/ioc/[id]'),
  'api/v1/ioc/search': () => require('../../api/v1/ioc/search'),
  'api/v1/newsletter': () => require('../../api/v1/newsletter'),
  'api/v1/products/approvals': () => require('../../api/v1/products/approvals'),
  'api/v1/products/export': () => require('../../api/v1/products/export'),
  'api/v1/products/index': () => require('../../api/v1/products/index'),
  'api/v1/quality/index': () => require('../../api/v1/quality/index'),
  'api/v1/reports/index': () => require('../../api/v1/reports/index'),
  'api/v1/workbench/cases': () => require('../../api/v1/workbench/cases'),
  'api/v1/workbench/dashboard': () => require('../../api/v1/workbench/dashboard'),
  'api/v1/workbench/investigations': () => require('../../api/v1/workbench/investigations'),
  'api/v1/workbench/search': () => require('../../api/v1/workbench/search'),
};

async function dispatch(handlerPath, request, routeQuery) {
  const load = HANDLER_MODULES[handlerPath];
  if (!load) {
    return new Response('Not Found', { status: 404 });
  }

  const handlerModule = load();
  const handler = typeof handlerModule === 'function' ? handlerModule : handlerModule.default;
  const handlerConfig = handlerModule.config;

  let req;
  try {
    req = await toNodeRequest(request, handlerConfig);
  } catch (err) {
    if (err && err.isBodyParseError) {
      return applyBaselineHeaders(new Response(JSON.stringify({
        error: { code: 'INVALID_JSON', message: 'Request body is not valid JSON.' },
        meta:  { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      }), { status: 400, headers: { 'content-type': 'application/json' } }));
    }
    if (err && err.isBodyTooLargeError) {
      return applyBaselineHeaders(new Response(JSON.stringify({
        error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds the maximum allowed size.' },
        meta:  { platform: 'CYBERDUDEBIVASH SENTINEL APEX v4.0', timestamp: new Date().toISOString() },
      }), { status: 413, headers: { 'content-type': 'application/json' } }));
    }
    throw err;
  }
  req.query = { ...req.query, ...routeQuery };

  const { res, response } = createNodeResponse();
  await handler(req, res);
  return applyBaselineHeaders(await response);
}

/**
 * @param {Request} request
 * @param {{ ASSETS: { fetch(req: Request): Promise<Response> }, DB?: object, PREMIUM_REPORTS?: object }} env
 */
async function handleFetch(request, env) {
  // Register Cloudflare-native state/storage bindings for HTTP handlers before
  // any route module runs. Existing D1-backed HTTP APIs previously fell back to
  // the REST transport because env was not threaded through dispatch(); this
  // setter pattern preserves every existing (req,res) handler signature while
  // giving premium commerce and the rest of the D1-backed HTTP surface the
  // zero-extra-hop native binding in Workers. R2 has no credential fallback by
  // design: premium downloads fail closed unless the binding is present.
  if (env && env.DB) setHttpD1Binding(env.DB);
  if (env && env.PREMIUM_REPORTS) setR2Binding(env.PREMIUM_REPORTS);

  const url = new URL(request.url);
  const route = resolveRoute(url.pathname);

  if (!route) {
    return env.ASSETS.fetch(request);
  }

  switch (route.type) {
    case 'blocked':
      return applyBaselineHeaders(new Response('Not Found', { status: 404 }));

    case 'redirect': {
      const destination = new URL(route.to, url);
      return applyBaselineHeaders(new Response(null, {
        status: route.status,
        headers: { Location: destination.toString() },
      }));
    }

    case 'asset': {
      const assetUrl = new URL(route.path, url);
      return env.ASSETS.fetch(new Request(assetUrl, request));
    }

    case 'handler':
      return dispatch(route.handlerPath, request, route.query);

    default:
      return applyBaselineHeaders(new Response('Not Found', { status: 404 }));
  }
}

/**
 * Cloudflare Cron Trigger entry point (workers/entry.js's `scheduled`
 * export calls this). wrangler.jsonc's triggers.crons entry is code-complete
 * but still requires an authenticated deploy before Cloudflare invokes it.
 */
async function handleScheduled(controller, env, ctx, deps = {}) {
  const { evaluateWatchedEntities } = deps.changeEngine || require('../../api/_lib/change-engine');
  const { processDueDeliveries } = deps.notificationDispatch || require('../../api/_lib/notification-dispatch');
  const { setD1Binding } = deps.d1 || require('../../api/_lib/d1');

  if (env && env.DB) setD1Binding(env.DB);

  const startedAt = Date.now();
  const evaluation = await evaluateWatchedEntities();
  const delivery = await processDueDeliveries();
  const summary = {
    trigger: 'cloudflare_cron', cron: controller && controller.cron,
    elapsed_ms: Date.now() - startedAt, evaluation, delivery,
  };
  console.log('[SCHEDULED]', JSON.stringify(summary));
  return summary;
}

module.exports = { handleFetch, dispatch, handleScheduled, HANDLER_MODULES };
