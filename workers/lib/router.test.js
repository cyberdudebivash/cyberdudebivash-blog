'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { handleFetch, dispatch, handleScheduled, HANDLER_MODULES } = require('./router');
const { DIRECT_API_HANDLERS, DYNAMIC_API_HANDLERS } = require('./route-table');
const d1 = require('../../api/_lib/d1');
const r2 = require('../../api/_lib/premium-report-storage');
const gateway = require('../../api/_lib/sentinel-gateway-binding');

function fakeEnv(assetsFetchImpl) {
  const calls = [];
  return {
    calls,
    env: {
      ASSETS: {
        async fetch(req) {
          calls.push(req);
          return assetsFetchImpl ? assetsFetchImpl(req) : new Response('asset-body', { status: 200 });
        },
      },
    },
  };
}

describe('router — HANDLER_MODULES parity with route-table.js', () => {
  test('every DIRECT_API_HANDLERS entry has a static require() in HANDLER_MODULES', () => {
    for (const p of DIRECT_API_HANDLERS) {
      assert.ok(p in HANDLER_MODULES, `${p} is in route-table.js's DIRECT_API_HANDLERS but missing from router.js's HANDLER_MODULES`);
    }
  });

  test('every DYNAMIC_API_HANDLERS entry has a static require() in HANDLER_MODULES', () => {
    for (const [, handlerPath] of DYNAMIC_API_HANDLERS) {
      assert.ok(handlerPath in HANDLER_MODULES, `${handlerPath} is in route-table.js's DYNAMIC_API_HANDLERS but missing from router.js's HANDLER_MODULES`);
    }
  });

  test('HANDLER_MODULES has no keys route-table.js does not know about', () => {
    const known = new Set([...DIRECT_API_HANDLERS, ...DYNAMIC_API_HANDLERS.map(([, p]) => p)]);
    for (const key of Object.keys(HANDLER_MODULES)) {
      assert.ok(known.has(key), `HANDLER_MODULES has ${key}, which route-table.js does not resolve to any route`);
    }
  });
});

describe('P0 Worker D1/R2/gateway binding lifecycle (missing-bindings fail closed)', () => {
  test('clears bindings on a subsequent request that omits privileged resources', async () => {
    const request = new Request('https://soc.cyberdudebivash.in/CLAUDE.md');
    const { env } = fakeEnv();
    const db = { prepare() { throw Error('no D1 writes allowed in routing test'); } };
    const bucket = { put() {}, get() {} };
    const service = { fetch() { throw Error('no outbound entitlement call'); } };
    try {
      await handleFetch(request, { ...env, DB: db, PREMIUM_REPORTS: bucket, SENTINEL_GATEWAY: service });
      assert.equal(d1.hasNativeBinding(), true);
      assert.equal(r2.isConfigured(), true);
      assert.equal(gateway.getSentinelGatewayBinding(), service);

      const response = await handleFetch(request, env);
      assert.equal(response.status, 404);
      assert.equal(d1.hasNativeBinding(), false, 'must not inherit prior D1');
      assert.equal(r2.isConfigured(), false, 'must not inherit prior private R2 bucket');
      assert.equal(gateway.getSentinelGatewayBinding(), null, 'must not inherit prior entitlement gateway');
    } finally {
      d1.setD1Binding(null);
      r2.setR2Binding(null);
      gateway.setSentinelGatewayBinding(null);
    }
  });

  test('partial bindings clear missing resources while keeping only current request D1', async () => {
    const request = new Request('https://soc.cyberdudebivash.in/CLAUDE.md');
    const { env } = fakeEnv();
    try {
      await handleFetch(request, { ...env, PREMIUM_REPORTS: { put() {}, get() {} },
        SENTINEL_GATEWAY: { fetch() {} }, DB: { prepare() {} } });
      await handleFetch(request, { ...env, DB: { prepare() {} } });
      assert.equal(d1.hasNativeBinding(), true);
      assert.equal(r2.isConfigured(), false);
      assert.equal(gateway.getSentinelGatewayBinding(), null);
    } finally {
      d1.setD1Binding(null);
      r2.setR2Binding(null);
      gateway.setSentinelGatewayBinding(null);
    }
  });
});

describe('handleFetch — routing by type', () => {
  test('unmatched path defers to env.ASSETS.fetch with the original request', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/posts/some-article.html');
    const response = await handleFetch(request, env);
    assert.equal(calls.length, 1);
    assert.equal(calls[0], request);
    assert.equal(response.status, 200);
  });

  test('blocked path returns 404 without ever calling env.ASSETS', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/CLAUDE.md');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 404);
    assert.equal(calls.length, 0);
  });

  test('/rss redirects to /rss.xml with a 308, without calling env.ASSETS', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/rss');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 308);
    assert.equal(new URL(response.headers.get('location')).pathname, '/rss.xml');
    assert.equal(calls.length, 0);
  });

  test('/feed.xml resolves as an asset rewrite to /rss.xml, fetched via env.ASSETS', async () => {
    const { env, calls } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/feed.xml');
    await handleFetch(request, env);
    assert.equal(calls.length, 1);
    assert.equal(new URL(calls[0].url).pathname, '/rss.xml');
  });
});

describe('handleFetch — real end-to-end handler dispatch', () => {
  test('GET /api/v1/intel?action=stats runs the real handler through the compat shim', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel?action=stats');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.success, true);
    assert.ok(body.stats);
  });

  test('GET /api/v1/intel/live is rewritten to action=live and reaches the same real handler', async () => {
    const { env } = fakeEnv();
    // No API key configured in this environment -- expect the handler's
    // own real 401, not a routing failure. Proves the rewrite→dispatch
    // path reaches actual application logic, not just a 200/404 shortcut.
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intel/live');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 401);
    const body = await response.json();
    assert.equal(body.error.code, 'UNAUTHORIZED');
  });

  test('dispatch() to an unknown handlerPath fails closed with 404', async () => {
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/does-not-exist');
    const response = await dispatch('api/v1/does-not-exist', request, {});
    assert.equal(response.status, 404);
  });

  test('GET /api/v1/intelligence/objects/{id} (apexSubpath route) reaches the real handler, not a 404', async () => {
    // Proves the full chain end-to-end: route-table.js's APEX_SUBPATH_HANDLERS
    // prefix match -> dispatch()'s req.query merge -> the real objects.js
    // handler's resolvePathParts()/requireAnalyst. No ANALYST_KEYS configured
    // in this environment, so the real handler's own 401 (not a routing 404)
    // proves the sub-path actually reached application logic.
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/intelligence/objects/intel-123');
    const response = await handleFetch(request, env);
    assert.equal(response.status, 401);
    const body = await response.json();
    assert.equal(body.error.code, 'UNAUTHORIZED');
  });

  test('POST /api/v1/workbench/cases/{id}/notes (apexSubpath route, multi-segment) reaches the real handler', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/workbench/cases/case-1/notes', { method: 'POST' });
    const response = await handleFetch(request, env);
    assert.equal(response.status, 401);
    const body = await response.json();
    assert.equal(body.error.code, 'UNAUTHORIZED');
  });
});

describe('handleFetch — malformed/oversized body handling (real handler dispatch)', () => {
  test('malformed JSON to a real handler returns a clean 400, not an uncaught exception', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/newsletter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"email": "a@b.com", not valid json',
    });
    const response = await handleFetch(request, env);
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.error.code, 'INVALID_JSON');
    // Confirms this went through applyBaselineHeaders(), not a bare Response
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  });

  test('an oversized body to a real handler returns a clean 413, not an uncaught exception', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/newsletter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: 'a'.repeat(5 * 1024 * 1024) }),
    });
    const response = await handleFetch(request, env);
    assert.equal(response.status, 413);
    const body = await response.json();
    assert.equal(body.error.code, 'PAYLOAD_TOO_LARGE');
  });

  test('a bodyParser:false route (webhook) is unaffected by the generic body-parse error path', async () => {
    const { env } = fakeEnv();
    const request = new Request('https://blog.cyberdudebivash.in/api/v1/billing/razorpay-webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-razorpay-signature': 'deadbeef' },
      body: '{"not":"valid json at all',
    });
    const response = await handleFetch(request, env);
    // Reaches the handler's own signature check first (readRawBody never
    // parses JSON) rather than tripping the generic INVALID_JSON path.
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.error, 'Invalid signature');
  });
});

// Dormant Cloudflare Cron Trigger entry point (Alert Orchestration v1) --
// see handleScheduled's own doc in router.js for why it is never live
// today. Tested via the `deps` injection seam so this stays plain
// node:test-runnable without a real Redis-backed change-engine.js/
// notification-dispatch.js in the loop -- those two functions already
// have full Jest coverage (fake-redis-backed) under api/_lib/__tests__/.
describe('handleScheduled — default-deny shared-account cron budget boundary', () => {
  test('default configuration does not load or execute any billed operation', async () => {
    const calls=[];
    const deps={
      changeEngine:{evaluateWatchedEntities:async()=>{calls.push('evaluate');}},
      notificationDispatch:{processDueDeliveries:async()=>{calls.push('deliver');}},
      d1:{setD1Binding:()=>{calls.push('bind');}},
    };
    const result=await handleScheduled({cron:'*/30 * * * *'},{DB:{marker:'test'}},{},deps);
    assert.equal(result.status,'disabled_cost_guard');
    assert.deepEqual(calls,[]);
  });
  test('only literal string true enables costed work and imposes fixed small batches',async()=>{
    const calls=[];const db={id:'private-d1'};
    const deps={
      changeEngine:{evaluateWatchedEntities:async args=>{calls.push(['evaluate',args]);return {evaluated:3};}},
      notificationDispatch:{processDueDeliveries:async args=>{calls.push(['deliver',args]);return {delivered:2};}},
      d1:{setD1Binding:value=>calls.push(['bind',value])},
    };
    const result=await handleScheduled({cron:'*/30 * * * *'},
      {DB:db,CDB_SOC_CRON_ENABLED:'true'},{},deps);
    assert.equal(result.status,'bounded_execution');
    assert.deepEqual(calls,[['bind',db],['evaluate',{batchLimit:10,boundedScan:true}],['deliver',{limit:10}]]);
    assert.deepEqual(result.evaluation,{evaluated:3});
    assert.deepEqual(result.delivery,{delivered:2});
  });
  test('cost guard rejection is visible in the aggregate scheduled status', async () => {
    const deps={
      changeEngine:{evaluateWatchedEntities:async()=>({fanout_blocked:1,event_budget_blocked:0})},
      notificationDispatch:{processDueDeliveries:async()=>({delivered:0})},
      d1:{setD1Binding:()=>{}},
    };
    const out=await handleScheduled({}, {DB:{},CDB_SOC_CRON_ENABLED:'true'}, {}, deps);
    assert.equal(out.status,'partial_cost_guard');
    assert.equal(out.evaluation.fanout_blocked,1);
  });
  test('boolean, uppercase, and other values fail closed',async()=>{
    for(const value of [true,'TRUE','1',false,'false',null,undefined]){
      const deps={changeEngine:{evaluateWatchedEntities:async()=>{throw Error('called unexpectedly')}}};
      const result=await handleScheduled({}, {DB:{},CDB_SOC_CRON_ENABLED:value},{},deps);
      assert.equal(result.status,'disabled_cost_guard');
    }
  });
  test('enabled without native D1 does not perform remote fallback',async()=>{
    let called=false;
    const deps={
      changeEngine:{evaluateWatchedEntities:async()=>{called=true;}},
      notificationDispatch:{processDueDeliveries:async()=>{called=true;}},
      d1:{setD1Binding:()=>{called=true;}},
    };
    const result=await handleScheduled({}, {CDB_SOC_CRON_ENABLED:'true'},{},deps);
    assert.equal(result.status,'blocked_missing_d1');
    assert.equal(called,false);
  });
  test('enabled execution preserves fail-closed error propagation',async()=>{
    const deps={
      changeEngine:{evaluateWatchedEntities:async()=>{throw Error('D1 unavailable')}},
      notificationDispatch:{processDueDeliveries:async()=>({delivered:0})},
      d1:{setD1Binding:()=>{}},
    };
    await assert.rejects(()=>handleScheduled({}, {DB:{},CDB_SOC_CRON_ENABLED:'true'},{},deps),/D1 unavailable/);
  });
});

test('SOC Wrangler must never silently enable the metered cron handler by default', () => {
  const fs=require('node:fs');
  const path=require('node:path');
  const raw=fs.readFileSync(path.resolve(__dirname,'../../wrangler.jsonc'),'utf8');
  const config=JSON.parse(raw.replace(/^\s*\/\/.*$/gm,''));
  assert.equal(config.vars?.CDB_SOC_CRON_ENABLED,undefined);
  assert.deepEqual(config.triggers.crons,['*/30 * * * *']);
  const src=fs.readFileSync(path.resolve(__dirname,'router.js'),'utf8');
  assert.match(src,/CRON_EVALUATION_LIMIT = 10/);
  assert.match(src,/CRON_DELIVERY_LIMIT = 10/);
  assert.match(src,/CDB_SOC_CRON_ENABLED !== 'true'/);
});
