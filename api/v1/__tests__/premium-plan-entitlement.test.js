'use strict';

// Sentinel APEX plan entitlement for Premium Intelligence, end to end through
// the real route handler, premium-commerce service and D1 store, on a real
// SQLite database built from migrations/0008 (node:sqlite behind the D1
// binding interface).
// Mocked: R2 artifact storage, the blog-key authenticate() (unchanged
// middleware, covered by its own suite), and the sentinel-apex-gateway
// service binding (its /api/auth/validate response).
//
// canDownload = legacy purchase OR (SELLABLE + PREMIUM_CERTIFIED + eligible plan)

process.env.RAZORPAY_KEY_ID = 'rzp_test_ppe';
process.env.RAZORPAY_KEY_SECRET = 'ppe_key_secret_for_tests';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

jest.mock('../../_lib/redis', () => ({
  incr: jest.fn(async () => 1), expire: jest.fn(async () => 1), get: jest.fn(async () => null),
  set: jest.fn(async () => 'OK'), hgetall: jest.fn(async () => null),
}));
jest.mock('../../_lib/middleware', () => ({ authenticate: jest.fn() }));
jest.mock('../../_lib/premium-report-storage', () => ({
  headCertifiedArtifact: jest.fn(async () => ({ ok: true })),
  getCertifiedArtifact: jest.fn(async () => ({ arrayBuffer: async () => Uint8Array.from(Buffer.from('# Ray v3 premium report\n', 'utf8')).buffer })),
}));

const d1 = require('../../_lib/d1');
const razorpay = require('../../_lib/razorpay');
const storage = require('../../_lib/premium-report-storage');
const store = require('../../_lib/premium-commerce-store');
const plan = require('../../_lib/sentinel-plan-entitlement');
const { authenticate } = require('../../_lib/middleware');
const handler = require('../premium-intelligence');

const ARTIFACT = Buffer.from('# Ray v3 premium report\n', 'utf8');
const SHA = '8b79dc179a4e6f339ae276c47552b00193e911351f6b387fa776fd73d5974b21';
const RAY = 'sentinel-apex-vuln-cve-2025-62593-ray-v3';
const QILIN = 'qilin-spoonful-of-comfort-premium-canary';
const CLIENT_IP = '203.0.113.7';

// Sentinel APEX platform keys and what the gateway's /api/auth/validate says.
const GATEWAY = {
  cdb_free_aaaaaaaaaaaaaaaaaaaa: { valid: true, tier: 'FREE', sub: 'cust_free' },
  cdb_pro_bbbbbbbbbbbbbbbbbbbbb: { valid: true, tier: 'PRO', sub: 'buyer@example.com' },
  cdb_ent_ccccccccccccccccccccc: { valid: true, tier: 'ENTERPRISE', sub: 'cust_ent' },
  cdb_mssp_dddddddddddddddddddd: { valid: true, tier: 'MSSP', sub: 'cust_mssp' },
  cdb_pro_unknowntierxxxxxxxxxx: { valid: true, tier: 'PLATINUM', sub: 'cust_x' },
  cdb_pro_lowercasexxxxxxxxxxxx: { valid: true, tier: 'pro', sub: 'cust_y' },
  cdb_pro_revokedxxxxxxxxxxxxxx: { valid: false, tier: 'free' },
};
// Blog sentinel_ keys (authenticate() result).
const BLOG = {
  sentinel_legacybuyer: { userId: 'usr_buyer', tier: 'free' },
  sentinel_otherfree: { userId: 'usr_other', tier: 'free' },
  sentinel_blogpro: { userId: 'usr_blogpro', tier: 'pro' },
  sentinel_blogteam: { userId: 'usr_team', tier: 'team' },
  sentinel_badcase: { userId: 'usr_badcase', tier: 'Pro' },
};

let db;
let gatewayCalls;
let gatewayMode;

function sqliteBinding(database) {
  const prep = (sql, params = []) => ({
    sql, params,
    bind(...p) { return prep(sql, p); },
    async run() {
      const stmt = database.prepare(sql);
      if (/^\s*(SELECT|WITH)/i.test(sql)) return { results: stmt.all(...params), success: true, meta: {} };
      const info = stmt.run(...params);
      return { results: [], success: true, meta: { changes: Number(info.changes) } };
    },
  });
  return { prepare: sql => prep(sql), async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; } };
}

function gatewayBinding() {
  return {
    fetch: jest.fn(async (url, init) => {
      gatewayCalls.push({ url, headers: init.headers });
      if (gatewayMode === 'down') throw new Error('connection refused');
      if (gatewayMode === '500') return new Response('err', { status: 500 });
      const key = init.headers['X-API-Key'];
      const body = GATEWAY[key] || { valid: false, tier: 'free' };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  };
}

function insertReport(reportId, status = 'SELLABLE') {
  db.prepare(`INSERT INTO premium_report_catalog (report_id, slug, title, report_type, summary, certification_state,
    artifact_sha256, artifact_key, artifact_filename, artifact_content_type, artifact_size_bytes, price_minor, currency,
    status, reviewer_identity, review_timestamp, published_at, updated_at)
    VALUES (?, ?, ?, 'VULNERABILITY', '', 'PREMIUM_CERTIFIED', ?, ?, ?, 'text/markdown; charset=utf-8', ?, 199900, 'INR',
    ?, 'cyberdudebivash', '2026-10-02T02:40:03Z', '2026-10-02T00:00:00Z', '2026-10-02T00:00:00Z')`)
    .run(reportId, reportId, `Report ${reportId}`, SHA, `premium-reports/${reportId}/${SHA}.md`, `${reportId}.md`, ARTIFACT.length, status);
}

function insertLegacyPurchase(ownerId, reportId) {
  db.prepare(`INSERT INTO premium_orders (order_id, owner_id, email, report_id, report_title, artifact_sha256, artifact_key,
    artifact_filename, artifact_content_type, artifact_size_bytes, amount_minor, currency, razorpay_order_id, razorpay_payment_id,
    state, created_at, updated_at, verified_at, entitled_at)
    VALUES ('pord_legacy', ?, '', ?, 'Legacy', ?, ?, 'legacy.md', 'text/markdown; charset=utf-8', ?, 199900, 'INR',
    'order_LEGACY', 'pay_LEGACY', 'ENTITLED', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`)
    .run(ownerId, reportId, SHA, `premium-reports/${reportId}/${SHA}.md`, ARTIFACT.length);
  db.prepare(`INSERT INTO premium_entitlements (entitlement_id, owner_id, report_id, order_id, status, granted_at, updated_at)
    VALUES ('pent_legacy', ?, ?, 'pord_legacy', 'ACTIVE', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`).run(ownerId, reportId);
}

function res() {
  const r = { statusCode: 200, body: null, headers: {} };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; return r; };
  r.status = s => { r.statusCode = s; return r; };
  r.json = b => { r.body = b; return r; };
  r.send = b => { r.body = b; return r; };
  r.end = () => r;
  return r;
}

async function call(action, key, { query = {}, method = 'GET', body } = {}) {
  const r = res();
  const headers = { 'x-forwarded-for': CLIENT_IP };
  if (key) headers.authorization = `Bearer ${key}`;
  await handler({ method, headers, body, query: { action, ...query }, socket: {} }, r);
  return r;
}
const download = (key, reportId = RAY, query = {}) => call('download', key, { query: { report_id: reportId, ...query } });
const audit = () => db.prepare('SELECT * FROM premium_download_audit').all();

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'migrations', '0008_premium_intelligence_commerce.sql'), 'utf8'));
  insertReport(RAY, 'SELLABLE');
  insertReport(QILIN, 'PAUSED');
  d1.setD1Binding(sqliteBinding(db));
  gatewayCalls = [];
  gatewayMode = 'ok';
  plan.setSentinelGatewayBinding(gatewayBinding());
  jest.clearAllMocks();
  authenticate.mockImplementation(async (req, r) => {
    const key = String(req.headers.authorization || '').replace(/^Bearer /, '');
    if (BLOG[key]) return BLOG[key];
    r.status(401).json({ error: { code: 'UNAUTHORIZED' } });
    return null;
  });
  jest.spyOn(razorpay, 'createOrder');
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => { jest.restoreAllMocks(); d1.setD1Binding(null); plan.setSentinelGatewayBinding(null); });

describe('Sentinel APEX plan access (gateway-validated)', () => {
  test.each([
    ['PRO', 'cdb_pro_bbbbbbbbbbbbbbbbbbbbb'],
    ['ENTERPRISE', 'cdb_ent_ccccccccccccccccccccc'],
    ['MSSP', 'cdb_mssp_dddddddddddddddddddd'],
  ])('%s subscriber downloads the active certified report with its SHA-256', async (tier, key) => {
    const r = await download(key);
    expect(r.statusCode).toBe(200);
    expect(Buffer.from(r.body).equals(ARTIFACT)).toBe(true);
    expect(r.headers['x-content-sha256']).toBe(SHA);
    expect(r.headers['cache-control']).toMatch(/no-store/);
    const [row] = audit();
    expect(row).toMatchObject({ report_id: RAY, order_id: `plan:${tier}` });
    expect(row.owner_id).toMatch(/^sentinel:[0-9a-f]{24}$/);
    expect(JSON.stringify(row)).not.toContain('@example.com');
    expect(JSON.stringify(row)).not.toContain(key);
  });

  test('Free subscriber: 403 PREMIUM_PLAN_REQUIRED with a Sentinel APEX upgrade URL, and no R2 read', async () => {
    const r = await download('cdb_free_aaaaaaaaaaaaaaaaaaaa');
    expect(r.statusCode).toBe(403);
    expect(r.body.error.code).toBe('PREMIUM_PLAN_REQUIRED');
    expect(r.body.error.message).toBe('This Premium Intelligence product requires an eligible Sentinel APEX plan.');
    expect(r.body.error.upgrade_url).toMatch(/^https:\/\/intel\.cyberdudebivash\.com\/upgrade\.html\?plan=pro&/);
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
    expect(storage.headCertifiedArtifact).not.toHaveBeenCalled();
    expect(audit()).toHaveLength(0);
  });

  test.each([
    ['an unknown tier', 'cdb_pro_unknowntierxxxxxxxxxx'],
    ['a mis-cased tier', 'cdb_pro_lowercasexxxxxxxxxxxx'],
  ])('%s is never elevated: 403', async (_, key) => {
    const r = await download(key);
    expect(r.statusCode).toBe(403);
    expect(r.body.error.code).toBe('PREMIUM_PLAN_REQUIRED');
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });

  test('a revoked or unknown platform credential is 401, never a grant', async () => {
    for (const key of ['cdb_pro_revokedxxxxxxxxxxxxxx', 'cdb_pro_neverissuedxxxxxxxxxx']) {
      const r = await download(key);
      expect(r.statusCode).toBe(401);
      expect(r.body.error.code).toBe('INVALID_KEY');
    }
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });

  test('URL parameters never grant access: ?plan=pro, tier and UTM tags are ignored', async () => {
    const r = await download('cdb_free_aaaaaaaaaaaaaaaaaaaa', RAY, { plan: 'pro', tier: 'ENTERPRISE', utm_source: 'intel-factory', utm_content: 'ray-v3' });
    expect(r.statusCode).toBe(403);
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });

  test('no credential: 401 and the gateway is not called', async () => {
    const r = await download(null);
    expect(r.statusCode).toBe(401);
    expect(gatewayCalls).toHaveLength(0);
  });

  test.each([['down'], ['500']])('gateway %s: 503, fail closed, no R2 read', async mode => {
    gatewayMode = mode;
    const r = await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(r.statusCode).toBe(503);
    expect(r.body.error.code).toBe('ENTITLEMENT_SERVICE_UNAVAILABLE');
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });

  test('missing service binding: 503, fail closed', async () => {
    plan.setSentinelGatewayBinding(null);
    const r = await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(r.statusCode).toBe(503);
    expect(r.body.error.code).toBe('ENTITLEMENT_SERVICE_UNAVAILABLE');
  });

  test('the gateway receives the key in a header and the real client IP (per-client brute-force buckets)', async () => {
    await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(gatewayCalls).toHaveLength(1);
    expect(new URL(gatewayCalls[0].url).pathname).toBe('/api/auth/validate');
    expect(gatewayCalls[0].url).not.toContain('cdb_');
    expect(gatewayCalls[0].headers['X-API-Key']).toBe('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(gatewayCalls[0].headers['CF-Connecting-IP']).toBe(CLIENT_IP);
  });

  test('library then download within 60 s is one gateway call (per-isolate validation cache)', async () => {
    await call('library', 'cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(gatewayCalls).toHaveLength(1);
  });

  test('a platform credential never reaches the blog key store', async () => {
    await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(authenticate).not.toHaveBeenCalled();
  });
});

describe('product status overrides plan', () => {
  test('a PRO subscriber cannot download a PAUSED report', async () => {
    const r = await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb', QILIN);
    expect(r.statusCode).toBe(403);
    expect(r.body.error.code).toBe('REPORT_NOT_AVAILABLE');
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });

  test('a RETIRED product is unavailable to plan holders', async () => {
    db.prepare("UPDATE premium_report_catalog SET status='RETIRED' WHERE report_id=?").run(RAY);
    const r = await download('cdb_ent_ccccccccccccccccccccc');
    expect(r.statusCode).toBe(403);
    expect(r.body.error.code).toBe('REPORT_NOT_AVAILABLE');
  });

  test('an uncertified product is unavailable even if a row got through', async () => {
    const real = store.getCatalogReport;
    jest.spyOn(store, 'getCatalogReport').mockImplementation(async id => ({ ...(await real(id)), certification_state: 'DRAFT' }));
    const r = await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(r.statusCode).toBe(403);
    expect(r.body.error.code).toBe('REPORT_NOT_AVAILABLE');
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });

  test('an unknown report is 404', async () => {
    const r = await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb', 'no-such-report');
    expect(r.statusCode).toBe(404);
  });

  test('a corrupted artifact is refused (R2 integrity check still applies on the plan path)', async () => {
    storage.headCertifiedArtifact.mockResolvedValueOnce({ ok: false, reason: 'sha256_mismatch' });
    const r = await download('cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(r.statusCode).toBe(503);
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });
});

describe('blog sentinel_ keys and legacy purchases', () => {
  test('a legacy buyer keeps access to the purchased report, even after it is paused', async () => {
    insertLegacyPurchase('usr_buyer', QILIN);
    const r = await download('sentinel_legacybuyer', QILIN);
    expect(r.statusCode).toBe(200);
    expect(audit()[0]).toMatchObject({ owner_id: 'usr_buyer', order_id: 'pord_legacy' });
  });

  test('another account cannot use someone else\'s legacy purchase', async () => {
    insertLegacyPurchase('usr_buyer', RAY);
    const r = await download('sentinel_otherfree', RAY);
    expect(r.statusCode).toBe(403);
    expect(r.body.error.code).toBe('PREMIUM_PLAN_REQUIRED');
    expect(storage.getCertifiedArtifact).not.toHaveBeenCalled();
  });

  test.each([['pro', 'sentinel_blogpro'], ['team', 'sentinel_blogteam']])('a blog key on the %s tier has plan access', async (_, key) => {
    const r = await download(key);
    expect(r.statusCode).toBe(200);
  });

  test('a free or mis-cased blog tier has no plan access', async () => {
    for (const key of ['sentinel_otherfree', 'sentinel_badcase']) {
      const r = await download(key);
      expect(r.statusCode).toBe(403);
    }
  });
});

describe('My Premium Intelligence library', () => {
  test('a PRO subscriber sees every available certified report, never a paused one', async () => {
    const r = await call('library', 'cdb_pro_bbbbbbbbbbbbbbbbbbbbb');
    expect(r.statusCode).toBe(200);
    expect(r.body.data.plan_access).toBe(true);
    expect(r.body.data.reports.map(x => [x.report_id, x.access])).toEqual([[RAY, 'SENTINEL_APEX_PLAN']]);
    expect(JSON.stringify(r.body)).not.toContain('artifact_key');
  });

  test('a Free subscriber sees an empty library and an upgrade URL', async () => {
    const r = await call('library', 'cdb_free_aaaaaaaaaaaaaaaaaaaa');
    expect(r.body.data).toMatchObject({ count: 0, plan_access: false });
    expect(r.body.data.upgrade_url).toMatch(/^https:\/\/intel\.cyberdudebivash\.com\//);
  });

  test('legacy purchase + plan for the same report is one entry (the purchase)', async () => {
    insertLegacyPurchase('usr_blogpro', RAY);
    const r = await call('library', 'sentinel_blogpro');
    expect(r.body.data.reports.map(x => [x.report_id, x.access])).toEqual([[RAY, 'PURCHASE']]);
  });
});

describe('standalone checkout is retired', () => {
  test('checkout answers 410 PREMIUM_CHECKOUT_MOVED with no Razorpay order, D1 row or auth call', async () => {
    const r = await call('checkout', 'sentinel_blogpro', { method: 'POST', body: { report_id: RAY } });
    expect(r.statusCode).toBe(410);
    expect(r.body.error.code).toBe('PREMIUM_CHECKOUT_MOVED');
    expect(r.body.error.upgrade_url).toMatch(/^https:\/\/intel\.cyberdudebivash\.com\/upgrade\.html\?plan=pro&/);
    expect(razorpay.createOrder).not.toHaveBeenCalled();
    expect(authenticate).not.toHaveBeenCalled();
    expect(db.prepare('SELECT COUNT(*) n FROM premium_orders').get().n).toBe(0);
  });

  test('the public catalog carries the required plan and a Sentinel APEX link, never the R2 key', async () => {
    const r = await call('catalog', null);
    const [ray] = r.body.data.reports;
    expect(ray).toMatchObject({ report_id: RAY, artifact_sha256: SHA, required_plan: 'PRO' });
    expect(ray.upgrade_url).toMatch(/^https:\/\/intel\.cyberdudebivash\.com\/upgrade\.html\?/);
    expect(ray).not.toHaveProperty('artifact_key');
  });
});
