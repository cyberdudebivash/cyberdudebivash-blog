'use strict';

jest.mock('../../_lib/premium-commerce-service', () => ({
  listCatalog: jest.fn(), getCatalogItem: jest.fn(), publishCertifiedReport: jest.fn(),
  createCheckout: jest.fn(), verifyCheckout: jest.fn(), listLibrary: jest.fn(), downloadReport: jest.fn(),
  listPremiumLibrary: jest.fn(), downloadPremiumReport: jest.fn(), planEligible: jest.fn(() => false),
}));
jest.mock('../../_lib/premium-commerce-store', () => ({ setCatalogStatus: jest.fn() }));
jest.mock('../../_lib/middleware', () => ({ authenticate: jest.fn() }));
jest.mock('../../_lib/analyst-auth', () => ({ requireAnalyst: jest.fn() }));
jest.mock('../../_lib/security', () => ({
  guardRequest: jest.fn(async () => true), globalIpRateLimit: jest.fn(async () => true),
  intentIpRateLimit: jest.fn(async () => true), submissionIpRateLimit: jest.fn(async () => true),
  applySecurityHeaders: jest.fn(),
  assertFieldWhitelist: jest.fn((body, allowed) => {
    const extra = Object.keys(body || {}).find(k => !allowed.includes(k));
    return extra ? `Unexpected field: ${extra}` : null;
  }),
}));

const service = require('../../_lib/premium-commerce-service');
const store = require('../../_lib/premium-commerce-store');
const security = require('../../_lib/security');
const { authenticate } = require('../../_lib/middleware');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const handler = require('../premium-intelligence');

function res() { const r={statusCode:200,body:null,headers:{}};r.setHeader=jest.fn((k,v)=>{r.headers[k.toLowerCase()]=v;return r});r.status=jest.fn(code=>{r.statusCode=code;return r});r.json=jest.fn(body=>{r.body=body;return r});r.send=jest.fn(body=>{r.body=body;return r});r.end=jest.fn(()=>r);return r; }
beforeEach(() => jest.clearAllMocks());

test('public catalog contains only service-approved sellable reports and needs no customer credential', async () => {
  service.listCatalog.mockResolvedValue([{report_id:'R1',title:'Premium Report'}]);const r=res();await handler({method:'GET',query:{action:'catalog'},headers:{}},r);expect(r.statusCode).toBe(200);expect(r.body.success).toBe(true);expect(authenticate).not.toHaveBeenCalled();
});

test('standalone checkout is retired: 410 PREMIUM_CHECKOUT_MOVED, never an order, whatever the payload', async () => {
  authenticate.mockResolvedValue({userId:'u1',email:'a@b.test'});
  for (const body of [{report_id:'R1'},{report_id:'R1',amount_minor:1,currency:'USD'}]) {
    const r=res();await handler({method:'POST',query:{action:'checkout'},body,headers:{}},r);
    expect(r.statusCode).toBe(410);expect(r.body.error.code).toBe('PREMIUM_CHECKOUT_MOVED');expect(r.body.error.upgrade_url).toMatch(/^https:\/\/intel\.cyberdudebivash\.com\/upgrade\.html\?plan=pro&/);
  }
  expect(service.createCheckout).not.toHaveBeenCalled();expect(authenticate).not.toHaveBeenCalled();
});

test('verify uses the stricter payment submission limiter', async () => {
  authenticate.mockResolvedValue(null);const r=res();await handler({method:'POST',query:{action:'verify'},body:{},headers:{}},r);expect(security.submissionIpRateLimit).toHaveBeenCalled();
});

test('publishing a sellable report requires verified analyst authority', async () => {
  requireAnalyst.mockResolvedValue(null);const r=res();await handler({method:'POST',query:{action:'publish-certified'},body:{reportx_export:{}},headers:{}},r);expect(service.publishCertifiedReport).not.toHaveBeenCalled();
});

test('analyst publication delegates only whitelisted commercial metadata to certification service', async () => {
  requireAnalyst.mockResolvedValue({id:'analyst-1'});service.publishCertifiedReport.mockResolvedValue({report_id:'R1'});const r=res();const body={reportx_export:{},title:'R',slug:'r',report_type:'MALWARE',summary:'s',price_minor:9900,currency:'INR'};await handler({method:'POST',query:{action:'publish-certified'},body,headers:{}},r);expect(r.statusCode).toBe(201);expect(r.body.data.published_by).toBe('analyst-1');
});

test('library is owner-authenticated and bounded by service', async () => {
  authenticate.mockResolvedValue({userId:'u1',tier:'free'});service.listPremiumLibrary.mockResolvedValue([{report_id:'R1'}]);const r=res();await handler({method:'GET',query:{action:'library',limit:'1000'},headers:{}},r);expect(service.listPremiumLibrary).toHaveBeenCalledWith({source:'blog_key',userId:'u1',tier:'free'},'1000');expect(r.body.data.count).toBe(1);
});

test('download returns binary with no-store, attachment and integrity headers', async () => {
  authenticate.mockResolvedValue({userId:'u1'});service.downloadPremiumReport.mockResolvedValue({bytes:Uint8Array.from([1,2]),filename:'report.md',contentType:'text/markdown',sha256:'a'.repeat(64)});const r=res();await handler({method:'GET',query:{action:'download',report_id:'R1'},headers:{}},r);expect(r.statusCode).toBe(200);expect(r.headers['cache-control']).toMatch(/no-store/);expect(r.headers['content-disposition']).toContain('report.md');expect(r.headers['x-content-sha256']).toBe('a'.repeat(64));expect(r.body).toBeInstanceOf(Uint8Array);
});

test('catalog status mutation is analyst-only', async () => {
  requireAnalyst.mockResolvedValue({id:'analyst-1'});store.setCatalogStatus.mockResolvedValue(true);const r=res();await handler({method:'POST',query:{action:'set-status'},body:{report_id:'R1',status:'PAUSED'},headers:{}},r);expect(store.setCatalogStatus).toHaveBeenCalledWith('R1','PAUSED');expect(r.body.data.changed_by).toBe('analyst-1');
});
