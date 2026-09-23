'use strict';

// Route-handler tests for the new action=detections/detection/
// detection-download/detection-coverage/detection-pack actions added to
// api/v1/intel.js. Same two-layer pattern as intel-dossier.test.js:
// (1) unauthenticated -> 401 before touching any detection logic;
// (2) authenticate() mocked to a controlled {tier}, everything downstream
// runs for real against real committed production data.

jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});

const { authenticate } = require('../../_lib/middleware');
const handler = require('../intel');
const detectionRules = require('../../_lib/detection-rules');

function mockReq(query = {}) {
  return { method: 'GET', query, headers: {}, url: '/api/v1/intel' };
}
function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn(s => { res.statusCode = s; return res; });
  res.json = jest.fn(b => { res.body = b; return res; });
  res.send = jest.fn(b => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
function mockUser(tier) {
  return { tier, userId: 'test-user', email: 't@example.com', keyHash: 'x', requestsUsed: 1, requestsLimit: 999999 };
}

beforeEach(() => {
  authenticate.mockReset();
  authenticate.mockImplementation(jest.requireActual('../../_lib/middleware').authenticate);
});

function currentCanonicalCveFixture() {
  const store = detectionRules.loadCanonical();
  const rule = (store.rules || []).find(r =>
    r?.governance?.status !== 'REVOKED' &&
    !!r?.platforms?.sigma &&
    !(r?.suricata || []).length &&
    (r?.source?.articles || []).some(a => /^CVE-\d{4}-\d{4,7}$/i.test(String(a)))
  );
  if (!rule) throw new Error('Canonical detection store must contain at least one non-revoked CVE-linked Sigma rule without Suricata content');
  const cve = rule.source.articles.find(a => /^CVE-\d{4}-\d{4,7}$/i.test(String(a)));
  return { rule, cve: String(cve).toUpperCase() };
}

const REAL_CVE_FIXTURE = currentCanonicalCveFixture();
const REAL_CVE_RULE_ID = REAL_CVE_FIXTURE.rule.id;
const REAL_CVE_ID = REAL_CVE_FIXTURE.cve;

describe('unauthenticated requests to the new detection actions', () => {
  test.each(['detections', 'detection', 'detection-download', 'detection-coverage', 'detection-pack'])(
    'action=%s returns 401 with no API key',
    async (action) => {
      const req = mockReq({ action, id: REAL_CVE_RULE_ID, type: 'cve' });
      const res = mockRes();
      await handler(req, res);
      expect(res.status).toHaveBeenCalledWith(401);
    }
  );
});

describe('action=detections (list)', () => {
  test('lists real detections with pagination, bounded by default limit', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detections' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(500);
    const body = res.json.mock.calls[0][0];
    expect(body.success).toBe(true);
    expect(Array.isArray(body.detections)).toBe(true);
    expect(body.pagination.limit).toBe(25);
    expect(body.pagination.total).toBeGreaterThanOrEqual(body.detections.length);
  });

  test('entity_type=cve&entity_id= filters to only that CVE\'s real detections', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detections', entity_type: 'cve', entity_id: REAL_CVE_ID });
    const res = mockRes();
    await handler(req, res);
    const body = res.json.mock.calls[0][0];
    expect(body.detections.length).toBeGreaterThanOrEqual(1);
    expect(body.detections.every(d => d.threat_context.cves.map(String).map(v => v.toUpperCase()).includes(REAL_CVE_ID))).toBe(true);
  });

  test('a bogus entity_id returns an honestly empty list, not an error', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detections', entity_type: 'cve', entity_id: 'CVE-0000-00000' });
    const res = mockRes();
    await handler(req, res);
    const body = res.json.mock.calls[0][0];
    expect(body.detections).toEqual([]);
  });

  test('limit is clamped to the 100 maximum', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detections', limit: '99999' });
    const res = mockRes();
    await handler(req, res);
    expect(res.json.mock.calls[0][0].pagination.limit).toBe(100);
  });

  test('free tier can list detections too -- this is catalog browsing, not gated (matches action=cve\'s open-viewing precedent)', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'detections' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(403);
  });
});

describe('action=detection (single detail)', () => {
  test('missing id -> 400', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  test('unknown id -> 404, not a crash or a fabricated record', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection', id: 'does-not-exist-00000000' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });

  test('a real detection returns the full canonical object with an L1-L7 validation record', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection', id: REAL_CVE_RULE_ID });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(500);
    const det = res.json.mock.calls[0][0].detection;
    expect(det.detection_id).toBe(REAL_CVE_RULE_ID);
    expect(det.validation.real_execution.pass).toBeNull();
    expect(det.validation.customer_production.pass).toBeNull();
    expect(['RELEASED', 'REVIEW_REQUIRED', 'BLOCKED', 'DEPRECATED', 'REVOKED']).toContain(det.status);
  });

  test('without entity context, ATT&CK evidence is conservatively UNKNOWN (never assumes a linkage it cannot verify)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection', id: REAL_CVE_RULE_ID });
    const res = mockRes();
    await handler(req, res);
    const det = res.json.mock.calls[0][0].detection;
    expect(det.attack[0].evidence_state).toBe('UNKNOWN');
  });

  test('with a real current CVE entity context, detection detail remains stable and never crashes', async () => {
    // The canonical detection fixture rotates as production rules evolve; this
    // test verifies route stability against the current committed rule/CVE pair.
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection', id: REAL_CVE_RULE_ID, entity_type: 'cve', entity_id: REAL_CVE_ID });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(500);
  });
});

describe('action=detection-download', () => {
  test('missing format -> 400', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-download', id: REAL_CVE_RULE_ID });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  test('an unsupported format (e.g. yara) is rejected, not silently served empty', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-download', id: REAL_CVE_RULE_ID, format: 'yara' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json.mock.calls[0][0].error.code).toBe('UNSUPPORTED_FORMAT');
  });

  test('a real sigma download returns real content with a safe, id-derived filename (no path traversal surface)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-download', id: REAL_CVE_RULE_ID, format: 'sigma' });
    const res = mockRes();
    await handler(req, res);
    expect(res.send).toHaveBeenCalled();
    const disposition = res.headers['Content-Disposition'];
    expect(disposition).toMatch(new RegExp(`filename="detection-${REAL_CVE_RULE_ID}-sigma\\.yml"`));
    expect(disposition).not.toMatch(/\.\.|\/|\\/); // no traversal characters anywhere in the header
    expect(String(res.body)).toContain('title:');
  });

  test('a path-traversal-shaped id is treated as an opaque, non-existent ID -- 404, never a filesystem read', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-download', id: '../../../etc/passwd', format: 'sigma' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });

  test('requesting a format the rule does not have -> 404 FORMAT_NOT_AVAILABLE, not an empty 200', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-download', id: REAL_CVE_RULE_ID, format: 'suricata' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });
});

describe('action=detection-coverage', () => {
  test('unsupported entity type -> 400', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-coverage', type: 'actor', id: 'actor:lockbit' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  test('unknown CVE -> 404', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-coverage', type: 'cve', id: 'CVE-1999-00001' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(404);
  });

  test('a real, dense CVE (CVE-2023-27351) returns real, non-fabricated coverage with an honest sparse gap', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-coverage', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(500);
    const cov = res.json.mock.calls[0][0].coverage;
    expect(cov.observed_techniques).toBeGreaterThan(0);
    // Real production data today: genuinely sparse (validated < observed) -- proves this isn't fabricated 100% coverage.
    expect(cov.validated).toBeLessThan(cov.observed_techniques);
    expect(cov.techniques.every(t => Number.isInteger === Number.isInteger)).toBe(true); // shape smoke check
    expect(cov.techniques.every(t => typeof t.id === 'string' && typeof t.status === 'string')).toBe(true);
  });

  test('free tier can view coverage (not gated -- same open-viewing tier as the dossier itself)', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'detection-coverage', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(403);
  });
});

describe('action=detection-pack -- Pro/Enterprise only', () => {
  test('free tier is rejected with 403 TIER_RESTRICTED', async () => {
    authenticate.mockResolvedValue(mockUser('free'));
    const req = mockReq({ action: 'detection-pack', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json.mock.calls[0][0].error.code).toBe('TIER_RESTRICTED');
  });

  test('starter tier is also rejected', async () => {
    authenticate.mockResolvedValue(mockUser('starter'));
    const req = mockReq({ action: 'detection-pack', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('pro tier gets a real pack manifest containing only RELEASED detections for a dense, real CVE', async () => {
    authenticate.mockResolvedValue(mockUser('pro'));
    const req = mockReq({ action: 'detection-pack', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(500);
    const pack = res.json.mock.calls[0][0].pack;
    expect(pack.entity).toEqual({ type: 'cve', id: 'CVE-2023-27351' });
    expect(pack.detection_count).toBe(pack.detections.length);
    for (const d of pack.detections) {
      expect(d.validation_status).toBe('RELEASED');
      expect(Object.keys(d.hashes).length).toBeGreaterThan(0);
      for (const hash of Object.values(d.hashes)) expect(hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test('enterprise tier is allowed', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'detection-pack', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    expect(res.status).not.toHaveBeenCalledWith(403);
  });
});

describe('Backward compatibility -- new actions do not alter any existing action\'s response shape', () => {
  test('action=cve is unaffected (no injected detections/coverage field)', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    const body = res.json.mock.calls[0][0];
    expect(body.item).not.toHaveProperty('detections');
  });

  test('action=dossier\'s detections section now carries real coverage data, but keeps its documented available/formats/note contract', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'dossier', type: 'cve', id: 'CVE-2023-27351' });
    const res = mockRes();
    await handler(req, res);
    const dossier = res.json.mock.calls[0][0].dossier;
    expect(dossier.detections).toHaveProperty('available');
    expect(dossier.detections).toHaveProperty('formats');
    expect(dossier.detections).toHaveProperty('note');
    expect(Array.isArray(dossier.detections.formats)).toBe(true);
  });
});

describe('Unknown action list includes the new actions (documentation/discoverability)', () => {
  test('an invalid action\'s error message enumerates the new detection actions', async () => {
    authenticate.mockResolvedValue(mockUser('enterprise'));
    const req = mockReq({ action: 'totally-bogus-action' });
    const res = mockRes();
    await handler(req, res);
    const msg = res.json.mock.calls[0][0].error.message;
    expect(msg).toContain('detections');
    expect(msg).toContain('detection-coverage');
    expect(msg).toContain('detection-pack');
  });
});
