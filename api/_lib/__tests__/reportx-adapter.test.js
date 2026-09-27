'use strict';

// Regression + proof-of-integration coverage for the System 5 adapter
// (ReportX Section 44 / REPORTX-ROLLOUT-RUNBOOK.md Phase 3). The fixture
// this file loads is a REAL export -- produced by running
// `python3 cli.py reportx-gate <bundle.json> --export out.json` against
// the Qilin/Spoonful of Comfort golden fixture
// (tests/fixtures/reportx-commercial-readiness/qilin_spoonful_of_comfort.py)
// -- not a hand-written JSON stub. Regenerate it if the Python schema
// changes: see that file's own module docstring for the exact command.

const path = require('path');
const { ReportXBundle, loadReportXBundle, loadReportXBundleFromFile } = require('../reportx-adapter');

const FIXTURE_PATH = path.join(
  __dirname, '..', '..', '..', 'tests', 'fixtures', 'reportx-commercial-readiness',
  'qilin-spoonful-of-comfort-exported-bundle.json'
);

describe('ReportXBundle -- loading', () => {
  test('loadReportXBundleFromFile reads a real System-3-exported artifact', () => {
    const bundle = loadReportXBundleFromFile(FIXTURE_PATH);
    expect(bundle).toBeInstanceOf(ReportXBundle);
    expect(bundle.reportId).toBe('qilin-spoonful-of-comfort-2026-08-16');
  });

  test('loadReportXBundle accepts an already-parsed object', () => {
    const raw = require(FIXTURE_PATH);
    const bundle = loadReportXBundle(raw);
    expect(bundle.reportId).toBe(raw.bundle.report_id);
  });

  test('loadReportXBundle accepts a raw JSON string', () => {
    const fs = require('fs');
    const text = fs.readFileSync(FIXTURE_PATH, 'utf8');
    const bundle = loadReportXBundle(text);
    expect(bundle.reportId).toBe('qilin-spoonful-of-comfort-2026-08-16');
  });

  test('constructing directly from an object missing required keys throws rather than silently producing a broken bundle', () => {
    expect(() => new ReportXBundle({ bundle: {} })).toThrow(/missing required key/);
    expect(() => new ReportXBundle({ commercial_readiness: {} })).toThrow(/missing required key/);
  });
});

describe('ReportXBundle -- reads System 3\'s validated output, never recomputes it', () => {
  let bundle;
  beforeEach(() => {
    bundle = loadReportXBundleFromFile(FIXTURE_PATH);
  });

  test('getClaims returns the real claim set, including the honestly-UNKNOWN compromise claim', () => {
    const claims = bundle.getClaims();
    expect(claims.length).toBe(6);
    const compromiseClaim = claims.find(c => c.claim_id === 'c-compromise-occurred');
    expect(compromiseClaim.status).toBe('UNKNOWN');
    expect(compromiseClaim.evidence_refs).toEqual([]);
  });

  test('getClaim looks up a single claim by id', () => {
    const claim = bundle.getClaim('c-leak-site-claim');
    expect(claim).not.toBeNull();
    expect(claim.status).toBe('REPORTED');
    expect(bundle.getClaim('does-not-exist')).toBeNull();
  });

  test('getIncidentSpecificClaims / getActorContextClaims correctly separate OBSERVED from CONTEXT', () => {
    const observed = bundle.getIncidentSpecificClaims();
    const context = bundle.getActorContextClaims();
    expect(observed.every(c => c.observed_vs_context === 'OBSERVED')).toBe(true);
    expect(context.every(c => c.observed_vs_context === 'CONTEXT')).toBe(true);
    // Every claim in the fixture is one or the other (or NOT_SET) -- no
    // claim should appear in both.
    const observedIds = new Set(observed.map(c => c.claim_id));
    expect(context.some(c => observedIds.has(c.claim_id))).toBe(false);
  });

  test('getSources / getSource expose the real source records', () => {
    expect(bundle.getSources().length).toBe(2);
    const source = bundle.getSource('s-hendryadrian');
    expect(source.publisher).toContain('hendryadrian.com');
  });

  test('getThreatProducts / getPrimaryThreatProduct expose the schema-isolated ransomware product', () => {
    const products = bundle.getThreatProducts();
    expect(products.length).toBe(1);
    const primary = bundle.getPrimaryThreatProduct();
    expect(primary.threat_type).toBe('RANSOMWARE_VICTIM_CLAIM');
    // The isolation guarantee, still visible after crossing the JS boundary:
    // no linked vulnerability -> all four vuln markers stay NOT_APPLICABLE.
    expect(primary.linked_vulnerabilities).toEqual([]);
    expect(primary.cisa_kev_state).toBe('NOT_APPLICABLE');
    expect(primary.cvss_state).toBe('NOT_APPLICABLE');
  });

  test('getControlResults exposes all 23 rows exactly as System 3 computed them', () => {
    const controls = bundle.getControlResults();
    expect(controls.length).toBe(23);
    expect(controls.map(c => c.control_id)).toContain('fortune_500_commercial_deliverable');
  });

  test('getControlResult looks up a single row', () => {
    const row = bundle.getControlResult('cross_section_consistency');
    expect(row.status).toBe('PASS');
    expect(bundle.getControlResult('not-a-real-row')).toBeNull();
  });

  test('getPassCount/getTotalControlCount/getVerdict/isCommercialReady are read directly from the export, not recomputed', () => {
    expect(bundle.getTotalControlCount()).toBe(23);
    expect(bundle.getPassCount()).toBeLessThan(23); // this fixture is a partial acceptance-test bundle, not a full premium submission
    expect(bundle.getVerdict()).toBe('NOT COMMERCIAL-READY');
    expect(bundle.isCommercialReady()).toBe(false);
  });

  test('getFailingControls returns exactly the non-PASS rows', () => {
    const failing = bundle.getFailingControls();
    const all = bundle.getControlResults();
    expect(failing.length).toBe(all.length - bundle.getPassCount());
    expect(failing.every(c => c.status !== 'PASS')).toBe(true);
  });

  test('isPremiumTier reflects the exported bundle field', () => {
    expect(bundle.isPremiumTier).toBe(false);
  });
});

describe('ReportXBundle -- toInvestigationShape() bridges into the existing product-composition shape', () => {
  let bundle;
  let investigation;
  beforeEach(() => {
    bundle = loadReportXBundleFromFile(FIXTURE_PATH);
    investigation = bundle.toInvestigationShape();
  });

  test('maps identity and actor fields from the validated victim/actor-context layers', () => {
    expect(investigation.id).toBe('qilin-spoonful-of-comfort-2026-08-16');
    expect(investigation.title).toBe('Qilin / Spoonful of Comfort');
    expect(investigation.threatActors).toHaveLength(1);
    expect(investigation.threatActors[0].name).toBe('Qilin');
    expect(investigation.threatActors[0].aliases).toEqual(['Agenda']);
  });

  test('findings preserve the real ReportX epistemic status alongside the flattened severity', () => {
    expect(investigation.findings.length).toBe(6);
    const compromiseFinding = investigation.findings.find(f => f.reportXClaimId === 'c-compromise-occurred');
    expect(compromiseFinding.reportXStatus).toBe('UNKNOWN');
  });

  test('does not fabricate IOCs the underlying claims never established', () => {
    expect(investigation.iocs).toEqual([]);
  });

  test('carries the real gate verdict through to the mapped object', () => {
    expect(investigation.reportXGate.verdict).toBe(bundle.getVerdict());
    expect(investigation.reportXGate.passCount).toBe(bundle.getPassCount());
  });

  test('timeline reflects the actual leak-site claim_date, not a fabricated one', () => {
    expect(investigation.timeline).toHaveLength(1);
    expect(investigation.timeline[0].timestamp).toBe('2026-08-16T18:56:20Z');
  });
});

describe('ReportXBundle -- real integration with the existing, unmodified ProductCompositionEngine', () => {
  const originalRedisUrl = process.env.UPSTASH_REDIS_REST_URL;
  const originalRedisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  beforeAll(() => {
    process.env.UPSTASH_REDIS_REST_URL = 'https://synthetic-test.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'synthetic_test_token';
  });

  afterAll(() => {
    process.env.UPSTASH_REDIS_REST_URL = originalRedisUrl;
    process.env.UPSTASH_REDIS_REST_TOKEN = originalRedisToken;
  });

  test('a ReportX-backed investigation composes a real threat-actor-profile product through the unmodified engine', async () => {
    // eslint-disable-next-line global-require
    const { ProductCompositionEngine } = require('../product-composition-engine');
    const bundle = loadReportXBundleFromFile(FIXTURE_PATH);
    const investigation = bundle.toInvestigationShape();
    const report = { id: 'rpt-reportx-test', createdAt: new Date().toISOString() };

    const engine = new ProductCompositionEngine();
    const product = await engine.composeThreatActorProfile(investigation, report);

    expect(product.productType).toBe('threat-intelligence');
    expect(product.modules.overview.content.name).toBe('Qilin');
    expect(product.modules.overview.content.aliases).toEqual(['Agenda']);
  });
  test('SOC evidence contract preserves canonical epistemic state without recomputation', () => {
    const bundle = loadReportXBundleFromFile(FIXTURE_PATH);
    const contract = bundle.toSocEvidenceContract();
    const raw = require(FIXTURE_PATH);
    expect(contract.schema).toBe('cdb.soc-evidence.v1');
    expect(contract.report_id).toBe(raw.bundle.report_id);
    expect(contract.claims).toEqual(raw.bundle.claims.map(c => ({
      claim_id: c.claim_id,
      claim_type: c.claim_type,
      text: c.text,
      status: c.status,
      confidence: c.confidence,
      corroboration_state: c.corroboration_state,
      source_independence: Boolean(c.source_independence),
      observed_vs_context: c.observed_vs_context,
      temporal_scope: c.temporal_scope || null,
      applicability: c.applicability || '',
      contradictions: c.contradictions || [],
      evidence_refs: c.evidence_refs || [],
      source_refs: c.source_refs || [],
    })));
    expect(contract.sources.every(s => Object.prototype.hasOwnProperty.call(s, 'content_sha256'))).toBe(true);
  });
});
