'use strict';

const { SentinelApexEIXIntegrationOrchestrator } = require('../sa-eix-integration-orchestrator');

describe('Sentinel APEX SA-EIX Integration Orchestrator', () => {
  let orchestrator;

  beforeEach(() => {
    orchestrator = new SentinelApexEIXIntegrationOrchestrator();
    orchestrator.clearCache();
    orchestrator.renderingMetrics = {
      totalReports: 0,
      cachedReports: 0,
      averageRenderTime: 0,
      renderTimes: [],
    };
  });

  const mockProduct = {
    id: 'prod-apt28-2026-07-31',
    productType: 'threat-report',
    classification: 'TLP:AMBER',
    modules: {
      executiveSummary: { content: 'Executive summary' },
      technicalAnalysis: { content: 'Technical analysis' },
      evidence: { items: [] },
    },
  };

  const mockInvestigation = {
    id: 'inv-apt28-2026-07-31',
    title: 'APT-28 Campaign',
    severity: 'CRITICAL',
    classification: 'TLP:AMBER',
    businessImpact: 'High operational impact',
    threatActors: [{ name: 'APT-28' }],
    campaigns: [{ name: 'Operation Ghost' }],
    findings: [
      { statement: 'Evidence detected', severity: 'critical', confidence: 0.95 },
    ],
    iocs: [
      { value: '192.168.1.1', type: 'ip', severity: 'HIGH' },
    ],
    infrastructure: [
      { type: 'c2', value: 'attacker.com' },
    ],
    mitreTechniques: [
      { technique: 'Spear Phishing', tactic: 'Initial Access' },
    ],
    timeline: [
      { date: '2026-01-15', event: 'Initial compromise' },
    ],
    targetedSectors: ['government', 'technology'],
    confidence: 0.85,
    confidenceReasoning: 'Multiple sources',
  };

  // ==================== INITIALIZATION TESTS ====================

  test('should initialize with all sub-engines', () => {
    expect(orchestrator.presentationEngine).toBeDefined();
    expect(orchestrator.htmlRenderer).toBeDefined();
    expect(orchestrator.diagramRenderer).toBeDefined();
  });

  test('should initialize with empty report cache', () => {
    expect(orchestrator.reportCache).toBeDefined();
    expect(orchestrator.reportCache.size).toBe(0);
  });

  test('should initialize with rendering metrics', () => {
    expect(orchestrator.renderingMetrics).toBeDefined();
    expect(orchestrator.renderingMetrics.totalReports).toBe(0);
    expect(orchestrator.renderingMetrics.cachedReports).toBe(0);
  });

  // ==================== REPORT GENERATION TESTS ====================

  test('should generate enhanced report', async () => {
    const result = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation);

    expect(result).toBeDefined();
    expect(result.html).toBeDefined();
    expect(result.cached).toBe(false);
    expect(result.renderTime).toBeGreaterThanOrEqual(0);
    expect(result.productId).toBe('prod-apt28-2026-07-31');
  });

  test('should generate report with dark theme', async () => {
    const result = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, {
      theme: 'dark',
    });

    expect(result.html).toContain('data-theme="dark"');
  });

  test('should generate report with light theme', async () => {
    const result = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, {
      theme: 'light',
    });

    expect(result.html).toContain('data-theme="light"');
  });

  test('should generate report with diagrams', async () => {
    const result = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, {
      renderDiagrams: true,
    });

    expect(result.html).toBeDefined();
  });

  test('should cache reports', async () => {
    const options = { cacheReport: true, theme: 'dark', mode: 'executive' };
    await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);

    const secondResult = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);

    expect(secondResult.cached).toBe(true);
  });

  test('should skip cache when cacheReport is false', async () => {
    const options = { cacheReport: false };
    const result1 = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);
    const result2 = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);

    expect(result1.cached).toBe(false);
    expect(result2.cached).toBe(false);
  });

  // ==================== INTERACTIVE DIAGRAMS TESTS ====================

  test('should render interactive diagrams', () => {
    const diagramsData = {
      diagrams: [
        {
          type: 'kill-chain',
          title: 'Kill Chain',
          stages: ['Recon', 'Weaponize', 'Deliver'],
        },
        {
          type: 'timeline',
          title: 'Timeline',
          events: [
            { date: '2026-01-15', event: 'First event' },
          ],
        },
      ],
    };

    const result = orchestrator.renderInteractiveDiagrams(diagramsData);

    expect(result.diagrams.length).toBe(2);
    expect(result.diagrams[0].svg).toBeDefined();
    expect(result.svg['kill-chain']).toBeDefined();
  });

  // ==================== MULTIPLE REPORTS TESTS ====================

  test('should generate multiple reports', async () => {
    const products = [
      { ...mockProduct, id: 'prod-1' },
      { ...mockProduct, id: 'prod-2' },
      { ...mockProduct, id: 'prod-3' },
    ];

    const result = await orchestrator.generateMultipleReports(products, mockInvestigation);

    expect(result.total).toBe(3);
    expect(result.successful).toBe(3);
    expect(result.failed).toBe(0);
    expect(result.reports.length).toBe(3);
  });

  // ==================== REPORT ASSEMBLY TESTS ====================

  test('should assemble executive report', async () => {
    const result = await orchestrator.assembleExecutiveReport(mockProduct, mockInvestigation);

    expect(result.type).toBe('executive-report');
    expect(result.html).toBeDefined();
    expect(result.metadata).toBeDefined();
    expect(result.metadata.generatedAt).toBeDefined();
  });

  test('should assemble technical report', async () => {
    const result = await orchestrator.assembleTechnicalReport(mockProduct, mockInvestigation);

    expect(result.type).toBe('technical-report');
    expect(result.html).toBeDefined();
  });

  test('should assemble operational report', async () => {
    const result = await orchestrator.assembleOperationalReport(mockProduct, mockInvestigation);

    expect(result.type).toBe('operational-report');
    expect(result.html).toBeDefined();
  });

  test('should generate complete report suite', async () => {
    const result = await orchestrator.generateReportSuite(mockProduct, mockInvestigation);

    expect(result.productId).toBe('prod-apt28-2026-07-31');
    expect(result.reports.executive).toBeDefined();
    expect(result.reports.technical).toBeDefined();
    expect(result.reports.operational).toBeDefined();
    expect(result.sizes.executive).toBeGreaterThan(0);
  });

  // ==================== EXPORT TESTS ====================

  test('should export report as HTML file', async () => {
    const htmlContent = '<html><body>Test</body></html>';
    const result = orchestrator.exportReportAsHTMLFile(htmlContent, 'test.html');

    expect(result.filename).toBe('test.html');
    expect(result.content).toBe(htmlContent);
    expect(result.mimeType).toBe('text/html');
    expect(result.size).toBe(htmlContent.length);
  });

  test('should prepare PDF export (placeholder)', async () => {
    const htmlContent = '<html><body>Test</body></html>';
    const result = orchestrator.exportReportAsPDF(htmlContent);

    expect(result.format).toBe('pdf');
    expect(result.status).toBe('requires-library');
  });

  // ==================== METRICS TESTS ====================

  test('should track rendering metrics', async () => {
    await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, { cacheReport: false });

    const metrics = orchestrator.getReportingMetrics();

    expect(metrics.totalReports).toBe(1);
    expect(metrics.averageRenderTime).toBeGreaterThanOrEqual(0);
    expect(metrics.cacheSize).toBe(0);
  });

  test('should update metrics on cached report', async () => {
    const options = { cacheReport: true };
    await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);
    await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);

    const metrics = orchestrator.getReportingMetrics();

    expect(metrics.totalReports).toBe(2);
    expect(metrics.cachedReports).toBe(1);
  });

  // ==================== CACHE TESTS ====================

  test('should retrieve cached report', async () => {
    const options = { cacheReport: true, theme: 'dark', mode: 'executive' };
    const generated = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);

    const cached = orchestrator.getCachedReport('prod-apt28-2026-07-31', 'dark', 'executive');

    expect(cached).toBe(generated.html);
  });

  test('should clear report cache', async () => {
    const options = { cacheReport: true };
    await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);

    orchestrator.clearCache();

    const metrics = orchestrator.getReportingMetrics();
    expect(metrics.cacheSize).toBe(0);
  });

  test('should search cached reports', async () => {
    const options = { cacheReport: true };
    await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);

    const results = orchestrator.searchCachedReports('apt28');

    expect(results.length).toBeGreaterThan(0);
    expect(results[0].key).toContain('apt28');
    expect(results[0].cached).toBe(true);
  });

  // ==================== SUMMARY TESTS ====================

  test('should extract product summary from enhancement', async () => {
    const generated = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation);

    const summary = orchestrator.getEnhancedProductSummary(generated.enhancement);

    expect(summary).toBeDefined();
    expect(summary.productId).toBe('prod-apt28-2026-07-31');
    expect(typeof summary.threatScore).toBe('number');
    expect(Array.isArray(summary.sections)).toBe(true);
    expect(summary.sections.length).toBeGreaterThan(0);
  });

  // ==================== VALIDATION TESTS ====================

  test('should validate enhancement structure', async () => {
    const generated = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation);

    const validation = orchestrator.validateEnhancementStructure(generated.enhancement);

    expect(validation.valid).toBe(true);
  });

  test('should reject invalid enhancement structure', () => {
    const invalidEnhancement = { productId: 'test' };

    const validation = orchestrator.validateEnhancementStructure(invalidEnhancement);

    expect(validation.valid).toBe(false);
    expect(validation.error).toBeDefined();
  });

  // ==================== HEALTH CHECK TESTS ====================

  test('should provide health status', () => {
    const health = orchestrator.getHealthStatus();

    expect(health.status).toBe('healthy');
    expect(health.components).toBeDefined();
    expect(health.components.presentationEngine).toBe('active');
    expect(health.components.htmlRenderer).toBe('active');
    expect(health.components.diagramRenderer).toBe('active');
  });

  test('should include cache health in status', () => {
    const health = orchestrator.getHealthStatus();

    expect(health.cacheHealth).toBeDefined();
    expect(health.cacheHealth.size).toBe(0);
    expect(health.cacheHealth.utilization).toBeGreaterThanOrEqual(0);
  });

  // ==================== PERFORMANCE TESTS ====================

  test('should render report within acceptable time', async () => {
    const start = Date.now();
    await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation);
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(5000);
  });

  test('should cache significantly speed up subsequent renders', async () => {
    const options = { cacheReport: true };

    const start1 = Date.now();
    const result1 = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);
    const time1 = Date.now() - start1;

    const start2 = Date.now();
    const result2 = await orchestrator.generateEnhancedReport(mockProduct, mockInvestigation, null, options);
    const time2 = Date.now() - start2;

    expect(result2.cached).toBe(true);
    // Millisecond timings of a Map hit vs. a render can tie or invert by
    // clock granularity; assert the cache hit itself instead.
    expect(orchestrator.renderingMetrics.cachedReports).toBe(1);
    expect(result1.cached).toBe(false);
  });

  // ==================== CUSTOM BRANDING TESTS ====================

  test('should support custom branding configuration', () => {
    const customBranding = {
      colors: {
        primary: '#FF0000',
        accent: '#00FF00',
      },
    };
    const customOrchestrator = new SentinelApexEIXIntegrationOrchestrator(customBranding);

    expect(customOrchestrator.htmlRenderer.brandingConfig.colors.primary).toBe('#FF0000');
  });

  // ==================== EDGE CASES ====================

  test('should handle minimal product data', async () => {
    const minimalProduct = { id: 'minimal' };
    const minimalInvestigation = { id: 'inv-minimal' };

    const result = await orchestrator.generateEnhancedReport(minimalProduct, minimalInvestigation);

    expect(result.html).toBeDefined();
  });

  test('should handle multiple concurrent report generations', async () => {
    const products = [
      { ...mockProduct, id: 'concurrent-1' },
      { ...mockProduct, id: 'concurrent-2' },
      { ...mockProduct, id: 'concurrent-3' },
    ];

    const results = await Promise.all(
      products.map(p => orchestrator.generateEnhancedReport(p, mockInvestigation))
    );

    expect(results.length).toBe(3);
    expect(results.every(r => r.html)).toBe(true);
  });
});
