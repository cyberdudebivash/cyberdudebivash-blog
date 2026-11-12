'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { runInNewContext } = require('node:vm');
const { test } = require('node:test');
const crypto = require('node:crypto');

function sourceModule(name, dependency = {}) {
  const source = readFileSync(join(__dirname, '..', 'api', '_lib', name), 'utf8');
  const module = { exports: {} };
  runInNewContext(source, {
    module, exports: module.exports, console, Date, JSON, Set, Number,
    require(id) {
      if (id === 'crypto') return crypto;
      if (id === './redis') return dependency.redis || {};
      // Constructor dependencies need not run when testing the actual review
      // function on an object with deliberately supplied mocked services.
      return new Proxy({}, { get: () => class Stub {} });
    },
  }, { timeout: 1000 });
  return module.exports;
}

const { FreshnessEngine } = sourceModule('freshness-engine.js');
const { PublicationManager } = sourceModule('publication-manager.js');

function past(days) { return new Date(Date.now() - days * 86400000).toISOString(); }

test('missing/invalid/zone-less/future IOC timestamps fail closed instead of being freshly observed', async () => {
  const engine = new FreshnessEngine({});
  const cases = [undefined, '', 'not-a-timestamp', '2026-11-13',
    new Date(Date.now() + 86400000).toISOString()];
  for (const lastSeen of cases) {
    const actual = await engine.scoreFreshness({ type: 'IOC', lastSeen });
    assert.equal(actual.status, 'unverified', String(lastSeen));
    assert.equal(actual.freshnessScore, 0);
    assert.equal(actual.daysSinceLastSeen, null);
    assert.equal(actual.confidenceImpact.impact, 'negative');
  }
});

test('known UTC observations remain recent, historical observations expire, unknown types cannot default to fresh', async () => {
  const engine = new FreshnessEngine({});
  const recent = await engine.scoreFreshness({ type: 'IOC', lastSeen: past(1) });
  const old = await engine.scoreFreshness({ type: 'IOC', lastSeen: past(200) });
  const unknown = await engine.scoreFreshness({ type: 'UNSUPPORTED', lastSeen: past(1) });
  assert.equal(recent.status, 'hot');
  assert.equal(recent.freshnessScore, 1);
  assert.equal(old.status, 'expired');
  assert.ok(old.freshnessScore < 0.1);
  assert.equal(unknown.status, 'unverified');
});

test('investigation missing timestamps never uses wall-clock fallback for undated IOCs', async () => {
  const redis = {
    async hgetall(key) {
      return key.startsWith('technical:')
        ? ['iocs', JSON.stringify([{ id: 'observed', lastSeen: past(1) }, { id: 'undated' }])]
        : [];
    },
  };
  const engine = new FreshnessEngine(redis);
  const report = await engine.evaluateInvestigationFreshness('investigation-test');
  assert.equal(report.iocCount, 2);
  assert.equal(report.unverifiedCount, 1);
  assert.equal(report.staleCount, 1);
  assert.equal(report.averageFreshnessScore, 0.5);
  assert.equal(report.freshnessScores[1].status, 'unverified');
  assert.match(report.overallRecommendation, /must not be published as fresh/);
});

test('no IOC observations is not medium confidence freshness', async () => {
  const engine = new FreshnessEngine({ async hgetall() { return []; } });
  const report = await engine.evaluateInvestigationFreshness('empty');
  assert.equal(report.iocCount, 0);
  assert.equal(report.averageFreshnessScore, 0);
  assert.match(report.overallRecommendation, /not attested/);
});

function reviewManager(unverifiedCount) {
  const manager = Object.create(PublicationManager.prototype);
  manager.redis = { async hset() {}, async zadd() {} };
  manager.analyticalValidator = { validate: () => ({ criticalIssues: [] }) };
  manager.editorialValidator = { validate: () => ({}) };
  manager.complianceValidator = { validate: () => ({}) };
  manager.consistencyEngine = { checkIntelligenceConsistency: async () => ({}) };
  manager.freshnessEngine = { evaluateInvestigationFreshness: async () => ({
    unverifiedCount, iocCount: 1, averageFreshnessScore: unverifiedCount ? 0 : 1,
  }) };
  manager.qualityScorer = { scoreReport: async () => ({ overallScore: 0.98, qualityGaps: [] }) };
  manager.publicationPolicy = {
    validatePublicationReadiness: async () => ({ isReady: true, issues: [] }),
  };
  return manager;
}

test('premium editorial score cannot override unknown IOC observation time', async () => {
  const review = await reviewManager(1).performFullQualityReview({ id: 'report-1' }, 'investigation-1');
  assert.equal(review.qualityScore.overallScore, 0.98);
  assert.equal(review.publicationReadiness.isReady, true);
  assert.equal(review.publishable, false);
  assert.equal(review.overallRecommendation.action, 'REJECT');
  assert.ok(review.overallRecommendation.criticalIssues.includes('IOC_TIMESTAMP_UNVERIFIED'));
});

test('dated IOC observations preserve existing editorial publication gate', async () => {
  const review = await reviewManager(0).performFullQualityReview({ id: 'report-2' }, 'investigation-2');
  assert.equal(review.publishable, true);
  assert.equal(review.overallRecommendation.action, 'ACCEPT');
});
