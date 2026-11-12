'use strict';

const redis = require('./redis');
const crypto = require('crypto');
const {
  AnalyticalQualityValidator,
  EditorialQualityValidator,
  ComplianceValidator,
} = require('./quality-validators');
const { ConsistencyEngine } = require('./consistency-engine');
const { SourceReliabilityEngine } = require('./source-reliability-engine');
const { FreshnessEngine } = require('./freshness-engine');
const { QualityScorer } = require('./quality-scorer');
const { PublicationPolicyEngine } = require('./publication-policy-engine');

class PublicationManager {
  constructor(redisClient = redis) {
    this.redis = redisClient;
    this.analyticalValidator = new AnalyticalQualityValidator();
    this.editorialValidator = new EditorialQualityValidator();
    this.complianceValidator = new ComplianceValidator();
    this.consistencyEngine = new ConsistencyEngine(redisClient);
    this.sourceReliability = new SourceReliabilityEngine(redisClient);
    this.freshnessEngine = new FreshnessEngine(redisClient);
    this.qualityScorer = new QualityScorer(redisClient);
    this.publicationPolicy = new PublicationPolicyEngine(redisClient);
  }

  async performFullQualityReview(report, investigationId, analyst = 'analyst') {
    const reviewId = crypto.randomBytes(16).toString('hex');
    const reviewStartTime = new Date().toISOString();

    console.log(`[QUALITY REVIEW] Starting review ${reviewId} for report ${report.id}`);

    const analyticalQuality = this.analyticalValidator.validate(report);
    const editorialQuality = this.editorialValidator.validate(report);
    const complianceResults = this.complianceValidator.validate(report, {
      requiresClassification: true,
      requiresAudience: true,
      minimumFindingCount: 1,
      requiresReview: true,
    });

    const consistencyResults = await this.consistencyEngine.checkIntelligenceConsistency(report, investigationId);
    const freshnessResults = await this.freshnessEngine.evaluateInvestigationFreshness(investigationId);

    const qualityScore = await this.qualityScorer.scoreReport(report, {
      analyticalQuality,
      editorialQuality,
      compliance: complianceResults,
    });

    const publicationReadiness = await this.publicationPolicy.validatePublicationReadiness(report, qualityScore.overallScore);
    // A valid editorial score cannot certify an IOC as live if its source
    // observation time is missing, invalid or future-dated. Qualitative
    // reports without IOC records retain their existing policy path.
    const undatedIocHold = Number(freshnessResults.unverifiedCount || 0) > 0;

    const review = {
      id: reviewId,
      reportId: report.id,
      investigationId,
      analyst,
      reviewStartTime,
      reviewCompletedAt: new Date().toISOString(),
      validations: {
        analyticalQuality,
        editorialQuality,
        compliance: complianceResults,
      },
      consistency: consistencyResults,
      freshness: freshnessResults,
      qualityScore,
      publicationReadiness,
      overallRecommendation: undatedIocHold
        ? {
            action: 'REJECT',
            message: 'IOC observation timestamps are unverified. Do not publish this review as fresh intelligence.',
            criticalIssues: ['IOC_TIMESTAMP_UNVERIFIED'],
          }
        : this.getOverallRecommendation(
            analyticalQuality,
            editorialQuality,
            complianceResults,
            qualityScore,
            publicationReadiness
          ),
      publishable: !undatedIocHold && publicationReadiness.isReady && qualityScore.overallScore >= 0.70,
    };

    const key = `review:${reviewId}`;
    const reviewData = { ...review };
    reviewData.validations = JSON.stringify(reviewData.validations);
    reviewData.consistency = JSON.stringify(reviewData.consistency);
    reviewData.freshness = JSON.stringify(reviewData.freshness);
    reviewData.qualityScore = JSON.stringify(reviewData.qualityScore);
    reviewData.publicationReadiness = JSON.stringify(reviewData.publicationReadiness);

    await this.redis.hset(key, Object.entries(reviewData).flat());
    await this.redis.zadd(`reviews:report:${report.id}`, Date.now(), reviewId);
    await this.redis.zadd(`reviews:investigation:${investigationId}`, Date.now(), reviewId);

    return review;
  }

  async getReview(reviewId) {
    const key = `review:${reviewId}`;
    const data = await this.redis.hgetall(key);

    if (!data || data.length === 0) {
      return null;
    }

    const review = {};
    for (let i = 0; i < data.length; i += 2) {
      const key = data[i];
      const value = data[i + 1];

      if (['validations', 'consistency', 'freshness', 'qualityScore', 'publicationReadiness'].includes(key)) {
        try {
          review[key] = JSON.parse(value);
        } catch (e) {
          review[key] = value;
        }
      } else {
        review[key] = value;
      }
    }

    return review;
  }

  async listReviews(investigationId, limit = 50) {
    const reviewIds = await this.redis.zrevrange(`reviews:investigation:${investigationId}`, 0, limit - 1);
    const reviews = [];

    for (const reviewId of reviewIds) {
      const review = await this.getReview(reviewId);
      if (review) reviews.push(review);
    }

    return reviews;
  }

  async getReportCertification(reportId) {
    const reviews = await this.redis.zrevrange(`reviews:report:${reportId}`, 0, 0);
    if (reviews.length === 0) return { certification: 'UNCERTIFIED' };

    const latestReview = await this.getReview(reviews[0]);
    if (!latestReview) return { certification: 'UNCERTIFIED' };

    return {
      reportId,
      certification: latestReview.qualityScore.certification,
      overallScore: latestReview.qualityScore.overallScore,
      publishable: latestReview.publishable,
      lastReviewedAt: latestReview.reviewCompletedAt,
      reviewDetails: {
        analyticalQuality: latestReview.qualityScore.scoreBreakdown.analyticalQuality,
        evidenceQuality: latestReview.qualityScore.scoreBreakdown.evidenceQuality,
        editorialQuality: latestReview.qualityScore.scoreBreakdown.editorialQuality,
      },
    };
  }

  getOverallRecommendation(analyticalQuality, editorialQuality, compliance, qualityScore, publicationReadiness) {
    const criticalIssues = [
      ...analyticalQuality.criticalIssues,
      ...publicationReadiness.issues.filter(i => i.severity === 'critical'),
    ];

    if (criticalIssues.length > 0) {
      return {
        action: 'REJECT',
        message: `Report has ${criticalIssues.length} critical issues. Not publishable.`,
        criticalIssues,
      };
    }

    if (qualityScore.overallScore >= 0.95) {
      return {
        action: 'ACCEPT',
        message: 'Report exceeds quality standards. Ready for immediate publication.',
        certification: 'CERTIFIED',
      };
    }

    if (qualityScore.overallScore >= 0.85) {
      return {
        action: 'ACCEPT_WITH_NOTES',
        message: 'Report meets publication standards. Consider addressing quality gaps before distribution.',
        gaps: qualityScore.qualityGaps,
        certification: 'PREMIUM',
      };
    }

    if (qualityScore.overallScore >= 0.70) {
      return {
        action: 'CONDITIONAL_ACCEPT',
        message: 'Report publishable but has quality gaps. Recommend review and improvements.',
        gaps: qualityScore.qualityGaps,
        certification: 'REVIEWED',
      };
    }

    return {
      action: 'REJECT',
      message: 'Report quality below publication threshold. Recommend improvements.',
      gaps: qualityScore.qualityGaps,
    };
  }

  async generatePublicationReport(reportId) {
    const reportKey = `report:${reportId}`;
    const reportData = await this.redis.hgetall(reportKey);

    if (!reportData || reportData.length === 0) {
      return { success: false, error: `Report not found: ${reportId}` };
    }

    const report = {};
    for (let i = 0; i < reportData.length; i += 2) {
      report[reportData[i]] = reportData[i + 1];
    }

    const reviews = await this.redis.zrevrange(`reviews:report:${reportId}`, 0, 0);
    let latestReview = null;
    if (reviews.length > 0) {
      latestReview = await this.getReview(reviews[0]);
    }

    return {
      reportId,
      title: report.title,
      status: report.status,
      classification: report.classification,
      createdAt: report.createdAt,
      createdBy: report.createdBy,
      latestReview,
      publishable: latestReview?.publishable || false,
      recommendations: latestReview?.overallRecommendation || null,
    };
  }

  async approveForPublication(reportId, approverName, approverRole = 'analyst') {
    const result = await this.publicationPolicy.recordApproval(reportId, 'standard', approverName, approverRole);

    if (!result.success) {
      return { success: false, error: result.error };
    }

    return {
      success: true,
      reportId,
      approver: approverName,
      role: approverRole,
      approvedAt: new Date().toISOString(),
    };
  }

  async requestExecutiveApproval(reportId, approverName) {
    return this.publicationPolicy.recordApproval(reportId, 'executive', approverName, 'executive');
  }

  async getPolicyCompliance(reportId) {
    return this.publicationPolicy.getPolicyCompliance(reportId);
  }
}

module.exports = { PublicationManager };
