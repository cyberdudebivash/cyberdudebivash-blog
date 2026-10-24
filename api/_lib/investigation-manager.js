'use strict';

const crypto = require('crypto');

const INVESTIGATION_STATUS = {
  OPEN: 'open',
  IN_PROGRESS: 'in_progress',
  PENDING_REVIEW: 'pending_review',
  CLOSED: 'closed',
  ARCHIVED: 'archived',
};

const INVESTIGATION_PRIORITY = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

class InvestigationManager {
  constructor(redis, intelligenceManager, graphEngine) {
    this.redis = redis;
    this.manager = intelligenceManager;
    this.graph = graphEngine;
  }

  async createInvestigation(title, description, priority, assignee, linkedIntelligence = [], createdBy = 'analyst') {
    const investigationId = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();

    const investigation = {
      id: investigationId,
      title,
      description,
      priority: INVESTIGATION_PRIORITY[priority] || INVESTIGATION_PRIORITY.MEDIUM,
      status: INVESTIGATION_STATUS.OPEN,
      assignee: assignee || 'unassigned',
      createdAt: now,
      createdBy,
      updatedAt: now,
      linkedIntelligence: JSON.stringify(linkedIntelligence),
      linkedEntities: JSON.stringify([]),
      caseCount: 0,
      evidenceCount: 0,
      noteCount: 0,
      version: 1,
    };

    // #455: creation writes the record and indexes in separate Redis operations.
    // A failed intermediate write can leave incomplete index membership;
    // transactional or idempotent reconciliation is required before release.
    const investKey = `investigation:${investigationId}`;
    await this.redis.hset(investKey, Object.entries(investigation).flat());
    await this.redis.expire(investKey, 31536000);

    // Add to index
    await this.redis.zadd('investigations:all', Date.now(), investigationId);
    await this.redis.zadd(`investigations:by:status:${investigation.status}`, Date.now(), investigationId);
    await this.redis.zadd(`investigations:by:priority:${investigation.priority}`, Date.now(), investigationId);
    if (assignee && assignee !== 'unassigned') {
      await this.redis.zadd(`investigations:assigned:${assignee}`, Date.now(), investigationId);
    }

    // Record audit
    await this.recordInvestigationAudit(investigationId, 'CREATE', 'system', {
      title,
      priority,
      assignee,
    });

    return investigation;
  }

  async getInvestigation(investigationId) {
    const investKey = `investigation:${investigationId}`;
    const data = await this.redis.hgetall(investKey);

    if (!data || data.length === 0) {
      return null;
    }

    const investigation = {};
    for (let i = 0; i < data.length; i += 2) {
      investigation[data[i]] = data[i + 1];
    }

    if (investigation.linkedIntelligence) {
      try {
        investigation.linkedIntelligence = JSON.parse(investigation.linkedIntelligence);
      } catch {
        investigation.linkedIntelligence = [];
      }
    }

    if (investigation.linkedEntities) {
      try {
        investigation.linkedEntities = JSON.parse(investigation.linkedEntities);
      } catch {
        investigation.linkedEntities = [];
      }
    }

    investigation.priority = parseInt(investigation.priority);
    investigation.caseCount = parseInt(investigation.caseCount || 0);
    investigation.evidenceCount = parseInt(investigation.evidenceCount || 0);
    investigation.noteCount = parseInt(investigation.noteCount || 0);
    investigation.version = parseInt(investigation.version);

    return investigation;
  }

  async updateInvestigation(investigationId, updates) {
    const investigation = await this.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const investKey = `investigation:${investigationId}`;
    const now = new Date().toISOString();

    // P0 #455: a mutable assignee without an atomic owner-index transition
    // creates stale/absent assignment entries and can undermine workbench
    // visibility. Until an atomic, idempotent reassignment operation is
    // implemented and certified, fail closed BEFORE any Redis mutation.
    // This guard also protects non-HTTP callers of this manager.
    if (Object.prototype.hasOwnProperty.call(updates, 'assignee') &&
        updates.assignee !== investigation.assignee) {
      throw new Error('SOC_INVESTIGATION_REASSIGNMENT_NOT_READY');
    }

    // Update allowed fields
    const allowed = ['title', 'description', 'priority', 'status', 'assignee'];
    const updateData = {};

    for (const field of allowed) {
      if (updates[field] !== undefined) {
        if (field === 'priority') {
          updateData[field] = INVESTIGATION_PRIORITY[updates[field]] || investigation.priority;
        } else {
          updateData[field] = updates[field];
        }
      }
    }

    updateData.updatedAt = now;
    updateData.version = investigation.version + 1;

    await this.redis.hset(investKey, Object.entries(updateData).flat());

    // Record audit
    await this.recordInvestigationAudit(investigationId, 'UPDATE', 'analyst', updates);

    return { ...investigation, ...updateData };
  }

  async linkIntelligence(investigationId, intelligenceId) {
    const [investigation, intelligence] = await Promise.all([
      this.getInvestigation(investigationId),
      this.manager.getIntelligence(intelligenceId),
    ]);

    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);
    if (!intelligence) throw new Error(`Intelligence not found: ${intelligenceId}`);

    let linked = investigation.linkedIntelligence || [];
    if (typeof linked === 'string') {
      try {
        linked = JSON.parse(linked);
      } catch {
        linked = [];
      }
    }

    if (linked.some(l => l === intelligenceId)) {
      throw new Error(`Intelligence already linked: ${intelligenceId}`);
    }

    linked.push(intelligenceId);

    const investKey = `investigation:${investigationId}`;
    await this.redis.hset(investKey, 'linkedIntelligence', JSON.stringify(linked));

    // Add to index
    await this.redis.zadd(`investigation:intelligence:${investigationId}`, Date.now(), intelligenceId);

    // Record audit
    await this.recordInvestigationAudit(investigationId, 'LINK_INTELLIGENCE', 'analyst', {
      intelligenceId,
    });

    return { linked: true, intelligenceId };
  }

  async unlinkIntelligence(investigationId, intelligenceId) {
    const investigation = await this.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    let linked = investigation.linkedIntelligence || [];
    if (typeof linked === 'string') {
      try {
        linked = JSON.parse(linked);
      } catch {
        linked = [];
      }
    }

    const initial = linked.length;
    linked = linked.filter(l => l !== intelligenceId);

    if (linked.length === initial) {
      throw new Error(`Intelligence not linked: ${intelligenceId}`);
    }

    const investKey = `investigation:${investigationId}`;
    await this.redis.hset(investKey, 'linkedIntelligence', JSON.stringify(linked));
    await this.redis.zrem(`investigation:intelligence:${investigationId}`, intelligenceId);

    // Record audit
    await this.recordInvestigationAudit(investigationId, 'UNLINK_INTELLIGENCE', 'analyst', {
      intelligenceId,
    });

    return { unlinked: true, intelligenceId };
  }

  async linkGraphEntity(investigationId, entityId) {
    const investigation = await this.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const entity = await this.graph.getEntity(entityId);
    if (!entity) throw new Error(`Entity not found: ${entityId}`);

    let entities = investigation.linkedEntities || [];
    if (typeof entities === 'string') {
      try {
        entities = JSON.parse(entities);
      } catch {
        entities = [];
      }
    }

    if (entities.some(e => e === entityId)) {
      throw new Error(`Entity already linked: ${entityId}`);
    }

    entities.push(entityId);

    const investKey = `investigation:${investigationId}`;
    await this.redis.hset(investKey, 'linkedEntities', JSON.stringify(entities));
    await this.redis.zadd(`investigation:entities:${investigationId}`, Date.now(), entityId);

    return { linked: true, entityId };
  }

  async getInvestigationTimeline(investigationId, limit = 100) {
    const investigation = await this.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const events = [];

    // Audit events
    const audits = await this.redis.zrevrange(
      `investigation:audit:${investigationId}`,
      0,
      limit - 1
    );

    for (const audit of audits) {
      try {
        events.push({
          ...JSON.parse(audit),
          eventType: 'investigation_event',
        });
      } catch (e) {
        // Skip malformed audit
      }
    }

    return events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }

  async getRelatedInvestigations(investigationId, limit = 20) {
    const investigation = await this.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    // Find investigations with overlapping linked intelligence
    const linkedIntel = investigation.linkedIntelligence || [];
    const related = new Set();

    for (const intelId of linkedIntel) {
      const investigations = await this.redis.zrange(
        `intelligence:in:investigations:${intelId}`,
        0,
        20
      );

      for (const investId of investigations) {
        if (investId !== investigationId) {
          related.add(investId);
        }
      }
    }

    const investigationIds = Array.from(related).slice(0, limit);
    const investigations = [];

    for (const id of investigationIds) {
      const invest = await this.getInvestigation(id);
      if (invest) investigations.push(invest);
    }

    return investigations;
  }

  async closeInvestigation(investigationId, closureReason, recommendations) {
    const investigation = await this.getInvestigation(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);

    const investKey = `investigation:${investigationId}`;
    const now = new Date().toISOString();

    await this.redis.hset(investKey, 'status', INVESTIGATION_STATUS.CLOSED);
    await this.redis.hset(investKey, 'closedAt', now);
    await this.redis.hset(investKey, 'closureReason', closureReason);
    await this.redis.hset(investKey, 'recommendations', JSON.stringify(recommendations || []));

    // Update status indices
    await this.redis.zrem(`investigations:by:status:${investigation.status}`, investigationId);
    await this.redis.zadd(
      `investigations:by:status:${INVESTIGATION_STATUS.CLOSED}`,
      Date.now(),
      investigationId
    );

    // Record audit
    await this.recordInvestigationAudit(investigationId, 'CLOSE', 'analyst', {
      closureReason,
      recommendations,
    });

    return { closed: true, investigationId };
  }

  async recordInvestigationAudit(investigationId, action, actor, metadata) {
    await this.redis.zadd(
      `investigation:audit:${investigationId}`,
      Date.now(),
      JSON.stringify({
        action,
        actor,
        metadata,
        timestamp: new Date().toISOString(),
      })
    );
  }

  async listInvestigations(filters = {}, limit = 50) {
    let investigationIds = [];

    if (filters.status) {
      investigationIds = await this.redis.zrevrange(
        `investigations:by:status:${filters.status}`,
        0,
        limit - 1
      );
    } else if (filters.assignee) {
      investigationIds = await this.redis.zrevrange(
        `investigations:assigned:${filters.assignee}`,
        0,
        limit - 1
      );
    } else {
      investigationIds = await this.redis.zrevrange('investigations:all', 0, limit - 1);
    }

    const investigations = [];
    for (const id of investigationIds) {
      const invest = await this.getInvestigation(id);
      if (invest) investigations.push(invest);
    }

    return investigations;
  }
}

module.exports = {
  InvestigationManager,
  INVESTIGATION_STATUS,
  INVESTIGATION_PRIORITY,
};
