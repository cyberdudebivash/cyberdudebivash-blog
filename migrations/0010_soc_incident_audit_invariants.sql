-- SENTINEL APEX SOC Phase 3 — atomic incident audit, allowed transitions and replay protection.
-- Do NOT apply to remote D1 until SOC cutover and identity-release gates are satisfied.
-- Requires 0009_soc_tenant_control_plane.sql. Additive-only; no customer rows seeded.
-- Application access remains BLOCKED: there is no production OIDC adapter or SOC API route.
--
-- Invariant: incident creation/update and audit log creation are the SAME SQLite
-- statement transaction (trigger), not two independent network requests.
-- A failed audit insert (including reused request_id) rolls back the incident write.
--
-- Deployment prerequisite: soc_incidents must be empty or all legacy rows must
-- be reconciled because older rows have no audited creation provenance.

ALTER TABLE soc_incidents ADD COLUMN audit_actor_id TEXT;
ALTER TABLE soc_incidents ADD COLUMN audit_request_id TEXT;

-- Duplicate request replay is rejected atomically, even across separate
-- incidents or concurrent requests in one tenant. Request IDs must be unique
-- per write, not generic page-level correlation IDs.
CREATE UNIQUE INDEX IF NOT EXISTS idx_soc_incident_audit_request
  ON soc_audit_events(tenant_id,request_id)
  WHERE action IN ('INCIDENT_CREATED','INCIDENT_UPDATED','INCIDENT_STATE_CHANGED');

CREATE TRIGGER IF NOT EXISTS soc_incident_insert_guard
BEFORE INSERT ON soc_incidents
BEGIN
  SELECT CASE WHEN NEW.state <> 'OPEN' OR NEW.version <> 1
    THEN RAISE(ABORT, 'SOC incident must start OPEN at version 1') END;
  SELECT CASE WHEN NEW.audit_actor_id IS NULL OR length(NEW.audit_actor_id)=0
    OR NEW.audit_request_id IS NULL OR length(NEW.audit_request_id)<16
    OR length(NEW.audit_request_id)>128
    THEN RAISE(ABORT, 'SOC incident requires audit identity and request ID') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_principals p
    JOIN soc_tenants t ON t.tenant_id=p.tenant_id
    WHERE p.tenant_id=NEW.tenant_id
      AND p.principal_id=NEW.audit_actor_id
      AND p.status='ACTIVE' AND t.status='ACTIVE'
      AND p.role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN')
  ) THEN RAISE(ABORT,'SOC incident actor is not authorized') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_incident_insert_audit
AFTER INSERT ON soc_incidents
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,resource_type,resource_id,
    outcome,request_id,event_at
  ) VALUES (
    NEW.tenant_id,lower(hex(randomblob(16))),'ANALYST',NEW.audit_actor_id,
    'INCIDENT_CREATED','INCIDENT',NEW.incident_id,'ALLOW',
    NEW.audit_request_id,NEW.created_at
  );
END;

CREATE TRIGGER IF NOT EXISTS soc_incident_update_guard
BEFORE UPDATE ON soc_incidents
BEGIN
  SELECT CASE WHEN NEW.tenant_id <> OLD.tenant_id
    OR NEW.incident_id <> OLD.incident_id
    OR NEW.created_at <> OLD.created_at
    THEN RAISE(ABORT,'SOC incident immutable identity changed') END;
  SELECT CASE WHEN NEW.version <> OLD.version+1
    THEN RAISE(ABORT,'SOC incident version conflict') END;
  SELECT CASE WHEN NEW.audit_actor_id IS NULL OR length(NEW.audit_actor_id)=0
    OR NEW.audit_request_id IS NULL OR length(NEW.audit_request_id)<16
    OR length(NEW.audit_request_id)>128
    THEN RAISE(ABORT,'SOC incident requires audit identity and request ID') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_principals p
    JOIN soc_tenants t ON t.tenant_id=p.tenant_id
    WHERE p.tenant_id=NEW.tenant_id
      AND p.principal_id=NEW.audit_actor_id
      AND p.status='ACTIVE' AND t.status='ACTIVE'
      AND p.role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN')
  ) THEN RAISE(ABORT,'SOC incident actor is not authorized') END;
  SELECT CASE WHEN NEW.title IS OLD.title AND NEW.severity IS OLD.severity
    AND NEW.state IS OLD.state AND NEW.owner_id IS OLD.owner_id
    THEN RAISE(ABORT,'SOC incident no-op revision rejected') END;
  -- Customer containment requires a separately recorded approval. Until
  -- that capability is implemented, transitions into CONTAINED fail closed.
  SELECT CASE WHEN NEW.state='CONTAINED'
    THEN RAISE(ABORT,'SOC response approval required') END;
  SELECT CASE WHEN NEW.state<>OLD.state AND NOT (
       (OLD.state='OPEN' AND NEW.state='TRIAGE')
    OR (OLD.state='TRIAGE' AND NEW.state IN ('OPEN','INVESTIGATING'))
    OR (OLD.state='INVESTIGATING' AND NEW.state IN ('TRIAGE','AWAITING_APPROVAL','RESOLVED'))
    OR (OLD.state='AWAITING_APPROVAL' AND NEW.state='INVESTIGATING')
    OR (OLD.state='RESOLVED' AND NEW.state IN ('INVESTIGATING','CLOSED'))
  ) THEN RAISE(ABORT,'SOC incident transition not permitted') END;
  SELECT CASE WHEN OLD.state='CLOSED'
    THEN RAISE(ABORT,'SOC closed incident immutable') END;
  -- Closure requires evidence-linked detection or an evidence manifest.
  -- This is a minimal integrity threshold, not proof of remediation quality.
  SELECT CASE WHEN NEW.state='CLOSED' AND NOT EXISTS (
    SELECT 1 FROM soc_incident_detections l
      WHERE l.tenant_id=NEW.tenant_id AND l.incident_id=NEW.incident_id
  ) AND NOT EXISTS (
    SELECT 1 FROM soc_evidence_manifests e
      WHERE e.tenant_id=NEW.tenant_id AND e.incident_id=NEW.incident_id
  ) THEN RAISE(ABORT,'SOC incident closure requires evidence') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_incident_update_audit
AFTER UPDATE ON soc_incidents
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,resource_type,resource_id,
    outcome,request_id,event_at
  ) VALUES (
    NEW.tenant_id,lower(hex(randomblob(16))),'ANALYST',NEW.audit_actor_id,
    CASE WHEN NEW.state<>OLD.state THEN 'INCIDENT_STATE_CHANGED'
      ELSE 'INCIDENT_UPDATED' END,
    'INCIDENT',NEW.incident_id,'ALLOW',NEW.audit_request_id,NEW.updated_at
  );
END;

-- Explicitly prohibit deletion while audit/evidence retention model is unresolved.
CREATE TRIGGER IF NOT EXISTS soc_incident_no_delete
BEFORE DELETE ON soc_incidents
BEGIN
  SELECT RAISE(ABORT,'SOC incident hard-delete prohibited');
END;
