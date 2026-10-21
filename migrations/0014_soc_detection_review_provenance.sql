-- SENTINEL APEX SOC — Phase 11 detection review and incident linkage controls.
-- Requires migrations 0009, 0010, 0012 and 0013. Source ONLY, no remote D1 apply.
-- PRECONDITION: reconcile existing SOC detections and incident links before apply.
-- No customer rows, demo alerts, auto-verification or incidents are seeded.
--
-- HMAC source receipt = source-attested event metadata, NOT proven malware.
-- Rule candidate = unverified; only an authenticated analyst + independently
-- validated source content can turn a candidate into analyst-verified status.
-- Database triggers enforce state/audit integrity but cannot independently
-- prove that a supplied digest represents real external source content.

ALTER TABLE soc_detections ADD COLUMN review_actor_id TEXT;
ALTER TABLE soc_detections ADD COLUMN review_request_id TEXT;
ALTER TABLE soc_detections ADD COLUMN review_note TEXT;
ALTER TABLE soc_detections ADD COLUMN reviewed_at TEXT;
ALTER TABLE soc_detections ADD COLUMN review_basis_sha256 TEXT;
ALTER TABLE soc_detections ADD COLUMN review_version INTEGER NOT NULL DEFAULT 0
  CHECK(review_version>=0);

CREATE UNIQUE INDEX IF NOT EXISTS idx_soc_detection_rule_idempotency
  ON soc_detections(tenant_id,event_id,rule_id,rule_version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_soc_detection_review_request
  ON soc_audit_events(tenant_id,request_id)
  WHERE action IN ('DETECTION_ANALYST_VERIFIED','DETECTION_REJECTED','INCIDENT_DETECTION_LINKED');

CREATE TRIGGER IF NOT EXISTS soc_detection_insert_guard
BEFORE INSERT ON soc_detections
BEGIN
  SELECT CASE WHEN NEW.evidence_state<>'SOURCE_REPORTED' OR
    NEW.review_actor_id IS NOT NULL OR NEW.review_request_id IS NOT NULL OR
    NEW.review_note IS NOT NULL OR NEW.reviewed_at IS NOT NULL OR
    NEW.review_basis_sha256 IS NOT NULL OR NEW.review_version<>0
    THEN RAISE(ABORT,'SOC candidate must start source-reported and unreviewed') END;
  SELECT CASE WHEN length(NEW.detection_id) NOT BETWEEN 8 AND 128 OR
    length(NEW.rule_id) NOT BETWEEN 1 AND 128 OR
    length(NEW.rule_version) NOT BETWEEN 1 AND 64 OR
    NEW.rule_id GLOB '*[^A-Za-z0-9_.:-]*' OR
    NEW.rule_version GLOB '*[^A-Za-z0-9_.:-]*'
    THEN RAISE(ABORT,'SOC candidate requires bounded rule provenance') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_event_receipts e
      JOIN soc_tenants t ON t.tenant_id=e.tenant_id
      JOIN soc_connectors c ON c.tenant_id=e.tenant_id
        AND c.connector_id=e.connector_id
    WHERE e.tenant_id=NEW.tenant_id AND e.event_id=NEW.event_id
      AND length(e.attestation_sha256)=64 AND e.signing_key_id IS NOT NULL
      AND t.status='ACTIVE' AND c.state='APPROVED'
  ) THEN RAISE(ABORT,'SOC candidate needs source-attested approved receipt') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_detection_insert_audit
AFTER INSERT ON soc_detections
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,resource_type,
    resource_id,outcome,request_id,event_at
  ) VALUES (
    NEW.tenant_id,lower(hex(randomblob(16))),'SYSTEM',NULL,
    'DETECTION_CANDIDATE_RECORDED','DETECTION',NEW.detection_id,'ALLOW',
    'detection:candidate:'||NEW.detection_id,NEW.created_at
  );
END;

CREATE TRIGGER IF NOT EXISTS soc_detection_review_guard
BEFORE UPDATE ON soc_detections
BEGIN
  SELECT CASE WHEN NEW.tenant_id<>OLD.tenant_id OR
    NEW.detection_id<>OLD.detection_id OR NEW.event_id<>OLD.event_id OR
    NEW.rule_id<>OLD.rule_id OR NEW.rule_version<>OLD.rule_version OR
    NEW.severity<>OLD.severity OR NEW.created_at<>OLD.created_at
    THEN RAISE(ABORT,'SOC detection provenance immutable') END;
  SELECT CASE WHEN OLD.evidence_state<>'SOURCE_REPORTED' OR
    NEW.evidence_state NOT IN ('ANALYST_VERIFIED','REJECTED') OR
    NEW.review_version<>OLD.review_version+1
    THEN RAISE(ABORT,'SOC analyst decision one-way and versioned') END;
  SELECT CASE WHEN NEW.review_actor_id IS NULL OR
    NEW.review_request_id IS NULL OR
    length(NEW.review_request_id) NOT BETWEEN 16 AND 128 OR
    NEW.review_note IS NULL OR
    length(trim(NEW.review_note)) NOT BETWEEN 24 AND 2000 OR
    NEW.reviewed_at IS NULL OR length(NEW.reviewed_at) NOT BETWEEN 20 AND 40
    THEN RAISE(ABORT,'SOC reviewer, request, rationale and time required') END;
  SELECT CASE WHEN NEW.review_note GLOB '*'||char(0)||'*'
    THEN RAISE(ABORT,'SOC invalid review note') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_principals p
      JOIN soc_tenants t ON t.tenant_id=p.tenant_id
    WHERE p.tenant_id=NEW.tenant_id AND p.principal_id=NEW.review_actor_id
      AND p.status='ACTIVE' AND t.status='ACTIVE'
      AND p.role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN')
  ) THEN RAISE(ABORT,'SOC analyst review actor unauthorized') END;
  SELECT CASE WHEN NEW.evidence_state='ANALYST_VERIFIED' AND NOT EXISTS (
    SELECT 1 FROM soc_event_receipts e
    WHERE e.tenant_id=NEW.tenant_id AND e.event_id=NEW.event_id
      AND NEW.review_basis_sha256=e.digest_sha256
      AND length(NEW.review_basis_sha256)=64
  ) THEN RAISE(ABORT,'SOC reviewer must confirm source payload digest') END;
  SELECT CASE WHEN NEW.evidence_state='REJECTED' AND
    NEW.review_basis_sha256 IS NOT NULL
    THEN RAISE(ABORT,'SOC rejected detection may not assert verified evidence') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_detection_review_audit
AFTER UPDATE ON soc_detections
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,resource_type,
    resource_id,outcome,request_id,event_at
  ) VALUES (
    NEW.tenant_id,lower(hex(randomblob(16))),'ANALYST',NEW.review_actor_id,
    CASE WHEN NEW.evidence_state='ANALYST_VERIFIED'
      THEN 'DETECTION_ANALYST_VERIFIED' ELSE 'DETECTION_REJECTED' END,
    'DETECTION',NEW.detection_id,'ALLOW',
    NEW.review_request_id,NEW.reviewed_at
  );
END;

CREATE TRIGGER IF NOT EXISTS soc_detection_no_delete
BEFORE DELETE ON soc_detections
BEGIN
  SELECT RAISE(ABORT,'SOC detection hard delete prohibited');
END;

-- Incident attribution: an incident may link only an analyst-verified
-- detection. Link actor is a separately authenticated active SOC analyst,
-- and every link must be written with an atomic tenant-scoped audit.
ALTER TABLE soc_incident_detections ADD COLUMN linked_by TEXT;
ALTER TABLE soc_incident_detections ADD COLUMN link_request_id TEXT;

CREATE TRIGGER IF NOT EXISTS soc_incident_detection_link_guard
BEFORE INSERT ON soc_incident_detections
BEGIN
  SELECT CASE WHEN NEW.linked_by IS NULL OR NEW.link_request_id IS NULL
    OR length(NEW.link_request_id) NOT BETWEEN 16 AND 128
    THEN RAISE(ABORT,'SOC incident detection link requires actor and request') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_principals p
      JOIN soc_tenants t ON t.tenant_id=p.tenant_id
    WHERE p.tenant_id=NEW.tenant_id AND p.principal_id=NEW.linked_by
      AND p.status='ACTIVE' AND t.status='ACTIVE'
      AND p.role IN ('ANALYST','LEAD_ANALYST','TENANT_ADMIN')
  ) THEN RAISE(ABORT,'SOC incident link actor unauthorized') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_detections d
      JOIN soc_incidents i ON i.tenant_id=d.tenant_id
    WHERE d.tenant_id=NEW.tenant_id AND d.detection_id=NEW.detection_id
      AND d.evidence_state='ANALYST_VERIFIED'
      AND i.incident_id=NEW.incident_id AND i.state<>'CLOSED'
  ) THEN RAISE(ABORT,'SOC incident may link only verified same-tenant detection') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_incident_detection_link_audit
AFTER INSERT ON soc_incident_detections
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,resource_type,
    resource_id,outcome,request_id,event_at
  ) VALUES (
    NEW.tenant_id,lower(hex(randomblob(16))),'ANALYST',NEW.linked_by,
    'INCIDENT_DETECTION_LINKED','INCIDENT',NEW.incident_id,'ALLOW',
    NEW.link_request_id,NEW.linked_at
  );
END;

CREATE TRIGGER IF NOT EXISTS soc_incident_detection_link_no_update
BEFORE UPDATE ON soc_incident_detections
BEGIN
  SELECT RAISE(ABORT,'SOC incident detection link immutable');
END;
CREATE TRIGGER IF NOT EXISTS soc_incident_detection_link_no_delete
BEFORE DELETE ON soc_incident_detections
BEGIN
  SELECT RAISE(ABORT,'SOC incident detection link hard delete prohibited');
END;
