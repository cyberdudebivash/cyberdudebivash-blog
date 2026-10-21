-- SENTINEL APEX SOC Phase 7: immutable connector signing-key registry.
-- Requires 0009 and 0012. Source-only, no approved production D1 apply.
-- No plaintext HMAC secrets, base64 secrets or raw customer telemetry in D1.
-- Activation and revocation require authenticated operator administration;
-- no public admin endpoint or self-service provisioner is part of this PR.

CREATE TABLE IF NOT EXISTS soc_connector_signing_keys (
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  key_id TEXT NOT NULL CHECK (
    length(key_id) BETWEEN 8 AND 64 AND
    key_id NOT GLOB '*[^a-z0-9_-]*'
  ),
  state TEXT NOT NULL DEFAULT 'PENDING'
    CHECK(state IN ('PENDING','ACTIVE','REVOKED')),
  valid_from_epoch INTEGER NOT NULL CHECK(valid_from_epoch>0),
  expires_epoch INTEGER NOT NULL CHECK(
    expires_epoch>valid_from_epoch AND
    expires_epoch-valid_from_epoch<=7776000
  ),
  created_by TEXT NOT NULL,
  changed_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY(tenant_id,connector_id,key_id),
  FOREIGN KEY(tenant_id,connector_id)
    REFERENCES soc_connectors(tenant_id,connector_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY(tenant_id,created_by)
    REFERENCES soc_principals(tenant_id,principal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY(tenant_id,changed_by)
    REFERENCES soc_principals(tenant_id,principal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK(
    (state='REVOKED' AND revoked_at IS NOT NULL) OR
    (state<>'REVOKED' AND revoked_at IS NULL)
  )
);
CREATE INDEX IF NOT EXISTS idx_soc_connector_key_active
ON soc_connector_signing_keys(tenant_id,connector_id,state,expires_epoch);

CREATE TRIGGER IF NOT EXISTS soc_key_insert_guard
BEFORE INSERT ON soc_connector_signing_keys
BEGIN
  SELECT CASE WHEN NEW.state<>'PENDING'
    THEN RAISE(ABORT,'SOC key must be enrolled pending') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_principals p
      JOIN soc_tenants t ON t.tenant_id=p.tenant_id
    WHERE p.tenant_id=NEW.tenant_id AND p.principal_id=NEW.created_by
      AND p.status='ACTIVE' AND p.role='TENANT_ADMIN' AND t.status='ACTIVE'
  ) OR NEW.changed_by<>NEW.created_by
    THEN RAISE(ABORT,'SOC key enrollment requires tenant admin') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_key_insert_audit
AFTER INSERT ON soc_connector_signing_keys
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,
    resource_type,resource_id,outcome,request_id,event_at
  ) VALUES(
    NEW.tenant_id,lower(hex(randomblob(16))),'ANALYST',NEW.created_by,
    'CONNECTOR_KEY_ENROLLED','CONNECTOR_KEY',NEW.connector_id||':'||NEW.key_id,
    'ALLOW','key:enroll:'||NEW.connector_id||':'||NEW.key_id,NEW.created_at
  );
END;

CREATE TRIGGER IF NOT EXISTS soc_key_update_guard
BEFORE UPDATE ON soc_connector_signing_keys
BEGIN
  SELECT CASE WHEN
      NEW.tenant_id<>OLD.tenant_id OR NEW.connector_id<>OLD.connector_id
      OR NEW.key_id<>OLD.key_id OR NEW.created_by<>OLD.created_by
      OR NEW.created_at<>OLD.created_at OR
      NEW.valid_from_epoch<>OLD.valid_from_epoch OR
      NEW.expires_epoch<>OLD.expires_epoch
    THEN RAISE(ABORT,'SOC signing key identity immutable') END;
  SELECT CASE WHEN NOT (
     (OLD.state='PENDING' AND NEW.state IN ('ACTIVE','REVOKED'))
     OR (OLD.state='ACTIVE' AND NEW.state='REVOKED')
    ) THEN RAISE(ABORT,'SOC key transition forbidden') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_principals p
      JOIN soc_tenants t ON t.tenant_id=p.tenant_id
    WHERE p.tenant_id=NEW.tenant_id AND p.principal_id=NEW.changed_by
      AND p.status='ACTIVE' AND p.role='TENANT_ADMIN' AND t.status='ACTIVE'
  ) THEN RAISE(ABORT,'SOC key change requires tenant admin') END;
  SELECT CASE WHEN NEW.state='ACTIVE' AND NOT EXISTS (
    SELECT 1 FROM soc_connectors c WHERE c.tenant_id=NEW.tenant_id
      AND c.connector_id=NEW.connector_id AND c.state='APPROVED'
  ) THEN RAISE(ABORT,'SOC connector not approved') END;
  SELECT CASE WHEN NEW.state='ACTIVE' AND
    (NEW.expires_epoch<=unixepoch('now') OR NEW.valid_from_epoch>unixepoch('now'))
    THEN RAISE(ABORT,'SOC key window not current') END;
  -- Permit one active successor during rotation; never unlimited live keys.
  SELECT CASE WHEN NEW.state='ACTIVE' AND (
    SELECT count(*) FROM soc_connector_signing_keys k
      WHERE k.tenant_id=NEW.tenant_id AND k.connector_id=NEW.connector_id
        AND k.state='ACTIVE' AND k.expires_epoch>unixepoch('now')
  )>=2 THEN RAISE(ABORT,'SOC two-key rotation limit') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_key_update_audit
AFTER UPDATE ON soc_connector_signing_keys
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,
    resource_type,resource_id,outcome,request_id,event_at
  ) VALUES(
    NEW.tenant_id,lower(hex(randomblob(16))),'ANALYST',NEW.changed_by,
    CASE WHEN NEW.state='ACTIVE' THEN 'CONNECTOR_KEY_ACTIVATED'
         ELSE 'CONNECTOR_KEY_REVOKED' END,
    'CONNECTOR_KEY',NEW.connector_id||':'||NEW.key_id,'ALLOW',
    'key:'||NEW.state||':'||NEW.connector_id||':'||NEW.key_id,
    NEW.updated_at
  );
END;

CREATE TRIGGER IF NOT EXISTS soc_key_no_delete
BEFORE DELETE ON soc_connector_signing_keys
BEGIN
  SELECT RAISE(ABORT,'SOC key ledger hard delete prohibited');
END;

ALTER TABLE soc_event_receipts ADD COLUMN signing_key_id TEXT;

-- Race safety: even if a key becomes revoked after intake's initial
-- read, receipt INSERT fails under the final database commit-time guard.
CREATE TRIGGER IF NOT EXISTS soc_event_receipt_signing_key_guard
BEFORE INSERT ON soc_event_receipts
BEGIN
  SELECT CASE WHEN NEW.signing_key_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM soc_connector_signing_keys k
    WHERE k.tenant_id=NEW.tenant_id AND k.connector_id=NEW.connector_id
      AND k.key_id=NEW.signing_key_id AND k.state='ACTIVE'
      AND k.valid_from_epoch<=unixepoch(NEW.source_signed_at)
      AND k.expires_epoch>unixepoch(NEW.source_signed_at)
      AND k.expires_epoch>unixepoch('now')
  ) THEN RAISE(ABORT,'SOC signing key inactive or expired') END;
END;

-- Existing rows remain unchanged; no tenant, key or event seeded.
