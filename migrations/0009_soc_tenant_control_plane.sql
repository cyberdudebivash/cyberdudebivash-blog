-- SENTINEL APEX SOC -- tenant-isolated, control-plane-only schema v0.
-- Source-only review: DO NOT apply to remote D1 or enable customer endpoints.
-- Does not store raw logs, secrets, customer telemetry payloads, payments,
-- incident claims or test tenants. No seed data or implicit account activation.
--
-- Cloudflare D1 enforces foreign keys; composite (tenant_id, resource_id)
-- references prevent cross-tenant linking even if an application has a bug.
-- Authorization of reads/queries is STILL an application responsibility.
--
-- No CASCADE deletes. Retention, legal holds, erasure and key rotation need
-- a separately designed and customer-approved lifecycle before live ingestion.

CREATE TABLE IF NOT EXISTS soc_tenants (
  tenant_id TEXT PRIMARY KEY
    CHECK (length(tenant_id) BETWEEN 3 AND 64 AND tenant_id NOT GLOB '*[^a-z0-9_-]*'),
  legal_name TEXT NOT NULL CHECK (length(legal_name) BETWEEN 1 AND 240),
  status TEXT NOT NULL DEFAULT 'PROVISIONING'
    CHECK (status IN ('PROVISIONING','ACTIVE','SUSPENDED','RETIRED')),
  data_region TEXT NOT NULL DEFAULT 'UNDECIDED',
  retention_days INTEGER CHECK (retention_days BETWEEN 1 AND 3650),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (status <> 'ACTIVE' OR (retention_days IS NOT NULL AND data_region <> 'UNDECIDED'))
);

CREATE INDEX IF NOT EXISTS idx_soc_tenants_status ON soc_tenants(status);

CREATE TABLE IF NOT EXISTS soc_principals (
  tenant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 128),
  oidc_issuer TEXT NOT NULL CHECK (length(oidc_issuer) BETWEEN 1 AND 512),
  oidc_subject TEXT NOT NULL CHECK (length(oidc_subject) BETWEEN 1 AND 512),
  role TEXT NOT NULL CHECK (role IN ('READ_ONLY','ANALYST','LEAD_ANALYST','TENANT_ADMIN')),
  status TEXT NOT NULL DEFAULT 'INVITED' CHECK (status IN ('INVITED','ACTIVE','REVOKED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,principal_id),
  UNIQUE (tenant_id,oidc_issuer,oidc_subject),
  FOREIGN KEY (tenant_id) REFERENCES soc_tenants(tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_principals_status
  ON soc_principals(tenant_id,status,role);

CREATE TABLE IF NOT EXISTS soc_connectors (
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('SIEM','EDR','CLOUD','IDENTITY','WEBHOOK','OTHER')),
  config_ref TEXT, -- reference only, NEVER a credential or raw secret
  authorized_scope TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'DRAFT'
    CHECK (state IN ('DRAFT','APPROVED','PAUSED','REVOKED')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,connector_id),
  FOREIGN KEY (tenant_id) REFERENCES soc_tenants(tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id,created_by) REFERENCES soc_principals(tenant_id,principal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_connectors_state
  ON soc_connectors(tenant_id,state);

-- Event METADATA ONLY: no source payload, raw logs or raw telemetry in D1.
CREATE TABLE IF NOT EXISTS soc_event_receipts (
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  source_event_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  digest_sha256 TEXT NOT NULL
    CHECK (length(digest_sha256)=64 AND digest_sha256 NOT GLOB '*[^0-9a-f]*'),
  payload_location_ref TEXT, -- external reference; not a D1 telemetry lake
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,event_id),
  FOREIGN KEY (tenant_id,connector_id) REFERENCES soc_connectors(tenant_id,connector_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_events_received
  ON soc_event_receipts(tenant_id,received_at DESC);

CREATE TABLE IF NOT EXISTS soc_detections (
  tenant_id TEXT NOT NULL,
  detection_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
  evidence_state TEXT NOT NULL DEFAULT 'SOURCE_REPORTED'
    CHECK (evidence_state IN ('SOURCE_REPORTED','ANALYST_VERIFIED','REJECTED')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,detection_id),
  FOREIGN KEY (tenant_id,event_id) REFERENCES soc_event_receipts(tenant_id,event_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_detections_evidence
  ON soc_detections(tenant_id,evidence_state,created_at DESC);

CREATE TABLE IF NOT EXISTS soc_incidents (
  tenant_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
  severity TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  state TEXT NOT NULL DEFAULT 'OPEN'
    CHECK (state IN ('OPEN','TRIAGE','INVESTIGATING','AWAITING_APPROVAL','CONTAINED','RESOLVED','CLOSED')),
  owner_id TEXT,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,incident_id),
  FOREIGN KEY (tenant_id) REFERENCES soc_tenants(tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id,owner_id) REFERENCES soc_principals(tenant_id,principal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_queue
  ON soc_incidents(tenant_id,state,severity,updated_at DESC);

CREATE TABLE IF NOT EXISTS soc_incident_detections (
  tenant_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  detection_id TEXT NOT NULL,
  linked_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,incident_id,detection_id),
  FOREIGN KEY (tenant_id,incident_id) REFERENCES soc_incidents(tenant_id,incident_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id,detection_id) REFERENCES soc_detections(tenant_id,detection_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS soc_evidence_manifests (
  tenant_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL
    CHECK (length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
  evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('EVENT','DOCUMENT','FORENSIC_ARTIFACT','OTHER')),
  collector_id TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  retention_until TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,manifest_id),
  UNIQUE (tenant_id,object_key),
  -- Reject an object path whose tenant prefix disagrees with the database tenant.
  CHECK (substr(object_key,1,length(tenant_id)+5)='soc/' || tenant_id || '/'
    AND length(object_key)>length(tenant_id)+5
    AND instr(object_key,'..')=0
    AND instr(object_key,'//')=0),
  FOREIGN KEY (tenant_id,incident_id) REFERENCES soc_incidents(tenant_id,incident_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id,collector_id) REFERENCES soc_principals(tenant_id,principal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_evidence_incident
  ON soc_evidence_manifests(tenant_id,incident_id,collected_at DESC);

CREATE TABLE IF NOT EXISTS soc_audit_events (
  tenant_id TEXT NOT NULL,
  audit_id TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('SYSTEM','ANALYST')),
  actor_id TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('ALLOW','DENY','ERROR')),
  request_id TEXT NOT NULL,
  event_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id,audit_id),
  CHECK (actor_type <> 'ANALYST' OR actor_id IS NOT NULL),
  FOREIGN KEY (tenant_id) REFERENCES soc_tenants(tenant_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id,actor_id) REFERENCES soc_principals(tenant_id,principal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_audit_timeline
  ON soc_audit_events(tenant_id,event_at DESC);

CREATE TRIGGER IF NOT EXISTS soc_audit_events_no_update
BEFORE UPDATE ON soc_audit_events
BEGIN
  SELECT RAISE(ABORT,'SOC audit log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS soc_audit_events_no_delete
BEFORE DELETE ON soc_audit_events
BEGIN
  SELECT RAISE(ABORT,'SOC audit log is append-only');
END;

-- All tables start empty. No SOC customer data is created by this migration.
