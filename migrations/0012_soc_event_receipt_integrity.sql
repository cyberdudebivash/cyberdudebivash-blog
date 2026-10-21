-- SENTINEL APEX SOC: append-only metadata-only source-attested event receipts.
-- Requires migration 0009; no production migration is authorized by this commit.
-- Event signatures are verified by a separate service before D1 inserts.
-- This database layer independently enforces approved connectors, active
-- tenants, atomic source-receipt audit, immutability and referential integrity.

-- Preserve proof-of-attestation fingerprint and signed timestamp for review.
-- Never retain the plaintext shared signing secret or raw event payload.
ALTER TABLE soc_event_receipts ADD COLUMN source_signed_at TEXT;
ALTER TABLE soc_event_receipts ADD COLUMN attestation_sha256 TEXT;

CREATE TRIGGER IF NOT EXISTS soc_event_receipt_insert_guard
BEFORE INSERT ON soc_event_receipts
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM soc_connectors c
    INNER JOIN soc_tenants t ON t.tenant_id=c.tenant_id
    WHERE c.tenant_id=NEW.tenant_id AND c.connector_id=NEW.connector_id
      AND c.state='APPROVED' AND t.status='ACTIVE'
  ) THEN RAISE(ABORT,'SOC connector not approved or tenant inactive') END;
  SELECT CASE WHEN NEW.event_id NOT GLOB 'evt_*'
    OR length(NEW.event_id)<>68
    OR substr(NEW.event_id,5) GLOB '*[^0-9a-f]*'
    THEN RAISE(ABORT,'SOC receipt ID must be deterministic SHA256') END;
  SELECT CASE WHEN NEW.source_signed_at IS NULL OR length(NEW.source_signed_at)<>24
    OR NEW.attestation_sha256 IS NULL OR length(NEW.attestation_sha256)<>64
    OR NEW.attestation_sha256 GLOB '*[^0-9a-f]*'
    THEN RAISE(ABORT,'SOC event signature attestation required') END;
  SELECT CASE WHEN NEW.payload_location_ref IS NOT NULL
    THEN RAISE(ABORT,'SOC pilot intake cannot store external payload references') END;
END;

CREATE TRIGGER IF NOT EXISTS soc_event_receipt_insert_audit
AFTER INSERT ON soc_event_receipts
BEGIN
  INSERT INTO soc_audit_events(
    tenant_id,audit_id,actor_type,actor_id,action,resource_type,
    resource_id,outcome,request_id,event_at
  ) VALUES(
    NEW.tenant_id,lower(hex(randomblob(16))),'SYSTEM',NULL,'EVENT_RECEIVED',
    'EVENT',NEW.event_id,'ALLOW','event:'||NEW.event_id,NEW.received_at
  );
END;

CREATE TRIGGER IF NOT EXISTS soc_event_receipt_no_update
BEFORE UPDATE ON soc_event_receipts
BEGIN
  SELECT RAISE(ABORT,'SOC source event receipt immutable');
END;

CREATE TRIGGER IF NOT EXISTS soc_event_receipt_no_delete
BEFORE DELETE ON soc_event_receipts
BEGIN
  SELECT RAISE(ABORT,'SOC source event receipt hard delete prohibited');
END;

-- No synthetic events, customer records or raw log storage created.
