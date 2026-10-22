-- SENTINEL APEX SOC Phase 12 — opaque provider event identity and source proof.
--
-- ADDITIVE, OFFLINE REVIEW ONLY. Requires migrations 0009..0014.
-- Do not apply remotely without customer-authorized data residency/retention,
-- migration inventory, backups, approval, native D1 rehearsal and roll-back.
--
-- Original signed HMAC-v2 envelope includes sourceEventId. Before this change
-- only a SHA-256 receipt ID was stored; a trusted EDR/SIEM source adapter
-- therefore could not locate the exact original event for independent review.
--
-- Store the provider's restricted OPAQUE technical event ID, never raw event
-- payload, credentials, email/user IP/PII, or arbitrary input. Existing rows
-- remain NULL and are INELIGIBLE for the new independent verifier; historical
-- recovery requires a separate authorized, auditable reconciliation.
ALTER TABLE soc_event_receipts ADD COLUMN source_event_id TEXT;

CREATE TRIGGER IF NOT EXISTS soc_source_event_identity_insert_guard
BEFORE INSERT ON soc_event_receipts
BEGIN
  SELECT CASE WHEN NEW.source_event_id IS NULL
    OR length(NEW.source_event_id) NOT BETWEEN 1 AND 128
    OR NEW.source_event_id GLOB '*[^A-Za-z0-9_.:-]*'
    THEN RAISE(ABORT,'SOC signed opaque source event identity required') END;
END;

-- The migration 0012 UPDATE and DELETE guards still enforce immutable receipt
-- contents, including source_event_id. No backfill or new customer data seeded.
