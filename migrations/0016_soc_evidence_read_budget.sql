-- SENTINEL APEX SOC Phase 14: durable, tenant-scoped evidence-read budget.
-- SOURCE ONLY. Requires 0009..0015 in order. No production D1 apply.
-- Budget is fixed five-minute windows; no event payload, provider secret,
-- user identifier or raw URL is stored.
-- This table is an admission *counter*, not an audit/event log; a successful
-- analyst verification still creates its own immutable review audit event.
CREATE TABLE IF NOT EXISTS soc_evidence_read_windows (
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  window_start_epoch INTEGER NOT NULL
    CHECK(window_start_epoch >= 0 AND window_start_epoch % 300 = 0),
  consumed INTEGER NOT NULL CHECK(consumed BETWEEN 1 AND 60),
  last_admitted_epoch INTEGER NOT NULL
    CHECK(last_admitted_epoch >= window_start_epoch AND
      last_admitted_epoch < window_start_epoch+300),
  PRIMARY KEY(tenant_id,connector_id,window_start_epoch),
  FOREIGN KEY(tenant_id,connector_id)
    REFERENCES soc_connectors(tenant_id,connector_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_soc_evidence_read_windows_expiration
  ON soc_evidence_read_windows(window_start_epoch);

-- Application uses exactly one primary-D1 UPSERT SELECT+RETURNING per attempt.
-- The SELECT verifies ACTIVE tenant and APPROVED connector even on conflicts.
-- All quota checks are handled atomically in one SQLite statement, not by
-- read-then-write. Do not update counters via a replica or split statements.
--
-- Historical rows are not seeded. Deleting old windows requires a separate
-- trusted, scheduled retention operation, after retention and legal review.
