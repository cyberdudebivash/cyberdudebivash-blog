-- SENTINEL APEX SOC: gated durable customer notification fanout outbox.
-- SOURCE ONLY: do not apply this migration to remote D1 until owner-approved
-- account-wide FinOps + security + customer-delivery acceptance passes.
-- No backfill: only events observed AFTER explicit gated activation qualify.
-- Records hold owner/watchlist identifiers only; no email, webhook URL,
-- signing key, threat payload or customer secret is stored here.
CREATE TABLE IF NOT EXISTS soc_notification_outbox (
  event_id          TEXT NOT NULL,
  watchlist_id      TEXT NOT NULL,
  owner_id          TEXT NOT NULL,
  state             TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','claimed','complete','skipped','blocked')),
  attempt_count     INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_ms   INTEGER NOT NULL,
  lease_expires_ms  INTEGER,
  claim_token       TEXT,
  last_error_code   TEXT NOT NULL DEFAULT '',
  created_at_ms     INTEGER NOT NULL,
  updated_at_ms     INTEGER NOT NULL,
  PRIMARY KEY (event_id, watchlist_id, owner_id)
);
CREATE INDEX IF NOT EXISTS idx_soc_outbox_due
  ON soc_notification_outbox (state, next_attempt_ms, created_at_ms);
-- Explicit lease-expiry seek. A state-only index may scan ALL claimed
-- rows before satisfying the expiry predicate despite LIMIT 5.
CREATE INDEX IF NOT EXISTS idx_soc_outbox_expired
  ON soc_notification_outbox (state, lease_expires_ms);
CREATE INDEX IF NOT EXISTS idx_soc_outbox_retention
  ON soc_notification_outbox (state, updated_at_ms);
