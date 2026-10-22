-- SENTINEL APEX SOC — bounded Cloudflare Cron watchlist sweep.
-- Separate from watchlist_eval_state.cursor (legacy GitHub publisher offset).
-- Must be applied via an explicitly authorized migration before enabling SOC
-- Cron; absence of this table fails closed in the bounded evaluator.
-- No data backfill or full-table migration scan is required.
CREATE TABLE IF NOT EXISTS watchlist_eval_keyset_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL
);
