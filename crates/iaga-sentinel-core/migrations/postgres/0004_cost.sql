-- 1.5 cost-control (ADR 0020): per-action usage/cost ledger denormalized onto
-- audit_events for fast aggregation, plus a durable cumulative spend table
-- keyed by (agent_id, session_id) backing the SpendStore.
--
-- All audit_events columns are nullable: rows written before 1.5, and rows for
-- actions with no reported usage, simply leave them NULL. The signed receipt
-- remains the exact ledger; cost_usd here is a denormalized double for reporting.

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS usage_json TEXT DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS savings_usd DOUBLE PRECISION DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS total_tokens BIGINT DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS provider TEXT DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS model TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_events_model ON audit_events(model);

CREATE TABLE IF NOT EXISTS agent_spend (
    agent_id   TEXT NOT NULL,
    session_id TEXT NOT NULL,
    total_usd  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, session_id)
);
