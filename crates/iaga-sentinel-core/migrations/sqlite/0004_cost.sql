-- 1.5 cost-control (ADR 0020): per-action usage/cost ledger denormalized onto
-- audit_events for fast aggregation, plus a durable cumulative spend table
-- keyed by (agent_id, session_id) backing the SpendStore.
--
-- All audit_events columns are nullable: rows written before 1.5, and rows for
-- actions with no reported usage, simply leave them NULL. The signed receipt
-- remains the exact ledger; cost_usd here is a denormalized REAL for reporting.

ALTER TABLE audit_events ADD COLUMN usage_json TEXT DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN cost_usd REAL DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN savings_usd REAL DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN total_tokens INTEGER DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN cache_hit INTEGER DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN provider TEXT DEFAULT NULL;
ALTER TABLE audit_events ADD COLUMN model TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_events_model ON audit_events(model);

CREATE TABLE IF NOT EXISTS agent_spend (
    agent_id   TEXT NOT NULL,
    session_id TEXT NOT NULL,
    total_usd  REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, session_id)
);
