-- v0.4.0: Durable State for all 8 security layers
-- Persists NHI identities, session graphs, taint labels, behavioral fingerprints, and rate limit config.

-- ── NHI Identities ──
CREATE TABLE IF NOT EXISTS nhi_identities (
    agent_id        TEXT PRIMARY KEY,
    spiffe_id       TEXT NOT NULL,
    public_key_hex  TEXT NOT NULL,
    secret_key_hex  TEXT NOT NULL,
    attestation_status TEXT NOT NULL DEFAULT 'registered',
    trust_score     REAL NOT NULL DEFAULT 0.5,
    capabilities    TEXT NOT NULL DEFAULT '[]',  -- JSON array
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── NHI Challenges ──
CREATE TABLE IF NOT EXISTS nhi_challenges (
    challenge_id    TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    nonce           TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_nhi_challenges_agent ON nhi_challenges(agent_id);
CREATE INDEX IF NOT EXISTS idx_nhi_challenges_expires ON nhi_challenges(expires_at);

-- ── Session Graphs ──
CREATE TABLE IF NOT EXISTS session_graphs (
    session_id      TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'idle',
    blocked         INTEGER NOT NULL DEFAULT 0,
    block_reason    TEXT,
    blocked_at      INTEGER NOT NULL DEFAULT 0,
    block_count     INTEGER NOT NULL DEFAULT 0,
    nodes_json      TEXT NOT NULL DEFAULT '[]',  -- JSON array of ToolCallNode
    edges_json      TEXT NOT NULL DEFAULT '[]',  -- JSON array of DataFlowEdge
    created_at      INTEGER NOT NULL DEFAULT 0,
    last_activity   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_session_graphs_agent ON session_graphs(agent_id);
CREATE INDEX IF NOT EXISTS idx_session_graphs_activity ON session_graphs(last_activity);

-- ── Taint Sessions ──
CREATE TABLE IF NOT EXISTS taint_sessions (
    session_id      TEXT PRIMARY KEY,
    labels_json     TEXT NOT NULL DEFAULT '[]',  -- JSON array of taint labels
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Behavioral Fingerprints ──
CREATE TABLE IF NOT EXISTS fingerprints (
    agent_id        TEXT PRIMARY KEY,
    total_requests  INTEGER NOT NULL DEFAULT 0,
    tool_usage      TEXT NOT NULL DEFAULT '{}',  -- JSON map
    action_types    TEXT NOT NULL DEFAULT '{}',  -- JSON map
    avg_risk_score  REAL NOT NULL DEFAULT 0.0,
    peak_risk_score REAL NOT NULL DEFAULT 0.0,
    hourly_pattern  TEXT NOT NULL DEFAULT '[]',  -- JSON array of 24 ints
    anomaly_score   REAL NOT NULL DEFAULT 0.0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    flags           TEXT NOT NULL DEFAULT '[]',  -- JSON array
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Rate Limit Config ──
CREATE TABLE IF NOT EXISTS rate_limit_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    max_per_minute  INTEGER NOT NULL DEFAULT 60,
    max_per_hour    INTEGER NOT NULL DEFAULT 1000,
    burst_limit     INTEGER NOT NULL DEFAULT 10,
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Policy Rules (v2 rules engine) ──
CREATE TABLE IF NOT EXISTS policy_rules (
    id              TEXT PRIMARY KEY,
    workspace_id    TEXT NOT NULL,
    name            TEXT NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    match_criteria  TEXT NOT NULL DEFAULT '{}',  -- JSON
    conditions      TEXT NOT NULL DEFAULT '{}',  -- JSON
    decision        TEXT NOT NULL,
    reason          TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_policy_rules_workspace ON policy_rules(workspace_id);

-- ── Policy Templates ──
CREATE TABLE IF NOT EXISTS policy_templates (
    template_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT 'general',
    workspace_json  TEXT NOT NULL,  -- JSON WorkspacePolicy
    rules_json      TEXT NOT NULL DEFAULT '[]',  -- JSON array of rules
    builtin         INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
