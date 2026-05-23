-- v0.4.0: Durable State for all 8 security layers
-- Persists NHI identities, session graphs, taint labels, behavioral fingerprints, and rate limit config.

-- ── NHI Identities ──
CREATE TABLE IF NOT EXISTS nhi_identities (
    agent_id        TEXT PRIMARY KEY,
    spiffe_id       TEXT NOT NULL,
    public_key_hex  TEXT NOT NULL,
    secret_key_hex  TEXT NOT NULL,
    attestation_status TEXT NOT NULL DEFAULT 'registered',
    trust_score     DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    capabilities    JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── NHI Challenges ──
CREATE TABLE IF NOT EXISTS nhi_challenges (
    challenge_id    TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    nonce           TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_nhi_challenges_agent ON nhi_challenges(agent_id);
CREATE INDEX IF NOT EXISTS idx_nhi_challenges_expires ON nhi_challenges(expires_at);

-- ── Session Graphs ──
CREATE TABLE IF NOT EXISTS session_graphs (
    session_id      TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'idle',
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    block_reason    TEXT,
    blocked_at      BIGINT NOT NULL DEFAULT 0,
    block_count     INTEGER NOT NULL DEFAULT 0,
    nodes_json      JSONB NOT NULL DEFAULT '[]',
    edges_json      JSONB NOT NULL DEFAULT '[]',
    created_at      BIGINT NOT NULL DEFAULT 0,
    last_activity   BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_session_graphs_agent ON session_graphs(agent_id);
CREATE INDEX IF NOT EXISTS idx_session_graphs_activity ON session_graphs(last_activity);

-- ── Taint Sessions ──
CREATE TABLE IF NOT EXISTS taint_sessions (
    session_id      TEXT PRIMARY KEY,
    labels_json     JSONB NOT NULL DEFAULT '[]',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Behavioral Fingerprints ──
CREATE TABLE IF NOT EXISTS fingerprints (
    agent_id        TEXT PRIMARY KEY,
    total_requests  BIGINT NOT NULL DEFAULT 0,
    tool_usage      JSONB NOT NULL DEFAULT '{}',
    action_types    JSONB NOT NULL DEFAULT '{}',
    avg_risk_score  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    peak_risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    hourly_pattern  JSONB NOT NULL DEFAULT '[]',
    anomaly_score   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    flags           JSONB NOT NULL DEFAULT '[]',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Rate Limit Config ──
CREATE TABLE IF NOT EXISTS rate_limit_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    max_per_minute  INTEGER NOT NULL DEFAULT 60,
    max_per_hour    INTEGER NOT NULL DEFAULT 1000,
    burst_limit     INTEGER NOT NULL DEFAULT 10,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Policy Rules (v2 rules engine) ──
CREATE TABLE IF NOT EXISTS policy_rules (
    id              TEXT PRIMARY KEY,
    workspace_id    TEXT NOT NULL,
    name            TEXT NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    match_criteria  JSONB NOT NULL DEFAULT '{}',
    conditions      JSONB NOT NULL DEFAULT '{}',
    decision        TEXT NOT NULL,
    reason          TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_policy_rules_workspace ON policy_rules(workspace_id);

-- ── Policy Templates ──
CREATE TABLE IF NOT EXISTS policy_templates (
    template_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT 'general',
    workspace_json  JSONB NOT NULL,
    rules_json      JSONB NOT NULL DEFAULT '[]',
    builtin         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
