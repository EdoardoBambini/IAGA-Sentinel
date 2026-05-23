CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tenant_id TEXT DEFAULT NULL,
    framework TEXT NOT NULL,
    action_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    review_status TEXT NOT NULL,
    reasons TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS review_requests (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tenant_id TEXT DEFAULT NULL,
    workspace_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    risk_score INTEGER NOT NULL,
    reasons TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_profiles (
    agent_id TEXT PRIMARY KEY,
    tenant_id TEXT DEFAULT NULL,
    workspace_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    role TEXT NOT NULL,
    approved_tools TEXT NOT NULL,
    approved_secrets TEXT NOT NULL,
    baseline_action_types TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS workspace_policies (
    workspace_id TEXT PRIMARY KEY,
    tenant_id TEXT DEFAULT NULL,
    allowed_protocols TEXT NOT NULL,
    allowed_domains TEXT NOT NULL,
    tools TEXT NOT NULL,
    threshold_block INTEGER NOT NULL DEFAULT 70,
    threshold_review INTEGER NOT NULL DEFAULT 35,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT DEFAULT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
