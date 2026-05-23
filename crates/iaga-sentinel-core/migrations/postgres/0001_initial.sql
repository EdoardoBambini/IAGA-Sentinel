CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    framework TEXT NOT NULL,
    action_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    review_status TEXT NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    timestamp TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS review_requests (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    workspace_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    risk_score INTEGER NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_profiles (
    agent_id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    workspace_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    role TEXT NOT NULL,
    approved_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    approved_secrets JSONB NOT NULL DEFAULT '[]'::jsonb,
    baseline_action_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspace_policies (
    workspace_id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    allowed_protocols JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    threshold_block INTEGER NOT NULL DEFAULT 70,
    threshold_review INTEGER NOT NULL DEFAULT 35,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
