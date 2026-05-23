CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_review_status ON review_requests(status);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_profiles_tenant ON agent_profiles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_tenant ON workspace_policies(tenant_id);
