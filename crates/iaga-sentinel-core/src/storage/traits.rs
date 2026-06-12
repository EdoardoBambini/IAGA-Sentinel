use async_trait::async_trait;

use crate::core::errors::SentinelError;
use crate::core::types::*;
use crate::modules::fingerprint::behavioral::AgentFingerprint;
use crate::modules::nhi::crypto_identity::{AgentIdentity, PendingChallenge};
use crate::modules::policy::rules_engine::PolicyRule;
use crate::modules::session_graph::session_dag::SessionDAG;
use std::collections::HashSet;

// Re-export async_trait for enterprise to use
pub use async_trait::async_trait as storage_async_trait;

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, event: &StoredAuditEvent) -> Result<(), SentinelError>;
    async fn list(&self, limit: u32) -> Result<Vec<StoredAuditEvent>, SentinelError>;
    async fn list_filtered(
        &self,
        filter: &AuditExportFilter,
    ) -> Result<Vec<StoredAuditEvent>, SentinelError>;
    async fn stats(&self) -> Result<AuditStats, SentinelError>;
    async fn agent_analytics(
        &self,
        agent_id: Option<&str>,
    ) -> Result<Vec<AgentAnalytics>, SentinelError>;

    // ── 1.5 cost-control aggregation ──
    // Default impls return empty/zero so non-SQL stores keep compiling; the
    // SQLite and Postgres backends override them with real queries over the
    // denormalized cost columns. `from`/`to` are optional RFC3339 bounds.
    async fn cost_summary(
        &self,
        _from: Option<&str>,
        _to: Option<&str>,
    ) -> Result<CostSummary, SentinelError> {
        Ok(CostSummary::default())
    }
    async fn cost_by_agent(
        &self,
        _from: Option<&str>,
        _to: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<CostByKey>, SentinelError> {
        Ok(Vec::new())
    }
    async fn cost_by_model(
        &self,
        _from: Option<&str>,
        _to: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<CostByKey>, SentinelError> {
        Ok(Vec::new())
    }
    async fn cost_by_tool(
        &self,
        _from: Option<&str>,
        _to: Option<&str>,
        _limit: u32,
    ) -> Result<Vec<CostByKey>, SentinelError> {
        Ok(Vec::new())
    }
    async fn cost_over_time(
        &self,
        _from: Option<&str>,
        _to: Option<&str>,
        _bucket: &str,
    ) -> Result<Vec<CostBucket>, SentinelError> {
        Ok(Vec::new())
    }
}

#[async_trait]
pub trait ReviewStore: Send + Sync {
    async fn create(&self, review: &ReviewRequest) -> Result<(), SentinelError>;
    async fn get(&self, id: &str) -> Result<ReviewRequest, SentinelError>;
    async fn update_status(&self, id: &str, status: &str) -> Result<ReviewRequest, SentinelError>;
    async fn list(&self) -> Result<Vec<ReviewRequest>, SentinelError>;
}

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn get_agent_profile(&self, agent_id: &str) -> Result<AgentProfile, SentinelError>;
    async fn get_workspace_policy(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspacePolicy, SentinelError>;
    async fn list_workspace_rules(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<PolicyRule>, SentinelError>;
    async fn list_profiles(&self) -> Result<Vec<AgentProfile>, SentinelError>;
    async fn list_workspaces(&self) -> Result<Vec<WorkspacePolicy>, SentinelError>;
    async fn upsert_profile(&self, profile: &AgentProfile) -> Result<(), SentinelError>;
    async fn upsert_workspace(&self, policy: &WorkspacePolicy) -> Result<(), SentinelError>;
    async fn upsert_workspace_rule(
        &self,
        workspace_id: &str,
        rule: &PolicyRule,
    ) -> Result<(), SentinelError>;
    async fn delete_profile(&self, agent_id: &str) -> Result<(), SentinelError>;
    async fn delete_workspace(&self, workspace_id: &str) -> Result<(), SentinelError>;
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn store_key(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
    ) -> Result<(), SentinelError>;
    /// Verify a raw API key against all stored hashes. Returns true if any match.
    async fn verify_raw_key(&self, raw_key: &str) -> Result<bool, SentinelError>;
    async fn delete_key(&self, key_id: &str) -> Result<(), SentinelError>;
    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, SentinelError>;

    /// Store a key with an explicit [`KeyScope`] (1.5.2). The default
    /// implementation delegates to [`store_key`](Self::store_key), which on a
    /// migrated database persists the `scope` column default (`admin`), so
    /// legacy implementors keep working unchanged.
    async fn store_key_scoped(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
        _scope: KeyScope,
    ) -> Result<(), SentinelError> {
        self.store_key(key_id, key_hash, label, raw_key).await
    }

    /// Verify a raw API key and return its identity + scope (1.5.2). The
    /// default implementation wraps [`verify_raw_key`](Self::verify_raw_key)
    /// and reports `Admin` scope on match, preserving the historical
    /// "any valid key may do anything" behavior for legacy implementors.
    async fn verify_raw_key_scoped(
        &self,
        raw_key: &str,
    ) -> Result<Option<VerifiedKey>, SentinelError> {
        Ok(self.verify_raw_key(raw_key).await?.then_some(VerifiedKey {
            key_id: None,
            scope: KeyScope::Admin,
        }))
    }
}

/// Tenant management store (enterprise multi-tenancy support).
#[async_trait]
pub trait TenantStore: Send + Sync {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), SentinelError>;
    async fn get_tenant(&self, tenant_id: &str) -> Result<Tenant, SentinelError>;
    async fn list_tenants(&self) -> Result<Vec<Tenant>, SentinelError>;
    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), SentinelError>;
}

// ═══════════════════════════════════════════════════════════════
// v0.4.0, Durable State Storage Traits
// ═══════════════════════════════════════════════════════════════

/// Persistent storage for NHI (Non-Human Identity) layer.
#[async_trait]
pub trait NhiStore: Send + Sync {
    async fn store_identity(
        &self,
        identity: &AgentIdentity,
        secret_key_hex: &str,
    ) -> Result<(), SentinelError>;
    async fn get_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>, SentinelError>;
    async fn get_secret_key_hex(&self, agent_id: &str) -> Result<Option<String>, SentinelError>;
    async fn list_identities(&self) -> Result<Vec<AgentIdentity>, SentinelError>;
    async fn update_trust(&self, agent_id: &str, trust_score: f64) -> Result<(), SentinelError>;
    async fn store_challenge(&self, challenge: &PendingChallenge) -> Result<(), SentinelError>;
    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<PendingChallenge>, SentinelError>;
    async fn delete_challenge(&self, challenge_id: &str) -> Result<(), SentinelError>;
    async fn prune_expired_challenges(&self) -> Result<usize, SentinelError>;
}

/// Persistent storage for Session Graph layer.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn store_session(&self, session: &SessionDAG) -> Result<(), SentinelError>;
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionDAG>, SentinelError>;
    async fn list_sessions(&self) -> Result<Vec<SessionDAG>, SentinelError>;
    async fn delete_session(&self, session_id: &str) -> Result<(), SentinelError>;
    async fn prune_stale_sessions(&self, max_age_ms: u64) -> Result<usize, SentinelError>;
}

/// Persistent storage for Taint Tracking layer.
#[async_trait]
pub trait TaintStore: Send + Sync {
    async fn get_session_taint(&self, session_id: &str) -> Result<HashSet<String>, SentinelError>;
    async fn update_session_taint(
        &self,
        session_id: &str,
        labels: &HashSet<String>,
    ) -> Result<(), SentinelError>;
    async fn prune_stale_sessions(&self, max_age_secs: u64) -> Result<usize, SentinelError>;
}

/// Persistent storage for Behavioral Fingerprinting.
#[async_trait]
pub trait FingerprintStore: Send + Sync {
    async fn get_fingerprint(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentFingerprint>, SentinelError>;
    async fn upsert_fingerprint(&self, fp: &AgentFingerprint) -> Result<(), SentinelError>;
    async fn list_fingerprints(&self) -> Result<Vec<AgentFingerprint>, SentinelError>;
    async fn delete_fingerprint(&self, agent_id: &str) -> Result<(), SentinelError>;
}

/// Persistent storage for Rate Limit state.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn load_config(&self) -> Result<Option<RateLimitConfig>, SentinelError>;
    async fn save_config(&self, config: &RateLimitConfig) -> Result<(), SentinelError>;
}

/// Describes which database backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyRecord {
    pub id: String,
    pub label: String,
    pub created_at: String,
    /// 1.5.2 key scope; records persisted before the scope column default to
    /// `admin` (the historical, fully-privileged behavior).
    #[serde(default = "default_admin_scope")]
    pub scope: String,
}

fn default_admin_scope() -> String {
    KeyScope::Admin.as_str().to_string()
}

/// Privilege scope of an API key (1.5.2). `Admin` keys may also manage the
/// gateway itself (keys, webhooks, rate-limit config, threat intel, plugin
/// reloads); `Agent` keys are limited to the governance surface. Deliberately
/// minimal and single-tenant: multi-tenant/SSO/SIEM stay Enterprise (ADR 0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyScope {
    Admin,
    Agent,
}

impl KeyScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyScope::Admin => "admin",
            KeyScope::Agent => "agent",
        }
    }

    /// Tolerant parse: unknown/legacy values fall back to `Admin`, matching
    /// the migration default so old rows never lose access.
    pub fn from_db(raw: &str) -> Self {
        match raw {
            "agent" => KeyScope::Agent,
            _ => KeyScope::Admin,
        }
    }
}

/// Outcome of a successful raw-key verification, carrying the key's identity
/// and scope for downstream authorization decisions.
#[derive(Debug, Clone)]
pub struct VerifiedKey {
    /// `None` when produced by a legacy [`ApiKeyStore::verify_raw_key`]
    /// implementation that only reports a boolean match.
    pub key_id: Option<String>,
    pub scope: KeyScope,
}
