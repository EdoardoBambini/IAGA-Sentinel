use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::plugins::PluginOutput;

// 1.5 cost-control: the canonical cost/usage types live in the leaf crate
// `iaga-sentinel-cost`; re-exported here so the rest of core (and tests) can
// reach them via `crate::core::types::*`.
pub use iaga_sentinel_cost::{CostSource, UsageData, UsageReport};

// ── Tenant ──

/// A tenant owns multiple workspaces. All data is scoped to a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    pub tenant_id: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

// ── Enums ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolKind {
    Mcp,
    Acp,
    A2a,
    HttpFunction,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Shell,
    FileRead,
    FileWrite,
    Http,
    DbQuery,
    Email,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GovernanceDecision {
    Allow,
    Review,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    NotRequired,
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    Builder,
    Researcher,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewAction {
    Approved,
    Rejected,
}

// ── Request / Response ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectRequest {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub framework: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ProtocolKind>,
    pub action: ActionDetail,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_secrets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// 1.5 cost-control: optional usage reported by the caller (an agent SDK or
    /// any client). Captured into the receipt + audit cost ledger when the host
    /// build enables `cost-control`; ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionDetail {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    pub tool_name: String,
    pub payload: HashMap<String, serde_json::Value>,
}

// ── Risk ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u32,
    pub decision: GovernanceDecision,
    pub reasons: Vec<String>,
}

// ── Profiles & Policies ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProfile {
    pub agent_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub workspace_id: String,
    pub framework: String,
    pub role: AgentRole,
    pub approved_tools: Vec<String>,
    pub approved_secrets: Vec<String>,
    pub baseline_action_types: Vec<ActionType>,
    /// Default tool trust score for risk scoring (0.0-1.0). Defaults to 0.7.
    #[serde(default = "default_tool_trust")]
    pub tool_trust: f64,
}

fn default_tool_trust() -> f64 {
    0.7
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPolicy {
    pub tool_name: String,
    pub allowed_action_types: Vec<ActionType>,
    pub max_decision: GovernanceDecision,
    #[serde(default)]
    pub requires_human_review: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePolicy {
    pub workspace_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub allowed_protocols: Vec<ProtocolKind>,
    pub tools: Vec<ToolPolicy>,
    pub allowed_domains: Vec<String>,
    /// Risk score threshold for blocking decisions (0-100). Default: 70.
    #[serde(default = "default_threshold_block")]
    pub threshold_block: u32,
    /// Risk score threshold for review decisions (0-100). Default: 35.
    #[serde(default = "default_threshold_review")]
    pub threshold_review: u32,
}

fn default_threshold_block() -> u32 {
    70
}

fn default_threshold_review() -> u32 {
    35
}

// ── Secrets ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInjectionPlan {
    pub approved: Vec<String>,
    pub denied: Vec<String>,
}

// ── Audit ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub event_id: String,
    pub agent_id: String,
    pub framework: String,
    pub action_type: ActionType,
    pub tool_name: String,
    pub decision: GovernanceDecision,
    pub timestamp: String,
    pub reasons: Vec<String>,
}

// ── Governance Result ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaValidation {
    pub tool_name: String,
    pub valid: bool,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceResult {
    pub trace_id: String,
    pub protocol: ProtocolKind,
    pub normalized_payload: HashMap<String, serde_json::Value>,
    pub decision: GovernanceDecision,
    pub review_status: ReviewStatus,
    pub risk: RiskScore,
    pub secret_plan: SecretInjectionPlan,
    pub audit_event: AuditEvent,
    pub profile: AgentProfile,
    pub workspace_policy: WorkspacePolicy,
    pub policy_findings: Vec<String>,
    pub schema_validation: SchemaValidation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_request_id: Option<String>,
    // ── 8-Layer Security Stack ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_graph: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_analysis: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adaptive_risk: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_firewall: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_verification: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry_span: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral_fingerprint: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_intel: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_results: Option<Vec<PluginOutput>>,
    /// Advisory signals computed from process-global mutable state (session
    /// burst + prior-block history, adaptive baseline velocity/novelty,
    /// behavioral fingerprint anomalies). Surfaced for dashboards/alerting but
    /// DELIBERATELY excluded from the signed verdict (`decision`/`risk`/
    /// `reasons`), so the receipt stays reproducible from its recorded inputs
    /// alone (D1 / DET-* cluster). `None` when no advisory signal fired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<serde_json::Value>,
}

// ── Review Request ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRequest {
    pub id: String,
    pub agent_id: String,
    pub workspace_id: String,
    pub tool_name: String,
    pub decision: GovernanceDecision,
    pub status: String,
    pub risk_score: u32,
    pub reasons: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ── Stored Audit Event (with extra fields) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAuditEvent {
    pub event_id: String,
    pub agent_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub framework: String,
    pub action_type: ActionType,
    pub tool_name: String,
    /// SHA-256 (hex) of the canonical action payload. Computed once in the
    /// pipeline and bound into the signed receipt's `input_hash`
    /// (PROOF-INPUTHASH-BIND-3), so the receipt commits to *what* the action
    /// did, not just which tool ran. Not persisted as an audit-store column;
    /// `#[serde(default)]` leaves it empty for events read back from the DB or
    /// deserialized from before this field existed.
    #[serde(default)]
    pub input_sha256: String,
    pub decision: GovernanceDecision,
    pub timestamp: String,
    pub reasons: Vec<String>,
    pub review_status: ReviewStatus,
    pub risk_score: u32,
    /// 1.5 cost-control: optional usage/cost ledger for this action.
    /// `None` (and elided) unless the host captured usage for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<iaga_sentinel_cost::UsageData>,
    /// Explicit `metadata.sessionId` for this action, when the caller supplied
    /// one. Used as the signed-receipt `run_id` so multiple actions in a logical
    /// session form one hash-chained run. `None` (and elided from serialization)
    /// when absent, in which case the receipt logger falls back to `event_id`
    /// (one receipt per run) and the serialized event stays byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

// ── Response Scanning ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseDecision {
    Allow,
    Review,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseScanRequest {
    pub request_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub response_payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseScanResult {
    pub request_id: String,
    pub decision: ResponseDecision,
    pub risk_score: u32,
    pub findings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SensitivePattern {
    pub name: String,
    pub description: String,
    pub category: String,
}

// ── Agent Behavioral Fingerprint (API response) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentFingerprintResponse {
    pub agent_id: String,
    pub total_requests: u64,
    pub tool_usage: HashMap<String, u64>,
    pub action_types: HashMap<String, u64>,
    pub avg_risk_score: f64,
    pub peak_risk_score: f64,
    pub hourly_pattern: [u64; 24],
    pub anomaly_score: f64,
    pub first_seen: String,
    pub last_seen: String,
    pub flags: Vec<String>,
}

// ── Rate Limiting ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    pub max_per_minute: u32,
    pub max_per_hour: u32,
    pub burst_limit: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_minute: 60,
            max_per_hour: 1000,
            burst_limit: 10,
        }
    }
}

// ── Config file ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub profiles: Vec<AgentProfile>,
    pub workspaces: Vec<WorkspacePolicy>,
    #[serde(default)]
    pub vault: Vec<String>,
}

// ── Audit Export & Analytics ──

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportFilter {
    pub tenant_id: Option<String>,
    pub agent_id: Option<String>,
    pub decision: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditStats {
    pub total_events: u64,
    pub decisions: HashMap<String, u64>,
    pub top_agents: Vec<(String, u64)>,
    pub top_tools: Vec<(String, u64)>,
    pub avg_risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAnalytics {
    pub agent_id: String,
    pub total_requests: u64,
    pub decisions: HashMap<String, u64>,
    pub avg_risk_score: f64,
    pub top_tools: Vec<(String, u64)>,
    pub last_activity: String,
    pub trust_score: f64,
}

// ── Cost Control (1.5) ──

/// Aggregate spend over a window. `gross = net + savings`: `net` is what was
/// actually paid, `savings` is what cache hits avoided.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CostSummary {
    pub gross_cost_usd: f64,
    pub net_cost_usd: f64,
    pub savings_usd: f64,
    pub total_tokens: u64,
    pub cache_hits: u64,
    pub total_actions: u64,
}

/// Spend grouped by a single key (agent, model, or tool).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostByKey {
    pub key: String,
    pub net_cost_usd: f64,
    pub savings_usd: f64,
    pub total_tokens: u64,
    pub actions: u64,
    pub cache_hits: u64,
}

/// Spend in one time bucket (hourly or daily) for trend charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostBucket {
    pub bucket: String,
    pub net_cost_usd: f64,
    pub savings_usd: f64,
    pub total_tokens: u64,
    pub actions: u64,
}

/// Query parameters shared by the `/v1/cost/*` endpoints and the `iaga cost`
/// CLI. All optional; `bucket` is `"hour"` (default) or `"day"`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CostQuery {
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub bucket: Option<String>,
    pub limit: Option<u32>,
}

// ── Demo scenario ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoScenario {
    pub step: String,
    pub title: String,
    pub request: InspectRequest,
}

#[derive(Debug, Serialize)]
pub struct DemoResult {
    pub step: String,
    pub title: String,
    pub decision: GovernanceDecision,
    pub risk: u32,
}
