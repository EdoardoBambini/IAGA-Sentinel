use async_trait::async_trait;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use super::migrations::run_sqlite_migrations;
use super::traits::*;
use crate::core::errors::SentinelError;
use crate::core::types::*;
use crate::modules::policy::rules_engine::PolicyRule;

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn new(database_url: &str) -> Result<Self, SentinelError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| SentinelError::Storage(format!("Failed to connect to SQLite: {e}")))?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    async fn run_migrations(&self) -> Result<(), SentinelError> {
        run_sqlite_migrations(&self.pool).await
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

// ── AuditStore ──

#[async_trait]
impl AuditStore for SqliteStorage {
    async fn append(&self, event: &StoredAuditEvent) -> Result<(), SentinelError> {
        let reasons = serde_json::to_string(&event.reasons).unwrap_or_default();
        let decision = serde_json::to_value(event.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("allow")
            .to_string();
        let action_type = serde_json::to_value(event.action_type)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("custom")
            .to_string();
        let review_status = serde_json::to_value(event.review_status)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("not_required")
            .to_string();

        sqlx::query(
            "INSERT INTO audit_events (event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&event.event_id)
        .bind(&event.agent_id)
        .bind(&event.tenant_id)
        .bind(&event.framework)
        .bind(&action_type)
        .bind(&event.tool_name)
        .bind(&decision)
        .bind(event.risk_score as i64)
        .bind(&review_status)
        .bind(&reasons)
        .bind(&event.timestamp)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list(&self, limit: u32) -> Result<Vec<StoredAuditEvent>, SentinelError> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT event_id, agent_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp
             FROM audit_events ORDER BY created_at DESC LIMIT ?"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_stored()).collect())
    }

    async fn list_filtered(
        &self,
        filter: &AuditExportFilter,
    ) -> Result<Vec<StoredAuditEvent>, SentinelError> {
        let limit = filter.limit.unwrap_or(1000) as i64;
        let agent = filter.agent_id.clone().unwrap_or_default();
        let decision = filter.decision.clone().unwrap_or_default();
        let from = filter.from_date.clone().unwrap_or_default();
        let to = filter.to_date.clone().unwrap_or_default();

        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT event_id, agent_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp
             FROM audit_events
             WHERE (? = '' OR agent_id = ?)
               AND (? = '' OR decision = ?)
               AND (? = '' OR timestamp >= ?)
               AND (? = '' OR timestamp <= ?)
             ORDER BY created_at DESC LIMIT ?"
        )
        .bind(&agent).bind(&agent)
        .bind(&decision).bind(&decision)
        .bind(&from).bind(&from)
        .bind(&to).bind(&to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_stored()).collect())
    }

    async fn stats(&self) -> Result<AuditStats, SentinelError> {
        use sqlx::Row;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await?;

        let avg: f64 =
            sqlx::query_scalar("SELECT COALESCE(AVG(risk_score), 0.0) FROM audit_events")
                .fetch_one(&self.pool)
                .await?;

        let decision_rows = sqlx::query(
            "SELECT decision, COUNT(*) as cnt FROM audit_events GROUP BY decision ORDER BY cnt DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut decisions = std::collections::HashMap::new();
        for row in &decision_rows {
            let d: String = row.try_get("decision")?;
            let c: i64 = row.try_get("cnt")?;
            decisions.insert(d, c as u64);
        }

        let agent_rows = sqlx::query(
            "SELECT agent_id, COUNT(*) as cnt FROM audit_events GROUP BY agent_id ORDER BY cnt DESC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let top_agents: Vec<(String, u64)> = agent_rows
            .iter()
            .map(|r| {
                let a: String = r.try_get("agent_id").unwrap_or_default();
                let c: i64 = r.try_get("cnt").unwrap_or(0);
                (a, c as u64)
            })
            .collect();

        let tool_rows = sqlx::query(
            "SELECT tool_name, COUNT(*) as cnt FROM audit_events GROUP BY tool_name ORDER BY cnt DESC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let top_tools: Vec<(String, u64)> = tool_rows
            .iter()
            .map(|r| {
                let t: String = r.try_get("tool_name").unwrap_or_default();
                let c: i64 = r.try_get("cnt").unwrap_or(0);
                (t, c as u64)
            })
            .collect();

        Ok(AuditStats {
            total_events: total as u64,
            decisions,
            top_agents,
            top_tools,
            avg_risk_score: avg,
        })
    }

    async fn agent_analytics(
        &self,
        agent_id: Option<&str>,
    ) -> Result<Vec<AgentAnalytics>, SentinelError> {
        use sqlx::Row;

        let agent_filter = agent_id.unwrap_or("");

        let rows = sqlx::query(
            "SELECT agent_id,
                    COUNT(*) as total,
                    AVG(risk_score) as avg_risk,
                    MAX(timestamp) as last_ts,
                    GROUP_CONCAT(DISTINCT decision) as decisions_csv,
                    GROUP_CONCAT(tool_name) as tools_csv
             FROM audit_events
             WHERE ? = '' OR agent_id = ?
             GROUP BY agent_id
             ORDER BY total DESC",
        )
        .bind(agent_filter)
        .bind(agent_filter)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in &rows {
            let aid: String = row.try_get("agent_id").unwrap_or_default();
            let total: i64 = row.try_get("total").unwrap_or(0);
            let avg_risk: f64 = row.try_get("avg_risk").unwrap_or(0.0);
            let last_ts: String = row.try_get("last_ts").unwrap_or_default();
            let tools_csv: String = row.try_get("tools_csv").unwrap_or_default();

            // Count decisions per type
            let decision_rows = sqlx::query(
                "SELECT decision, COUNT(*) as cnt FROM audit_events WHERE agent_id = ? GROUP BY decision",
            )
            .bind(&aid)
            .fetch_all(&self.pool)
            .await?;

            let mut decisions = std::collections::HashMap::new();
            for dr in &decision_rows {
                let d: String = dr.try_get("decision").unwrap_or_default();
                let c: i64 = dr.try_get("cnt").unwrap_or(0);
                decisions.insert(d, c as u64);
            }

            // Count tool usage
            let mut tool_counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for tool in tools_csv.split(',') {
                let t = tool.trim().to_string();
                if !t.is_empty() {
                    *tool_counts.entry(t).or_insert(0) += 1;
                }
            }
            let mut top_tools: Vec<(String, u64)> = tool_counts.into_iter().collect();
            top_tools.sort_by_key(|t| std::cmp::Reverse(t.1));
            top_tools.truncate(5);

            let trust = crate::modules::nhi::crypto_identity::get_agent_trust(&aid);

            results.push(AgentAnalytics {
                agent_id: aid,
                total_requests: total as u64,
                decisions,
                avg_risk_score: avg_risk,
                top_tools,
                last_activity: last_ts,
                trust_score: trust,
            });
        }

        Ok(results)
    }
}

struct AuditRow {
    event_id: String,
    agent_id: String,
    tenant_id: Option<String>,
    framework: String,
    action_type: String,
    tool_name: String,
    decision: String,
    risk_score: i64,
    review_status: String,
    reasons: String,
    timestamp: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for AuditRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            event_id: row.try_get("event_id")?,
            agent_id: row.try_get("agent_id")?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            framework: row.try_get("framework")?,
            action_type: row.try_get("action_type")?,
            tool_name: row.try_get("tool_name")?,
            decision: row.try_get("decision")?,
            risk_score: row.try_get("risk_score")?,
            review_status: row.try_get("review_status")?,
            reasons: row.try_get("reasons")?,
            timestamp: row.try_get("timestamp")?,
        })
    }
}

impl AuditRow {
    fn into_stored(self) -> StoredAuditEvent {
        StoredAuditEvent {
            event_id: self.event_id,
            agent_id: self.agent_id,
            tenant_id: self.tenant_id,
            framework: self.framework,
            action_type: serde_json::from_value(serde_json::Value::String(self.action_type))
                .unwrap_or(ActionType::Custom),
            tool_name: self.tool_name,
            decision: serde_json::from_value(serde_json::Value::String(self.decision))
                .unwrap_or(GovernanceDecision::Block),
            risk_score: self.risk_score as u32,
            review_status: serde_json::from_value(serde_json::Value::String(self.review_status))
                .unwrap_or(ReviewStatus::NotRequired),
            reasons: serde_json::from_str(&self.reasons).unwrap_or_default(),
            timestamp: self.timestamp,
        }
    }
}

// ── ReviewStore ──

#[async_trait]
impl ReviewStore for SqliteStorage {
    async fn create(&self, review: &ReviewRequest) -> Result<(), SentinelError> {
        let reasons = serde_json::to_string(&review.reasons).unwrap_or_default();
        let decision = serde_json::to_value(review.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("review")
            .to_string();

        sqlx::query(
            "INSERT INTO review_requests (id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&review.id)
        .bind(&review.agent_id)
        .bind(&review.workspace_id)
        .bind(&review.tool_name)
        .bind(&decision)
        .bind(&review.status)
        .bind(review.risk_score as i64)
        .bind(&reasons)
        .bind(&review.created_at)
        .bind(&review.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get(&self, id: &str) -> Result<ReviewRequest, SentinelError> {
        let row = sqlx::query_as::<_, ReviewRow>(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at
             FROM review_requests WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::ReviewNotFound(id.to_string()))?;

        Ok(row.into_review())
    }

    async fn update_status(&self, id: &str, status: &str) -> Result<ReviewRequest, SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE review_requests SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        self.get(id).await
    }

    async fn list(&self) -> Result<Vec<ReviewRequest>, SentinelError> {
        let rows = sqlx::query_as::<_, ReviewRow>(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at
             FROM review_requests ORDER BY created_at ASC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_review()).collect())
    }
}

struct ReviewRow {
    id: String,
    agent_id: String,
    workspace_id: String,
    tool_name: String,
    decision: String,
    status: String,
    risk_score: i64,
    reasons: String,
    created_at: String,
    updated_at: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ReviewRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            agent_id: row.try_get("agent_id")?,
            workspace_id: row.try_get("workspace_id")?,
            tool_name: row.try_get("tool_name")?,
            decision: row.try_get("decision")?,
            status: row.try_get("status")?,
            risk_score: row.try_get("risk_score")?,
            reasons: row.try_get("reasons")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl ReviewRow {
    fn into_review(self) -> ReviewRequest {
        ReviewRequest {
            id: self.id,
            agent_id: self.agent_id,
            workspace_id: self.workspace_id,
            tool_name: self.tool_name,
            decision: serde_json::from_value(serde_json::Value::String(self.decision))
                .unwrap_or(GovernanceDecision::Review),
            status: self.status,
            risk_score: self.risk_score as u32,
            reasons: serde_json::from_str(&self.reasons).unwrap_or_default(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ── PolicyStore ──

#[async_trait]
impl PolicyStore for SqliteStorage {
    async fn get_agent_profile(&self, agent_id: &str) -> Result<AgentProfile, SentinelError> {
        let row = sqlx::query_as::<_, ProfileRow>(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types
             FROM agent_profiles WHERE agent_id = ?"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::AgentNotFound(agent_id.to_string()))?;

        Ok(row.into_profile())
    }

    async fn get_workspace_policy(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspacePolicy, SentinelError> {
        let row = sqlx::query_as::<_, WorkspaceRow>(
            "SELECT workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review
             FROM workspace_policies WHERE workspace_id = ?",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::WorkspaceNotFound(workspace_id.to_string()))?;

        Ok(row.into_policy())
    }

    async fn list_profiles(&self) -> Result<Vec<AgentProfile>, SentinelError> {
        let rows = sqlx::query_as::<_, ProfileRow>(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types
             FROM agent_profiles ORDER BY agent_id"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_profile()).collect())
    }

    async fn list_workspace_rules(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<PolicyRule>, SentinelError> {
        let rows = sqlx::query(
            "SELECT id, name, priority, match_criteria, conditions, decision, reason, enabled
             FROM policy_rules
             WHERE workspace_id = ?
             ORDER BY priority ASC, id ASC",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(sqlite_row_to_policy_rule).collect()
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspacePolicy>, SentinelError> {
        let rows = sqlx::query_as::<_, WorkspaceRow>(
            "SELECT workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review
             FROM workspace_policies ORDER BY workspace_id",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_policy()).collect())
    }

    async fn upsert_profile(&self, profile: &AgentProfile) -> Result<(), SentinelError> {
        let tools = serde_json::to_string(&profile.approved_tools).unwrap_or_default();
        let secrets = serde_json::to_string(&profile.approved_secrets).unwrap_or_default();
        let baselines = serde_json::to_string(&profile.baseline_action_types).unwrap_or_default();
        let role = serde_json::to_value(profile.role)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("builder")
            .to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO agent_profiles (agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                tenant_id = excluded.tenant_id,
                workspace_id = excluded.workspace_id,
                framework = excluded.framework,
                role = excluded.role,
                approved_tools = excluded.approved_tools,
                approved_secrets = excluded.approved_secrets,
                baseline_action_types = excluded.baseline_action_types,
                updated_at = excluded.updated_at"
        )
        .bind(&profile.agent_id)
        .bind(&profile.tenant_id)
        .bind(&profile.workspace_id)
        .bind(&profile.framework)
        .bind(&role)
        .bind(&tools)
        .bind(&secrets)
        .bind(&baselines)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_workspace(&self, policy: &WorkspacePolicy) -> Result<(), SentinelError> {
        let protocols = serde_json::to_string(&policy.allowed_protocols).unwrap_or_default();
        let domains = serde_json::to_string(&policy.allowed_domains).unwrap_or_default();
        let tools = serde_json::to_string(&policy.tools).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO workspace_policies (workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id) DO UPDATE SET
                tenant_id = excluded.tenant_id,
                allowed_protocols = excluded.allowed_protocols,
                allowed_domains = excluded.allowed_domains,
                tools = excluded.tools,
                threshold_block = excluded.threshold_block,
                threshold_review = excluded.threshold_review,
                updated_at = excluded.updated_at"
        )
        .bind(&policy.workspace_id)
        .bind(&policy.tenant_id)
        .bind(&protocols)
        .bind(&domains)
        .bind(&tools)
        .bind(policy.threshold_block as i64)
        .bind(policy.threshold_review as i64)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_workspace_rule(
        &self,
        workspace_id: &str,
        rule: &PolicyRule,
    ) -> Result<(), SentinelError> {
        let match_criteria = serde_json::to_string(&rule.match_criteria).unwrap_or_default();
        let conditions = serde_json::to_string(&rule.conditions).unwrap_or_default();
        let decision = serde_json::to_value(rule.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("review")
            .to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO policy_rules (id, workspace_id, name, priority, match_criteria, conditions, decision, reason, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                name = excluded.name,
                priority = excluded.priority,
                match_criteria = excluded.match_criteria,
                conditions = excluded.conditions,
                decision = excluded.decision,
                reason = excluded.reason,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at"
        )
        .bind(&rule.id)
        .bind(workspace_id)
        .bind(&rule.name)
        .bind(rule.priority)
        .bind(&match_criteria)
        .bind(&conditions)
        .bind(&decision)
        .bind(&rule.reason)
        .bind(rule.enabled as i64)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_profile(&self, agent_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM agent_profiles WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_workspace(&self, workspace_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM workspace_policies WHERE workspace_id = ?")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

struct ProfileRow {
    agent_id: String,
    tenant_id: Option<String>,
    workspace_id: String,
    framework: String,
    role: String,
    approved_tools: String,
    approved_secrets: String,
    baseline_action_types: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ProfileRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            agent_id: row.try_get("agent_id")?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            workspace_id: row.try_get("workspace_id")?,
            framework: row.try_get("framework")?,
            role: row.try_get("role")?,
            approved_tools: row.try_get("approved_tools")?,
            approved_secrets: row.try_get("approved_secrets")?,
            baseline_action_types: row.try_get("baseline_action_types")?,
        })
    }
}

impl ProfileRow {
    fn into_profile(self) -> AgentProfile {
        AgentProfile {
            agent_id: self.agent_id,
            tenant_id: self.tenant_id,
            workspace_id: self.workspace_id,
            framework: self.framework,
            role: serde_json::from_value(serde_json::Value::String(self.role))
                .unwrap_or(AgentRole::Builder),
            approved_tools: serde_json::from_str(&self.approved_tools).unwrap_or_default(),
            approved_secrets: serde_json::from_str(&self.approved_secrets).unwrap_or_default(),
            baseline_action_types: serde_json::from_str(&self.baseline_action_types)
                .unwrap_or_default(),
            tool_trust: 0.7,
        }
    }
}

struct WorkspaceRow {
    workspace_id: String,
    tenant_id: Option<String>,
    allowed_protocols: String,
    allowed_domains: String,
    tools: String,
    threshold_block: i64,
    threshold_review: i64,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for WorkspaceRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            workspace_id: row.try_get("workspace_id")?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            allowed_protocols: row.try_get("allowed_protocols")?,
            allowed_domains: row.try_get("allowed_domains")?,
            tools: row.try_get("tools")?,
            threshold_block: row.try_get("threshold_block").unwrap_or(70),
            threshold_review: row.try_get("threshold_review").unwrap_or(35),
        })
    }
}

impl WorkspaceRow {
    fn into_policy(self) -> WorkspacePolicy {
        WorkspacePolicy {
            workspace_id: self.workspace_id,
            tenant_id: self.tenant_id,
            allowed_protocols: serde_json::from_str(&self.allowed_protocols).unwrap_or_default(),
            allowed_domains: serde_json::from_str(&self.allowed_domains).unwrap_or_default(),
            tools: serde_json::from_str(&self.tools).unwrap_or_default(),
            threshold_block: self.threshold_block as u32,
            threshold_review: self.threshold_review as u32,
        }
    }
}

fn sqlite_row_to_policy_rule(row: &sqlx::sqlite::SqliteRow) -> Result<PolicyRule, SentinelError> {
    use sqlx::Row;

    let match_criteria: String = row.try_get("match_criteria")?;
    let conditions: String = row.try_get("conditions")?;
    let decision: String = row.try_get("decision")?;
    let enabled: i64 = row.try_get("enabled").unwrap_or(1);

    Ok(PolicyRule {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        priority: row.try_get("priority").unwrap_or(0),
        match_criteria: serde_json::from_str(&match_criteria).unwrap_or_default(),
        conditions: serde_json::from_str(&conditions).unwrap_or_default(),
        decision: serde_json::from_value(serde_json::Value::String(decision))
            .unwrap_or(GovernanceDecision::Review),
        reason: row.try_get("reason").unwrap_or(None),
        enabled: enabled != 0,
    })
}

// ── ApiKeyStore ──

#[async_trait]
impl ApiKeyStore for SqliteStorage {
    async fn store_key(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
    ) -> Result<(), SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        sqlx::query("INSERT INTO api_keys (id, key_hash, key_prefix, label) VALUES (?, ?, ?, ?)")
            .bind(key_id)
            .bind(key_hash)
            .bind(prefix)
            .bind(label)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn verify_raw_key(&self, raw_key: &str) -> Result<bool, SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        let hashes =
            sqlx::query_scalar::<_, String>("SELECT key_hash FROM api_keys WHERE key_prefix = ?")
                .bind(prefix)
                .fetch_all(&self.pool)
                .await?;

        for stored_hash in &hashes {
            if crate::auth::api_keys::verify_key(raw_key, stored_hash) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM api_keys WHERE id = ?")
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, SentinelError> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, label, created_at FROM api_keys ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ApiKeyRecord {
                id: r.id,
                label: r.label,
                created_at: r.created_at,
            })
            .collect())
    }
}

struct ApiKeyRow {
    id: String,
    label: String,
    created_at: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ApiKeyRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            label: row.try_get("label")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

// ── TenantStore ──

#[async_trait]
impl TenantStore for SqliteStorage {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), SentinelError> {
        let metadata = tenant
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());
        sqlx::query(
            "INSERT INTO tenants (tenant_id, name, enabled, metadata, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&tenant.tenant_id)
        .bind(&tenant.name)
        .bind(tenant.enabled)
        .bind(&metadata)
        .bind(&tenant.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_tenant(&self, tenant_id: &str) -> Result<Tenant, SentinelError> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT tenant_id, name, enabled, metadata, created_at FROM tenants WHERE tenant_id = ?",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::Storage(format!("Tenant not found: {tenant_id}")))?;

        let metadata_str: Option<String> = row.try_get("metadata").unwrap_or(None);
        Ok(Tenant {
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            enabled: row.try_get::<bool, _>("enabled").unwrap_or(true),
            created_at: row.try_get("created_at")?,
            metadata: metadata_str.and_then(|s| serde_json::from_str(&s).ok()),
        })
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, SentinelError> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT tenant_id, name, enabled, metadata, created_at FROM tenants ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut tenants = Vec::new();
        for row in &rows {
            let metadata_str: Option<String> = row.try_get("metadata").unwrap_or(None);
            tenants.push(Tenant {
                tenant_id: row.try_get("tenant_id")?,
                name: row.try_get("name")?,
                enabled: row.try_get::<bool, _>("enabled").unwrap_or(true),
                created_at: row.try_get("created_at")?,
                metadata: metadata_str.and_then(|s| serde_json::from_str(&s).ok()),
            });
        }
        Ok(tenants)
    }

    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM tenants WHERE tenant_id = ?")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── NhiStore ──

use crate::modules::nhi::crypto_identity::{AgentIdentity, PendingChallenge};

#[async_trait]
impl NhiStore for SqliteStorage {
    async fn store_identity(
        &self,
        identity: &AgentIdentity,
        secret_key_hex: &str,
    ) -> Result<(), SentinelError> {
        let capabilities = serde_json::to_string(&identity.capabilities).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO nhi_identities (agent_id, spiffe_id, public_key_hex, secret_key_hex, attestation_status, trust_score, capabilities, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                spiffe_id = excluded.spiffe_id,
                public_key_hex = excluded.public_key_hex,
                secret_key_hex = excluded.secret_key_hex,
                attestation_status = excluded.attestation_status,
                trust_score = excluded.trust_score,
                capabilities = excluded.capabilities,
                updated_at = excluded.updated_at"
        )
        .bind(&identity.agent_id)
        .bind(&identity.spiffe_id)
        .bind(&identity.public_key_hex)
        .bind(secret_key_hex)
        .bind(&identity.attestation_status)
        .bind(identity.trust_score)
        .bind(&capabilities)
        .bind(&identity.created_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT agent_id, spiffe_id, public_key_hex, attestation_status, trust_score, capabilities, created_at
             FROM nhi_identities WHERE agent_id = ?"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let caps_json: String = r.try_get("capabilities").unwrap_or_default();
                Ok(Some(AgentIdentity {
                    agent_id: r.try_get("agent_id")?,
                    spiffe_id: r.try_get("spiffe_id")?,
                    public_key_hex: r.try_get("public_key_hex")?,
                    created_at: r.try_get("created_at")?,
                    attestation_status: r.try_get("attestation_status")?,
                    trust_score: r.try_get("trust_score").unwrap_or(0.5),
                    capabilities: serde_json::from_str(&caps_json).unwrap_or_default(),
                }))
            }
            None => Ok(None),
        }
    }

    async fn get_secret_key_hex(&self, agent_id: &str) -> Result<Option<String>, SentinelError> {
        let key: Option<String> =
            sqlx::query_scalar("SELECT secret_key_hex FROM nhi_identities WHERE agent_id = ?")
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(key)
    }

    async fn list_identities(&self) -> Result<Vec<AgentIdentity>, SentinelError> {
        use sqlx::Row;

        let rows = sqlx::query(
            "SELECT agent_id, spiffe_id, public_key_hex, attestation_status, trust_score, capabilities, created_at
             FROM nhi_identities ORDER BY created_at"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut identities = Vec::new();
        for r in &rows {
            let caps_json: String = r.try_get("capabilities").unwrap_or_default();
            identities.push(AgentIdentity {
                agent_id: r.try_get("agent_id")?,
                spiffe_id: r.try_get("spiffe_id")?,
                public_key_hex: r.try_get("public_key_hex")?,
                created_at: r.try_get("created_at")?,
                attestation_status: r.try_get("attestation_status")?,
                trust_score: r.try_get("trust_score").unwrap_or(0.5),
                capabilities: serde_json::from_str(&caps_json).unwrap_or_default(),
            });
        }
        Ok(identities)
    }

    async fn update_trust(&self, agent_id: &str, trust_score: f64) -> Result<(), SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE nhi_identities SET trust_score = ?, updated_at = ? WHERE agent_id = ?")
            .bind(trust_score)
            .bind(&now)
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn store_challenge(&self, challenge: &PendingChallenge) -> Result<(), SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO nhi_challenges (challenge_id, agent_id, nonce, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(challenge_id) DO UPDATE SET
                agent_id = excluded.agent_id,
                nonce = excluded.nonce,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at",
        )
        .bind(&challenge.challenge_id)
        .bind(&challenge.agent_id)
        .bind(&challenge.nonce)
        .bind(&challenge.expires_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<PendingChallenge>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT challenge_id, agent_id, nonce, expires_at FROM nhi_challenges WHERE challenge_id = ?"
        )
        .bind(challenge_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(PendingChallenge {
                challenge_id: r.try_get("challenge_id")?,
                agent_id: r.try_get("agent_id")?,
                nonce: r.try_get("nonce")?,
                expires_at: r.try_get("expires_at")?,
            })),
            None => Ok(None),
        }
    }

    async fn delete_challenge(&self, challenge_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM nhi_challenges WHERE challenge_id = ?")
            .bind(challenge_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn prune_expired_challenges(&self) -> Result<usize, SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query("DELETE FROM nhi_challenges WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}

// ── SessionStore ──

use crate::modules::session_graph::session_dag::{FSAState, SessionDAG};

#[async_trait]
impl SessionStore for SqliteStorage {
    async fn store_session(&self, session: &SessionDAG) -> Result<(), SentinelError> {
        let nodes_json = serde_json::to_string(&session.nodes).unwrap_or_default();
        let edges_json = serde_json::to_string(&session.edges).unwrap_or_default();
        let state = serde_json::to_value(session.state)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("idle")
            .to_string();

        sqlx::query(
            "INSERT INTO session_graphs (session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json, edges_json, created_at, last_activity)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET
                agent_id = excluded.agent_id,
                state = excluded.state,
                blocked = excluded.blocked,
                block_reason = excluded.block_reason,
                blocked_at = excluded.blocked_at,
                block_count = excluded.block_count,
                nodes_json = excluded.nodes_json,
                edges_json = excluded.edges_json,
                last_activity = excluded.last_activity"
        )
        .bind(&session.session_id)
        .bind(&session.agent_id)
        .bind(&state)
        .bind(session.blocked as i64)
        .bind(&session.block_reason)
        .bind(session.blocked_at as i64)
        .bind(session.block_count as i64)
        .bind(&nodes_json)
        .bind(&edges_json)
        .bind(session.created_at as i64)
        .bind(session.last_activity as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionDAG>, SentinelError> {
        let row = sqlx::query(
            "SELECT session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json, edges_json, created_at, last_activity
             FROM session_graphs WHERE session_id = ?"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(session_dag_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn list_sessions(&self) -> Result<Vec<SessionDAG>, SentinelError> {
        let rows = sqlx::query(
            "SELECT session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json, edges_json, created_at, last_activity
             FROM session_graphs ORDER BY last_activity DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut sessions = Vec::new();
        for r in &rows {
            sessions.push(session_dag_from_row(r)?);
        }
        Ok(sessions)
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM session_graphs WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn prune_stale_sessions(&self, max_age_ms: u64) -> Result<usize, SentinelError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let cutoff = now_ms - max_age_ms as i64;

        let result = sqlx::query("DELETE FROM session_graphs WHERE last_activity < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}

fn session_dag_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<SessionDAG, SentinelError> {
    use sqlx::Row;

    let nodes_json: String = r.try_get("nodes_json").unwrap_or_default();
    let edges_json: String = r.try_get("edges_json").unwrap_or_default();
    let state_str: String = r.try_get("state").unwrap_or_else(|_| "idle".to_string());
    let blocked_int: i64 = r.try_get("blocked").unwrap_or(0);

    Ok(SessionDAG {
        session_id: r.try_get("session_id")?,
        agent_id: r.try_get("agent_id")?,
        nodes: serde_json::from_str(&nodes_json).unwrap_or_default(),
        edges: serde_json::from_str(&edges_json).unwrap_or_default(),
        created_at: r.try_get::<i64, _>("created_at").unwrap_or(0) as u64,
        last_activity: r.try_get::<i64, _>("last_activity").unwrap_or(0) as u64,
        state: serde_json::from_value(serde_json::Value::String(state_str))
            .unwrap_or(FSAState::Idle),
        blocked: blocked_int != 0,
        block_reason: r.try_get("block_reason").unwrap_or(None),
        blocked_at: r.try_get::<i64, _>("blocked_at").unwrap_or(0) as u64,
        block_count: r.try_get::<i64, _>("block_count").unwrap_or(0) as u32,
    })
}

// ── TaintStore ──

use std::collections::HashSet;

#[async_trait]
impl TaintStore for SqliteStorage {
    async fn get_session_taint(&self, session_id: &str) -> Result<HashSet<String>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query("SELECT labels_json FROM taint_sessions WHERE session_id = ?")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let labels_json: String = r.try_get("labels_json").unwrap_or_default();
                Ok(serde_json::from_str(&labels_json).unwrap_or_default())
            }
            None => Ok(HashSet::new()),
        }
    }

    async fn update_session_taint(
        &self,
        session_id: &str,
        labels: &HashSet<String>,
    ) -> Result<(), SentinelError> {
        let labels_json = serde_json::to_string(labels).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO taint_sessions (session_id, labels_json, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET
                labels_json = excluded.labels_json,
                updated_at = excluded.updated_at",
        )
        .bind(session_id)
        .bind(&labels_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn prune_stale_sessions(&self, max_age_secs: u64) -> Result<usize, SentinelError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_secs as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let result = sqlx::query("DELETE FROM taint_sessions WHERE updated_at < ?")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}

// ── FingerprintStore ──

use crate::modules::fingerprint::behavioral::AgentFingerprint;

#[async_trait]
impl FingerprintStore for SqliteStorage {
    async fn get_fingerprint(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentFingerprint>, SentinelError> {
        let row = sqlx::query(
            "SELECT agent_id, total_requests, tool_usage, action_types, avg_risk_score, peak_risk_score, hourly_pattern, anomaly_score, first_seen, last_seen, flags
             FROM fingerprints WHERE agent_id = ?"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(fingerprint_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_fingerprint(&self, fp: &AgentFingerprint) -> Result<(), SentinelError> {
        let tool_usage = serde_json::to_string(&fp.tool_usage).unwrap_or_default();
        let action_types = serde_json::to_string(&fp.action_types).unwrap_or_default();
        let hourly_pattern = serde_json::to_string(&fp.hourly_pattern).unwrap_or_default();
        let flags = serde_json::to_string(&fp.flags).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO fingerprints (agent_id, total_requests, tool_usage, action_types, avg_risk_score, peak_risk_score, hourly_pattern, anomaly_score, first_seen, last_seen, flags, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                total_requests = excluded.total_requests,
                tool_usage = excluded.tool_usage,
                action_types = excluded.action_types,
                avg_risk_score = excluded.avg_risk_score,
                peak_risk_score = excluded.peak_risk_score,
                hourly_pattern = excluded.hourly_pattern,
                anomaly_score = excluded.anomaly_score,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                flags = excluded.flags,
                updated_at = excluded.updated_at"
        )
        .bind(&fp.agent_id)
        .bind(fp.total_requests as i64)
        .bind(&tool_usage)
        .bind(&action_types)
        .bind(fp.avg_risk_score)
        .bind(fp.peak_risk_score)
        .bind(&hourly_pattern)
        .bind(fp.anomaly_score)
        .bind(&fp.first_seen)
        .bind(&fp.last_seen)
        .bind(&flags)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_fingerprints(&self) -> Result<Vec<AgentFingerprint>, SentinelError> {
        let rows = sqlx::query(
            "SELECT agent_id, total_requests, tool_usage, action_types, avg_risk_score, peak_risk_score, hourly_pattern, anomaly_score, first_seen, last_seen, flags
             FROM fingerprints ORDER BY last_seen DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut fingerprints = Vec::new();
        for r in &rows {
            fingerprints.push(fingerprint_from_row(r)?);
        }
        Ok(fingerprints)
    }

    async fn delete_fingerprint(&self, agent_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM fingerprints WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn fingerprint_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<AgentFingerprint, SentinelError> {
    use sqlx::Row;

    let tool_usage_json: String = r.try_get("tool_usage").unwrap_or_default();
    let action_types_json: String = r.try_get("action_types").unwrap_or_default();
    let hourly_json: String = r.try_get("hourly_pattern").unwrap_or_default();
    let flags_json: String = r.try_get("flags").unwrap_or_default();

    let hourly_vec: Vec<u64> =
        serde_json::from_str(&hourly_json).unwrap_or_else(|_| vec![0u64; 24]);
    let mut hourly_pattern = [0u64; 24];
    for (i, v) in hourly_vec.iter().enumerate().take(24) {
        hourly_pattern[i] = *v;
    }

    Ok(AgentFingerprint {
        agent_id: r.try_get("agent_id")?,
        total_requests: r.try_get::<i64, _>("total_requests").unwrap_or(0) as u64,
        tool_usage: serde_json::from_str(&tool_usage_json).unwrap_or_default(),
        action_types: serde_json::from_str(&action_types_json).unwrap_or_default(),
        avg_risk_score: r.try_get("avg_risk_score").unwrap_or(0.0),
        peak_risk_score: r.try_get("peak_risk_score").unwrap_or(0.0),
        hourly_pattern,
        anomaly_score: r.try_get("anomaly_score").unwrap_or(0.0),
        first_seen: r.try_get("first_seen")?,
        last_seen: r.try_get("last_seen")?,
        flags: serde_json::from_str(&flags_json).unwrap_or_default(),
    })
}

// ── RateLimitStore ──

#[async_trait]
impl RateLimitStore for SqliteStorage {
    async fn load_config(&self) -> Result<Option<RateLimitConfig>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT max_per_minute, max_per_hour, burst_limit FROM rate_limit_config WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(RateLimitConfig {
                max_per_minute: r.try_get::<i64, _>("max_per_minute").unwrap_or(60) as u32,
                max_per_hour: r.try_get::<i64, _>("max_per_hour").unwrap_or(600) as u32,
                burst_limit: r.try_get::<i64, _>("burst_limit").unwrap_or(10) as u32,
            })),
            None => Ok(None),
        }
    }

    async fn save_config(&self, config: &RateLimitConfig) -> Result<(), SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO rate_limit_config (id, max_per_minute, max_per_hour, burst_limit, updated_at)
             VALUES (1, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                max_per_minute = excluded.max_per_minute,
                max_per_hour = excluded.max_per_hour,
                burst_limit = excluded.burst_limit,
                updated_at = excluded.updated_at"
        )
        .bind(config.max_per_minute as i64)
        .bind(config.max_per_hour as i64)
        .bind(config.burst_limit as i64)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
