//! Policy-as-Code v2 Rules Engine
//!
//! Provides conditional rules with match criteria, time windows,
//! payload inspection, and risk-score thresholds. Rules are evaluated
//! in priority order; the first matching rule wins.

use serde::{Deserialize, Serialize};

use crate::core::types::{ActionType, AgentRole, GovernanceDecision, InspectRequest};

use super::time_window::TimeWindow;

// ── Rule Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    /// Unique identifier for this rule.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Priority (lower = evaluated first). Default: 0.
    #[serde(default)]
    pub priority: i32,
    /// Criteria the request must match for this rule to apply.
    #[serde(default)]
    pub match_criteria: MatchCriteria,
    /// Additional conditions that must be true.
    #[serde(default)]
    pub conditions: ConditionSet,
    /// Decision to apply if the rule matches.
    pub decision: GovernanceDecision,
    /// Optional reason string attached to governance findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether this rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchCriteria {
    /// Match on action type (e.g. "shell", "http"). Empty = match all.
    #[serde(default)]
    pub action_type: Vec<ActionType>,
    /// Match on tool name patterns. Empty = match all.
    #[serde(default)]
    pub tool_name: Vec<String>,
    /// Match on agent roles. Empty = match all.
    #[serde(default)]
    pub agent_role: Vec<AgentRole>,
    /// Match on specific agent IDs. Empty = match all.
    #[serde(default)]
    pub agent_id: Vec<String>,
    /// Match on frameworks. Empty = match all.
    #[serde(default)]
    pub framework: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionSet {
    /// Time window during which this rule is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Maximum risk score for this rule to apply (below this → rule applies).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_risk_score: Option<u32>,
    /// Minimum risk score for this rule to apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_risk_score: Option<u32>,
    /// Payload must contain ALL of these strings.
    #[serde(default)]
    pub payload_contains: Vec<String>,
    /// Payload must NOT contain any of these strings.
    #[serde(default)]
    pub payload_excludes: Vec<String>,
}

// ── Rule Evaluation ──

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub decision: GovernanceDecision,
    pub reason: String,
}

/// Evaluate rules against an inspect request and optional context.
/// Rules are sorted by priority (ascending), first match wins.
pub fn evaluate_rules(
    rules: &[PolicyRule],
    input: &InspectRequest,
    agent_role: AgentRole,
    current_risk_score: Option<u32>,
) -> Option<RuleMatch> {
    let mut sorted: Vec<&PolicyRule> = rules.iter().filter(|r| r.enabled).collect();
    sorted.sort_by_key(|r| r.priority);

    let payload_str = serde_json::to_string(&input.action.payload).unwrap_or_default();

    for rule in sorted {
        if matches_criteria(&rule.match_criteria, input, agent_role)
            && check_conditions(&rule.conditions, &payload_str, current_risk_score)
        {
            let reason = rule.reason.clone().unwrap_or_else(|| {
                format!("policy rule '{}' matched → {:?}", rule.name, rule.decision)
            });
            return Some(RuleMatch {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                decision: rule.decision,
                reason,
            });
        }
    }

    None
}

fn matches_criteria(
    criteria: &MatchCriteria,
    input: &InspectRequest,
    agent_role: AgentRole,
) -> bool {
    // Action type
    if !criteria.action_type.is_empty() && !criteria.action_type.contains(&input.action.action_type)
    {
        return false;
    }

    // Tool name
    if !criteria.tool_name.is_empty() {
        let matches_tool = criteria.tool_name.iter().any(|pattern| {
            if pattern.contains('*') {
                // Simple glob: "filesystem.*" matches "filesystem.read"
                let prefix = pattern.trim_end_matches('*');
                input.action.tool_name.starts_with(prefix)
            } else {
                &input.action.tool_name == pattern
            }
        });
        if !matches_tool {
            return false;
        }
    }

    // Agent role
    if !criteria.agent_role.is_empty() && !criteria.agent_role.contains(&agent_role) {
        return false;
    }

    // Agent ID
    if !criteria.agent_id.is_empty() && !criteria.agent_id.contains(&input.agent_id) {
        return false;
    }

    // Framework
    if !criteria.framework.is_empty() && !criteria.framework.contains(&input.framework) {
        return false;
    }

    true
}

fn check_conditions(
    conditions: &ConditionSet,
    payload_str: &str,
    current_risk: Option<u32>,
) -> bool {
    // Time window
    if let Some(ref tw) = conditions.time_window {
        if !tw.is_active() {
            return false;
        }
    }

    // Risk score bounds
    if let Some(max) = conditions.max_risk_score {
        if let Some(risk) = current_risk {
            if risk > max {
                return false;
            }
        }
    }
    if let Some(min) = conditions.min_risk_score {
        if let Some(risk) = current_risk {
            if risk < min {
                return false;
            }
        }
    }

    // Payload contains
    let payload_lower = payload_str.to_lowercase();
    for required in &conditions.payload_contains {
        if !payload_lower.contains(&required.to_lowercase()) {
            return false;
        }
    }

    // Payload excludes
    for excluded in &conditions.payload_excludes {
        if payload_lower.contains(&excluded.to_lowercase()) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ActionDetail;
    use std::collections::HashMap;

    fn make_request(action_type: ActionType, tool: &str) -> InspectRequest {
        InspectRequest {
            agent_id: "test-agent".into(),
            tenant_id: None,
            workspace_id: Some("test-ws".into()),
            framework: "anthropic".into(),
            protocol: None,
            action: ActionDetail {
                action_type,
                tool_name: tool.into(),
                payload: HashMap::new(),
            },
            requested_secrets: None,
            metadata: None,
        }
    }

    #[test]
    fn test_simple_block_rule() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "block-email".into(),
            priority: 0,
            match_criteria: MatchCriteria {
                action_type: vec![ActionType::Email],
                ..Default::default()
            },
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Block,
            reason: Some("Email disabled".into()),
            enabled: true,
        }];

        let req = make_request(ActionType::Email, "smtp.send");
        let result = evaluate_rules(&rules, &req, AgentRole::Builder, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, GovernanceDecision::Block);
    }

    #[test]
    fn test_no_match_returns_none() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "block-email".into(),
            priority: 0,
            match_criteria: MatchCriteria {
                action_type: vec![ActionType::Email],
                ..Default::default()
            },
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Block,
            reason: None,
            enabled: true,
        }];

        let req = make_request(ActionType::FileRead, "filesystem.read");
        let result = evaluate_rules(&rules, &req, AgentRole::Builder, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_risk_score_condition() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "allow-low-risk".into(),
            priority: 0,
            match_criteria: MatchCriteria::default(),
            conditions: ConditionSet {
                max_risk_score: Some(30),
                ..Default::default()
            },
            decision: GovernanceDecision::Allow,
            reason: None,
            enabled: true,
        }];

        let req = make_request(ActionType::Shell, "terminal.exec");
        // Risk 20 → should match (under 30)
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, Some(20)).is_some());
        // Risk 50 → should NOT match (over 30)
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, Some(50)).is_none());
    }

    #[test]
    fn test_priority_ordering() {
        let rules = vec![
            PolicyRule {
                id: "r1".into(),
                name: "low-priority-allow".into(),
                priority: 10,
                match_criteria: MatchCriteria::default(),
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Allow,
                reason: None,
                enabled: true,
            },
            PolicyRule {
                id: "r2".into(),
                name: "high-priority-block".into(),
                priority: 1,
                match_criteria: MatchCriteria::default(),
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: None,
                enabled: true,
            },
        ];

        let req = make_request(ActionType::Shell, "terminal.exec");
        let result = evaluate_rules(&rules, &req, AgentRole::Builder, None);
        assert_eq!(result.unwrap().decision, GovernanceDecision::Block);
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "disabled".into(),
            priority: 0,
            match_criteria: MatchCriteria::default(),
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Block,
            reason: None,
            enabled: false,
        }];

        let req = make_request(ActionType::Shell, "terminal.exec");
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, None).is_none());
    }

    #[test]
    fn test_tool_glob_pattern() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "block-fs-writes".into(),
            priority: 0,
            match_criteria: MatchCriteria {
                tool_name: vec!["filesystem.*".into()],
                ..Default::default()
            },
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Review,
            reason: None,
            enabled: true,
        }];

        let req = make_request(ActionType::FileWrite, "filesystem.write");
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, None).is_some());

        let req2 = make_request(ActionType::Shell, "terminal.exec");
        assert!(evaluate_rules(&rules, &req2, AgentRole::Builder, None).is_none());
    }
}
