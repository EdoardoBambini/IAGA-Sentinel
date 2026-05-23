use crate::core::types::{
    AgentProfile, GovernanceDecision, InspectRequest, ProtocolKind, WorkspacePolicy,
};

pub struct PolicyEvaluation {
    pub findings: Vec<String>,
    pub minimum_decision: GovernanceDecision,
}

pub fn evaluate_policy(
    input: &InspectRequest,
    profile: &AgentProfile,
    workspace_policy: &WorkspacePolicy,
    protocol: ProtocolKind,
) -> PolicyEvaluation {
    let mut findings: Vec<String> = Vec::new();
    let mut minimum_decision = GovernanceDecision::Allow;

    // Check protocol allowed
    if !workspace_policy.allowed_protocols.contains(&protocol) {
        findings.push(format!(
            "protocol {:?} is not allowed for workspace {}",
            protocol, workspace_policy.workspace_id
        ));
        minimum_decision = GovernanceDecision::Block;
    }

    // Check tool policy
    let tool_policy = workspace_policy
        .tools
        .iter()
        .find(|t| t.tool_name == input.action.tool_name);

    match tool_policy {
        None => {
            findings.push(format!(
                "tool {} is not registered in workspace policy",
                input.action.tool_name
            ));
            minimum_decision = GovernanceDecision::Block;
        }
        Some(tp) => {
            if !tp.allowed_action_types.contains(&input.action.action_type) {
                findings.push(format!(
                    "tool {} cannot run action type {:?}",
                    input.action.tool_name, input.action.action_type
                ));
                minimum_decision = GovernanceDecision::Block;
            }

            if tp.requires_human_review && minimum_decision != GovernanceDecision::Block {
                findings.push(format!(
                    "tool {} requires human review",
                    input.action.tool_name
                ));
                minimum_decision = GovernanceDecision::Review;
            }

            if tp.max_decision == GovernanceDecision::Review
                && minimum_decision == GovernanceDecision::Allow
            {
                findings.push(format!(
                    "tool {} is capped at review in workspace policy",
                    input.action.tool_name
                ));
                minimum_decision = GovernanceDecision::Review;
            }
        }
    }

    // Check agent approved for tool
    if !profile.approved_tools.contains(&input.action.tool_name) {
        findings.push(format!(
            "agent {} is not approved for tool {}",
            profile.agent_id, input.action.tool_name
        ));
        minimum_decision = GovernanceDecision::Block;
    }

    // Check baseline action types
    if !profile
        .baseline_action_types
        .contains(&input.action.action_type)
    {
        findings.push(format!(
            "action type {:?} is outside baseline for agent {}",
            input.action.action_type, profile.agent_id
        ));
        if minimum_decision == GovernanceDecision::Allow {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // Check destination domain
    if let Some(destination) = extract_destination(&input.action.payload) {
        if !workspace_policy.allowed_domains.contains(&destination) {
            findings.push(format!(
                "destination {destination} is outside allowed workspace domains"
            ));
            minimum_decision = GovernanceDecision::Block;
        }
    }

    if findings.is_empty() {
        findings.push("request matched registered tool and workspace policy".to_string());
    }

    PolicyEvaluation {
        findings,
        minimum_decision,
    }
}

fn extract_destination(
    payload: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<String> {
    payload
        .get("destination")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
