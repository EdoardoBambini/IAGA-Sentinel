use chrono::Utc;
use uuid::Uuid;

use crate::core::types::{AgentProfile, AuditEvent, InspectRequest, RiskScore};

pub fn build_audit_event(
    input: &InspectRequest,
    profile: &AgentProfile,
    risk: &RiskScore,
) -> AuditEvent {
    let mut reasons = risk.reasons.clone();
    reasons.push(format!("agent-role:{:?}", profile.role).to_lowercase());

    AuditEvent {
        event_id: Uuid::new_v4().to_string(),
        agent_id: input.agent_id.clone(),
        framework: input.framework.clone(),
        action_type: input.action.action_type,
        tool_name: input.action.tool_name.clone(),
        decision: risk.decision,
        timestamp: Utc::now().to_rfc3339(),
        reasons,
    }
}
