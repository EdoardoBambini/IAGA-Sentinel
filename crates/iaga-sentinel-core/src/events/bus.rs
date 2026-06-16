use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::core::types::{GovernanceDecision, GovernanceResult};

/// Events emitted by the governance pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SentinelEvent {
    /// An action was inspected and a decision was made.
    ActionGoverned {
        event_id: String,
        agent_id: String,
        tool_name: String,
        decision: GovernanceDecision,
        risk_score: u32,
        timestamp: String,
        reasons: Vec<String>,
        /// Unsigned advisory signals (burst/velocity/fingerprint novelty) that
        /// did NOT enter the signed verdict, surfaced for live alerting only.
        /// Absent when no advisory signal fired. Never confuse with the signed
        /// `decision`/`risk_score`/`reasons` above.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        advisory: Option<serde_json::Value>,
    },
    /// A review request was created.
    ReviewCreated {
        review_id: String,
        agent_id: String,
        tool_name: String,
        risk_score: u32,
    },
    /// A review request was resolved (approved/rejected).
    ReviewResolved { review_id: String, status: String },
}

impl SentinelEvent {
    pub fn from_governance_result(result: &GovernanceResult) -> Self {
        SentinelEvent::ActionGoverned {
            event_id: result.audit_event.event_id.clone(),
            agent_id: result.audit_event.agent_id.clone(),
            tool_name: result.audit_event.tool_name.clone(),
            decision: result.decision,
            risk_score: result.risk.score,
            timestamp: result.audit_event.timestamp.clone(),
            reasons: result.risk.reasons.clone(),
            advisory: result.advisory.clone(),
        }
    }
}

/// Broadcast channel for real-time events (SSE + webhooks).
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<SentinelEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: SentinelEvent) {
        // Ignore send error (no active subscribers)
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SentinelEvent> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_governed_carries_advisory_in_the_wire_shape() {
        // The live dashboard reads `event.advisory` off the SSE event; pin that
        // the unsigned advisory rides along, and is elided when absent.
        let ev = SentinelEvent::ActionGoverned {
            event_id: "e".into(),
            agent_id: "a".into(),
            tool_name: "t".into(),
            decision: GovernanceDecision::Review,
            risk_score: 41,
            timestamp: "2026-01-01T00:00:00Z".into(),
            reasons: vec!["r".into()],
            advisory: Some(serde_json::json!([{ "name": "burst", "score": 50 }])),
        };
        let v = serde_json::to_value(&ev).expect("serialize");
        assert_eq!(v["type"], "action_governed");
        assert_eq!(v["advisory"][0]["name"], "burst");

        let ev_none = SentinelEvent::ActionGoverned {
            event_id: "e".into(),
            agent_id: "a".into(),
            tool_name: "t".into(),
            decision: GovernanceDecision::Allow,
            risk_score: 0,
            timestamp: "x".into(),
            reasons: vec![],
            advisory: None,
        };
        let v_none = serde_json::to_value(&ev_none).expect("serialize");
        assert!(
            v_none.get("advisory").is_none(),
            "advisory must be elided when None so the event stays lean"
        );
    }
}
