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
