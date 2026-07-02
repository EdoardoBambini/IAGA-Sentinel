//! Process-global cumulative spend per `(agent_id, session_id)`.
//!
//! Mirrors the in-memory, process-global model of the session graph and taint
//! trackers (`session_dag::SESSIONS`, `taint_tracker`): spend is held as integer
//! micro-USD per session and read at governance time so a Dictum policy or the
//! non-Dictum fallback can block once a session's cumulative spend exceeds its
//! budget.
//!
//! Scope for 1.5: session-scoped, in-memory only (lost on restart). Durable
//! backing via the `agent_spend` table and time-windowed (hourly/daily) budgets
//! are follow-ups; the table already exists (migration 0004).

use std::collections::HashMap;
use std::sync::RwLock;

use once_cell::sync::Lazy;

use crate::core::types::InspectRequest;

static SPEND: Lazy<RwLock<HashMap<SpendKey, u64>>> = Lazy::new(|| RwLock::new(HashMap::new()));

/// Cumulative-spend key: an agent within a logical session.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SpendKey {
    pub agent_id: String,
    pub session_id: String,
}

impl SpendKey {
    /// Derive from an inspect request. The session falls back to the agent id
    /// when the caller sends no `metadata.sessionId`, matching the session-graph
    /// key so cost attribution and session correlation stay consistent.
    pub fn from_request(input: &InspectRequest) -> Self {
        let session_id = input
            .metadata
            .as_ref()
            .and_then(|m| m.get("sessionId"))
            .and_then(|v| v.as_str())
            .unwrap_or(&input.agent_id)
            .to_string();
        Self {
            agent_id: input.agent_id.clone(),
            session_id,
        }
    }
}

/// Cumulative spend recorded so far for this key, in USD.
pub fn session_spend_usd(key: &SpendKey) -> f64 {
    let micros = SPEND
        .read()
        .map(|m| m.get(key).copied().unwrap_or(0))
        .unwrap_or(0);
    iaga_sentinel_cost::micros_to_usd(micros)
}

/// Add `micros` of spend to this key's cumulative total. No-op for zero.
pub fn add(key: &SpendKey, micros: u64) {
    if micros == 0 {
        return;
    }
    if let Ok(mut map) = SPEND.write() {
        *map.entry(key.clone()).or_insert(0) += micros;
    }
}

/// Atomically check the current spend against `limit_usd` and, if within
/// budget, add `micros` to the session total. Returns `true` if the session
/// is within budget (action allowed). When `limit_usd` is `None` the check
/// is skipped and the cost is always added (no budget configured).
///
/// Both operations run under the same write lock, eliminating the TOCTOU
/// window between a separate `session_spend_usd` read and a later `add`.
pub fn check_and_add(key: &SpendKey, limit_usd: Option<f64>, micros: u64) -> bool {
    if let Ok(mut map) = SPEND.write() {
        let current_usd =
            iaga_sentinel_cost::micros_to_usd(map.get(key).copied().unwrap_or(0));
        if let Some(limit) = limit_usd {
            if current_usd > limit {
                return false;
            }
        }
        if micros > 0 {
            *map.entry(key.clone()).or_insert(0) += micros;
        }
        true
    } else {
        true
    }
}

#[cfg(test)]
pub fn reset() {
    if let Ok(mut map) = SPEND.write() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(agent: &str, session: &str) -> SpendKey {
        SpendKey {
            agent_id: agent.into(),
            session_id: session.into(),
        }
    }

    #[test]
    fn accumulates_per_session() {
        reset();
        let k = key("agent-x", "spend-test-accumulate");
        assert_eq!(session_spend_usd(&k), 0.0);
        add(&k, 1_500_000); // $1.50
        add(&k, 500_000); //  $0.50
        assert!((session_spend_usd(&k) - 2.0).abs() < 1e-9);
        // A different session for the same agent is isolated.
        let other = key("agent-x", "spend-test-other");
        assert_eq!(session_spend_usd(&other), 0.0);
    }
}
