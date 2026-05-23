//! Agent Behavioral Fingerprinting Engine
//!
//! Tracks agent behavior patterns over time and detects anomalies by comparing
//! current actions against established baselines. Flags include risk spikes,
//! novel tool usage, unusual hours, and new action types.

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{Timelike, Utc};
use serde::{Deserialize, Serialize};

// ── Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentFingerprint {
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

// ── Engine ──

pub struct BehavioralEngine {
    fingerprints: RwLock<HashMap<String, AgentFingerprint>>,
}

impl Default for BehavioralEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralEngine {
    pub fn new() -> Self {
        Self {
            fingerprints: RwLock::new(HashMap::new()),
        }
    }

    /// Record an action and update the agent's fingerprint.
    pub fn record_action(
        &self,
        agent_id: &str,
        tool_name: &str,
        action_type: &str,
        risk_score: f64,
    ) {
        let now = Utc::now();
        let hour = now.hour() as usize;
        let timestamp = now.to_rfc3339();

        let mut store = self.fingerprints.write().unwrap_or_else(|e| e.into_inner());
        let fp = store
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentFingerprint {
                agent_id: agent_id.to_string(),
                total_requests: 0,
                tool_usage: HashMap::new(),
                action_types: HashMap::new(),
                avg_risk_score: 0.0,
                peak_risk_score: 0.0,
                hourly_pattern: [0u64; 24],
                anomaly_score: 0.0,
                first_seen: timestamp.clone(),
                last_seen: timestamp.clone(),
                flags: Vec::new(),
            });

        fp.total_requests += 1;
        *fp.tool_usage.entry(tool_name.to_string()).or_insert(0) += 1;
        *fp.action_types.entry(action_type.to_string()).or_insert(0) += 1;

        // Update running average risk score
        let n = fp.total_requests as f64;
        fp.avg_risk_score = fp.avg_risk_score * ((n - 1.0) / n) + risk_score / n;

        if risk_score > fp.peak_risk_score {
            fp.peak_risk_score = risk_score;
        }

        fp.hourly_pattern[hour] += 1;
        fp.last_seen = timestamp;
    }

    /// Get a snapshot of the agent's behavioral fingerprint.
    pub fn get_fingerprint(&self, agent_id: &str) -> Option<AgentFingerprint> {
        let store = self.fingerprints.read().unwrap_or_else(|e| e.into_inner());
        store.get(agent_id).cloned()
    }

    /// Hydrate a fingerprint into the in-memory store (used on startup to load from DB).
    pub fn hydrate_fingerprint(&self, fp: AgentFingerprint) {
        let mut store = self.fingerprints.write().unwrap_or_else(|e| e.into_inner());
        store.insert(fp.agent_id.clone(), fp);
    }

    /// List summary fingerprints for all tracked agents.
    pub fn list_fingerprints(&self) -> Vec<AgentFingerprint> {
        let store = self.fingerprints.read().unwrap_or_else(|e| e.into_inner());
        store.values().cloned().collect()
    }

    /// Detect anomalies by comparing the current action against the agent's baseline.
    /// Returns a list of anomaly flag strings. Also updates the fingerprint's flags
    /// and anomaly_score.
    pub fn detect_anomalies(
        &self,
        agent_id: &str,
        tool_name: &str,
        risk_score: f64,
    ) -> Vec<String> {
        let now = Utc::now();
        let hour = now.hour() as usize;

        let mut store = self.fingerprints.write().unwrap_or_else(|e| e.into_inner());
        let fp = match store.get_mut(agent_id) {
            Some(fp) => fp,
            None => return Vec::new(),
        };

        let mut anomalies: Vec<String> = Vec::new();

        // 1. Risk spike: current risk > 2x the average
        if fp.avg_risk_score > 0.0 && risk_score > fp.avg_risk_score * 2.0 {
            anomalies.push("risk_spike".to_string());
        }

        // 2. Novel tool usage: tool not in top 5 and agent has > 20 requests
        if fp.total_requests > 20 {
            let mut tool_counts: Vec<(&String, &u64)> = fp.tool_usage.iter().collect();
            tool_counts.sort_by(|a, b| b.1.cmp(a.1));
            let top5: Vec<&String> = tool_counts.iter().take(5).map(|(k, _)| *k).collect();
            if !top5.contains(&&tool_name.to_string()) {
                anomalies.push("novel_tool_usage".to_string());
            }
        }

        // 3. Unusual hours: current hour has < 5% of total requests historically
        if fp.total_requests > 20 {
            let hour_count = fp.hourly_pattern[hour];
            let threshold = (fp.total_requests as f64 * 0.05) as u64;
            if hour_count < threshold {
                anomalies.push("unusual_hours".to_string());
            }
        }

        // 4. New action type: if action_type for this tool was never seen and agent has > 10 requests
        // We check tool_name presence since action_type was already recorded by record_action
        // before detect_anomalies is called — so we check if count == 1 (just added)
        // Actually, we compare against action_types map. Since record_action is called first,
        // a truly new action_type will have count == 1.
        // We re-derive from the current state: iterate action_types, find any with count == 1
        // and total_requests > 10. But the spec says "action_type never seen before", so we
        // check the current tool_name in action_types — but we don't receive action_type here.
        // The spec says detect_anomalies takes (agent_id, tool_name, risk_score).
        // We'll check if the tool_name count == 1 (meaning first time this tool was used)
        // and total_requests > 10, as a proxy for "new action pattern".
        if fp.total_requests > 10 {
            if let Some(&count) = fp.tool_usage.get(tool_name) {
                if count == 1 {
                    anomalies.push("new_action_type".to_string());
                }
            }
        }

        // Compute anomaly score: each flag contributes 25 points (max 100)
        fp.anomaly_score = (anomalies.len() as f64 * 25.0).min(100.0);

        // Merge new anomaly flags into fingerprint (keep unique)
        for flag in &anomalies {
            if !fp.flags.contains(flag) {
                fp.flags.push(flag.clone());
            }
        }

        anomalies
    }
}
