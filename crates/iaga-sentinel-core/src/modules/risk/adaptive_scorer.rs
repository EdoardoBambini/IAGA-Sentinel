//! LAYER 4 — Adaptive Risk Scoring Engine
//!
//! 5-signal ensemble: STATIC + CONTEXT + BEHAVIORAL + TEMPORAL + REPUTATION
//! Weights calibrate via online learning from user feedback. All local.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::modules::taint::taint_tracker::TaintAnalysisResult;

// ── Types ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskSignal {
    pub name: String,
    pub score: u32,
    pub weight: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdaptiveRiskResult {
    pub total_score: u32,
    pub decision: String,
    pub signals: Vec<RiskSignal>,
}

#[derive(Debug, Clone)]
struct Weights {
    stat: f64,
    context: f64,
    behavioral: f64,
    temporal: f64,
    reputation: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            stat: 0.20,
            context: 0.25,
            behavioral: 0.20,
            temporal: 0.15,
            reputation: 0.20,
        }
    }
}

static WEIGHTS: Lazy<Mutex<Weights>> = Lazy::new(|| Mutex::new(Weights::default()));

// ── Baselines ──

#[derive(Debug, Clone)]
struct AgentBaseline {
    avg_calls: f64,
    common_tools: HashMap<String, u32>,
    common_actions: HashMap<String, u32>,
    total_sessions: u32,
}

static BASELINES: Lazy<Mutex<HashMap<String, AgentBaseline>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn get_baseline(agent_id: &str) -> AgentBaseline {
    let store = BASELINES.lock().unwrap_or_else(|e| e.into_inner());
    store.get(agent_id).cloned().unwrap_or(AgentBaseline {
        avg_calls: 5.0,
        common_tools: HashMap::new(),
        common_actions: HashMap::new(),
        total_sessions: 0,
    })
}

pub fn update_baseline(agent_id: &str, tool_name: &str, action_type: &str, call_count: u32) {
    let mut store = BASELINES.lock().unwrap_or_else(|e| e.into_inner());
    let bl = store.entry(agent_id.to_string()).or_insert(AgentBaseline {
        avg_calls: 5.0,
        common_tools: HashMap::new(),
        common_actions: HashMap::new(),
        total_sessions: 0,
    });
    bl.total_sessions += 1;
    let alpha = 0.1;
    bl.avg_calls = (1.0 - alpha) * bl.avg_calls + alpha * call_count as f64;
    *bl.common_tools.entry(tool_name.to_string()).or_insert(0) += 1;
    *bl.common_actions
        .entry(action_type.to_string())
        .or_insert(0) += 1;
}

// ── Static Risk ──

fn static_risk(action_type: &str, tool_name: &str, payload_str: &str) -> RiskSignal {
    let w = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut score: u32 = match action_type {
        "file_read" => 15,
        "file_write" => 40,
        "shell" => 60,
        "http" => 30,
        "db_query" => 35,
        "email" => 45,
        "custom" => 25,
        _ => 20,
    };
    let mut reasons = vec![format!("base risk for {}: {}", action_type, score)];
    let text = format!("{} {}", tool_name, payload_str).to_lowercase();

    let patterns: Vec<(&str, u32, &str)> = vec![
        (r"database\.delete", 90, "database deletion"),
        (r"database\.drop", 95, "database drop"),
        (r"rm\s+-rf", 85, "recursive force delete"),
        (r"chmod\s+777", 75, "world-writable permissions"),
        (r"curl.+\|.+sh", 90, "pipe from curl to shell"),
        (r"powershell.+-enc", 85, "encoded powershell"),
        (
            r"ngrok|pastebin|webhook\.site",
            70,
            "suspicious external service",
        ),
        (r"passwd|shadow", 60, "system auth files"),
        (r"\.ssh", 55, "SSH keys access"),
        (r"\.env", 50, "environment secrets"),
    ];

    for (pat, bonus, reason) in &patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(&text) {
                score = (score + bonus / 2).min(100);
                reasons.push(reason.to_string());
            }
        }
    }

    RiskSignal {
        name: "static".into(),
        score: score.min(100),
        weight: w.stat,
        reasons,
    }
}

// ── Context Risk (from taint) ──

fn context_risk(taint: Option<&TaintAnalysisResult>) -> RiskSignal {
    let w = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut score: u32 = 0;
    let mut reasons = Vec::new();

    if let Some(t) = taint {
        if t.exfiltration_detected {
            score = 100;
            reasons.push("data exfiltration detected by taint tracking".into());
        } else if t.blocked {
            score = 90;
            reasons.push("taint policy violation".into());
        } else if !t.violations.is_empty() {
            score = 60 + (t.violations.len() as u32 * 10).min(40);
            reasons.push(format!("{} taint violation(s)", t.violations.len()));
        }

        if t.accumulated_labels.len() >= 4 {
            score = score.max(50);
            reasons.push(format!(
                "high taint accumulation: {} labels",
                t.accumulated_labels.len()
            ));
        }
        if t.source_taints.contains(&"secret".to_string()) {
            score = score.max(60);
            reasons.push("secret data involved".into());
        }
    } else {
        reasons.push("no taint data".into());
    }

    RiskSignal {
        name: "context".into(),
        score: score.min(100),
        weight: w.context,
        reasons,
    }
}

// ── Behavioral Risk ──

fn behavioral_risk(
    agent_id: &str,
    tool_name: &str,
    action_type: &str,
    session_calls: u32,
) -> RiskSignal {
    let w = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
    let bl = get_baseline(agent_id);
    let mut score: u32 = 0;
    let mut reasons = Vec::new();

    if bl.total_sessions == 0 {
        score = 15;
        reasons.push("new agent, no baseline established".into());
        return RiskSignal {
            name: "behavioral".into(),
            score,
            weight: w.behavioral,
            reasons,
        };
    }

    // Tool novelty
    let tool_freq = bl.common_tools.get(tool_name).copied().unwrap_or(0);
    let total_calls: u32 = bl.common_tools.values().sum();
    if total_calls > 0 && tool_freq == 0 {
        score += 30;
        reasons.push(format!("tool \"{}\" never used before", tool_name));
    }

    // Call count deviation
    if bl.avg_calls > 0.0 {
        let deviation = session_calls as f64 / bl.avg_calls;
        if deviation > 5.0 {
            score += 40;
            reasons.push(format!("call count {}x above baseline", deviation as u32));
        } else if deviation > 3.0 {
            score += 20;
            reasons.push(format!("elevated call count: {:.1}x baseline", deviation));
        }
    }

    // Action novelty
    if !bl.common_actions.contains_key(action_type) && bl.total_sessions > 5 {
        score += 25;
        reasons.push(format!("action type \"{}\" is novel", action_type));
    }

    RiskSignal {
        name: "behavioral".into(),
        score: score.min(100),
        weight: w.behavioral,
        reasons,
    }
}

// ── Temporal Risk ──

fn temporal_risk(call_timestamps: &[u64]) -> RiskSignal {
    let w = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let recent = call_timestamps.iter().filter(|&&t| now - t < 5_000).count();
    if recent > 10 {
        score += 50;
        reasons.push(format!("burst: {} calls in 5s", recent));
    } else if recent > 5 {
        score += 25;
        reasons.push(format!("elevated rate: {} calls in 5s", recent));
    }

    // Off-hours
    let hour = chrono::Utc::now().hour();
    if !(6..=22).contains(&hour) {
        score += 10;
        reasons.push(format!("off-hours activity (hour: {})", hour));
    }

    RiskSignal {
        name: "temporal".into(),
        score: score.min(100),
        weight: w.temporal,
        reasons,
    }
}

use chrono::Timelike;

// ── Reputation Risk ──

fn reputation_risk(agent_trust: f64, tool_trust: f64) -> RiskSignal {
    let w = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
    let avg = (agent_trust + tool_trust) / 2.0;
    let mut score = ((1.0 - avg) * 70.0) as u32;
    let mut reasons = Vec::new();

    if agent_trust < 0.2 {
        score += 15;
        reasons.push(format!("low agent trust: {:.2}", agent_trust));
    }
    if tool_trust < 0.2 {
        score += 15;
        reasons.push(format!("low tool trust: {:.2}", tool_trust));
    }

    if avg > 0.8 {
        reasons.push(format!("high trust: {:.2}", avg));
    } else if avg > 0.5 {
        reasons.push(format!("moderate trust: {:.2}", avg));
    } else {
        reasons.push(format!("insufficient trust history: {:.2}", avg));
    }

    RiskSignal {
        name: "reputation".into(),
        score: score.min(100),
        weight: w.reputation,
        reasons,
    }
}

// ── Main Scoring ──

pub struct AdaptiveScoreInput<'a> {
    pub agent_id: &'a str,
    pub action_type: &'a str,
    pub tool_name: &'a str,
    pub payload_str: &'a str,
    pub taint_result: Option<&'a TaintAnalysisResult>,
    pub session_call_count: u32,
    pub call_timestamps: &'a [u64],
    pub agent_trust: f64,
    pub tool_trust: f64,
}

pub fn calculate_adaptive_risk(input: &AdaptiveScoreInput) -> AdaptiveRiskResult {
    let signals = vec![
        static_risk(input.action_type, input.tool_name, input.payload_str),
        context_risk(input.taint_result),
        behavioral_risk(
            input.agent_id,
            input.tool_name,
            input.action_type,
            input.session_call_count,
        ),
        temporal_risk(input.call_timestamps),
        reputation_risk(input.agent_trust, input.tool_trust),
    ];

    let total: f64 = signals.iter().map(|s| s.score as f64 * s.weight).sum();
    let total_score = (total.round() as u32).min(100);

    // Unified thresholds — must match tool_risk::THRESHOLD_BLOCK / THRESHOLD_REVIEW
    let mut decision = if total_score >= 70 {
        "block"
    } else if total_score >= 35 {
        "human_review"
    } else {
        "pass"
    };

    if input.taint_result.is_some_and(|t| t.exfiltration_detected) {
        decision = "block";
    }

    AdaptiveRiskResult {
        total_score,
        decision: decision.to_string(),
        signals,
    }
}

// ── Weights API ──

#[derive(Debug, Clone, Serialize)]
pub struct WeightsInfo {
    pub stat: f64,
    pub context: f64,
    pub behavioral: f64,
    pub temporal: f64,
    pub reputation: f64,
}

pub fn get_current_weights() -> WeightsInfo {
    let w = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
    WeightsInfo {
        stat: w.stat,
        context: w.context,
        behavioral: w.behavioral,
        temporal: w.temporal,
        reputation: w.reputation,
    }
}

pub fn apply_feedback(feedback: &str) {
    let mut w = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
    let lr = 0.02;
    match feedback {
        "false_positive" => {
            w.stat = (w.stat - lr).max(0.05);
            w.context = (w.context - lr).max(0.05);
        }
        "false_negative" => {
            w.stat = (w.stat + lr).min(0.5);
            w.context = (w.context + lr).min(0.5);
        }
        _ => {}
    }
    let sum = w.stat + w.context + w.behavioral + w.temporal + w.reputation;
    w.stat /= sum;
    w.context /= sum;
    w.behavioral /= sum;
    w.temporal /= sum;
    w.reputation /= sum;
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn reset_state() {
        let mut weights = WEIGHTS.lock().unwrap_or_else(|e| e.into_inner());
        *weights = Weights::default();
        drop(weights);

        let mut baselines = BASELINES.lock().unwrap_or_else(|e| e.into_inner());
        baselines.clear();
    }

    #[test]
    fn adaptive_risk_uses_real_session_call_count() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();

        for _ in 0..10 {
            update_baseline("agent-session-aware", "tool-a", "file_read", 2);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let timestamps = vec![now];
        let input = AdaptiveScoreInput {
            agent_id: "agent-session-aware",
            action_type: "file_read",
            tool_name: "tool-a",
            payload_str: "{}",
            taint_result: None,
            session_call_count: 20,
            call_timestamps: &timestamps,
            agent_trust: 0.8,
            tool_trust: 0.8,
        };

        let result = calculate_adaptive_risk(&input);
        let behavioral = result
            .signals
            .iter()
            .find(|signal| signal.name == "behavioral")
            .expect("behavioral signal should exist");

        assert!(
            behavioral.score >= 40,
            "expected elevated behavioral score from real session length, got {:?}",
            behavioral
        );
        assert!(
            behavioral
                .reasons
                .iter()
                .any(|reason| reason.contains("call count")),
            "expected call-count deviation reason, got {:?}",
            behavioral.reasons
        );
    }

    #[test]
    fn adaptive_risk_uses_recent_timestamps_for_burst_detection() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_state();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let timestamps = vec![now; 11];
        let input = AdaptiveScoreInput {
            agent_id: "agent-burst-aware",
            action_type: "http",
            tool_name: "tool-b",
            payload_str: "{\"url\":\"https://example.com\"}",
            taint_result: None,
            session_call_count: 11,
            call_timestamps: &timestamps,
            agent_trust: 0.7,
            tool_trust: 0.7,
        };

        let result = calculate_adaptive_risk(&input);
        let temporal = result
            .signals
            .iter()
            .find(|signal| signal.name == "temporal")
            .expect("temporal signal should exist");

        assert!(
            temporal.score >= 50,
            "expected burst detection from recent timestamps, got {:?}",
            temporal
        );
        assert!(
            temporal
                .reasons
                .iter()
                .any(|reason| reason.contains("burst")),
            "expected burst reason, got {:?}",
            temporal.reasons
        );
    }
}
