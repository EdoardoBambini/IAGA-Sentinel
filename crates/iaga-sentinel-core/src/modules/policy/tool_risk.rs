use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::types::{ActionType, GovernanceDecision, InspectRequest, RiskScore};

static HIGH_RISK_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"(?i)rm\s+-rf",
        r"(?i)chmod\s+777",
        r"(?i)curl.+\|.+sh",
        r"(?i)powershell.+-enc",
        r"(?i)base64",
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

static SUSPICIOUS_URL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [r"(?i)ngrok", r"(?i)pastebin", r"(?i)discordapp"]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

/// Unified decision thresholds (single source of truth).
pub const THRESHOLD_BLOCK: u32 = 70;
pub const THRESHOLD_REVIEW: u32 = 35;

/// Accumulated risk contributions from each security layer.
/// Built up in execute_pipeline and passed here for final scoring.
#[derive(Debug, Default)]
pub struct LayerRiskContributions {
    /// Firewall detection score (0-100)
    pub firewall: u32,
    /// Threat intelligence match score
    pub threat_intel: u32,
    /// Taint tracking violation score
    pub taint: u32,
    /// Session graph anomaly score
    pub session_graph: u32,
    /// Adaptive risk ensemble score
    pub adaptive: u32,
    /// Behavioral fingerprint anomaly score
    pub behavioral: u32,
    /// Policy violations (not approved, baseline deviation, etc.)
    pub policy: u32,
    /// Secret injection risk
    pub secrets: u32,
    /// Optional WASM plugin risk contribution
    pub plugins: u32,
}

pub fn score_tool_risk(
    input: &InspectRequest,
    minimum_decision: GovernanceDecision,
    policy_findings: &[String],
    layers: &LayerRiskContributions,
) -> RiskScore {
    score_tool_risk_with_thresholds(
        input,
        minimum_decision,
        policy_findings,
        layers,
        THRESHOLD_BLOCK,
        THRESHOLD_REVIEW,
    )
}

pub fn score_tool_risk_with_thresholds(
    input: &InspectRequest,
    minimum_decision: GovernanceDecision,
    policy_findings: &[String],
    layers: &LayerRiskContributions,
    threshold_block: u32,
    threshold_review: u32,
) -> RiskScore {
    let mut reasons: Vec<String> = Vec::new();

    let payload_text = serde_json::to_string(&input.action.payload).unwrap_or_default();

    // ── Local pattern scoring (fast, deterministic) ──
    let mut pattern_score: u32 = 0;

    if input.action.action_type == ActionType::Shell {
        pattern_score += 25;
        reasons.push("shell execution requires elevated scrutiny".to_string());
    }

    for pattern in HIGH_RISK_PATTERNS.iter() {
        if pattern.is_match(&payload_text) {
            pattern_score += 40;
            reasons.push(format!("matched high-risk pattern: {}", pattern.as_str()));
        }
    }

    for pattern in SUSPICIOUS_URL_PATTERNS.iter() {
        if pattern.is_match(&payload_text) {
            pattern_score += 25;
            reasons.push(format!(
                "matched suspicious destination: {}",
                pattern.as_str()
            ));
        }
    }

    if input
        .requested_secrets
        .as_ref()
        .is_some_and(|s| !s.is_empty())
    {
        pattern_score += 15;
        reasons.push("action requests dynamic secret injection".to_string());
    }

    if input.action.action_type == ActionType::DbQuery {
        pattern_score += 20;
        reasons.push("database access should be policy-gated".to_string());
    }

    if policy_findings
        .iter()
        .any(|f| f.contains("outside baseline"))
    {
        pattern_score += 20;
        reasons.push("behavior deviates from baseline".to_string());
    }

    pattern_score = pattern_score.min(100);

    // ── Composite score from all 8 layers ──
    // Each layer contributes proportionally to its detection confidence.
    // We take the MAX of each signal group to avoid double-counting,
    // then compute a weighted composite.
    //
    // Weight allocation:
    //   - Pattern matching (local):  15%  — fast regex-based detection
    //   - Adaptive ensemble:         20%  — 5-signal ML-style scoring
    //   - Firewall:                  20%  — injection-specific detection
    //   - Policy + behavioral:       15%  — authorization & baseline
    //   - Taint + threat intel:      15%  — data flow & IOC matching
    //   - Secrets:                   10%  — vault policy enforcement
    //   - Session graph:              5%  — stateful anomaly
    //   - WASM plugins:              10%  — custom detectors/community extensions

    let composite = (pattern_score as f64 * 0.15)
        + (layers.adaptive as f64 * 0.20)
        + (layers.firewall as f64 * 0.20)
        + ((layers.policy.max(layers.behavioral)) as f64 * 0.15)
        + ((layers.taint.max(layers.threat_intel)) as f64 * 0.15)
        + (layers.secrets as f64 * 0.10)
        + (layers.session_graph as f64 * 0.05)
        + (layers.plugins as f64 * 0.10);

    let mut score = (composite.round() as u32).min(100);

    // ── Decision-aware score adjustment ──
    // When security layers force a higher decision, the score should
    // reflect that severity — but proportionally, not as a flat floor.
    // This ensures Block decisions always score >= 70 and Review >= 35,
    // while preserving granularity WITHIN each band.
    match minimum_decision {
        GovernanceDecision::Block => {
            if score < threshold_block {
                let headroom = 100u32.saturating_sub(threshold_block);
                score = threshold_block + (score * headroom / 100).min(headroom);
                reasons.push(format!(
                    "escalated by security layers (raw composite: {:.0})",
                    composite
                ));
            }
        }
        GovernanceDecision::Review => {
            if score < threshold_review {
                let headroom = threshold_block.saturating_sub(threshold_review);
                score = threshold_review + (score * headroom / 100).min(headroom);
                reasons.push(format!(
                    "escalated to review by security layers (raw composite: {:.0})",
                    composite
                ));
            }
        }
        GovernanceDecision::Allow => {}
    }

    score = score.min(100);

    // ── Final decision ──
    let score_decision = if score >= threshold_block {
        GovernanceDecision::Block
    } else if score >= threshold_review {
        GovernanceDecision::Review
    } else {
        GovernanceDecision::Allow
    };

    let final_decision = if minimum_decision > score_decision {
        minimum_decision
    } else {
        score_decision
    };

    if reasons.is_empty() {
        reasons.push("no high-risk rule matched".to_string());
    }

    RiskScore {
        score,
        decision: final_decision,
        reasons,
    }
}
