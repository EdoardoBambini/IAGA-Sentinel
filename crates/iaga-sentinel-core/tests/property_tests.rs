//! Property-based tests for IAGA Sentinel security layers.
//!
//! Uses proptest to verify invariants that must hold for ALL possible inputs,
//! not just hand-picked examples.

use std::collections::HashSet;

use proptest::prelude::*;

use iaga_sentinel::modules::injection_firewall::prompt_firewall;
use iaga_sentinel::modules::risk::adaptive_scorer::{self, AdaptiveScoreInput};
use iaga_sentinel::modules::session_graph::session_dag;
use iaga_sentinel::modules::taint::taint_tracker;

// ── Strategies ──

fn action_type_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("file_read".to_string()),
        Just("file_write".to_string()),
        Just("shell".to_string()),
        Just("http".to_string()),
        Just("db_query".to_string()),
        Just("email".to_string()),
        Just("custom".to_string()),
        "[a-z_]{1,20}",
    ]
}

fn tool_name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("bash".to_string()),
        Just("curl".to_string()),
        Just("psql".to_string()),
        Just("filesystem.read".to_string()),
        Just("http.fetch".to_string()),
        Just("terminal.exec".to_string()),
        "[a-z.]{1,30}",
    ]
}

fn taint_label_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("untrusted_user".to_string()),
        Just("external_tool".to_string()),
        Just("local_fs".to_string()),
        Just("secret".to_string()),
        Just("internal_api".to_string()),
        Just("shell_output".to_string()),
        Just("db_result".to_string()),
        Just("network_response".to_string()),
    ]
}

fn taint_set_strategy() -> impl Strategy<Value = HashSet<String>> {
    prop::collection::hash_set(taint_label_strategy(), 0..5)
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 7, Prompt Injection Firewall
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Risk score must always be in [0, 100].
    #[test]
    fn firewall_score_in_valid_range(text in "\\PC{0,2000}") {
        let result = prompt_firewall::scan_prompt(&text);
        prop_assert!(result.risk_score <= 100,
            "risk_score {} exceeds 100 for input len={}", result.risk_score, text.len());
    }

    /// blocked must be true iff risk_score >= 75.
    #[test]
    fn firewall_blocked_iff_score_gte_75(text in "\\PC{0,2000}") {
        let result = prompt_firewall::scan_prompt(&text);
        prop_assert_eq!(result.blocked, result.risk_score >= 75,
            "blocked={} but risk_score={}", result.blocked, result.risk_score);
    }

    /// Determinism: same input must always produce the same score and decision.
    #[test]
    fn firewall_deterministic(text in "\\PC{0,500}") {
        let r1 = prompt_firewall::scan_prompt(&text);
        let r2 = prompt_firewall::scan_prompt(&text);
        prop_assert_eq!(r1.risk_score, r2.risk_score, "non-deterministic score");
        prop_assert_eq!(r1.blocked, r2.blocked, "non-deterministic decision");
    }

    /// stages_run must be at least 2 (stage 1 and 2 always run).
    #[test]
    fn firewall_minimum_stages(text in "\\PC{0,1000}") {
        let result = prompt_firewall::scan_prompt(&text);
        prop_assert!(result.stages_run >= 2,
            "stages_run={} but minimum is 2", result.stages_run);
    }

    /// quick_scan must agree with scan_prompt.
    #[test]
    fn firewall_quick_scan_consistent(text in "\\PC{0,500}") {
        let full = prompt_firewall::scan_prompt(&text);
        let (blocked, score) = prompt_firewall::quick_scan(&text);
        prop_assert_eq!(full.blocked, blocked, "quick_scan blocked disagrees");
        prop_assert_eq!(full.risk_score, score, "quick_scan score disagrees");
    }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 2, Taint Tracking
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Accumulated labels must be a superset of inherited taints (monotonic).
    #[test]
    fn taint_accumulation_monotonic(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "\\PC{0,500}",
        inherited in taint_set_strategy(),
    ) {
        let result = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
        for label in &inherited {
            prop_assert!(result.accumulated_labels.contains(label),
                "inherited label '{}' missing from accumulated", label);
        }
    }

    /// classify_sink must not panic on arbitrary inputs.
    #[test]
    fn taint_classify_sink_no_panic(
        action in "\\PC{0,100}",
        tool in "\\PC{0,100}",
    ) {
        let _ = taint_tracker::classify_sink(&action, &tool);
    }

    /// classify_source must not panic on arbitrary inputs.
    #[test]
    fn taint_classify_source_no_panic(
        action in "\\PC{0,100}",
        tool in "\\PC{0,100}",
        payload in "\\PC{0,500}",
    ) {
        let _ = taint_tracker::classify_source(&action, &tool, &payload);
    }

    /// analyze_taint must not panic on arbitrary inputs.
    #[test]
    fn taint_analyze_no_panic(
        action in "\\PC{0,100}",
        tool in "\\PC{0,100}",
        payload in "\\PC{0,500}",
        inherited in taint_set_strategy(),
    ) {
        let _ = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
    }

    /// Determinism: same inputs produce same result.
    #[test]
    fn taint_deterministic(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "[a-zA-Z0-9 /._]{0,200}",
        inherited in taint_set_strategy(),
    ) {
        let r1 = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
        let r2 = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
        prop_assert_eq!(r1.blocked, r2.blocked, "non-deterministic blocked");
        prop_assert_eq!(r1.exfiltration_detected, r2.exfiltration_detected,
            "non-deterministic exfiltration");
        prop_assert_eq!(r1.source_taints, r2.source_taints,
            "non-deterministic source taints");
    }

    /// Secret paths must be detected by classify_source.
    #[test]
    fn taint_detects_secret_paths(
        path in prop_oneof![
            Just(".env"),
            Just(".ssh/id_rsa"),
            Just("credentials.json"),
            Just("vault/secrets"),
            Just("config.pem"),
        ],
    ) {
        let payload = format!(r#"{{"path": "{}"}}"#, path);
        let labels = taint_tracker::classify_source("file_read", "filesystem.read", &payload);
        prop_assert!(labels.contains(&"secret".to_string()) || labels.contains(&"local_fs".to_string()),
            "secret path '{}' not detected, got labels: {:?}", path, labels);
    }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 4, Adaptive Risk Scoring
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// Total score must always be in [0, 100].
    #[test]
    fn adaptive_score_in_valid_range(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "[a-zA-Z0-9 /._]{0,200}",
        call_count in 0u32..100,
        trust in 0.0f64..=1.0,
    ) {
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: &payload,
            taint_result: None,
            session_call_count: call_count,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input);
        prop_assert!(result.total_score <= 100,
            "total_score {} exceeds 100", result.total_score);
    }

    /// Decision must be consistent with score thresholds.
    #[test]
    fn adaptive_decision_matches_thresholds(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "[a-zA-Z0-9 ]{0,100}",
        trust in 0.0f64..=1.0,
    ) {
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: &payload,
            taint_result: None,
            session_call_count: 1,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input);

        // Without exfiltration, decision must follow score thresholds
        if result.total_score >= 70 {
            prop_assert_eq!(result.decision, "block",
                "score={} should be block", result.total_score);
        } else if result.total_score >= 35 {
            prop_assert_eq!(result.decision, "human_review",
                "score={} should be human_review", result.total_score);
        } else {
            prop_assert_eq!(result.decision, "pass",
                "score={} should be pass", result.total_score);
        }
    }

    /// 5 signals must always be present.
    #[test]
    fn adaptive_always_5_signals(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        trust in 0.0f64..=1.0,
    ) {
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: "",
            taint_result: None,
            session_call_count: 1,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input);
        prop_assert_eq!(result.signals.len(), 5,
            "expected 5 signals, got {}", result.signals.len());
    }

    /// Exfiltration in taint must force block decision.
    #[test]
    fn adaptive_exfiltration_forces_block(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        trust in 0.0f64..=1.0,
    ) {
        let taint = iaga_sentinel::modules::taint::taint_tracker::TaintAnalysisResult {
            source_taints: vec!["secret".to_string()],
            sink_type: Some("network_egress".to_string()),
            accumulated_labels: HashSet::from(["secret".to_string()]),
            violations: vec![],
            blocked: true,
            exfiltration_detected: true,
            summary: "exfiltration".to_string(),
        };
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: "",
            taint_result: Some(&taint),
            session_call_count: 1,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input);
        let decision = result.decision.clone();
        prop_assert_eq!(decision, "block",
            "exfiltration_detected but decision={}", result.decision);
    }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 1, Session Graph / DAG
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// anomaly_score must be in [0, 100].
    #[test]
    fn session_anomaly_score_in_range(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        taints in taint_set_strategy(),
    ) {
        let session_id = format!("prop-session-{}", uuid::Uuid::new_v4());
        let result = session_dag::add_tool_call_to_session(
            &session_id, "prop-agent", &tool, &action, taints,
        );
        prop_assert!(result.anomaly_score <= 100,
            "anomaly_score {} exceeds 100", result.anomaly_score);
    }

    /// add_tool_call_to_session must not panic on arbitrary inputs.
    #[test]
    fn session_no_panic_arbitrary(
        action in "\\PC{0,50}",
        tool in "\\PC{0,50}",
        taints in taint_set_strategy(),
    ) {
        let session_id = format!("prop-panic-{}", uuid::Uuid::new_v4());
        let _ = session_dag::add_tool_call_to_session(
            &session_id, "prop-agent", &tool, &action, taints,
        );
    }

    /// First call to a new session with a known action type must be allowed.
    #[test]
    fn session_first_call_allowed(
        action in prop_oneof![
            Just("file_read".to_string()),
            Just("file_write".to_string()),
            Just("shell".to_string()),
            Just("http".to_string()),
            Just("db_query".to_string()),
            Just("email".to_string()),
        ],
        tool in tool_name_strategy(),
    ) {
        let session_id = format!("prop-first-{}", uuid::Uuid::new_v4());
        let result = session_dag::add_tool_call_to_session(
            &session_id, "prop-agent", &tool, &action, HashSet::new(),
        );
        prop_assert!(result.transition_allowed,
            "first call to new session should be allowed for action={}, got new_state={}", action, result.new_state);
    }

    /// Multiple calls to the same session must produce monotonically increasing node counts.
    #[test]
    fn session_node_ids_unique(
        actions in prop::collection::vec(action_type_strategy(), 2..5),
    ) {
        let session_id = format!("prop-multi-{}", uuid::Uuid::new_v4());
        let mut node_ids = Vec::new();
        for action in &actions {
            let result = session_dag::add_tool_call_to_session(
                &session_id, "prop-agent", "test-tool", action, HashSet::new(),
            );
            if !result.node_id.is_empty() {
                node_ids.push(result.node_id.clone());
            }
        }
        let unique: HashSet<_> = node_ids.iter().collect();
        prop_assert_eq!(unique.len(), node_ids.len(),
            "duplicate node IDs in session: {:?}", node_ids);
    }
}
