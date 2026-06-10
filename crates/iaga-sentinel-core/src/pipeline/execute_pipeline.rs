use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use uuid::Uuid;

use crate::core::errors::SentinelError;
use crate::core::types::*;
use crate::modules::injection_firewall::prompt_firewall;
use crate::modules::nhi::crypto_identity;
use crate::modules::policy::evaluate_policy::evaluate_policy;
use crate::modules::policy::formal_verify;
use crate::modules::policy::rules_engine::evaluate_rules;
use crate::modules::policy::tool_risk::{score_tool_risk_with_thresholds, LayerRiskContributions};
use crate::modules::protocol::detect_protocol::detect_protocol;
use crate::modules::protocol::protocol_envelope::{
    normalize_protocol_payload, validate_protocol_payload,
};
use crate::modules::risk::adaptive_scorer::{self, AdaptiveScoreInput};
use crate::modules::sandbox::sandbox_executor;
use crate::modules::secrets::secret_references::plan_secret_injection;
use crate::modules::session_graph::session_dag;
use crate::modules::taint::taint_tracker;
use crate::modules::telemetry::otel_emitter;
use crate::plugins::PluginInspectRequest;
use crate::server::app_state::AppState;

fn action_type_str(at: ActionType) -> &'static str {
    match at {
        ActionType::Shell => "shell",
        ActionType::FileRead => "file_read",
        ActionType::FileWrite => "file_write",
        ActionType::Http => "http",
        ActionType::DbQuery => "db_query",
        ActionType::Email => "email",
        ActionType::Custom => "custom",
    }
}

fn protocol_name(protocol: ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::Mcp => "mcp",
        ProtocolKind::Acp => "acp",
        ProtocolKind::A2a => "a2a",
        ProtocolKind::HttpFunction => "http-function",
        ProtocolKind::Unknown => "unknown",
    }
}

pub async fn execute_pipeline(
    input: &InspectRequest,
    state: &Arc<AppState>,
) -> Result<GovernanceResult, SentinelError> {
    let pipeline_start = std::time::Instant::now();
    let trace_id = Uuid::new_v4().to_string();

    tracing::debug!(
        trace_id = %trace_id,
        agent_id = %input.agent_id,
        tool_name = %input.action.tool_name,
        "governance pipeline started"
    );

    let profile = state
        .policy_store
        .get_agent_profile(&input.agent_id)
        .await?;
    let workspace_id = input
        .workspace_id
        .as_deref()
        .unwrap_or(&profile.workspace_id);
    let workspace_policy = state
        .policy_store
        .get_workspace_policy(workspace_id)
        .await?;
    let tenant_id = input
        .tenant_id
        .clone()
        .or(profile.tenant_id.clone())
        .or(workspace_policy.tenant_id.clone());

    // ═══════════════════════════════════════════════════════════════
    // RATE LIMIT CHECK, runs before all security layers
    // ═══════════════════════════════════════════════════════════════
    let rate_result = state
        .rate_limiter
        .check_rate(&input.agent_id, Some(&input.action.tool_name))
        .await;

    if !rate_result.allowed {
        let now = Utc::now().to_rfc3339();
        let event_id = Uuid::new_v4().to_string();
        let finding = format!(
            "Rate limit exceeded (remaining={}, retry_after={}s)",
            rate_result.remaining,
            rate_result.retry_after_secs.unwrap_or(0)
        );

        let risk = RiskScore {
            score: 0,
            decision: GovernanceDecision::Block,
            reasons: vec![finding.clone()],
        };

        let audit_event = AuditEvent {
            event_id: event_id.clone(),
            agent_id: input.agent_id.clone(),
            framework: input.framework.clone(),
            action_type: input.action.action_type,
            tool_name: input.action.tool_name.clone(),
            decision: GovernanceDecision::Block,
            timestamp: now.clone(),
            reasons: vec![finding.clone()],
        };

        let stored = StoredAuditEvent {
            event_id: audit_event.event_id.clone(),
            agent_id: audit_event.agent_id.clone(),
            tenant_id: tenant_id.clone(),
            framework: audit_event.framework.clone(),
            action_type: audit_event.action_type,
            tool_name: audit_event.tool_name.clone(),
            decision: GovernanceDecision::Block,
            timestamp: audit_event.timestamp.clone(),
            reasons: audit_event.reasons.clone(),
            review_status: ReviewStatus::NotRequired,
            risk_score: 0,
            usage: None,
        };
        if let Err(e) = state.audit_store.append(&stored).await {
            tracing::error!(event_id = %stored.event_id, error = %e, "Failed to persist audit event");
        }
        if let Some(rl) = state.receipts.as_ref() {
            // Fast-path block: no ML evidence or usage at this stage.
            rl.record(&stored, None, None).await;
        }

        return Ok(GovernanceResult {
            trace_id,
            protocol: detect_protocol(input),
            normalized_payload: input.action.payload.clone(),
            decision: GovernanceDecision::Block,
            review_status: ReviewStatus::NotRequired,
            risk,
            secret_plan: SecretInjectionPlan {
                approved: vec![],
                denied: vec![],
            },
            audit_event,
            profile,
            workspace_policy,
            policy_findings: vec![finding],
            schema_validation: SchemaValidation {
                tool_name: input.action.tool_name.clone(),
                valid: true,
                findings: vec![],
            },
            review_request_id: None,
            session_graph: None,
            taint_analysis: None,
            adaptive_risk: None,
            sandbox_result: None,
            injection_firewall: None,
            policy_verification: None,
            telemetry_span: None,
            behavioral_fingerprint: None,
            threat_intel: None,
            plugin_results: None,
        });
    }

    let protocol = detect_protocol(input);

    let normalized_payload = normalize_protocol_payload(input, protocol);

    let schema_validation = validate_protocol_payload(input, protocol);

    let action_type_s = action_type_str(input.action.action_type);
    let payload_json = serde_json::Value::Object(
        input
            .action
            .payload
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    let payload_str = serde_json::to_string(&payload_json).unwrap_or_default();

    // ═══════════════════════════════════════════════════════════════
    // LAYER 7, Prompt Injection Firewall (runs FIRST, fastest gate)
    // ═══════════════════════════════════════════════════════════════
    let firewall_result = prompt_firewall::scan_prompt(&payload_str);
    let firewall_json = serde_json::to_value(&firewall_result).ok();

    // ═══════════════════════════════════════════════════════════════
    // THREAT INTELLIGENCE, check payload against known IOCs
    // ═══════════════════════════════════════════════════════════════
    let threat_matches = state.threat_feed.check_threats(&payload_str);
    let threat_intel_json = if threat_matches.is_empty() {
        None
    } else {
        serde_json::to_value(serde_json::json!({
            "matches": threat_matches,
            "count": threat_matches.len(),
        }))
        .ok()
    };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 1, Session Graph Analysis
    // ═══════════════════════════════════════════════════════════════
    // Session key: prefer an explicit `sessionId` from metadata. When the caller
    // omits it we fall back to `agent_id`, which groups every session-less call
    // from the same agent into ONE long-lived DAG (session_dag::SESSIONS, 30-min
    // TTL refreshed per call). Attack-signature matching is a subsequence scan
    // over the whole uncapped node history, so a busy agent that never sets a
    // sessionId can eventually match multi-step signatures across unrelated
    // operations (false positives; fail-safe toward Review/Block, not a bypass).
    // For precise per-task correlation, pass a stable `metadata.sessionId` per
    // logical session (all SDK adapters expose it).
    let session_id = input
        .metadata
        .as_ref()
        .and_then(|m| m.get("sessionId"))
        .and_then(|v| v.as_str())
        .unwrap_or(&input.agent_id);

    // We need inherited taints for session graph too, so get them first
    let inherited_taints = taint_tracker::get_session_taint(session_id);

    let session_result = session_dag::add_tool_call_to_session(
        session_id,
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        inherited_taints.clone(),
    );
    let session_json = serde_json::to_value(&session_result).ok();

    // v0.4.0, persist session graph to durable storage (write-behind)
    if let Some(session) = session_dag::get_session(session_id) {
        let session_store = state.session_store.clone();
        let session_owned = session;
        tokio::spawn(async move {
            if let Err(e) = session_store.store_session(&session_owned).await {
                tracing::warn!(error = %e, "failed to persist session graph");
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // LAYER 2, Taint Tracking
    // ═══════════════════════════════════════════════════════════════
    let taint_result = taint_tracker::analyze_taint(
        action_type_s,
        &input.action.tool_name,
        &payload_str,
        &inherited_taints,
    );
    taint_tracker::update_session_taint(session_id, &taint_result.accumulated_labels);
    let taint_json = serde_json::to_value(&taint_result).ok();

    // v0.4.0, persist taint labels to durable storage (write-behind)
    {
        let taint_store = state.taint_store.clone();
        let sid = session_id.to_string();
        let labels = taint_result.accumulated_labels.clone();
        tokio::spawn(async move {
            if let Err(e) = taint_store.update_session_taint(&sid, &labels).await {
                tracing::warn!(error = %e, "failed to persist taint labels");
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // LAYER 3, Crypto NHI (ensure agent identity exists)
    // ═══════════════════════════════════════════════════════════════
    if crypto_identity::get_identity(&input.agent_id).is_none() {
        let identity = crypto_identity::register_identity(
            &input.agent_id,
            Some(workspace_id),
            profile.approved_tools.clone(),
        );
        // v0.4.0, persist new NHI identity to durable storage
        let secret_hex = crypto_identity::get_secret_key_hex(&input.agent_id).unwrap_or_default();
        let nhi_store = state.nhi_store.clone();
        let identity_owned = identity;
        tokio::spawn(async move {
            if let Err(e) = nhi_store.store_identity(&identity_owned, &secret_hex).await {
                tracing::warn!(error = %e, "failed to persist NHI identity");
            }
        });
    }
    let agent_trust = crypto_identity::get_agent_trust(&input.agent_id);

    // ═══════════════════════════════════════════════════════════════
    // LAYER 4, Adaptive Risk Scoring (5-signal ensemble)
    // ═══════════════════════════════════════════════════════════════
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let session_call_count = session_result.session_call_count.max(1);
    let call_timestamps = if session_result.recent_call_timestamps.is_empty() {
        vec![now_ms]
    } else {
        session_result.recent_call_timestamps.clone()
    };

    let adaptive_input = AdaptiveScoreInput {
        agent_id: &input.agent_id,
        action_type: action_type_s,
        tool_name: &input.action.tool_name,
        payload_str: &payload_str,
        taint_result: Some(&taint_result),
        session_call_count,
        call_timestamps: &call_timestamps,
        agent_trust,
        tool_trust: profile.tool_trust,
    };
    let adaptive_result = adaptive_scorer::calculate_adaptive_risk(&adaptive_input);
    let adaptive_json = serde_json::to_value(&adaptive_result).ok();

    // Update baseline for future behavioral analysis
    adaptive_scorer::update_baseline(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        session_call_count,
    );

    // ═══════════════════════════════════════════════════════════════
    // Behavioral Fingerprinting, record action & detect anomalies
    // ═══════════════════════════════════════════════════════════════
    state.behavioral_engine.record_action(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        adaptive_result.total_score as f64,
    );
    let fingerprint_anomalies = state.behavioral_engine.detect_anomalies(
        &input.agent_id,
        &input.action.tool_name,
        adaptive_result.total_score as f64,
    );

    // v0.4.0, persist behavioral fingerprint to durable storage (write-behind)
    if let Some(fp) = state.behavioral_engine.get_fingerprint(&input.agent_id) {
        let fp_store = state.fingerprint_store.clone();
        tokio::spawn(async move {
            if let Err(e) = fp_store.upsert_fingerprint(&fp).await {
                tracing::warn!(error = %e, "failed to persist behavioral fingerprint");
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // LAYER 5, Sandbox Execution (dry-run for high-risk)
    // ═══════════════════════════════════════════════════════════════
    let sandbox_json =
        if sandbox_executor::should_sandbox(action_type_s, adaptive_result.total_score) {
            let sb = sandbox_executor::sandbox_execute(
                &input.action.tool_name,
                action_type_s,
                &payload_json,
                adaptive_result.total_score,
            );
            serde_json::to_value(&sb).ok()
        } else {
            None
        };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 6, Formal Policy Verification
    // ═══════════════════════════════════════════════════════════════
    let verification = formal_verify::verify_policy(&workspace_policy);
    let verification_json = serde_json::to_value(&verification).ok();

    let plugin_evaluation = state.plugin_registry.evaluate(&PluginInspectRequest {
        agent_id: input.agent_id.clone(),
        tool_name: input.action.tool_name.clone(),
        action_type: action_type_s.to_string(),
        framework: input.framework.clone(),
        payload: payload_json.clone(),
        risk_score: adaptive_result.total_score,
    });

    // ═══════════════════════════════════════════════════════════════
    // Original policy evaluation + risk scoring
    // ═══════════════════════════════════════════════════════════════
    let policy_eval = evaluate_policy(input, &profile, &workspace_policy, protocol);
    let workspace_rules = state
        .policy_store
        .list_workspace_rules(workspace_id)
        .await?;
    let matched_workspace_rule = evaluate_rules(
        &workspace_rules,
        input,
        profile.role,
        Some(adaptive_result.total_score),
    );
    let secret_plan = plan_secret_injection(input, &profile);
    let secret_denied = !secret_plan.denied.is_empty();

    let mut policy_findings = policy_eval.findings;

    if let Some(rule_match) = &matched_workspace_rule {
        policy_findings.push(format!(
            "policy rule [{}]: {}",
            rule_match.rule_name, rule_match.reason
        ));
    }

    if secret_denied {
        policy_findings
            .push("one or more requested secrets were denied by vault policy".to_string());
    }
    if !schema_validation.valid {
        policy_findings.push(format!(
            "{} protocol schema validation failed",
            protocol_name(protocol)
        ));
    }
    for error in &plugin_evaluation.errors {
        policy_findings.push(format!("plugin runtime: {}", error));
    }

    // ═══════════════════════════════════════════════════════════════
    // Integrate 8-layer signals into decision + layer risk scores
    // ═══════════════════════════════════════════════════════════════
    let mut minimum_decision = policy_eval.minimum_decision;

    if let Some(rule_match) = &matched_workspace_rule {
        match rule_match.decision {
            GovernanceDecision::Block => minimum_decision = GovernanceDecision::Block,
            GovernanceDecision::Review => {
                if minimum_decision != GovernanceDecision::Block {
                    minimum_decision = GovernanceDecision::Review;
                }
            }
            GovernanceDecision::Allow => {
                if minimum_decision == GovernanceDecision::Review {
                    minimum_decision = GovernanceDecision::Allow;
                }
            }
        }
    }

    let mut layer_risks = LayerRiskContributions {
        firewall: firewall_result.risk_score,
        ..Default::default()
    };

    // ── Firewall ──
    if firewall_result.blocked {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!("injection firewall: {}", firewall_result.summary));
    }

    // ── Threat Intelligence ──
    if !threat_matches.is_empty() {
        for tm in &threat_matches {
            policy_findings.push(format!(
                "threat intel [{}]: {} (severity={})",
                tm.indicator_type, tm.description, tm.severity
            ));
        }
        let has_critical = threat_matches.iter().any(|m| m.severity == "critical");
        let has_high = threat_matches.iter().any(|m| m.severity == "high");
        layer_risks.threat_intel = if has_critical {
            95
        } else if has_high {
            75
        } else {
            50
        };
        if has_critical {
            minimum_decision = GovernanceDecision::Block;
        } else if has_high && minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // ── Taint ──
    if taint_result.exfiltration_detected {
        layer_risks.taint = 100;
    } else if taint_result.blocked {
        layer_risks.taint = 90;
    } else if !taint_result.violations.is_empty() {
        layer_risks.taint = 60 + (taint_result.violations.len() as u32 * 10).min(30);
    }
    if taint_result.blocked {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!("taint tracking: {}", taint_result.summary));
    }

    // ── Plugins ──
    if !plugin_evaluation.outputs.is_empty() {
        layer_risks.plugins = plugin_evaluation
            .outputs
            .iter()
            .map(|output| output.result.risk_score)
            .max()
            .unwrap_or(0);

        for output in &plugin_evaluation.outputs {
            for finding in &output.result.findings {
                policy_findings.push(format!("plugin [{}]: {}", output.plugin_name, finding));
            }

            if let Some(hint) = output.result.decision_hint.as_deref() {
                match hint.to_ascii_lowercase().as_str() {
                    "block" => {
                        minimum_decision = GovernanceDecision::Block;
                        policy_findings.push(format!(
                            "plugin [{}]: decision hint -> block",
                            output.plugin_name
                        ));
                    }
                    "review" | "human_review" => {
                        if minimum_decision != GovernanceDecision::Block {
                            minimum_decision = GovernanceDecision::Review;
                        }
                        policy_findings.push(format!(
                            "plugin [{}]: decision hint -> review",
                            output.plugin_name
                        ));
                    }
                    _ => {}
                }
            }
        }

        if layer_risks.plugins >= workspace_policy.threshold_block {
            minimum_decision = GovernanceDecision::Block;
            policy_findings.push(format!(
                "plugin risk: score={} → block",
                layer_risks.plugins
            ));
        } else if layer_risks.plugins >= workspace_policy.threshold_review
            && minimum_decision != GovernanceDecision::Block
        {
            minimum_decision = GovernanceDecision::Review;
            policy_findings.push(format!(
                "plugin risk: score={} → review",
                layer_risks.plugins
            ));
        }
    } else if !plugin_evaluation.errors.is_empty() && minimum_decision != GovernanceDecision::Block
    {
        minimum_decision = GovernanceDecision::Review;
    }

    // ── Session Graph ──
    layer_risks.session_graph = session_result.anomaly_score;
    if !session_result.attacks_detected.is_empty() || session_result.anomaly_score >= 50 {
        if minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
        for attack in &session_result.attacks_detected {
            policy_findings.push(format!("session graph attack: {}", attack.name));
        }
        for reason in &session_result.anomaly_reasons {
            policy_findings.push(format!("session graph: {}", reason));
        }
    }
    if !session_result.transition_allowed {
        minimum_decision = GovernanceDecision::Block;
        layer_risks.session_graph = layer_risks.session_graph.max(90);
        policy_findings.push("session graph: state transition blocked".into());
    }

    // ── Adaptive Risk ──
    layer_risks.adaptive = adaptive_result.total_score;
    if adaptive_result.decision == "block" {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!(
            "adaptive risk: score={} → block",
            adaptive_result.total_score
        ));
    } else if adaptive_result.decision == "human_review"
        && minimum_decision != GovernanceDecision::Block
    {
        minimum_decision = GovernanceDecision::Review;
        policy_findings.push(format!(
            "adaptive risk: score={} → review",
            adaptive_result.total_score
        ));
    }

    // ── Behavioral Fingerprint ──
    if !fingerprint_anomalies.is_empty() {
        layer_risks.behavioral = 60 + (fingerprint_anomalies.len() as u32 * 10).min(40);
        for flag in &fingerprint_anomalies {
            policy_findings.push(format!("behavioral fingerprint: {}", flag));
        }
        if minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // ── Policy ──
    // Score based on how many policy violations were found
    let policy_violation_count = policy_findings
        .iter()
        .filter(|f| {
            f.contains("not approved")
                || f.contains("outside baseline")
                || f.contains("requires human review")
                || f.contains("action type")
        })
        .count();
    if policy_violation_count > 0 {
        layer_risks.policy = (30 + policy_violation_count as u32 * 20).min(100);
    }

    // ── Secrets ──
    if secret_denied {
        layer_risks.secrets = 90;
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push("unauthorized secret access denied by vault policy".into());
    }
    if !schema_validation.valid && minimum_decision != GovernanceDecision::Block {
        minimum_decision = GovernanceDecision::Block;
    }

    // 1.0 M3.5: optional probabilistic reasoning. Produces evidence
    // consumed by the receipt logger; never fails the pipeline.
    let ml_outcome = match state.reasoning.as_ref() {
        Some(eng) => Some(
            eng.evaluate_json(
                &input.agent_id,
                &input.action.tool_name,
                action_type_str(input.action.action_type),
                &serde_json::to_string(&input.action.payload).unwrap_or_default(),
            )
            .await,
        ),
        None => None,
    };

    let risk = score_tool_risk_with_thresholds(
        input,
        minimum_decision,
        &policy_findings,
        &layer_risks,
        workspace_policy.threshold_block,
        workspace_policy.threshold_review,
    );

    // Build audit event
    let mut reasons = risk.reasons.clone();
    reasons.push(format!("agent-role:{:?}", profile.role).to_lowercase());

    // 1.5 cost-control: cumulative session spend so far + the configured budget,
    // injected into the APL context and enforced by the non-APL fallback below.
    #[cfg(feature = "cost-control")]
    let (cost_session_usd, cost_budget_usd) = {
        let key = crate::modules::cost::spend_store::SpendKey::from_request(input);
        (
            Some(crate::modules::cost::spend_store::session_spend_usd(&key)),
            crate::pipeline::cost::session_budget_usd(),
        )
    };
    #[cfg(not(feature = "cost-control"))]
    let (cost_session_usd, cost_budget_usd): (Option<f64>, Option<f64>) = (None, None);

    // 1.0 M6: APL live overlay. If a policy bundle is loaded on the
    // host, run it after the YAML risk score and merge stricter-wins.
    // APL can tighten the verdict; it never relaxes it.
    let mut decision = risk.decision;
    #[cfg(feature = "apl")]
    if let Some(overlay) = state.apl_overlay.as_ref() {
        let ml_scores = ml_outcome.as_ref().map(|o| &o.scores);
        let ctx = crate::pipeline::apl_overlay::build_overlay_context(
            input,
            risk.score,
            risk.decision,
            Some(&workspace_policy.workspace_id),
            &workspace_policy.allowed_domains,
            ml_scores,
            cost_session_usd,
            cost_budget_usd,
        );
        if let Some(fired) = overlay.evaluate(&ctx) {
            let merged = crate::pipeline::apl_overlay::merge_decisions(decision, fired.verdict);
            let reason_str = fired.reason.unwrap_or_else(|| "fired".to_string());
            reasons.push(format!("apl[{}]: {}", fired.policy_name, reason_str));
            decision = merged;
        }
    }

    // 1.5 cost-control: enforce the session budget even without an APL policy.
    // Tightens to Block once the session's prior cumulative spend exceeds the
    // configured limit (block-next semantics; this action's cost is added after
    // recording). Stricter-wins: this can only tighten the verdict.
    #[cfg(feature = "cost-control")]
    if let (Some(spent), Some(limit)) = (cost_session_usd, cost_budget_usd) {
        if spent > limit {
            decision = GovernanceDecision::Block;
            reasons.push(format!(
                "cost: session spend ${spent:.4} exceeds budget ${limit:.4}"
            ));
        }
    }

    let audit_event = AuditEvent {
        event_id: Uuid::new_v4().to_string(),
        agent_id: input.agent_id.clone(),
        framework: input.framework.clone(),
        action_type: input.action.action_type,
        tool_name: input.action.tool_name.clone(),
        decision,
        timestamp: Utc::now().to_rfc3339(),
        reasons,
    };

    let review_status = if decision == GovernanceDecision::Review {
        ReviewStatus::Pending
    } else {
        ReviewStatus::NotRequired
    };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 8, Telemetry
    // ═══════════════════════════════════════════════════════════════
    let duration_ms = pipeline_start.elapsed().as_millis() as u64;
    // After M6: use the merged `decision` (YAML + APL stricter-wins) so
    // telemetry reflects the actual final verdict.
    let decision_str = format!("{:?}", decision).to_lowercase();

    let mut layer_attrs = HashMap::new();
    layer_attrs.insert(
        "session_graph".into(),
        serde_json::json!(session_result.new_state),
    );
    layer_attrs.insert(
        "taint_blocked".into(),
        serde_json::json!(taint_result.blocked),
    );
    layer_attrs.insert(
        "firewall_score".into(),
        serde_json::json!(firewall_result.risk_score),
    );
    layer_attrs.insert(
        "adaptive_score".into(),
        serde_json::json!(adaptive_result.total_score),
    );

    let telemetry_span = otel_emitter::emit_governance_span(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        &decision_str,
        risk.score,
        duration_ms,
        layer_attrs,
    );
    otel_emitter::emit_pipeline_metrics(&decision_str, risk.score, duration_ms, action_type_s);
    let telemetry_json = serde_json::to_value(&telemetry_span).ok();

    // Update NHI trust based on outcome (severity-aware)
    let new_trust =
        crypto_identity::update_trust_from_decision(&input.agent_id, &decision_str, risk.score);

    // v0.4.0, persist updated trust score to durable storage (write-behind)
    if let Some(trust) = new_trust {
        let nhi_store = state.nhi_store.clone();
        let aid = input.agent_id.clone();
        tokio::spawn(async move {
            if let Err(e) = nhi_store.update_trust(&aid, trust).await {
                tracing::warn!(error = %e, "failed to persist NHI trust update");
            }
        });
    }

    let mut result = GovernanceResult {
        trace_id: trace_id.clone(),
        protocol,
        normalized_payload,
        decision,
        review_status,
        risk,
        secret_plan,
        audit_event,
        profile,
        workspace_policy,
        policy_findings,
        schema_validation,
        review_request_id: None,
        // 8-layer results
        session_graph: session_json,
        taint_analysis: taint_json,
        adaptive_risk: adaptive_json,
        sandbox_result: sandbox_json,
        injection_firewall: firewall_json,
        policy_verification: verification_json,
        telemetry_span: telemetry_json,
        behavioral_fingerprint: state
            .behavioral_engine
            .get_fingerprint(&input.agent_id)
            .and_then(|fp| serde_json::to_value(fp).ok()),
        threat_intel: threat_intel_json,
        plugin_results: (!plugin_evaluation.outputs.is_empty())
            .then_some(plugin_evaluation.outputs.clone()),
    };

    // 1.5 cost-control: resolve any caller-reported usage into the canonical
    // cost ledger (priced locally; a caller-supplied cost wins). No-op (None)
    // when the feature is off, keeping the default build byte-identical.
    #[cfg(feature = "cost-control")]
    let captured_usage = crate::pipeline::cost::resolve_for_request(input);
    #[cfg(not(feature = "cost-control"))]
    let captured_usage: Option<iaga_sentinel_cost::UsageData> = None;

    // Persist audit event
    let stored = StoredAuditEvent {
        event_id: result.audit_event.event_id.clone(),
        agent_id: result.audit_event.agent_id.clone(),
        tenant_id,
        framework: result.audit_event.framework.clone(),
        action_type: result.audit_event.action_type,
        tool_name: result.audit_event.tool_name.clone(),
        decision: result.audit_event.decision,
        timestamp: result.audit_event.timestamp.clone(),
        reasons: result.audit_event.reasons.clone(),
        review_status: result.review_status,
        risk_score: result.risk.score,
        usage: captured_usage,
    };
    state.audit_store.append(&stored).await?;
    if let Some(rl) = state.receipts.as_ref() {
        rl.record(&stored, ml_outcome.as_ref(), stored.usage.as_ref())
            .await;
    }

    // 1.5 cost-control: add this action's cost to the session's cumulative
    // spend so the next action in the session sees it for budget enforcement.
    #[cfg(feature = "cost-control")]
    if let Some(u) = stored.usage.as_ref() {
        let key = crate::modules::cost::spend_store::SpendKey::from_request(input);
        crate::modules::cost::spend_store::add(&key, u.cost_micros);
    }

    // Create review request if needed
    if result.decision == GovernanceDecision::Review {
        let now = Utc::now().to_rfc3339();
        let mut review_reasons = result.policy_findings.clone();
        review_reasons.extend(result.risk.reasons.clone());

        let review = ReviewRequest {
            id: Uuid::new_v4().to_string(),
            agent_id: result.profile.agent_id.clone(),
            workspace_id: result.profile.workspace_id.clone(),
            tool_name: result.audit_event.tool_name.clone(),
            decision: result.decision,
            status: "pending".to_string(),
            risk_score: result.risk.score,
            reasons: review_reasons,
            created_at: now.clone(),
            updated_at: now,
        };

        state.review_store.create(&review).await?;
        result.review_request_id = Some(review.id);
        result.review_status = ReviewStatus::Pending;
    }

    tracing::info!(
        trace_id = %trace_id,
        agent_id = %result.audit_event.agent_id,
        tool_name = %result.audit_event.tool_name,
        decision = ?result.decision,
        risk_score = result.risk.score,
        duration_ms,
        "governance pipeline completed"
    );

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════
// Response-Side Scanning
// ═══════════════════════════════════════════════════════════════

struct SensitivePatternDef {
    name: &'static str,
    description: &'static str,
    category: &'static str,
    regex: &'static str,
    redact_with: &'static str,
}

const SENSITIVE_PATTERNS: &[SensitivePatternDef] = &[
    SensitivePatternDef {
        name: "ssn",
        description: "US Social Security Number",
        category: "pii",
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
        redact_with: "[REDACTED-SSN]",
    },
    SensitivePatternDef {
        name: "credit_card",
        description: "Credit card number (Visa, MC, Amex, Discover)",
        category: "financial",
        regex: r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b",
        redact_with: "[REDACTED-CC]",
    },
    SensitivePatternDef {
        name: "aws_access_key",
        description: "AWS Access Key ID",
        category: "credential",
        regex: r"\bAKIA[0-9A-Z]{16}\b",
        redact_with: "[REDACTED-AWS-KEY]",
    },
    SensitivePatternDef {
        name: "aws_secret_key",
        description: "AWS Secret Access Key",
        category: "credential",
        regex: r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        redact_with: "[REDACTED-AWS-SECRET]",
    },
    SensitivePatternDef {
        name: "github_token",
        description: "GitHub personal access token",
        category: "credential",
        regex: r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
        redact_with: "[REDACTED-GH-TOKEN]",
    },
    SensitivePatternDef {
        name: "openai_api_key",
        description: "OpenAI API key",
        category: "credential",
        regex: r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
        redact_with: "[REDACTED-OPENAI-KEY]",
    },
    SensitivePatternDef {
        name: "generic_api_key",
        description: "Generic API key in assignment",
        category: "credential",
        regex: r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?"#,
        redact_with: "[REDACTED-API-KEY]",
    },
    SensitivePatternDef {
        name: "password_assignment",
        description: "Password in assignment or config",
        category: "credential",
        regex: r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?"#,
        redact_with: "[REDACTED-PASSWORD]",
    },
    SensitivePatternDef {
        name: "private_key_block",
        description: "PEM private key block",
        category: "credential",
        regex: r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----",
        redact_with: "[REDACTED-PRIVATE-KEY]",
    },
    SensitivePatternDef {
        name: "bearer_token",
        description: "Bearer authentication token",
        category: "credential",
        regex: r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
        redact_with: "[REDACTED-BEARER]",
    },
    SensitivePatternDef {
        name: "connection_string",
        description: "Database connection string with credentials",
        category: "credential",
        regex: r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s@]+:[^\s@]+@",
        redact_with: "[REDACTED-CONN-STRING]",
    },
];

/// Build compiled regex patterns (cached via Lazy).
static COMPILED_PATTERNS: Lazy<Vec<(Regex, &'static SensitivePatternDef)>> = Lazy::new(|| {
    SENSITIVE_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.regex).ok().map(|re| (re, p)))
        .collect()
});

/// Return the list of sensitive patterns being checked.
pub fn get_sensitive_patterns() -> Vec<SensitivePattern> {
    SENSITIVE_PATTERNS
        .iter()
        .map(|p| SensitivePattern {
            name: p.name.to_string(),
            description: p.description.to_string(),
            category: p.category.to_string(),
        })
        .collect()
}

/// Scan a tool response for prompt injection, taint leaks, and sensitive data.
pub fn scan_response(input: &ResponseScanRequest) -> ResponseScanResult {
    let payload_str = serde_json::to_string(&input.response_payload).unwrap_or_default();
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: u32 = 0;

    // ── Check 1: Injection firewall on response content ──
    let firewall_result = prompt_firewall::scan_prompt(&payload_str);
    if firewall_result.blocked {
        findings.push(format!("injection firewall: {}", firewall_result.summary));
    }
    if firewall_result.risk_score > risk_score {
        risk_score = firewall_result.risk_score;
    }

    // ── Check 2: Taint tracking (detect secret/credential leaks) ──
    let inherited_taints = input
        .metadata
        .as_ref()
        .and_then(|m| m.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(taint_tracker::get_session_taint)
        .unwrap_or_default();

    let taint_result = taint_tracker::analyze_taint(
        "http", // response is coming back from a tool, treat as network data
        &input.tool_name,
        &payload_str,
        &inherited_taints,
    );
    if taint_result.blocked {
        findings.push(format!("taint tracking: {}", taint_result.summary));
        if risk_score < 80 {
            risk_score = 80;
        }
    }
    if taint_result.exfiltration_detected {
        findings.push("taint: potential data exfiltration in response".to_string());
    }

    // ── Check 3: Sensitive pattern matching with redaction ──
    let mut redacted = payload_str.clone();
    let mut has_sensitive = false;

    for (re, pat) in COMPILED_PATTERNS.iter() {
        if re.is_match(&redacted) {
            has_sensitive = true;
            let count = re.find_iter(&redacted).count();
            findings.push(format!(
                "sensitive pattern: {} ({} occurrence{})",
                pat.name,
                count,
                if count > 1 { "s" } else { "" }
            ));
            // Each pattern category carries different weight
            let pattern_score = match pat.category {
                "credential" => 70,
                "financial" => 75,
                "pii" => 65,
                _ => 50,
            };
            if pattern_score > risk_score {
                risk_score = pattern_score;
            }
            redacted = re.replace_all(&redacted, pat.redact_with).to_string();
        }
    }

    // ── Build decision ──
    let decision = if risk_score >= 80 {
        ResponseDecision::Block
    } else if risk_score >= 40 {
        ResponseDecision::Review
    } else {
        ResponseDecision::Allow
    };

    let redacted_payload = if has_sensitive {
        serde_json::from_str::<serde_json::Value>(&redacted)
            .ok()
            .or(Some(serde_json::Value::String(redacted)))
    } else {
        None
    };

    ResponseScanResult {
        request_id: input.request_id.clone(),
        decision,
        risk_score,
        findings,
        redacted_payload,
    }
}
