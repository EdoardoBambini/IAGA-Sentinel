//! Gate orchestration: parse → map → inspect → exit code.
//!
//! Exit-code contract assumed for Codex hooks (the one hard-block
//! mechanism in the design doc): **0** lets the pending tool call
//! proceed, **2** blocks it. The justification is returned as a
//! plain-text message for stdout so Codex can surface it to the user and
//! the model; structured stdout, if Codex supports one, is a post-spike
//! refinement and would live here only.
//!
//! Diagnostics go to stderr exclusively, and the raw tool payload is
//! never logged — it is attacker-influenced (see `codex_event`).

use iaga_sentinel_integrations::{GovernanceDecision, GovernanceResult};

use crate::codex_event::{self, EventKind};
use crate::hook_config::{Config, FailPolicy};
use crate::inspect_client::{InspectClient, InspectError};

/// Exit code that lets the pending tool call proceed.
pub const EXIT_ALLOW: i32 = 0;
/// Exit code that blocks the pending tool call inside Codex's loop.
pub const EXIT_BLOCK: i32 = 2;

/// What the binary should do: exit code plus an optional stdout message
/// (the justification Codex shows on a block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateOutcome {
    pub exit_code: i32,
    pub message: Option<String>,
}

impl GateOutcome {
    fn allow() -> Self {
        Self {
            exit_code: EXIT_ALLOW,
            message: None,
        }
    }

    fn block(message: String) -> Self {
        Self {
            exit_code: EXIT_BLOCK,
            message: Some(message),
        }
    }
}

/// Exit code for "no verdict could even be attempted" (e.g. the async
/// runtime failed to start): same fail policy as an unreachable sidecar.
pub fn transport_failure_exit_code(config: &Config) -> i32 {
    match config.fail_policy {
        FailPolicy::Closed => EXIT_BLOCK,
        FailPolicy::Open => EXIT_ALLOW,
    }
}

/// Run the gate on one raw hook event.
pub async fn run(raw: &str, config: &Config) -> GateOutcome {
    // 1. Parse. A malformed event means we cannot know what the agent is
    //    about to do — that is exactly what the fail policy decides.
    let event = match codex_event::parse_event(raw) {
        Ok(event) => event,
        Err(e) => {
            eprintln!("[iaga-codex] could not parse the hook event as JSON: {e}");
            return no_verdict_outcome(config, "the hook event was malformed");
        }
    };

    // 2. Route. Only PreToolUse is gated in the minimal gate; recognized
    //    other events are a declared no-op. A missing discriminator is
    //    gated defensively: a fail-closed gate must not degrade into a
    //    silent no-op because Codex renamed a field.
    match event.kind() {
        EventKind::PreToolUse => {}
        EventKind::Other(name) => {
            eprintln!("[iaga-codex] event '{name}' is not gated (PreToolUse only); allowing");
            return GateOutcome::allow();
        }
        EventKind::Unknown => {
            eprintln!(
                "[iaga-codex] event has no recognizable discriminator; \
                 gating it defensively as a pending tool call"
            );
        }
    }

    // 3. Map onto the public inspect contract (all Codex field-name
    //    knowledge stays inside codex_event).
    let request = codex_event::to_inspect_request(&event, config);

    // 4. Ask for a verdict.
    let client = match InspectClient::new(config) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("[iaga-codex] could not build the HTTP client: {e}");
            return no_verdict_outcome(config, "the inspect client could not be built");
        }
    };

    match client.inspect(&request).await {
        Ok(result) => {
            let receipt_id = result
                .audit_event
                .get("eventId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reasons = justification_reasons(&result);
            match result.decision {
                GovernanceDecision::Allow => {
                    eprintln!(
                        "[iaga-codex] allow (risk={}, receipt={receipt_id})",
                        result.risk.score
                    );
                    GateOutcome::allow()
                }
                GovernanceDecision::Block => {
                    eprintln!(
                        "[iaga-codex] block (risk={}, receipt={receipt_id})",
                        result.risk.score
                    );
                    let why = if reasons.is_empty() {
                        "blocked by IAGA Sentinel policy".to_string()
                    } else {
                        reasons
                    };
                    GateOutcome::block(format!("IAGA Sentinel blocked this action: {why}"))
                }
                // Codex hooks have no confirmed "ask the user" response, so
                // review maps to a conservative block until the spike says
                // otherwise (an enforcement point must not auto-approve
                // actions that require a human).
                GovernanceDecision::Review => {
                    eprintln!(
                        "[iaga-codex] review -> conservative block (risk={}, receipt={receipt_id})",
                        result.risk.score
                    );
                    let why = if reasons.is_empty() {
                        "approve it from the IAGA Sentinel dashboard, then retry".to_string()
                    } else {
                        reasons
                    };
                    GateOutcome::block(format!(
                        "IAGA Sentinel requires human review before this action runs: {why}"
                    ))
                }
            }
        }
        Err(InspectError::AgentNotRegistered { agent_id, base_url }) => {
            eprintln!(
                "[iaga-codex] agent '{agent_id}' is not registered at {base_url} — \
                 run: iaga import examples/integrations/codex/codex.policy.yaml"
            );
            no_verdict_outcome(
                config,
                &format!(
                    "agent '{agent_id}' is not registered \
                     (run: iaga import examples/integrations/codex/codex.policy.yaml)"
                ),
            )
        }
        Err(e) => {
            eprintln!("[iaga-codex] no verdict: {e}");
            no_verdict_outcome(config, "the IAGA Sentinel sidecar is unreachable")
        }
    }
}

/// Apply the transport-failure policy when no verdict exists.
///
/// Fail-closed blocks with an actionable message; fail-open allows but
/// declares the coverage gap on stderr — the action proceeds unattested
/// and there will be no receipt for it.
fn no_verdict_outcome(config: &Config, detail: &str) -> GateOutcome {
    match config.fail_policy {
        FailPolicy::Closed => GateOutcome::block(format!(
            "IAGA Sentinel: {detail}; failing closed \
             (set IAGA_CODEX_FAIL=open to trade enforcement for availability)"
        )),
        FailPolicy::Open => {
            eprintln!(
                "[iaga-codex] {detail}; failing OPEN — \
                 this action proceeds unattested (no receipt)"
            );
            GateOutcome::allow()
        }
    }
}

/// The reason string shown to the user and the model on a non-allow verdict.
///
/// `risk.reasons` carries only the risk engine's generic lines (e.g. "shell
/// execution requires elevated scrutiny"). The *specific* reason that drove
/// the verdict — an APL overlay policy such as an egress rule — lands in the
/// signed audit event's `reasons`, which is also what the receipt records.
/// Prefer those so the model learns why it was actually stopped; drop
/// pure-metadata lines (`agent-role:*`) and fall back to `risk.reasons` when
/// the audit event carries none.
fn justification_reasons(result: &GovernanceResult) -> String {
    let from_audit: Vec<String> = result
        .audit_event
        .get("reasons")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|r| !r.starts_with("agent-role:"))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let reasons = if from_audit.is_empty() {
        result.risk.reasons.clone()
    } else {
        from_audit
    };
    reasons.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_from(json: serde_json::Value) -> GovernanceResult {
        serde_json::from_value(json).expect("valid GovernanceResult")
    }

    #[test]
    fn justification_prefers_the_audit_policy_reason_over_generic_risk() {
        // A block driven by the egress overlay: risk.reasons is generic, the
        // policy reason lives in the audit event (as on the wire).
        let result = result_from(serde_json::json!({
            "traceId": "t",
            "decision": "block",
            "risk": {
                "score": 9,
                "decision": "block",
                "reasons": ["shell execution requires elevated scrutiny"]
            },
            "auditEvent": {
                "eventId": "e",
                "reasons": [
                    "shell execution requires elevated scrutiny",
                    "agent-role:builder",
                    "apl[block_secret_exfil_via_egress]: egress of local secrets off-box is blocked"
                ]
            }
        }));
        let why = justification_reasons(&result);
        assert!(why.contains("egress of local secrets off-box is blocked"));
        // Pure-metadata lines are dropped; generic context is kept.
        assert!(!why.contains("agent-role:"));
        assert!(why.contains("shell execution requires elevated scrutiny"));
    }

    #[test]
    fn justification_falls_back_to_risk_reasons_without_an_audit_list() {
        // The in-process mock sidecar returns no audit `reasons` array.
        let result = result_from(serde_json::json!({
            "traceId": "t",
            "decision": "block",
            "risk": { "score": 95, "decision": "block", "reasons": ["no-external-egress"] },
            "auditEvent": { "eventId": "e" }
        }));
        assert_eq!(justification_reasons(&result), "no-external-egress");
    }
}
