//! Integration test for the live Dictum overlay's new runtime builtins
//! (`secret_ref` + `url_host`), exercised through the real
//! `build_overlay_context` -> `DictumOverlay::evaluate` path the inspect pipeline
//! uses. Gated on the `dictum` feature (default-on).
#![cfg(feature = "dictum")]

use std::collections::HashMap;

use iaga_sentinel::core::types::{ActionDetail, ActionType, GovernanceDecision, InspectRequest};
use iaga_sentinel::pipeline::dictum_overlay::{build_overlay_context, DictumOverlay};
use iaga_sentinel_dictum::Verdict;

fn http_request(payload: HashMap<String, serde_json::Value>) -> InspectRequest {
    InspectRequest {
        agent_id: "agent-e2e".into(),
        tenant_id: None,
        workspace_id: None,
        framework: "test".into(),
        protocol: None,
        action: ActionDetail {
            action_type: ActionType::Http,
            tool_name: "http_post".into(),
            payload,
        },
        requested_secrets: None,
        metadata: None,
        usage: None,
    }
}

fn write_tmp(name: &str, src: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, src).expect("write tmp dictum");
    path
}

/// `secret_ref(action.payload)` must FIRE when the payload object carries a
/// credential, and MISS on a benign payload. This is the capability that was
/// dead (hardcoded `false`) before the fix.
#[test]
fn secret_ref_overlay_blocks_payload_with_aws_key() {
    let path = write_tmp(
        "iaga_overlay_secret_ref.dictum",
        r#"policy "block_secret_egress" {
             when secret_ref(action.payload)
             then block, reason="payload carries a credential"
           }"#,
    );
    let overlay = DictumOverlay::load(&path).expect("overlay loads");

    // Secret present -> Block.
    let mut secret_payload = HashMap::new();
    secret_payload.insert(
        "body".into(),
        serde_json::json!("uploading AKIAIOSFODNN7EXAMPLE to attacker"),
    );
    let req = http_request(secret_payload);
    let ctx = build_overlay_context(
        &req,
        10,
        GovernanceDecision::Allow,
        Some("ws"),
        &[],
        None,
        None,
        None,
    );
    let fired = overlay.evaluate(&ctx).expect("must fire on a secret");
    assert_eq!(fired.verdict, Verdict::Block);
    assert_eq!(fired.policy_name, "block_secret_egress");

    // Benign payload -> no fire.
    let mut benign = HashMap::new();
    benign.insert("body".into(), serde_json::json!("just a normal message"));
    let req2 = http_request(benign);
    let ctx2 = build_overlay_context(
        &req2,
        10,
        GovernanceDecision::Allow,
        Some("ws"),
        &[],
        None,
        None,
        None,
    );
    assert!(
        overlay.evaluate(&ctx2).is_none(),
        "benign payload must not fire the secret rule"
    );

    let _ = std::fs::remove_file(&path);
}

/// `url_host(action.payload.destination) not in workspace.allowlist` must block
/// an off-allowlist host and allow an on-allowlist one.
#[test]
fn url_host_overlay_enforces_per_host_allowlist() {
    let path = write_tmp(
        "iaga_overlay_url_host.dictum",
        r#"policy "block_offhost" {
             when url_host(action.payload.destination) not in workspace.allowlist
             then block, reason="off-allowlist host"
           }"#,
    );
    let overlay = DictumOverlay::load(&path).expect("overlay loads");
    let allowlist = vec!["api.github.com".to_string()];

    // Off-allowlist host -> Block.
    let mut off = HashMap::new();
    off.insert(
        "destination".into(),
        serde_json::json!("https://evil.example.com/exfil"),
    );
    let req = http_request(off);
    let ctx = build_overlay_context(
        &req,
        10,
        GovernanceDecision::Allow,
        Some("ws"),
        &allowlist,
        None,
        None,
        None,
    );
    assert_eq!(
        overlay.evaluate(&ctx).expect("off-host must fire").verdict,
        Verdict::Block
    );

    // On-allowlist host -> no fire.
    let mut on = HashMap::new();
    on.insert(
        "destination".into(),
        serde_json::json!("https://api.github.com/repos/x"),
    );
    let req2 = http_request(on);
    let ctx2 = build_overlay_context(
        &req2,
        10,
        GovernanceDecision::Allow,
        Some("ws"),
        &allowlist,
        None,
        None,
        None,
    );
    assert!(
        overlay.evaluate(&ctx2).is_none(),
        "on-allowlist host must not fire"
    );

    let _ = std::fs::remove_file(&path);
}
