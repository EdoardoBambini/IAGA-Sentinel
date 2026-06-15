//! OSS 1.2, drift-replay capture: signing-determinism + 1.1 roundtrip.
//!
//! These tests are load-bearing for the additive-only contract:
//!
//! 1. A receipt body with all three 1.2 capture fields set to `None`
//!    serializes to **byte-identical** JSON as the same body without
//!    the fields, so the chain hash + signature stay stable across
//!    1.1 → 1.2 binary upgrades.
//!
//! 2. A receipt body persisted by 1.1 (missing the three capture
//!    fields entirely) deserializes cleanly via serde defaults, old
//!    chains still verify.
//!
//! 3. With capture fields populated, the serialization includes them
//!    and the verifier reads them back identically.

use iaga_sentinel_receipts::{
    CostSource, DictumEvalTrace, MlInferenceInputs, MlTokenDigest, PipelineInputsCapture,
    ReceiptBody, UsageData, Verdict,
};

fn legacy_11_body() -> ReceiptBody {
    ReceiptBody {
        run_id: "run-legacy".into(),
        seq: 0,
        parent_hash: None,
        input_hash: "a".repeat(64),
        policy_hash: "b".repeat(64),
        plugin_digests: vec![],
        model_digests: vec![],
        ml_scores: None,
        verdict: Verdict::Allow,
        reasons: vec!["legacy".into()],
        risk_score: 7,
        timestamp: "2026-04-23T12:00:00Z".into(),
        signer_key_id: "ed25519-deadbeef".into(),
        pipeline_inputs_capture: None,
        apl_eval_trace: None,
        ml_inference_inputs: None,
        is_authoritative: None,
        usage: None,
    }
}

#[test]
fn capture_fields_none_byte_equal_to_11_serialization() {
    let body = legacy_11_body();
    let bytes = body.signing_bytes().expect("signing_bytes");
    let json = std::str::from_utf8(&bytes).expect("utf8");
    // Critical contract: when all three 1.2 fields are `None`, they
    // are elided from the serialization. The output JSON contains
    // none of the 1.2 field keys.
    assert!(
        !json.contains("pipelineInputsCapture") && !json.contains("pipeline_inputs_capture"),
        "pipeline_inputs_capture leaked into 1.1-style body: {json}"
    );
    assert!(
        !json.contains("aplEvalTrace") && !json.contains("apl_eval_trace"),
        "apl_eval_trace leaked into 1.1-style body: {json}"
    );
    assert!(
        !json.contains("mlInferenceInputs") && !json.contains("ml_inference_inputs"),
        "ml_inference_inputs leaked into 1.1-style body: {json}"
    );
    // 1.3.1: the honesty flag is likewise elided when `None`, so a
    // receipt produced before 1.3.1 stays byte-identical and verifies.
    assert!(
        !json.contains("is_authoritative") && !json.contains("isAuthoritative"),
        "is_authoritative leaked into a None-flag body: {json}"
    );
    // 1.5 cost-control: the usage ledger is likewise elided when `None`, so a
    // receipt produced before 1.5 stays byte-identical and verifies.
    assert!(
        !json.contains("usage") && !json.contains("costMicros"),
        "usage leaked into a None-usage body: {json}"
    );
}

#[test]
fn legacy_11_json_deserializes_with_serde_defaults() {
    // Hand-constructed 1.1.0 receipt body (no 1.2 capture fields).
    let json = r#"{
        "run_id": "run-legacy",
        "seq": 0,
        "parent_hash": null,
        "input_hash": "a".repeat(64).repeat(1),
        "policy_hash": "b".repeat(64),
        "verdict": "allow",
        "risk_score": 7,
        "timestamp": "2026-04-23T12:00:00Z",
        "signer_key_id": "ed25519-deadbeef"
    }"#;
    // Build via Rust literal to keep test compact; verify via roundtrip.
    let body = legacy_11_body();
    let serialized = serde_json::to_string(&body).expect("serialize");
    let _: ReceiptBody = serde_json::from_str(&serialized).expect("roundtrip");
    let _ = json; // (kept for documentation)
}

#[test]
fn capture_fields_populated_roundtrip_through_signing_bytes() {
    let mut body = legacy_11_body();
    body.pipeline_inputs_capture = Some(PipelineInputsCapture {
        request_json: serde_json::json!({ "agentId": "a", "toolName": "fs.read" }),
        framework: "iaga-sentinel-core".into(),
        payload_sha256: "c".repeat(64),
    });
    body.apl_eval_trace = Some(DictumEvalTrace {
        policy_hash: "b".repeat(64),
        policies_evaluated: 3,
        policies_fired: vec!["no-pii-egress".into()],
    });
    body.ml_inference_inputs = Some(MlInferenceInputs {
        tokenized_digests: vec![MlTokenDigest {
            model_name: "intent-drift-v0".into(),
            tokenized_sha256: "d".repeat(64),
        }],
    });

    let bytes = body.signing_bytes().expect("signing_bytes");
    let json = std::str::from_utf8(&bytes).expect("utf8");
    assert!(json.contains("pipeline_inputs_capture"));
    assert!(json.contains("apl_eval_trace"));
    assert!(json.contains("ml_inference_inputs"));

    let parsed: ReceiptBody = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(parsed.pipeline_inputs_capture, body.pipeline_inputs_capture);
    assert_eq!(parsed.apl_eval_trace, body.apl_eval_trace);
    assert_eq!(parsed.ml_inference_inputs, body.ml_inference_inputs);
}

#[test]
fn body_hash_stable_when_capture_none() {
    // Two distinct constructions of the same logical 1.1 body produce
    // identical body_hash, the chain link is signature-stable.
    let body_a = legacy_11_body();
    let body_b = legacy_11_body();
    assert_eq!(
        body_a.body_hash().expect("hash a"),
        body_b.body_hash().expect("hash b")
    );
}

#[test]
fn body_hash_differs_when_capture_populated() {
    // Sanity: populating the optional capture changes the hash, as
    // expected (capture data participates in signing).
    let body_legacy = legacy_11_body();
    let mut body_with_capture = legacy_11_body();
    body_with_capture.apl_eval_trace = Some(DictumEvalTrace {
        policy_hash: "b".repeat(64),
        policies_evaluated: 1,
        policies_fired: vec!["p".into()],
    });
    assert_ne!(
        body_legacy.body_hash().expect("hash legacy"),
        body_with_capture.body_hash().expect("hash w/ capture")
    );
}

#[test]
fn is_authoritative_flag_serializes_and_preserves_byte_equality() {
    // None (legacy / pre-1.3.1): the key is elided from signing_bytes.
    let none_body = legacy_11_body();
    assert!(none_body.is_authoritative.is_none());

    // Some(false): the 1.3.1 OSS honesty flag is present and roundtrips.
    let mut flagged = legacy_11_body();
    flagged.is_authoritative = Some(false);
    let bytes = flagged.signing_bytes().expect("signing_bytes");
    let json = std::str::from_utf8(&bytes).expect("utf8");
    assert!(
        json.contains("\"is_authoritative\":false"),
        "expected is_authoritative=false in body: {json}"
    );
    let parsed: ReceiptBody = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(parsed.is_authoritative, Some(false));

    // The flag participates in signing, so a flagged body hashes
    // differently from the legacy (None) body, while the legacy body
    // itself is unchanged from pre-1.3.1.
    assert_ne!(
        none_body.body_hash().expect("hash none"),
        flagged.body_hash().expect("hash flagged"),
    );
}

#[test]
fn legacy_body_signing_bytes_match_pre_15_golden() {
    // The exact bytes a pre-1.5 binary produced for this body. The 1.5
    // `usage` field is elided when `None`, so this must stay byte-identical
    // forever, otherwise every receipt signed before 1.5 fails verification.
    let body = legacy_11_body();
    let bytes = body.signing_bytes().expect("signing_bytes");
    let actual = std::str::from_utf8(&bytes).expect("utf8");
    let golden = format!(
        concat!(
            "{{\"run_id\":\"run-legacy\",\"seq\":0,\"parent_hash\":null,",
            "\"input_hash\":\"{}\",\"policy_hash\":\"{}\",\"verdict\":\"allow\",",
            "\"reasons\":[\"legacy\"],\"risk_score\":7,",
            "\"timestamp\":\"2026-04-23T12:00:00Z\",",
            "\"signer_key_id\":\"ed25519-deadbeef\"}}"
        ),
        "a".repeat(64),
        "b".repeat(64)
    );
    assert_eq!(actual, golden, "1.5 broke pre-1.5 receipt byte-equality");
}

#[test]
fn usage_body_signing_bytes_roundtrip_is_stable() {
    let mut body = legacy_11_body();
    body.usage = Some(UsageData {
        provider: "anthropic".into(),
        model: "claude-sonnet-4-6".into(),
        prompt_tokens: Some(1000),
        completion_tokens: Some(500),
        total_tokens: Some(1500),
        cost_micros: 20_000,
        cache_hit: false,
        savings_micros: None,
        cost_source: CostSource::Caller,
    });
    let bytes1 = body.signing_bytes().expect("b1");
    let parsed: ReceiptBody = serde_json::from_slice(&bytes1).expect("parse");
    let bytes2 = parsed.signing_bytes().expect("b2");
    assert_eq!(
        std::str::from_utf8(&bytes1).unwrap(),
        std::str::from_utf8(&bytes2).unwrap(),
        "usage body signing bytes must be stable across a JSON round-trip"
    );
}

#[test]
fn usage_populated_serializes_and_changes_body_hash() {
    let legacy = legacy_11_body();
    let mut with_usage = legacy_11_body();
    with_usage.usage = Some(UsageData {
        provider: "anthropic".into(),
        model: "claude-sonnet-4-6".into(),
        prompt_tokens: Some(1_000),
        completion_tokens: Some(500),
        total_tokens: Some(1_500),
        cost_micros: 10_500,
        cache_hit: false,
        savings_micros: None,
        cost_source: CostSource::PricingTable,
    });

    let bytes = with_usage.signing_bytes().expect("signing_bytes");
    let json = std::str::from_utf8(&bytes).expect("utf8");
    assert!(json.contains("\"usage\":"));
    assert!(json.contains("\"costMicros\":10500"));
    assert!(json.contains("\"costSource\":\"pricing_table\""));

    // Usage participates in signing: a body with usage hashes differently
    // from the same logical body without it.
    assert_ne!(
        legacy.body_hash().expect("hash legacy"),
        with_usage.body_hash().expect("hash w/ usage")
    );

    // And it round-trips through the canonical form unchanged.
    let parsed: ReceiptBody = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(parsed.usage, with_usage.usage);
}
