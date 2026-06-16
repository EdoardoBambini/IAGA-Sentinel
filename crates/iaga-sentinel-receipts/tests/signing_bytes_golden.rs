//! Golden-vector tests for the canonical receipt serialization.
//!
//! `ReceiptBody::signing_bytes()` is the byte stream that gets signed and
//! Merkle-hashed; if its output ever changes for an existing receipt shape,
//! every previously issued signature and `parent_hash` link breaks. These
//! tests freeze the exact bytes (and `body_hash`) for every optional-field
//! combination shipped since 1.1, so any accidental serialization drift
//! (field rename, reorder, changed elision) fails loudly.
//!
//! Deliberately NOT enforced via `serde(deny_unknown_fields)`: older
//! verifiers must keep accepting receipts from newer builds.

use iaga_sentinel_receipts::{
    CostSource, DictumEvalTrace, MlInferenceInputs, MlScoreBundle, MlTokenDigest, ModelDigest,
    PipelineInputsCapture, PluginDigest, ReceiptBody, UsageData, Verdict,
};

/// Minimal 1.1-shaped body: every optional/additive field unset.
fn minimal_body() -> ReceiptBody {
    ReceiptBody {
        run_id: "golden-run".into(),
        seq: 0,
        parent_hash: None,
        input_hash: "a".repeat(64),
        policy_hash: "b".repeat(64),
        threat_feed_hash: None,
        plugin_digests: vec![],
        model_digests: vec![],
        ml_scores: None,
        verdict: Verdict::Allow,
        reasons: vec![],
        risk_score: 12,
        timestamp: "2026-01-01T00:00:00Z".into(),
        signer_key_id: "ed25519:golden".into(),
        pipeline_inputs_capture: None,
        apl_eval_trace: None,
        ml_inference_inputs: None,
        is_authoritative: None,
        usage: None,
    }
}

fn signing_string(body: &ReceiptBody) -> String {
    String::from_utf8(body.signing_bytes().expect("signing_bytes")).expect("utf8")
}

fn body_hash_hex(body: &ReceiptBody) -> String {
    body.body_hash()
        .expect("body_hash")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn plugin_body() -> ReceiptBody {
    ReceiptBody {
        plugin_digests: vec![
            PluginDigest {
                name: "regex-guard".into(),
                sha256: "c".repeat(64),
                attested: None,
                attestation_issuer: None,
            },
            PluginDigest {
                name: "pii-scrubber".into(),
                sha256: "d".repeat(64),
                attested: Some(true),
                attestation_issuer: Some("sigstore:golden@example.org".into()),
            },
        ],
        ..minimal_body()
    }
}

fn ml_body() -> ReceiptBody {
    ReceiptBody {
        model_digests: vec![ModelDigest {
            name: "intent-drift".into(),
            sha256: "e".repeat(64),
        }],
        ml_scores: Some(MlScoreBundle(serde_json::json!({
            "intent_drift": { "score": 0.5 }
        }))),
        ..minimal_body()
    }
}

fn capture_body() -> ReceiptBody {
    ReceiptBody {
        pipeline_inputs_capture: Some(PipelineInputsCapture {
            request_json: serde_json::json!({"action":"file_read","agentId":"golden-agent"}),
            framework: "iaga-sentinel-core".into(),
            payload_sha256: "f".repeat(64),
        }),
        ..minimal_body()
    }
}

fn dictum_trace_body() -> ReceiptBody {
    ReceiptBody {
        apl_eval_trace: Some(DictumEvalTrace {
            policy_hash: "b".repeat(64),
            policies_evaluated: 3,
            policies_fired: vec!["high_risk".into()],
            evidence_sha256: None,
        }),
        ..minimal_body()
    }
}

fn ml_inputs_body() -> ReceiptBody {
    ReceiptBody {
        ml_inference_inputs: Some(MlInferenceInputs {
            tokenized_digests: vec![MlTokenDigest {
                model_name: "intent-drift".into(),
                tokenized_sha256: "1".repeat(64),
            }],
        }),
        ..minimal_body()
    }
}

fn authoritative_body() -> ReceiptBody {
    ReceiptBody {
        is_authoritative: Some(false),
        ..minimal_body()
    }
}

fn usage_body() -> ReceiptBody {
    ReceiptBody {
        usage: Some(UsageData {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-6".into(),
            prompt_tokens: Some(10),
            completion_tokens: Some(20),
            total_tokens: Some(30),
            cost_micros: 50_000,
            cache_hit: false,
            savings_micros: None,
            cost_source: CostSource::PricingTable,
        }),
        ..minimal_body()
    }
}

fn kitchen_sink_body() -> ReceiptBody {
    ReceiptBody {
        run_id: "golden-run".into(),
        seq: 7,
        parent_hash: Some("9".repeat(64)),
        input_hash: "a".repeat(64),
        policy_hash: "b".repeat(64),
        threat_feed_hash: None,
        plugin_digests: plugin_body().plugin_digests,
        model_digests: ml_body().model_digests,
        ml_scores: ml_body().ml_scores,
        verdict: Verdict::Block,
        reasons: vec!["policy high_risk fired".into(), "risk 88".into()],
        risk_score: 88,
        timestamp: "2026-01-01T00:00:00Z".into(),
        signer_key_id: "ed25519:golden".into(),
        pipeline_inputs_capture: capture_body().pipeline_inputs_capture,
        apl_eval_trace: dictum_trace_body().apl_eval_trace,
        ml_inference_inputs: ml_inputs_body().ml_inference_inputs,
        is_authoritative: Some(false),
        usage: Some(UsageData {
            provider: "anthropic".into(),
            model: "claude-haiku-4-5".into(),
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            cost_micros: 0,
            cache_hit: true,
            savings_micros: Some(1_200),
            cost_source: CostSource::Cache,
        }),
    }
}

/// Asserts a body serializes to exactly `golden` and hashes to `hash`.
/// The literals were generated from this crate at 1.5.1 and must never
/// change for these shapes.
fn assert_golden(body: &ReceiptBody, golden: &str, hash: &str) {
    assert_eq!(signing_string(body), golden, "signing bytes drifted");
    assert_eq!(body_hash_hex(body), hash, "body hash drifted");
    // The signed bytes must round-trip: a verifier deserializing this exact
    // JSON has to reproduce the same bytes and hash.
    let back: ReceiptBody = serde_json::from_str(golden).expect("golden must deserialize");
    assert_eq!(&back, body, "round-trip changed the body");
}

#[test]
fn minimal_1_1_shape_is_frozen() {
    let body = minimal_body();
    let s = signing_string(&body);
    assert_golden(
        &body,
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden"}"#,
        "605393e0410f30b43d5d2d37a819311a70fe3b3487a1eee481a8512df0c2108c",
    );
    // Every additive-since-1.1 field must be elided, not serialized as
    // null/empty, or pre-1.2 signatures stop verifying.
    for absent in [
        "plugin_digests",
        "model_digests",
        "ml_scores",
        "reasons",
        "pipeline_inputs_capture",
        "apl_eval_trace",
        "ml_inference_inputs",
        "is_authoritative",
        "usage",
    ] {
        assert!(
            !s.contains(&format!("\"{absent}\"")),
            "unset field `{absent}` leaked into signing bytes"
        );
    }
    // `parent_hash` is NOT optional-elided: seq=0 receipts always carry null.
    assert!(s.contains("\"parent_hash\":null"));
}

#[test]
fn plugin_digests_shape_is_frozen() {
    let body = plugin_body();
    let s = signing_string(&body);
    assert_golden(
        &body,
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","plugin_digests":[{"name":"regex-guard","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},{"name":"pii-scrubber","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","attested":true,"attestation_issuer":"sigstore:golden@example.org"}],"verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden"}"#,
        "cae0c0a613a1f69f6b2f6e9753476b920d43767af848d945a38d246c02d9f234",
    );
    // Un-attested plugin entries (1.1 shape) elide both attestation fields
    // instead of serializing them as null.
    assert!(!s.contains(r#""attested":null"#));
    assert!(!s.contains(r#""attestation_issuer":null"#));
}

#[test]
fn model_digests_and_ml_scores_shape_is_frozen() {
    assert_golden(
        &ml_body(),
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","model_digests":[{"name":"intent-drift","sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}],"ml_scores":{"intent_drift":{"score":0.5}},"verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden"}"#,
        "e8c98fad5dd5ae0cbda2537fd9041e3be61845b6be0ad0ea1b9dc53d5293877d",
    );
}

#[test]
fn pipeline_inputs_capture_shape_is_frozen() {
    assert_golden(
        &capture_body(),
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden","pipeline_inputs_capture":{"requestJson":{"action":"file_read","agentId":"golden-agent"},"framework":"iaga-sentinel-core","payloadSha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}"#,
        "02c726f0b0c8e8d97ff47f1efb195361cc54245a553788b1a4c645deeb6d8e08",
    );
}

#[test]
fn apl_eval_trace_shape_is_frozen() {
    assert_golden(
        &dictum_trace_body(),
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden","apl_eval_trace":{"policyHash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","policiesEvaluated":3,"policiesFired":["high_risk"]}}"#,
        "2a1ed3f096107a4676d44a728681f3a2b965244fffb7bc947915732e7b1e3e29",
    );
}

#[test]
fn ml_inference_inputs_shape_is_frozen() {
    assert_golden(
        &ml_inputs_body(),
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden","ml_inference_inputs":{"tokenizedDigests":[{"modelName":"intent-drift","tokenizedSha256":"1111111111111111111111111111111111111111111111111111111111111111"}]}}"#,
        "155a64d94da305110c21cb53ad0bbe0051a7d4a715cca80def71d60b88dd1f83",
    );
}

#[test]
fn is_authoritative_shape_is_frozen() {
    assert_golden(
        &authoritative_body(),
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden","is_authoritative":false}"#,
        "3f07164b99899c6674f756637dfcfbeac4b8cb81fd95d034bcf8ad65a170fa3d",
    );
}

#[test]
fn usage_shape_is_frozen() {
    let body = usage_body();
    let s = signing_string(&body);
    assert_golden(
        &body,
        r#"{"run_id":"golden-run","seq":0,"parent_hash":null,"input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","verdict":"allow","risk_score":12,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden","usage":{"provider":"anthropic","model":"claude-sonnet-4-6","promptTokens":10,"completionTokens":20,"totalTokens":30,"costMicros":50000,"costSource":"pricing_table"}}"#,
        "e3f1ed944b5927bc65f6601abb5763691eb7b4a535d0479ab7619a6f98a68f6d",
    );
    // `cacheHit: false` and `savingsMicros: None` are elided inside usage.
    assert!(!s.contains("cacheHit"));
    assert!(!s.contains("savingsMicros"));
}

#[test]
fn kitchen_sink_shape_is_frozen() {
    assert_golden(
        &kitchen_sink_body(),
        r#"{"run_id":"golden-run","seq":7,"parent_hash":"9999999999999999999999999999999999999999999999999999999999999999","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","plugin_digests":[{"name":"regex-guard","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},{"name":"pii-scrubber","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","attested":true,"attestation_issuer":"sigstore:golden@example.org"}],"model_digests":[{"name":"intent-drift","sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}],"ml_scores":{"intent_drift":{"score":0.5}},"verdict":"block","reasons":["policy high_risk fired","risk 88"],"risk_score":88,"timestamp":"2026-01-01T00:00:00Z","signer_key_id":"ed25519:golden","pipeline_inputs_capture":{"requestJson":{"action":"file_read","agentId":"golden-agent"},"framework":"iaga-sentinel-core","payloadSha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"apl_eval_trace":{"policyHash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","policiesEvaluated":3,"policiesFired":["high_risk"]},"ml_inference_inputs":{"tokenizedDigests":[{"modelName":"intent-drift","tokenizedSha256":"1111111111111111111111111111111111111111111111111111111111111111"}]},"is_authoritative":false,"usage":{"provider":"anthropic","model":"claude-haiku-4-5","costMicros":0,"cacheHit":true,"savingsMicros":1200,"costSource":"cache"}}"#,
        "5cd21ce9fb7369a361e9ac616cef1cd97bf05c3e304db8c788f1435c466d3b28",
    );
}
