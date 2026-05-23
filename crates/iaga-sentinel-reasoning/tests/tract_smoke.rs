//! TractEngine smoke tests — gated on the `ml` feature.
//!
//! These cover the wiring (load failure surfacing, digest stability,
//! env spec parsing, empty-engine behavior). End-to-end inference
//! against a real ONNX file is a tract-onnx concern — covered upstream
//! in their own test suite — and re-tested integration-side in
//! `iaga-sentinel-core` once a real model is provided in M3.5.1.

#![cfg(feature = "ml")]

use std::path::PathBuf;

use iaga_sentinel_reasoning::{
    parse_env_spec, EvalInput, ReasoningEngine, ReasoningError, TractEngine,
};

#[tokio::test]
async fn empty_engine_returns_empty_evidence() {
    let eng = TractEngine::empty();
    assert_eq!(eng.model_count(), 0);
    let ev = eng.evaluate(&EvalInput::new("a", "t", "k", "p")).await;
    assert!(ev.is_empty());
}

#[test]
fn missing_model_path_surfaces_typed_error() {
    let bad = std::path::PathBuf::from("does/not/exist.onnx");
    match TractEngine::from_paths(&[("missing", &bad)]) {
        Ok(_) => panic!("expected error for missing model"),
        Err(ReasoningError::ModelNotFound { path }) => {
            assert!(path.contains("exist.onnx"), "unexpected path: {}", path)
        }
        Err(other) => panic!("wrong error variant: {:?}", other),
    }
}

#[test]
fn env_spec_parses_two_models() {
    let v = parse_env_spec(Some("intent_drift:/m/a.onnx,prompt_injection:/m/b.onnx"));
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].0, "intent_drift");
    assert_eq!(v[0].1, PathBuf::from("/m/a.onnx"));
    assert_eq!(v[1].0, "prompt_injection");
}

#[test]
fn env_spec_skips_malformed_entries() {
    let v = parse_env_spec(Some("good:/m/g.onnx,bad_no_colon,:empty_name,name_only:"));
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].0, "good");
}

#[test]
fn env_spec_handles_none_and_empty() {
    assert!(parse_env_spec(None).is_empty());
    assert!(parse_env_spec(Some("")).is_empty());
}

#[test]
fn tract_engine_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TractEngine>();
}

#[tokio::test]
async fn empty_engine_reports_no_digests() {
    let eng = TractEngine::empty();
    assert!(eng.model_digests().is_empty());
    assert_eq!(eng.name(), "tract");
}
