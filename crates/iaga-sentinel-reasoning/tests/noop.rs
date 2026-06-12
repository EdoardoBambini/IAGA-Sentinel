//! NoopEngine smoke tests, always available, no `ml` feature needed.

use iaga_sentinel_reasoning::{EvalInput, MlEvidence, NoopEngine, ReasoningEngine};

fn input() -> EvalInput {
    EvalInput::new("agent-1", "fs.read", "file_read", "hello world")
}

#[tokio::test]
async fn noop_returns_empty_evidence() {
    let eng = NoopEngine::new();
    let ev = eng.evaluate(&input()).await;
    assert!(ev.is_empty());
    assert!(ev.model_digests.is_empty());
}

#[test]
fn noop_lists_no_model_digests() {
    let eng = NoopEngine::new();
    assert_eq!(eng.model_digests().len(), 0);
}

#[test]
fn noop_engine_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NoopEngine>();
}

#[test]
fn noop_name_is_stable() {
    let eng = NoopEngine::new();
    assert_eq!(eng.name(), "noop");
}

/// 1.5.2: `failed_models` must be invisible when empty (the pre-1.5.2 wire
/// shape, byte for byte) and must round-trip from old JSON without the field.
#[test]
fn failed_models_is_elided_when_empty_and_defaults_on_old_json() {
    let ev = MlEvidence::empty();
    let json = serde_json::to_string(&ev).expect("serialize");
    assert!(
        !json.contains("failed_models"),
        "empty failed_models must not change the serialized shape: {json}"
    );

    // Old producers (≤1.5.1) emit no `failed_models`; it must default to [].
    let old: MlEvidence =
        serde_json::from_str(r#"{"scores":{},"model_digests":[]}"#).expect("old JSON parses");
    assert!(old.failed_models.is_empty());

    // When populated, the field round-trips.
    let mut with_failure = MlEvidence::empty();
    with_failure.failed_models.push("intent_drift".into());
    let json = serde_json::to_string(&with_failure).expect("serialize");
    assert!(json.contains(r#""failed_models":["intent_drift"]"#));
    let back: MlEvidence = serde_json::from_str(&json).expect("round-trip");
    assert_eq!(back, with_failure);
}
