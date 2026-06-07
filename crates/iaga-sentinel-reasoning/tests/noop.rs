//! NoopEngine smoke tests, always available, no `ml` feature needed.

use iaga_sentinel_reasoning::{EvalInput, NoopEngine, ReasoningEngine};

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
