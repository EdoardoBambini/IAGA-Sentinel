//! Reasoning engine trait + the always-available no-op implementation.

use async_trait::async_trait;

use crate::evidence::{EvalInput, MlEvidence, ModelDigest};

/// Probabilistic reasoning surface. Implementations evaluate inputs
/// through one or more ONNX models and return *evidence* — never
/// verdicts. Verdicts are the deterministic policy layer's job.
///
/// Two invariants every implementation must respect:
/// - `evaluate` must never panic and must never propagate errors. A
///   broken model degrades to empty evidence; the host pipeline keeps
///   running.
/// - `model_digests` must be stable for the lifetime of the engine.
///   Receipts embed these digests for replay.
#[async_trait]
pub trait ReasoningEngine: Send + Sync {
    async fn evaluate(&self, input: &EvalInput) -> MlEvidence;
    fn model_digests(&self) -> Vec<ModelDigest>;
    /// Human-readable name for diagnostics (`iaga reasoning info`).
    fn name(&self) -> &'static str;
}

/// No-op engine. Always present so consumer code can call
/// `state.reasoning.as_ref().map(|e| e.evaluate(...))` without
/// caring whether the `ml` feature was compiled in.
pub struct NoopEngine;

impl NoopEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReasoningEngine for NoopEngine {
    async fn evaluate(&self, _input: &EvalInput) -> MlEvidence {
        MlEvidence::empty()
    }

    fn model_digests(&self) -> Vec<ModelDigest> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}
