//! Glue between the governance pipeline and `iaga-sentinel-reasoning`.
//!
//! Mirrors the design of `pipeline::receipts`:
//! - `ReasoningHandle` is a feature-agnostic trait. `AppState` always
//!   has a slot for it; the slot is `None` unless the host wired one.
//! - The concrete impl (`SignedReceiptLogger` analogue here is just a
//!   thin adapter) only compiles when the `reasoning` feature is on.
//! - `try_build_reasoning_engine(env_spec)` returns `None` when the
//!   feature is off, an empty `NoopEngine` when on but no models are
//!   configured, or a `TractEngine` when `ml` is on and at least one
//!   `name:path` pair is provided through the env var.

use async_trait::async_trait;

/// Public, feature-agnostic surface used by `AppState`.
///
/// We do not re-export `iaga_sentinel_reasoning::ReasoningEngine` directly so
/// that `iaga-sentinel-core` can compile cleanly without `iaga-sentinel-reasoning` in
/// the dependency graph (e.g. when a downstream embedder strips the
/// `reasoning` feature out for binary size).
#[async_trait]
pub trait ReasoningHandle: Send + Sync {
    /// Best-effort evaluation. Implementations must never panic and
    /// must never propagate errors, empty evidence is the failure
    /// mode. Output JSON shape is whatever the underlying engine emits.
    async fn evaluate_json(
        &self,
        agent_id: &str,
        tool_name: &str,
        action_kind: &str,
        payload_text: &str,
    ) -> ReasoningOutcome;

    /// Stable name (`noop`, `tract`, ...).
    fn engine_name(&self) -> &'static str;

    /// `(model_name, sha256_hex)` for every loaded model.
    fn model_digests(&self) -> Vec<(String, String)>;
}

/// Output of one reasoning evaluation, in a shape both the receipt
/// logger and (in M5) the APL evaluator can consume directly.
#[derive(Debug, Clone, Default)]
pub struct ReasoningOutcome {
    pub scores: serde_json::Value,
    pub model_digests: Vec<(String, String)>,
}

impl ReasoningOutcome {
    pub fn empty() -> Self {
        Self {
            scores: serde_json::Value::Object(Default::default()),
            model_digests: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.model_digests.is_empty()
            && self
                .scores
                .as_object()
                .map(|m| m.is_empty())
                .unwrap_or(true)
    }
}

#[cfg(feature = "reasoning")]
pub use wired::{try_build_reasoning_engine, ReasoningAdapter};

#[cfg(feature = "reasoning")]
mod wired {
    use std::sync::Arc;

    use async_trait::async_trait;
    use iaga_sentinel_reasoning::{EvalInput, NoopEngine, ReasoningEngine};

    use super::{ReasoningHandle, ReasoningOutcome};

    /// Adapter that implements the feature-agnostic `ReasoningHandle`
    /// trait on top of any concrete `iaga_sentinel_reasoning::ReasoningEngine`.
    pub struct ReasoningAdapter {
        inner: Arc<dyn ReasoningEngine>,
    }

    impl ReasoningAdapter {
        pub fn new(inner: Arc<dyn ReasoningEngine>) -> Self {
            Self { inner }
        }
    }

    #[async_trait]
    impl ReasoningHandle for ReasoningAdapter {
        async fn evaluate_json(
            &self,
            agent_id: &str,
            tool_name: &str,
            action_kind: &str,
            payload_text: &str,
        ) -> ReasoningOutcome {
            let input = EvalInput::new(agent_id, tool_name, action_kind, payload_text);
            let ev = self.inner.evaluate(&input).await;
            ReasoningOutcome {
                scores: ev.scores,
                model_digests: ev
                    .model_digests
                    .into_iter()
                    .map(|d| (d.name, d.sha256))
                    .collect(),
            }
        }

        fn engine_name(&self) -> &'static str {
            self.inner.name()
        }

        fn model_digests(&self) -> Vec<(String, String)> {
            self.inner
                .model_digests()
                .into_iter()
                .map(|d| (d.name, d.sha256))
                .collect()
        }
    }

    /// Resolve a reasoning engine from the environment.
    ///
    /// Decision tree:
    /// 1. Feature `ml` off → always returns `Some(Arc<NoopEngine>)`. The
    ///    plumbing is live so receipts and CLI tooling have something
    ///    to talk to, but no models are loaded.
    /// 2. Feature `ml` on + `IAGA_SENTINEL_REASONING_MODELS` empty/missing →
    ///    same as above (NoopEngine).
    /// 3. Feature `ml` on + valid env spec → tries to load all listed
    ///    models. On any load failure logs at warn and falls back to
    ///    `NoopEngine` so the pipeline still runs.
    pub fn try_build_reasoning_engine() -> Option<Arc<dyn ReasoningHandle>> {
        let inner: Arc<dyn ReasoningEngine> = build_inner_engine();
        Some(Arc::new(ReasoningAdapter::new(inner)) as Arc<dyn ReasoningHandle>)
    }

    #[cfg(feature = "ml")]
    fn build_inner_engine() -> Arc<dyn ReasoningEngine> {
        use iaga_sentinel_reasoning::{parse_env_spec, TractEngine};

        let spec_env = std::env::var("IAGA_SENTINEL_REASONING_MODELS").ok();
        let pairs = parse_env_spec(spec_env.as_deref());
        if pairs.is_empty() {
            tracing::info!("reasoning: ml feature on, no models configured; using NoopEngine");
            return Arc::new(NoopEngine::new());
        }
        let refs: Vec<(&str, &std::path::Path)> = pairs
            .iter()
            .map(|(n, p)| (n.as_str(), p.as_path()))
            .collect();
        match TractEngine::from_paths(&refs) {
            Ok(eng) => {
                tracing::info!(models = eng.model_count(), "reasoning: tract engine active");
                Arc::new(eng)
            }
            Err(e) => {
                tracing::warn!(error = %e, "reasoning: tract load failed; falling back to NoopEngine");
                Arc::new(NoopEngine::new())
            }
        }
    }

    #[cfg(not(feature = "ml"))]
    fn build_inner_engine() -> Arc<dyn ReasoningEngine> {
        tracing::info!("reasoning: feature `ml` off; using NoopEngine");
        Arc::new(NoopEngine::new())
    }
}

#[cfg(not(feature = "reasoning"))]
pub fn try_build_reasoning_engine() -> Option<std::sync::Arc<dyn ReasoningHandle>> {
    None
}
