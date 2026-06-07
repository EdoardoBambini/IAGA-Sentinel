//! # iaga-sentinel-reasoning
//!
//! Probabilistic Reasoning Plane for IAGA Sentinel 1.0, pillar 7 of the
//! 1.0 design. ML produces **evidence**, never verdicts. The deterministic
//! policy layer decides; this crate just feeds it scores.
//!
//! Two backends:
//!
//! - [`NoopEngine`], always present, returns empty evidence. Lets the
//!   host write feature-agnostic glue code.
//! - `TractEngine` (feature `ml`), pure-Rust ONNX inference via `tract`.
//!   Loads models from disk, computes SHA-256 digests for every file,
//!   and emits a single scalar `score` per model. Zero native deps.
//!
//! Models registered with the engine have their digests embedded in
//! every receipt the host produces. This is what makes the M2 receipt
//! chain robust to ML model changes: replay the same input against
//! the same digests and you get the same scores. Change the model,
//! the digest changes, and replay flags drift cleanly.
//!
//! See `docs/adr/0005-reasoning-plane-mvp.md` for scope decisions.

pub mod digest;
pub mod engine;
pub mod errors;
pub mod evidence;

#[cfg(feature = "ml")]
pub mod tract_engine;

pub use engine::{NoopEngine, ReasoningEngine};
pub use errors::{ReasoningError, Result};
pub use evidence::{EvalInput, MlEvidence, ModelDigest};

#[cfg(feature = "ml")]
pub use tract_engine::{parse_env_spec, TractEngine, INPUT_DIM};
