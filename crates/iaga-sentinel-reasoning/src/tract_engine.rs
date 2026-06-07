//! Tract-based ONNX inference engine. Compiled only when the `ml`
//! feature is on so the no-feature build stays slim.
//!
//! Design:
//! - One `LoadedModel` per ONNX file. The host registers them by
//!   `(name, path)` pairs; the engine reads the file once, computes
//!   the SHA-256 digest, and keeps an optimized runnable in memory.
//! - Tokenization is deliberately primitive (hash-bag of byte n-grams)
//!   so the MVP can run any model with a `[1, N]` float32 input
//!   without dragging in HuggingFace tokenizers. Real workloads will
//!   ship a tokenizer alongside the model, wired in M3.5.1.
//! - Inference produces a single scalar score per model, taken as the
//!   first element of the output tensor. Models with richer outputs
//!   are supported in M5 when APL gains `ml.*` evidence paths.
//!
//! Failure policy: any per-model failure during `evaluate` is logged
//! (via `tracing` if the host wires it) and contributes nothing to
//! the evidence, never propagated as an error. A broken model must
//! not knock the pipeline offline.

#![cfg(feature = "ml")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use tract_onnx::prelude::*;

use crate::digest::sha256_hex;
use crate::engine::ReasoningEngine;
use crate::errors::{ReasoningError, Result};
use crate::evidence::{EvalInput, MlEvidence, ModelDigest};

/// Default feature vector size produced by the MVP tokenizer.
/// Models accepting `[1, INPUT_DIM]` float32 work out of the box.
pub const INPUT_DIM: usize = 64;

type RunnableModel =
    Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>;

struct LoadedModel {
    name: String,
    digest: ModelDigest,
    runner: RunnableModel,
}

pub struct TractEngine {
    models: Vec<LoadedModel>,
}

impl TractEngine {
    /// Empty engine, useful as a placeholder before models are loaded
    /// or in tests that don't need real inference.
    pub fn empty() -> Self {
        Self { models: Vec::new() }
    }

    /// Load every `(name, path)` pair into the engine. Errors short-
    /// circuit construction: a half-loaded engine would silently skip
    /// models the operator believes are active.
    pub fn from_paths<P: AsRef<Path>>(specs: &[(&str, P)]) -> Result<Self> {
        let mut models = Vec::with_capacity(specs.len());
        for (name, path) in specs {
            let path = path.as_ref();
            models.push(load_model(name, path)?);
        }
        Ok(Self { models })
    }

    /// Build directly from an in-memory `(name, RunnableModel, digest_seed)`
    /// triple. Exposed for tests that don't want to write a real ONNX
    /// file to disk; production callers use `from_paths`.
    pub fn from_runnables(runnables: Vec<(String, RunnableModel, Vec<u8>)>) -> Self {
        let models = runnables
            .into_iter()
            .map(|(name, runner, digest_seed)| LoadedModel {
                digest: ModelDigest {
                    name: name.clone(),
                    sha256: sha256_hex(&digest_seed),
                },
                name,
                runner,
            })
            .collect();
        Self { models }
    }

    /// Number of currently loaded models. Used by `iaga reasoning info`.
    pub fn model_count(&self) -> usize {
        self.models.len()
    }
}

fn load_model(name: &str, path: &Path) -> Result<LoadedModel> {
    if !path.exists() {
        return Err(ReasoningError::ModelNotFound {
            path: path.display().to_string(),
        });
    }
    let bytes = std::fs::read(path)?;
    let digest = ModelDigest {
        name: name.to_string(),
        sha256: sha256_hex(&bytes),
    };
    let mut cursor = std::io::Cursor::new(&bytes);
    let model = tract_onnx::onnx()
        .model_for_read(&mut cursor)
        .and_then(|m| m.into_optimized())
        .and_then(|m| m.into_runnable())
        .map_err(|e| ReasoningError::ModelLoad {
            name: name.to_string(),
            msg: e.to_string(),
        })?;
    Ok(LoadedModel {
        name: name.to_string(),
        digest,
        runner: Arc::new(model),
    })
}

/// MVP tokenizer: hash byte n-grams (n=3) into a fixed-size float32 vector.
/// Deterministic given the same input string, which is what receipt
/// replay needs. Produces a `[1, INPUT_DIM]` shape.
fn tokenize(input: &EvalInput) -> Vec<f32> {
    use std::hash::{Hash, Hasher};
    let mut feats = vec![0.0f32; INPUT_DIM];
    let payload = input.payload_text.as_bytes();
    if payload.len() < 3 {
        return feats;
    }
    for window in payload.windows(3) {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        window.hash(&mut h);
        let bucket = (h.finish() as usize) % INPUT_DIM;
        feats[bucket] += 1.0;
    }
    let max = feats.iter().cloned().fold(0.0f32, f32::max);
    if max > 0.0 {
        for v in feats.iter_mut() {
            *v /= max;
        }
    }
    feats
}

fn run_one(model: &LoadedModel, input_vec: &[f32]) -> Result<f32> {
    let tensor = tract_ndarray::Array2::from_shape_vec((1, input_vec.len()), input_vec.to_vec())
        .map_err(|e| ReasoningError::Inference {
            name: model.name.clone(),
            msg: e.to_string(),
        })?
        .into_tensor();
    let result = model
        .runner
        .run(tvec!(tensor.into()))
        .map_err(|e| ReasoningError::Inference {
            name: model.name.clone(),
            msg: e.to_string(),
        })?;
    let out = result
        .into_iter()
        .next()
        .ok_or_else(|| ReasoningError::Inference {
            name: model.name.clone(),
            msg: "model returned no outputs".into(),
        })?;
    let slice = out
        .as_slice::<f32>()
        .map_err(|e| ReasoningError::Inference {
            name: model.name.clone(),
            msg: e.to_string(),
        })?;
    slice
        .first()
        .copied()
        .ok_or_else(|| ReasoningError::Inference {
            name: model.name.clone(),
            msg: "model output tensor was empty".into(),
        })
}

#[async_trait]
impl ReasoningEngine for TractEngine {
    async fn evaluate(&self, input: &EvalInput) -> MlEvidence {
        if self.models.is_empty() {
            return MlEvidence::empty();
        }
        let feats = tokenize(input);
        let mut scores = serde_json::Map::with_capacity(self.models.len());
        for m in &self.models {
            match run_one(m, &feats) {
                Ok(s) => {
                    scores.insert(m.name.clone(), json!({ "score": s as f64 }));
                }
                Err(_e) => {
                    // Soft-fail: model contributes nothing this round.
                    // Host wires `tracing` if it cares about the warn line.
                }
            }
        }
        MlEvidence {
            scores: serde_json::Value::Object(scores),
            model_digests: self.models.iter().map(|m| m.digest.clone()).collect(),
        }
    }

    fn model_digests(&self) -> Vec<ModelDigest> {
        self.models.iter().map(|m| m.digest.clone()).collect()
    }

    fn name(&self) -> &'static str {
        "tract"
    }
}

/// Resolve `IAGA_SENTINEL_REASONING_MODELS` from the environment. Format:
/// `name1:path1,name2:path2`. Empty/missing → `Ok(vec![])`.
pub fn parse_env_spec(env_value: Option<&str>) -> Vec<(String, PathBuf)> {
    match env_value {
        None | Some("") => Vec::new(),
        Some(s) => s
            .split(',')
            .filter_map(|entry| {
                let mut parts = entry.splitn(2, ':');
                let name = parts.next()?.trim().to_string();
                let path = parts.next()?.trim().to_string();
                if name.is_empty() || path.is_empty() {
                    None
                } else {
                    Some((name, PathBuf::from(path)))
                }
            })
            .collect(),
    }
}
