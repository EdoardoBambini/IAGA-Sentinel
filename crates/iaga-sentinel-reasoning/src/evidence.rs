//! Types exchanged between the reasoning plane and its consumers
//! (the receipt logger and, in M5, the APL evaluator).

use serde::{Deserialize, Serialize};

/// Stable identifier of an ONNX model that produced evidence.
///
/// This struct mirrors `iaga_sentinel_receipts::ModelDigest` so the host can
/// pass it straight through to the receipt body. Defining it here
/// keeps `iaga-sentinel-reasoning` independent of `iaga-sentinel-receipts` (the
/// `iaga-sentinel-core` glue code converts between the two; they're trivially
/// equal in shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDigest {
    pub name: String,
    /// Hex-encoded SHA-256 of the ONNX file bytes.
    pub sha256: String,
}

/// Input passed to `ReasoningEngine::evaluate`. Hosts construct this
/// from the inbound governance request before the policy layer runs.
#[derive(Debug, Clone)]
pub struct EvalInput {
    pub agent_id: String,
    pub tool_name: String,
    pub action_kind: String,
    pub payload_text: String,
}

impl EvalInput {
    pub fn new(
        agent_id: impl Into<String>,
        tool_name: impl Into<String>,
        action_kind: impl Into<String>,
        payload_text: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            tool_name: tool_name.into(),
            action_kind: action_kind.into(),
            payload_text: payload_text.into(),
        }
    }
}

/// Evidence produced by running an `EvalInput` through every model
/// loaded in the engine. The shape of `scores` is intentionally a
/// loose JSON document so different model families (classifier,
/// regressor, anomaly score) can coexist without a tagged enum.
///
/// Convention used by the MVP backends:
/// ```json
/// {
///   "intent_drift":     { "score": 0.12 },
///   "prompt_injection": { "score": 0.87 }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MlEvidence {
    pub scores: serde_json::Value,
    pub model_digests: Vec<ModelDigest>,
    /// Names of loaded models whose inference FAILED for this input (1.5.2).
    /// Before this field, a crashed model was indistinguishable from one that
    /// produced no score. Elided when empty so the serialized shape (and any
    /// consumer of it) is unchanged in the no-failure case. Receipts embed
    /// only `scores`, so this can never alter receipt signing bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_models: Vec<String>,
}

impl MlEvidence {
    pub fn empty() -> Self {
        Self {
            scores: serde_json::Value::Object(Default::default()),
            model_digests: Vec::new(),
            failed_models: Vec::new(),
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

impl Default for MlEvidence {
    fn default() -> Self {
        Self::empty()
    }
}
