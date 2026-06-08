//! Signed action receipt, the unit of the Merkle append-log.
//!
//! A Receipt is the signed record of a single governance verdict. Receipts
//! for the same `run_id` form a hash-linked chain via `parent_hash`. The
//! `signature` field covers all other fields (see `signing_bytes`).

use serde::{Deserialize, Serialize};

use crate::errors::Result;

/// Governance verdict recorded in the receipt. Mirrors the three terminal
/// decisions of the core pipeline but is defined locally so this crate has
/// no dependency on `iaga-sentinel-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Review,
    Block,
}

/// Digest of a plugin (WASM module) that was invoked while producing the verdict.
///
/// 1.2: `attested` and `attestation_issuer` are additive optional
/// fields populated when the host has the `plugin-attestation` feature
/// enabled and the plugin shipped with a sibling Sigstore bundle. Both
/// fields are elided from the receipt body when `None`, so 1.1
/// receipts deserialize cleanly and signing-bytes stay byte-identical
/// when attestation is off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDigest {
    pub name: String,
    /// Hex-encoded SHA-256 of the plugin bytes.
    pub sha256: String,
    /// 1.2: `true` if the host verified an offline Sigstore bundle
    /// (well-formed + payload digest matches) at load time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested: Option<bool>,
    /// 1.2: free-form attestation issuer string when known (e.g.
    /// Sigstore Fulcio cert identity). Best-effort; receipts only
    /// store, never interpret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_issuer: Option<String>,
}

/// Digest of an ML model that was consulted (only present when the `ml`
/// feature of `iaga-sentinel-reasoning` is active in the host process).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDigest {
    pub name: String,
    /// Hex-encoded SHA-256 of the ONNX file.
    pub sha256: String,
}

/// Bundle of ML evidence scores attached to a receipt. Opaque to receipts:
/// the structure is whatever `iaga-sentinel-reasoning` emits; receipts only store,
/// never interpret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlScoreBundle(pub serde_json::Value);

/// Pipeline inputs captured at receipt time so `iaga replay --re-execute`
/// can re-evaluate the request against the *current* policy bundle.
///
/// Opt-in via the host env `IAGA_SENTINEL_RECEIPT_CAPTURE=1` (default off).
/// When the env is unset, the field is `None` and is elided from
/// `signing_bytes` via `skip_serializing_if`, so receipts produced by
/// 1.2.0 with capture off are **byte-identical** to receipts produced
/// by 1.1.0, the chain link and signature stay stable.
///
/// Forensic time-travel (event-sourcing + DB-state-per-verdict snapshots)
/// is intentionally out of scope here and lives in IAGA Sentinel
/// Enterprise (ADR 0010 §2.13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineInputsCapture {
    /// JSON snapshot of the request that drove this verdict. The shape is
    /// host-defined (typically the `StoredAuditEvent` as JSON); the
    /// receipt only stores, never interprets.
    pub request_json: serde_json::Value,
    /// Free-form tag for the host pipeline that produced the capture,
    /// e.g. `iaga-sentinel-core`.
    pub framework: String,
    /// Hex-encoded SHA-256 of the serialized request bytes, mirroring
    /// `ReceiptBody::input_hash` but computed over the captured payload
    /// (so re-execute can confirm it has the right bytes before
    /// re-running the pipeline).
    pub payload_sha256: String,
}

/// APL evaluation trace summary captured alongside the verdict. Records
/// which policies were considered and which fired, without leaking
/// secret/PII content from the request body.
///
/// Optional and additive: when absent the receipt has no APL trace
/// (1.1 behaviour preserved bit-identically).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AplEvalTrace {
    /// Hex-encoded SHA-256 of the compiled APL bundle (mirrors
    /// `ReceiptBody::policy_hash` for cross-check).
    pub policy_hash: String,
    /// Number of APL policies evaluated for this verdict.
    pub policies_evaluated: u32,
    /// Names of APL policies that fired (i.e. matched and produced a
    /// verdict). Empty when the YAML baseline alone produced the
    /// decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies_fired: Vec<String>,
}

/// ML reasoning inputs captured alongside the verdict. Records the
/// tokenized input digest per model consulted, so a `--re-execute`
/// pass can confirm the same bytes drove the inference.
///
/// Stores **digests only**, never raw tokenized input, that would
/// leak request content into receipts and breaks the
/// "operator can publish receipts without leaking customer data"
/// posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MlInferenceInputs {
    /// Hex-encoded SHA-256 of the tokenized input fed to each model
    /// (`model_name` → digest).
    pub tokenized_digests: Vec<MlTokenDigest>,
}

/// Pair of model name and digest of its tokenized input. Used inside
/// [`MlInferenceInputs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MlTokenDigest {
    pub model_name: String,
    /// Hex-encoded SHA-256 of the tokenized bytes fed to this model.
    pub tokenized_sha256: String,
}

/// Canonical form of a receipt, everything except the signature itself.
/// This is what gets signed: stable serialization, no extraneous fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    pub run_id: String,
    pub seq: u64,
    /// Hex-encoded SHA-256 of the parent receipt body, or None for seq=0.
    pub parent_hash: Option<String>,
    pub input_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugin_digests: Vec<PluginDigest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_digests: Vec<ModelDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_scores: Option<MlScoreBundle>,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub risk_score: u32,
    /// RFC3339 UTC timestamp.
    pub timestamp: String,
    /// Identifier of the signer key (not the key itself).
    pub signer_key_id: String,
    /// 1.2 drift-replay capture (optional, additive). Populated only
    /// when `IAGA_SENTINEL_RECEIPT_CAPTURE=1`. Elided from
    /// `signing_bytes` when `None`, preserving 1.1 byte-equality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline_inputs_capture: Option<PipelineInputsCapture>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apl_eval_trace: Option<AplEvalTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_inference_inputs: Option<MlInferenceInputs>,
    /// 1.3.1 honesty flag. `Some(false)` on every OSS receipt because the
    /// community build enforces softly: no authoritative kernel ships in
    /// OSS (`UserspaceKernel::is_authoritative()` is `false` and
    /// `BpfKernel` is a scaffold). An Enterprise build wired to an
    /// authoritative eBPF/LSM kernel would set `Some(true)`. Elided from
    /// `signing_bytes` when `None`, so receipts produced before 1.3.1
    /// stay byte-identical and verify unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_authoritative: Option<bool>,
}

impl ReceiptBody {
    /// Canonical serialization used for both signing and Merkle hashing.
    ///
    /// We rely on `serde_json` preserving struct field order and on the
    /// struct having no `HashMap` / `BTreeMap` fields. This gives
    /// byte-deterministic output without pulling in a full RFC 8785
    /// implementation.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// SHA-256 of the signing bytes. This is what children reference in
    /// `parent_hash`.
    pub fn body_hash(&self) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_bytes()?);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Ok(arr)
    }
}

/// Full receipt: body + Ed25519 signature over `body.signing_bytes()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(flatten)]
    pub body: ReceiptBody,
    /// Hex-encoded 64-byte Ed25519 signature over `body.signing_bytes()`.
    pub signature: String,
}

/// Summary of a run for listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub receipt_count: u64,
    pub first_timestamp: String,
    pub last_timestamp: String,
    pub terminal_verdict: Verdict,
}

/// Outcome of chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainStatus {
    /// Chain is intact: every signature verifies and every parent_hash matches.
    Valid { receipt_count: u64 },
    /// Chain break at the given sequence number.
    Broken { seq: u64, reason: String },
    /// No receipts for this run_id.
    Empty,
}
