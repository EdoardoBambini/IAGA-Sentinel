//! Signed action receipt — the unit of the Merkle append-log.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDigest {
    pub name: String,
    /// Hex-encoded SHA-256 of the plugin bytes.
    pub sha256: String,
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

/// Canonical form of a receipt — everything except the signature itself.
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
