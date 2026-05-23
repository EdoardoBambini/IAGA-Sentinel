//! SHA-256 digest helpers for ONNX model files.
//!
//! Digests are hex-encoded and embedded in every receipt that the host
//! signs while a given model is loaded — that's what makes replay
//! reproducible across model versions.

use sha2::{Digest, Sha256};

/// Hex-encoded SHA-256 of an arbitrary byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
