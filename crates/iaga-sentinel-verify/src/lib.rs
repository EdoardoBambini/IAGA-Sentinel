//! Standalone offline verifier for IAGA Sentinel signed receipt chains.
//!
//! Given an exported chain (`ChainExport`) this verifies every Ed25519
//! signature and the Merkle parent-hash links with a single public key,
//! with no database, no network, and no async runtime. It is the artifact
//! an auditor runs to confirm a receipt chain is intact and unaltered,
//! without trusting IAGA.
//!
//! The verification itself reuses `iaga_sentinel_receipts::verify_chain`,
//! the exact function the full runtime uses, so this tool and the runtime
//! cannot disagree about what a valid chain is.

use ed25519_dalek::VerifyingKey;
use iaga_sentinel_receipts::{verify_chain, ChainExport, ChainStatus};

/// Which public key the chain was verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// A key the caller pinned out of band. Trusted.
    Pinned,
    /// The key embedded in the export itself. Self-asserted, not authenticated.
    Embedded,
}

/// An error that prevents the chain from being checked at all.
#[derive(Debug)]
pub enum VerifyError {
    /// The hex public key could not be decoded into a 32-byte Ed25519 key.
    BadKey(String),
    /// `verify_chain` itself errored (for example malformed signature hex).
    Verify(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadKey(m) => write!(f, "invalid public key: {m}"),
            VerifyError::Verify(m) => write!(f, "verification error: {m}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Decode a hex-encoded 32-byte Ed25519 public key.
pub fn parse_key(hex_key: &str) -> Result<VerifyingKey, VerifyError> {
    let bytes =
        hex::decode(hex_key.trim()).map_err(|e| VerifyError::BadKey(format!("not hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::BadKey(format!("expected 32 bytes, got {}", bytes.len())))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| VerifyError::BadKey(e.to_string()))
}

/// Verify an exported receipt chain. If `pinned_key_hex` is provided the
/// chain is checked against that trusted key; otherwise it falls back to the
/// key embedded in the export, which is self-asserted.
pub fn verify_export(
    export: &ChainExport,
    pinned_key_hex: Option<&str>,
) -> Result<(ChainStatus, KeySource), VerifyError> {
    let (key_hex, source) = match pinned_key_hex {
        Some(k) => (k, KeySource::Pinned),
        None => (export.signer_verifying_key.as_str(), KeySource::Embedded),
    };
    let vk = parse_key(key_hex)?;
    let status =
        verify_chain(&export.receipts, &vk).map_err(|e| VerifyError::Verify(e.to_string()))?;
    Ok((status, source))
}
