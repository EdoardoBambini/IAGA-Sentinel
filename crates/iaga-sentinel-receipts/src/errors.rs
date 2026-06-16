use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("signature verification failed for receipt seq={seq}")]
    SignatureInvalid { seq: u64 },

    #[error("Merkle chain broken at seq={seq}: {reason}")]
    ChainBroken { seq: u64, reason: String },

    /// An `append` was rejected because the incoming receipt does not link
    /// the current head: its `seq` is not `head.seq + 1`, or its
    /// `parent_hash` does not equal the head body hash (or seq != 0 / a
    /// parent is set on an empty run). Raised by the store *inside* the
    /// append transaction so a malformed chain can never be persisted.
    #[error("chain violation at seq={seq}: {reason}")]
    ChainViolation { seq: u64, reason: String },

    /// An `append` collided with an existing `(run_id, seq)` row (the
    /// PRIMARY KEY rejected it). Distinct from `ChainViolation`: the link
    /// was well-formed but another writer already took this `seq`. The
    /// caller is expected to re-read the head and retry.
    #[error("duplicate seq={seq} for this run")]
    DuplicateSeq { seq: u64 },

    #[error("unknown run_id: {0}")]
    UnknownRun(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("canonical serialization failed: {0}")]
    Canonical(#[from] serde_json::Error),

    #[error("key material error: {0}")]
    Key(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),
}

impl From<ed25519_dalek::SignatureError> for ReceiptError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        ReceiptError::Key(err.to_string())
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl From<sqlx::Error> for ReceiptError {
    fn from(err: sqlx::Error) -> Self {
        ReceiptError::Storage(err.to_string())
    }
}

/// `true` when a sqlx error is a UNIQUE/PRIMARY KEY violation. Backends use
/// this to map a `(run_id, seq)` collision to [`ReceiptError::DuplicateSeq`]
/// (retryable) instead of a generic `Storage` error. Works for both SQLite
/// and Postgres via the shared `DatabaseError` trait.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .map(|d| d.is_unique_violation())
        .unwrap_or(false)
}

pub type Result<T> = std::result::Result<T, ReceiptError>;
