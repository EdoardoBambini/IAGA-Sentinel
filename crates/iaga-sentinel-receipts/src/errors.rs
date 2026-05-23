use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("signature verification failed for receipt seq={seq}")]
    SignatureInvalid { seq: u64 },

    #[error("Merkle chain broken at seq={seq}: {reason}")]
    ChainBroken { seq: u64, reason: String },

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

impl From<sqlx::Error> for ReceiptError {
    fn from(err: sqlx::Error) -> Self {
        ReceiptError::Storage(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ReceiptError>;
