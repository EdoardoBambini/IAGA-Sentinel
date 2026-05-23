use thiserror::Error;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("spawn failed for `{program}`: {msg}")]
    Spawn { program: String, msg: String },

    #[error("kernel decision denied: {reason}")]
    Denied { reason: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("kernel backend `{backend}` is not available on this platform")]
    Unsupported { backend: String },
}

pub type Result<T> = std::result::Result<T, KernelError>;
