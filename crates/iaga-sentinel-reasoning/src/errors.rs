use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReasoningError {
    #[error("model not found at {path}")]
    ModelNotFound { path: String },

    #[error("model load failed for `{name}`: {msg}")]
    ModelLoad { name: String, msg: String },

    #[error("inference failed for `{name}`: {msg}")]
    Inference { name: String, msg: String },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ReasoningError>;
