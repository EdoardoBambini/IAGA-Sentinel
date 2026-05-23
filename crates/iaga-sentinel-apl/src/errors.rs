use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AplError {
    #[error("parse error at {line}:{col}: {msg}")]
    Parse { line: u32, col: u32, msg: String },

    #[error("type error: {0}")]
    Type(String),

    #[error("runtime error: {0}")]
    Eval(String),

    #[error("budget exhausted after {steps} eval steps")]
    BudgetExhausted { steps: u64 },
}

pub type Result<T> = std::result::Result<T, AplError>;
