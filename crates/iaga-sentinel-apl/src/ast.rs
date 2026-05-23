//! Abstract syntax tree for APL (Agent Policy Language).

use serde::{Deserialize, Serialize};

/// A top-level APL program is a list of independent policies. The
/// evaluator runs them in declaration order; the first policy whose
/// `when` fires produces the verdict (unless the host opts into
/// "run all, collect evidence" mode).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Program {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub when: Expr,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Review,
    Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional `evidence=<expr>` binding; evaluated at policy-fire time
    /// and attached to the receipt for downstream observability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    Lit(Lit),
    /// Dotted path reference, e.g. `action.url.host`. Stored as a
    /// non-empty segment list so the evaluator can walk JSON directly.
    Path(Vec<String>),
    Call(String, Vec<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Unary(UnOp, Box<Expr>),
    /// `x in y` / `x not in y`.
    Membership {
        not: bool,
        needle: Box<Expr>,
        haystack: Box<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Lit {
    Str(String),
    Int(i64),
    Bool(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Eq,
    Neq,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Not,
}
