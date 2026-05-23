//! # iaga-sentinel-apl
//!
//! Agent Policy Language (APL) — MVP for 1.0 M3.
//!
//! APL is a typed DSL that replaces 0.4.0's YAML + template pipeline
//! for policy authoring. This crate ships:
//!
//! - a `logos`-based lexer,
//! - a recursive-descent parser producing a [`Program`] AST,
//! - a structural validator (see [`validate`]),
//! - a deterministic tree-walk evaluator with an instruction budget.
//!
//! **Scope note (M3 MVP)**: the design in `IAGA_SENTINEL_1.0.md` calls for
//! WASM bytecode as the execution target. For M3 we ship a tree-walk
//! interpreter that is pure and deterministic (no I/O, no wall clock,
//! no RNG, single-threaded). This is already sufficient for receipt
//! replay: given the same AST and context, eval yields the same result.
//! WASM codegen is planned for M3.1 and will slot in behind the same
//! evaluator entrypoints without AST changes.
//!
//! Example policy:
//!
//! ```text
//! policy "no_secrets_to_public_http" {
//!   when action.kind == "http.request"
//!    and action.url.host not in workspace.allowlist
//!    and secret_ref(payload)
//!   then block, reason="PII egress"
//! }
//! ```
//!
//! See `docs/adr/0004-apl-mvp.md` for the full design rationale.

pub mod ast;
pub mod errors;
pub mod eval;
pub mod lexer;
pub mod parser;
pub mod validator;

pub use ast::{Action, BinOp, Expr, Lit, Policy, Program, UnOp, Verdict};
pub use errors::{AplError, Result};
pub use eval::{eval_expr, evaluate_program, Context, EvalBudget, PolicyFired, Value};
pub use parser::parse;
pub use validator::validate;

/// Parse and validate in one shot. Most hosts want this:
/// eval comes later with a concrete context.
pub fn compile(src: &str) -> Result<Program> {
    let program = parse(src)?;
    validate(&program)?;
    Ok(program)
}
