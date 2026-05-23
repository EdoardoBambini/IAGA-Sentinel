//! Structural validator for APL programs.
//!
//! This is **not** a full type checker. For M3 the evaluator is
//! dynamically typed against a JSON-ish `Value` — runtime errors from
//! type mismatches are normal and produce `AplError::Eval`. What this
//! validator enforces are *structural* invariants that catch obvious
//! mistakes before eval time:
//!
//! - policy names are non-empty and unique,
//! - every policy has a non-empty `when` expression,
//! - known builtin calls have the right arity,
//! - identifier paths have non-empty head segments.
//!
//! A full Hindley–Milner style type checker is an M3.1 follow-up and
//! will share the AST.

use std::collections::HashSet;

use crate::ast::*;
use crate::errors::{AplError, Result};

const BUILTIN_ARITIES: &[(&str, usize)] = &[
    ("contains", 2),
    ("starts_with", 2),
    ("ends_with", 2),
    ("len", 1),
    ("lower", 1),
    ("upper", 1),
    ("secret_ref", 1),
];

pub fn validate(program: &Program) -> Result<()> {
    let mut seen = HashSet::new();
    for p in &program.policies {
        if p.name.trim().is_empty() {
            return Err(AplError::Type(
                "policy name must be a non-empty string".into(),
            ));
        }
        if !seen.insert(p.name.clone()) {
            return Err(AplError::Type(format!("duplicate policy name: {}", p.name)));
        }
        validate_expr(&p.when)?;
        if let Some(ev) = &p.action.evidence {
            validate_expr(ev)?;
        }
    }
    Ok(())
}

fn validate_expr(e: &Expr) -> Result<()> {
    match e {
        Expr::Lit(_) => Ok(()),
        Expr::Path(segs) => {
            if segs.is_empty() {
                return Err(AplError::Type("empty identifier path".into()));
            }
            Ok(())
        }
        Expr::Call(name, args) => {
            if let Some((_, arity)) = BUILTIN_ARITIES.iter().find(|(n, _)| n == name) {
                if args.len() != *arity {
                    return Err(AplError::Type(format!(
                        "builtin `{}` takes {} args, got {}",
                        name,
                        arity,
                        args.len()
                    )));
                }
            }
            // unknown-name calls pass through — user extensions can
            // register dynamic builtins at eval time.
            for a in args {
                validate_expr(a)?;
            }
            Ok(())
        }
        Expr::Binary(_, l, r) => {
            validate_expr(l)?;
            validate_expr(r)
        }
        Expr::Unary(_, inner) => validate_expr(inner),
        Expr::Membership {
            needle, haystack, ..
        } => {
            validate_expr(needle)?;
            validate_expr(haystack)
        }
    }
}
