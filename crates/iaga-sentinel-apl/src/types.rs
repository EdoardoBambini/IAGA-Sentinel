//! OSS 1.2, Hindley-Milner type checker for APL (ADR 0014).
//!
//! Algorithm W over the existing [`crate::ast::Expr`] enum with a
//! substitution-based unification. Path references (`action.url.host`)
//! receive fresh type variables, the host context is dynamically
//! typed and the inferer cannot know the shape ahead of time. Builtin
//! `Call(name, args)` lookups consult a small table; unknown builtins
//! degrade to fresh-var return type.
//!
//! Used as an additive correctness layer above the tree-walk
//! evaluator. The evaluator continues to be the canonical executor;
//! the type checker is opt-in via [`crate::compile_with_types`].
//!
//! Out of scope (Enterprise differentiation per ADR 0010):
//! - Bidirectional type-directed elaboration.
//! - Row polymorphism for path access.
//! - Type-error pretty-printing with span-level highlighting (the
//!   1.2 MVP returns structured errors without source spans).

use std::collections::BTreeMap;
use std::fmt;

use crate::ast::{BinOp, Expr, Lit, Program, UnOp};

/// HM monotypes. `Var` is a type variable created during inference;
/// `Unknown` is the catch-all for path resolutions whose shape can't
/// be inferred ahead of time (the context is dynamically typed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ty {
    Bool,
    Int,
    Str,
    /// Catch-all for path lookups (`action.url.host`), the runtime
    /// context is JSON, so the static shape is genuinely unknown.
    /// Treated as compatible with any concrete type during
    /// unification.
    Unknown,
    List(Box<Ty>),
    Var(u32),
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ty::Bool => write!(f, "bool"),
            Ty::Int => write!(f, "int"),
            Ty::Str => write!(f, "str"),
            Ty::Unknown => write!(f, "?"),
            Ty::List(t) => write!(f, "[{t}]"),
            Ty::Var(n) => write!(f, "α{n}"),
        }
    }
}

/// Substitution-backed type environment. Used internally by [`infer`]
/// and exposed to the caller so policy compile pipelines can inspect
/// the inferred types of each policy's `when` expression.
#[derive(Debug, Default, Clone)]
pub struct TypeEnv {
    next_var: u32,
    /// `Var(n) → Ty` mapping, walked transitively by [`apply`].
    subst: BTreeMap<u32, Ty>,
    /// Inferred type of each policy `when` expression (always `Bool`
    /// after unification succeeds).
    when_types: Vec<Ty>,
}

impl TypeEnv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fresh type variable.
    pub fn fresh(&mut self) -> Ty {
        let v = self.next_var;
        self.next_var += 1;
        Ty::Var(v)
    }

    /// Resolve a type fully through the substitution. Used for output
    /// and final reporting.
    pub fn apply(&self, ty: &Ty) -> Ty {
        match ty {
            Ty::Var(v) => match self.subst.get(v) {
                Some(t) => {
                    let resolved = self.apply(t);
                    // Sanity: if substitution circles back, return Unknown.
                    if matches!(resolved, Ty::Var(x) if x == *v) {
                        Ty::Unknown
                    } else {
                        resolved
                    }
                }
                None => Ty::Var(*v),
            },
            Ty::List(t) => Ty::List(Box::new(self.apply(t))),
            other => other.clone(),
        }
    }

    /// Unify two types. Both directions are tried; `Unknown` is
    /// compatible with everything (path lookups are dynamically
    /// typed).
    pub fn unify(&mut self, a: &Ty, b: &Ty) -> Result<(), TypeError> {
        let a = self.apply(a);
        let b = self.apply(b);
        match (a, b) {
            (Ty::Unknown, _) | (_, Ty::Unknown) => Ok(()),
            (Ty::Bool, Ty::Bool) | (Ty::Int, Ty::Int) | (Ty::Str, Ty::Str) => Ok(()),
            (Ty::List(x), Ty::List(y)) => self.unify(&x, &y),
            (Ty::Var(v), other) | (other, Ty::Var(v)) => {
                if matches!(&other, Ty::Var(w) if *w == v) {
                    return Ok(());
                }
                if occurs_in(v, &other, self) {
                    return Err(TypeError::OccursCheck { var: v });
                }
                self.subst.insert(v, other);
                Ok(())
            }
            (lhs, rhs) => Err(TypeError::Mismatch {
                expected: lhs.to_string(),
                actual: rhs.to_string(),
            }),
        }
    }

    /// Per-policy `when` types, in declaration order. Always `Bool`
    /// after a successful [`infer`] call.
    pub fn when_types(&self) -> &[Ty] {
        &self.when_types
    }
}

fn occurs_in(v: u32, ty: &Ty, env: &TypeEnv) -> bool {
    match env.apply(ty) {
        Ty::Var(w) => w == v,
        Ty::List(inner) => occurs_in(v, &inner, env),
        _ => false,
    }
}

/// Structured type error. Keeps shape-only signatures, span-level
/// pretty printing is left to the host (or to the future Enterprise
/// editor integration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeError {
    Mismatch {
        expected: String,
        actual: String,
    },
    OccursCheck {
        var: u32,
    },
    BuiltinArity {
        name: String,
        expected: usize,
        got: usize,
    },
    /// The `when` clause of a policy does not have type `bool`.
    NonBoolWhen {
        policy: String,
        actual: String,
    },
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch { expected, actual } => {
                write!(f, "type mismatch: expected {expected}, got {actual}")
            }
            Self::OccursCheck { var } => {
                write!(f, "occurs check failed for α{var} (recursive type)")
            }
            Self::BuiltinArity {
                name,
                expected,
                got,
            } => write!(f, "builtin `{name}` expects {expected} args, got {got}"),
            Self::NonBoolWhen { policy, actual } => {
                write!(
                    f,
                    "policy `{policy}` `when` clause must be bool, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for TypeError {}

/// Top-level entrypoint: infer types for every policy `when` clause
/// in `program`. Returns a [`TypeEnv`] with the substitution and the
/// per-policy inferred types.
pub fn infer(program: &Program) -> Result<TypeEnv, TypeError> {
    let mut env = TypeEnv::new();
    for p in &program.policies {
        let ty = infer_expr(&mut env, &p.when)?;
        env.unify(&ty, &Ty::Bool).map_err(|e| match e {
            TypeError::Mismatch { actual, .. } => TypeError::NonBoolWhen {
                policy: p.name.clone(),
                actual,
            },
            other => other,
        })?;
        let resolved = env.apply(&ty);
        env.when_types.push(resolved);
    }
    Ok(env)
}

/// Builtin signature: `(return_type, arg_types)`. `Unknown` in either
/// position means "accepts anything" (used for `len`, `secret_ref`).
fn builtin_signature(name: &str) -> Option<(Ty, Vec<Ty>)> {
    match name {
        "contains" => Some((Ty::Bool, vec![Ty::Str, Ty::Str])),
        "starts_with" => Some((Ty::Bool, vec![Ty::Str, Ty::Str])),
        "ends_with" => Some((Ty::Bool, vec![Ty::Str, Ty::Str])),
        "len" => Some((Ty::Int, vec![Ty::Unknown])),
        "lower" => Some((Ty::Str, vec![Ty::Str])),
        "upper" => Some((Ty::Str, vec![Ty::Str])),
        // `secret_ref` accepts anything, returns bool, the runtime
        // detects sensitive material structurally.
        "secret_ref" => Some((Ty::Bool, vec![Ty::Unknown])),
        _ => None,
    }
}

fn infer_expr(env: &mut TypeEnv, expr: &Expr) -> Result<Ty, TypeError> {
    match expr {
        Expr::Lit(Lit::Bool(_)) => Ok(Ty::Bool),
        Expr::Lit(Lit::Int(_)) => Ok(Ty::Int),
        Expr::Lit(Lit::Str(_)) => Ok(Ty::Str),
        // Dotted path lookups walk JSON, dynamically typed.
        Expr::Path(_) => Ok(Ty::Unknown),
        Expr::Unary(UnOp::Not, inner) => {
            let t = infer_expr(env, inner)?;
            env.unify(&t, &Ty::Bool)?;
            Ok(Ty::Bool)
        }
        Expr::Binary(op, l, r) => {
            let lt = infer_expr(env, l)?;
            let rt = infer_expr(env, r)?;
            match op {
                BinOp::Eq | BinOp::Neq => {
                    // Both sides must have the same monotype.
                    env.unify(&lt, &rt)?;
                    Ok(Ty::Bool)
                }
                BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
                    // Numeric comparison.
                    env.unify(&lt, &Ty::Int)?;
                    env.unify(&rt, &Ty::Int)?;
                    Ok(Ty::Bool)
                }
                BinOp::And | BinOp::Or => {
                    env.unify(&lt, &Ty::Bool)?;
                    env.unify(&rt, &Ty::Bool)?;
                    Ok(Ty::Bool)
                }
            }
        }
        Expr::Membership {
            not: _,
            needle,
            haystack,
        } => {
            let _ = infer_expr(env, needle)?;
            let _ = infer_expr(env, haystack)?;
            // No constraint on element/container type for MVP, both
            // sides are commonly dynamic (path lookups).
            Ok(Ty::Bool)
        }
        Expr::Call(name, args) => {
            if let Some((ret, sig)) = builtin_signature(name) {
                if sig.len() != args.len() {
                    return Err(TypeError::BuiltinArity {
                        name: name.clone(),
                        expected: sig.len(),
                        got: args.len(),
                    });
                }
                for (i, arg) in args.iter().enumerate() {
                    let at = infer_expr(env, arg)?;
                    env.unify(&at, &sig[i])?;
                }
                Ok(ret)
            } else {
                // Unknown builtin, fresh var return, no constraint
                // on args. The validator already catches truly
                // unknown calls at parse-validate time.
                for arg in args {
                    let _ = infer_expr(env, arg)?;
                }
                Ok(env.fresh())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Action, Policy, Verdict};

    fn prog(when: Expr) -> Program {
        Program {
            policies: vec![Policy {
                name: "p".into(),
                when,
                action: Action {
                    verdict: Verdict::Block,
                    reason: None,
                    evidence: None,
                },
            }],
        }
    }

    #[test]
    fn lit_bool_when_clause() {
        let env = infer(&prog(Expr::Lit(Lit::Bool(true)))).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }

    #[test]
    fn lit_int_when_clause_rejected() {
        let err = infer(&prog(Expr::Lit(Lit::Int(42)))).expect_err("must reject");
        assert!(matches!(err, TypeError::NonBoolWhen { .. }));
    }

    #[test]
    fn eq_int_int_is_bool() {
        let when = Expr::Binary(
            BinOp::Eq,
            Box::new(Expr::Lit(Lit::Int(1))),
            Box::new(Expr::Lit(Lit::Int(2))),
        );
        let env = infer(&prog(when)).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }

    #[test]
    fn eq_int_str_rejected() {
        let when = Expr::Binary(
            BinOp::Eq,
            Box::new(Expr::Lit(Lit::Int(1))),
            Box::new(Expr::Lit(Lit::Str("x".into()))),
        );
        let err = infer(&prog(when)).expect_err("must reject");
        assert!(matches!(err, TypeError::Mismatch { .. }));
    }

    #[test]
    fn lt_requires_int() {
        let when = Expr::Binary(
            BinOp::Lt,
            Box::new(Expr::Lit(Lit::Str("a".into()))),
            Box::new(Expr::Lit(Lit::Int(1))),
        );
        let err = infer(&prog(when)).expect_err("must reject string < int");
        assert!(matches!(err, TypeError::Mismatch { .. }));
    }

    #[test]
    fn and_requires_bool() {
        let when = Expr::Binary(
            BinOp::And,
            Box::new(Expr::Lit(Lit::Bool(true))),
            Box::new(Expr::Lit(Lit::Bool(false))),
        );
        let env = infer(&prog(when)).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }

    #[test]
    fn not_requires_bool_inner() {
        let when = Expr::Unary(UnOp::Not, Box::new(Expr::Lit(Lit::Int(1))));
        let err = infer(&prog(when)).expect_err("must reject not int");
        assert!(matches!(err, TypeError::Mismatch { .. }));
    }

    #[test]
    fn path_is_unknown_and_compatible_with_anything() {
        let when = Expr::Binary(
            BinOp::Eq,
            Box::new(Expr::Path(vec!["action".into(), "url".into()])),
            Box::new(Expr::Lit(Lit::Str("https://example.com".into()))),
        );
        let env = infer(&prog(when)).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }

    #[test]
    fn builtin_contains_ok() {
        let when = Expr::Call(
            "contains".into(),
            vec![
                Expr::Lit(Lit::Str("hello".into())),
                Expr::Lit(Lit::Str("ell".into())),
            ],
        );
        let env = infer(&prog(when)).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }

    #[test]
    fn builtin_contains_wrong_arity() {
        let when = Expr::Call("contains".into(), vec![Expr::Lit(Lit::Str("x".into()))]);
        let err = infer(&prog(when)).expect_err("must reject arity");
        assert!(matches!(err, TypeError::BuiltinArity { .. }));
    }

    #[test]
    fn builtin_len_returns_int_not_bool() {
        // len(x) is int, not bool, should fail as when-clause.
        let when = Expr::Call("len".into(), vec![Expr::Lit(Lit::Str("x".into()))]);
        let err = infer(&prog(when)).expect_err("must reject int when");
        assert!(matches!(err, TypeError::NonBoolWhen { .. }));
    }

    #[test]
    fn builtin_len_in_comparison_ok() {
        let when = Expr::Binary(
            BinOp::Gt,
            Box::new(Expr::Call(
                "len".into(),
                vec![Expr::Lit(Lit::Str("hello".into()))],
            )),
            Box::new(Expr::Lit(Lit::Int(3))),
        );
        let env = infer(&prog(when)).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }

    #[test]
    fn membership_returns_bool() {
        let when = Expr::Membership {
            not: false,
            needle: Box::new(Expr::Lit(Lit::Str("admin".into()))),
            haystack: Box::new(Expr::Path(vec!["workspace".into(), "blocked".into()])),
        };
        let env = infer(&prog(when)).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }

    #[test]
    fn unknown_builtin_returns_fresh_var() {
        let when = Expr::Binary(
            BinOp::Eq,
            Box::new(Expr::Call("custom_fn".into(), vec![])),
            Box::new(Expr::Lit(Lit::Bool(true))),
        );
        // Unknown builtin returns a fresh var; the var unifies with
        // bool via equality with the literal, so the when clause
        // resolves to bool.
        let env = infer(&prog(when)).expect("infer ok");
        assert_eq!(env.when_types(), &[Ty::Bool]);
    }
}
