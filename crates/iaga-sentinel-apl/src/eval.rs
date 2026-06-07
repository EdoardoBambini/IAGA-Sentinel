//! Deterministic tree-walk evaluator.
//!
//! The evaluator is pure: it reads from a `Context` (a `serde_json::Value`
//! tree holding `action`, `workspace`, `payload`, `ml`, etc.), walks the
//! AST, and returns a `Value`. It does no I/O, no clock reads, no RNG.
//! Given the same AST and same context it always yields the same result,
//! which is exactly the property we want for receipt replay.
//!
//! An instruction budget (`EvalBudget`) caps the number of AST nodes
//! visited, so pathological programs cannot wedge the host. 1.0 defaults
//! to 10_000 steps per policy firing, generous for any realistic rule.

use std::fmt;

use serde_json::Value as Json;

use crate::ast::*;
use crate::errors::{AplError, Result};

/// Runtime-tagged value produced by evaluating an expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
}

impl Value {
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Int(n) => *n != 0,
            Value::Float(f) => *f != 0.0 && !f.is_nan(),
            Value::Str(s) => !s.is_empty(),
            Value::List(xs) => !xs.is_empty(),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Int(n) => write!(f, "{}", n),
            Value::Float(x) => write!(f, "{}", x),
            Value::Str(s) => write!(f, "\"{}\"", s),
            Value::List(xs) => {
                write!(f, "[")?;
                for (i, v) in xs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Evaluation context, a JSON document the policy reads through paths
/// like `action.url.host` and `workspace.allowlist`.
#[derive(Debug, Clone)]
pub struct Context {
    pub root: Json,
}

impl Context {
    pub fn new(root: Json) -> Self {
        Self { root }
    }

    pub fn from_value(v: serde_json::Value) -> Self {
        Self { root: v }
    }
}

/// Instruction budget. Implementations decrement on every AST node visit.
#[derive(Debug)]
pub struct EvalBudget {
    pub remaining: u64,
    pub total: u64,
}

impl EvalBudget {
    pub fn new(max_steps: u64) -> Self {
        Self {
            remaining: max_steps,
            total: 0,
        }
    }

    fn tick(&mut self) -> Result<()> {
        self.total += 1;
        if self.remaining == 0 {
            return Err(AplError::BudgetExhausted { steps: self.total });
        }
        self.remaining -= 1;
        Ok(())
    }
}

impl Default for EvalBudget {
    fn default() -> Self {
        Self::new(10_000)
    }
}

/// Result of firing a single policy in its `when` + `then` entirety.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyFired {
    pub policy_name: String,
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub evidence: Option<Value>,
}

/// Evaluate a program against a context. Returns the *first* policy that
/// fires (when-expr evaluates truthy), or `None` if none fire. Evaluation
/// in declaration order is deliberate: policy authors order by severity.
pub fn evaluate_program(
    program: &Program,
    ctx: &Context,
    budget: &mut EvalBudget,
) -> Result<Option<PolicyFired>> {
    for p in &program.policies {
        let fired = eval_expr(&p.when, ctx, budget)?;
        if fired.is_truthy() {
            let evidence = match &p.action.evidence {
                Some(e) => Some(eval_expr(e, ctx, budget)?),
                None => None,
            };
            return Ok(Some(PolicyFired {
                policy_name: p.name.clone(),
                verdict: p.action.verdict.clone(),
                reason: p.action.reason.clone(),
                evidence,
            }));
        }
    }
    Ok(None)
}

/// Evaluate a single expression. Exposed for hosts that want to evaluate
/// expressions independently (e.g. for APL-as-filter use cases).
pub fn eval_expr(e: &Expr, ctx: &Context, budget: &mut EvalBudget) -> Result<Value> {
    budget.tick()?;
    match e {
        Expr::Lit(Lit::Str(s)) => Ok(Value::Str(s.clone())),
        Expr::Lit(Lit::Int(n)) => Ok(Value::Int(*n)),
        Expr::Lit(Lit::Bool(b)) => Ok(Value::Bool(*b)),
        Expr::Path(segs) => Ok(walk_path(&ctx.root, segs)),
        Expr::Unary(UnOp::Not, inner) => {
            let v = eval_expr(inner, ctx, budget)?;
            Ok(Value::Bool(!v.is_truthy()))
        }
        Expr::Binary(op, l, r) => eval_binop(*op, l, r, ctx, budget),
        Expr::Membership {
            not,
            needle,
            haystack,
        } => {
            let n = eval_expr(needle, ctx, budget)?;
            let h = eval_expr(haystack, ctx, budget)?;
            let contains = match h {
                Value::List(xs) => xs.contains(&n),
                Value::Str(s) => match n {
                    Value::Str(sub) => s.contains(&sub),
                    _ => {
                        return Err(AplError::Eval(
                            "`in` against string requires string needle".into(),
                        ))
                    }
                },
                _ => return Err(AplError::Eval("`in` rhs must be list or string".into())),
            };
            Ok(Value::Bool(if *not { !contains } else { contains }))
        }
        Expr::Call(name, args) => eval_builtin(name, args, ctx, budget),
    }
}

fn eval_binop(
    op: BinOp,
    l: &Expr,
    r: &Expr,
    ctx: &Context,
    budget: &mut EvalBudget,
) -> Result<Value> {
    // short-circuit logic
    if matches!(op, BinOp::And) {
        let lv = eval_expr(l, ctx, budget)?;
        if !lv.is_truthy() {
            return Ok(Value::Bool(false));
        }
        let rv = eval_expr(r, ctx, budget)?;
        return Ok(Value::Bool(rv.is_truthy()));
    }
    if matches!(op, BinOp::Or) {
        let lv = eval_expr(l, ctx, budget)?;
        if lv.is_truthy() {
            return Ok(Value::Bool(true));
        }
        let rv = eval_expr(r, ctx, budget)?;
        return Ok(Value::Bool(rv.is_truthy()));
    }
    let lv = eval_expr(l, ctx, budget)?;
    let rv = eval_expr(r, ctx, budget)?;
    match op {
        BinOp::Eq => Ok(Value::Bool(values_eq(&lv, &rv))),
        BinOp::Neq => Ok(Value::Bool(!values_eq(&lv, &rv))),
        BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => cmp_values(op, &lv, &rv),
        BinOp::And | BinOp::Or => unreachable!(),
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Float(x), Value::Float(y)) => x == y,
        (Value::Int(x), Value::Float(y)) => (*x as f64) == *y,
        (Value::Float(x), Value::Int(y)) => *x == (*y as f64),
        _ => a == b,
    }
}

fn cmp_values(op: BinOp, a: &Value, b: &Value) -> Result<Value> {
    let ord = match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.partial_cmp(y),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y),
        (Value::Int(x), Value::Float(y)) => (*x as f64).partial_cmp(y),
        (Value::Float(x), Value::Int(y)) => x.partial_cmp(&(*y as f64)),
        (Value::Str(x), Value::Str(y)) => x.partial_cmp(y),
        _ => return Err(AplError::Eval(format!("cannot compare {} and {}", a, b))),
    };
    let ord = ord.ok_or_else(|| AplError::Eval("NaN comparison".into()))?;
    Ok(Value::Bool(match op {
        BinOp::Lt => ord == std::cmp::Ordering::Less,
        BinOp::Gt => ord == std::cmp::Ordering::Greater,
        BinOp::Le => ord != std::cmp::Ordering::Greater,
        BinOp::Ge => ord != std::cmp::Ordering::Less,
        _ => unreachable!(),
    }))
}

fn walk_path(root: &Json, segs: &[String]) -> Value {
    let mut cur = root;
    for s in segs {
        match cur {
            Json::Object(m) => match m.get(s) {
                Some(next) => cur = next,
                None => return Value::Null,
            },
            _ => return Value::Null,
        }
    }
    json_to_value(cur)
}

fn json_to_value(v: &Json) -> Value {
    match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        Json::String(s) => Value::Str(s.clone()),
        Json::Array(xs) => Value::List(xs.iter().map(json_to_value).collect()),
        Json::Object(_) => Value::Null,
    }
}

fn eval_builtin(
    name: &str,
    args: &[Expr],
    ctx: &Context,
    budget: &mut EvalBudget,
) -> Result<Value> {
    let evaluated: Result<Vec<Value>> = args.iter().map(|a| eval_expr(a, ctx, budget)).collect();
    let evaluated = evaluated?;
    match (name, evaluated.as_slice()) {
        ("contains", [Value::Str(s), Value::Str(sub)]) => Ok(Value::Bool(s.contains(sub))),
        ("contains", [Value::List(xs), v]) => Ok(Value::Bool(xs.contains(v))),
        ("starts_with", [Value::Str(s), Value::Str(pre)]) => Ok(Value::Bool(s.starts_with(pre))),
        ("ends_with", [Value::Str(s), Value::Str(suf)]) => Ok(Value::Bool(s.ends_with(suf))),
        ("len", [Value::Str(s)]) => Ok(Value::Int(s.chars().count() as i64)),
        ("len", [Value::List(xs)]) => Ok(Value::Int(xs.len() as i64)),
        ("lower", [Value::Str(s)]) => Ok(Value::Str(s.to_lowercase())),
        ("upper", [Value::Str(s)]) => Ok(Value::Str(s.to_uppercase())),
        ("secret_ref", [_]) => {
            // MVP placeholder: secret detection lives in the firewall
            // layer of iaga-sentinel-core today. When M3.5 lands we wire this to
            // the real taint tracker. Until then, always false.
            Ok(Value::Bool(false))
        }
        (other, args) => Err(AplError::Eval(format!(
            "unknown or mistyped call `{}` with {} arg(s)",
            other,
            args.len()
        ))),
    }
}
