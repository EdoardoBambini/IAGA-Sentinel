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
use crate::errors::{DictumError, Result};

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
            return Err(DictumError::BudgetExhausted { steps: self.total });
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

/// Rich trace of evaluating a program for a *host overlay* that can only
/// tighten a baseline verdict. Carries the first fired policy (if any), how
/// many policies were evaluated, the names that fired, and whether an eval
/// error forced a fail-closed decision.
#[derive(Debug, Clone)]
pub struct EvalTrace {
    pub fired: Option<PolicyFired>,
    pub policies_evaluated: u32,
    pub policies_fired: Vec<String>,
    pub eval_errored: bool,
}

/// Like [`evaluate_program`], but **never fails open** and never lets one
/// policy's `when` starve another's budget — the properties an enforcing
/// overlay needs (PIP-DICTUM-FAILOPEN, DET-DICTUM-2).
///
/// - Each policy's `when` gets its **own** fresh [`EvalBudget`]; the fired
///   policy's `evidence` gets a **separate** budget.
/// - An `evidence` eval error keeps the verdict and drops the evidence —
///   evidence is observability, not a gate, so it must never downgrade.
/// - A `when` eval error on a Block/Review policy is a **fail-closed fire**
///   with that policy's verdict (an attacker must not be able to craft a
///   payload that errors the guard and silently disables it). A `when` error
///   on an Allow policy cannot tighten, so it is skipped (we keep scanning for
///   a stricter later policy); `eval_errored` is still set so the host can
///   surface a `dictum-eval-error` reason.
pub fn evaluate_program_traced(program: &Program, ctx: &Context) -> EvalTrace {
    let mut policies_evaluated = 0u32;
    let mut eval_errored = false;
    for p in &program.policies {
        policies_evaluated += 1;
        let mut when_budget = EvalBudget::default();
        match eval_expr(&p.when, ctx, &mut when_budget) {
            Ok(v) if v.is_truthy() => {
                let mut evidence_budget = EvalBudget::default();
                let evidence = match &p.action.evidence {
                    // Evidence error -> None, never a verdict downgrade.
                    Some(e) => eval_expr(e, ctx, &mut evidence_budget).ok(),
                    None => None,
                };
                return EvalTrace {
                    fired: Some(PolicyFired {
                        policy_name: p.name.clone(),
                        verdict: p.action.verdict.clone(),
                        reason: p.action.reason.clone(),
                        evidence,
                    }),
                    policies_evaluated,
                    policies_fired: vec![p.name.clone()],
                    eval_errored,
                };
            }
            Ok(_) => continue,
            Err(_e) => {
                eval_errored = true;
                match p.action.verdict {
                    // An erroring Allow can't tighten; keep scanning so a later
                    // Block/Review still applies.
                    Verdict::Allow => continue,
                    // Fail closed: apply the policy's own (stricter) verdict.
                    Verdict::Review | Verdict::Block => {
                        return EvalTrace {
                            fired: Some(PolicyFired {
                                policy_name: p.name.clone(),
                                verdict: p.action.verdict.clone(),
                                reason: Some("dictum-eval-error".to_string()),
                                evidence: None,
                            }),
                            policies_evaluated,
                            policies_fired: vec![p.name.clone()],
                            eval_errored,
                        };
                    }
                }
            }
        }
    }
    EvalTrace {
        fired: None,
        policies_evaluated,
        policies_fired: Vec::new(),
        eval_errored,
    }
}

/// Evaluate a single expression. Exposed for hosts that want to evaluate
/// expressions independently (e.g. for Dictum-as-filter use cases).
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
                        return Err(DictumError::Eval(
                            "`in` against string requires string needle".into(),
                        ))
                    }
                },
                _ => return Err(DictumError::Eval("`in` rhs must be list or string".into())),
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
        _ => return Err(DictumError::Eval(format!("cannot compare {} and {}", a, b))),
    };
    let ord = ord.ok_or_else(|| DictumError::Eval("NaN comparison".into()))?;
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
    // `secret_ref` is special-cased *before* the generic argument evaluation
    // below. It needs the raw JSON subtree of its argument, not the flattened
    // `Value`: `json_to_value` collapses objects to `Null`, so by the time a
    // payload object reached the generic path there would be nothing left to
    // scan. We resolve the sub-`Json` directly and run the credential detector
    // over its serialized form. Still pure and deterministic.
    if name == "secret_ref" {
        if args.len() != 1 {
            return Err(DictumError::Eval(format!(
                "secret_ref takes 1 arg, got {}",
                args.len()
            )));
        }
        let raw = resolve_json(&args[0], ctx, budget)?;
        let haystack = match &raw {
            Json::String(s) => s.clone(),
            Json::Null => String::new(),
            other => serde_json::to_string(other).unwrap_or_default(),
        };
        return Ok(Value::Bool(crate::secrets::contains_secret(&haystack)));
    }

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
        // Extract the lowercased host from a URL so a policy can write a real
        // per-host egress allowlist: `url_host(action.payload.destination) not
        // in workspace.allowlist`.
        ("url_host", [Value::Str(s)]) => Ok(Value::Str(extract_host(s))),
        (other, args) => Err(DictumError::Eval(format!(
            "unknown or mistyped call `{}` with {} arg(s)",
            other,
            args.len()
        ))),
    }
}

/// Resolve an expression to its raw JSON subtree. For a path, walk the context
/// and return the sub-`Json` verbatim (objects/arrays preserved). For any other
/// expression, evaluate it and lift the resulting leaf `Value` back to `Json`.
/// Used by `secret_ref`, which must see structure the flattened `Value` loses.
fn resolve_json(e: &Expr, ctx: &Context, budget: &mut EvalBudget) -> Result<Json> {
    match e {
        Expr::Path(segs) => {
            budget.tick()?;
            Ok(walk_path_json(&ctx.root, segs))
        }
        other => Ok(value_to_json(&eval_expr(other, ctx, budget)?)),
    }
}

/// Like `walk_path`, but returns the raw sub-`Json` (keeping objects/arrays)
/// instead of flattening through `json_to_value`.
fn walk_path_json(root: &Json, segs: &[String]) -> Json {
    let mut cur = root;
    for s in segs {
        match cur {
            Json::Object(m) => match m.get(s) {
                Some(next) => cur = next,
                None => return Json::Null,
            },
            _ => return Json::Null,
        }
    }
    cur.clone()
}

/// Inverse of `json_to_value` for the leaf kinds the evaluator produces. Only
/// used to feed non-path `secret_ref` arguments (e.g. a string literal) back
/// into a scannable JSON value, so the lossy object case never arises here.
fn value_to_json(v: &Value) -> Json {
    match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(n) => Json::Number((*n).into()),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        Value::Str(s) => Json::String(s.clone()),
        Value::List(xs) => Json::Array(xs.iter().map(value_to_json).collect()),
    }
}

/// Extract the lowercased host from a URL string. Hand-rolled and fully
/// deterministic (no external URL crate): strips the scheme, userinfo, port,
/// and any path/query/fragment, and preserves a bracketed IPv6 literal.
/// Unparseable input yields an empty string, which matches no allowlist entry,
/// so a `not in` rule blocks it (fail-safe).
fn extract_host(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 literal: keep everything through the closing bracket.
        match rest.split_once(']') {
            Some((h6, _)) => format!("[{h6}]"),
            None => hostport.to_string(),
        }
    } else {
        hostport
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostport)
            .to_string()
    };
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile;

    fn fired(src: &str, ctx_json: serde_json::Value) -> Option<PolicyFired> {
        let program = compile(src).expect("compile");
        let ctx = Context::from_value(ctx_json);
        let mut budget = EvalBudget::default();
        evaluate_program(&program, &ctx, &mut budget).expect("eval")
    }

    // ── secret_ref ──────────────────────────────────────────────────────────

    #[test]
    fn secret_ref_fires_on_aws_key_in_nested_object() {
        let src = r#"policy "p" { when secret_ref(action.payload) then block }"#;
        let ctx = serde_json::json!({
            "action": { "payload": { "note": "see AKIAIOSFODNN7EXAMPLE here" } }
        });
        let f = fired(src, ctx).expect("must fire on a secret");
        assert_eq!(f.verdict, Verdict::Block);
    }

    #[test]
    fn secret_ref_fires_on_pem_block_string() {
        let src = r#"policy "p" { when secret_ref(action.payload.body) then block }"#;
        let ctx = serde_json::json!({
            "action": { "payload": { "body": "-----BEGIN OPENSSH PRIVATE KEY-----" } }
        });
        assert_eq!(fired(src, ctx).unwrap().verdict, Verdict::Block);
    }

    #[test]
    fn secret_ref_does_not_fire_on_benign_object() {
        let src = r#"policy "p" { when secret_ref(action.payload) then block }
                     policy "ok" { when true then allow }"#;
        let ctx = serde_json::json!({
            "action": { "payload": { "city": "Berlin", "count": 42 } }
        });
        // First policy must miss; the catch-all allow fires instead.
        assert_eq!(fired(src, ctx).unwrap().verdict, Verdict::Allow);
    }

    #[test]
    fn secret_ref_false_on_missing_path() {
        let src = r#"policy "p" { when secret_ref(action.nope) then block }
                     policy "ok" { when true then allow }"#;
        let ctx = serde_json::json!({ "action": { "payload": "x" } });
        assert_eq!(fired(src, ctx).unwrap().verdict, Verdict::Allow);
    }

    // ── url_host ────────────────────────────────────────────────────────────

    #[test]
    fn url_host_extraction_cases() {
        assert_eq!(
            extract_host("https://evil.example.com/exfil?x=1#f"),
            "evil.example.com"
        );
        assert_eq!(extract_host("http://user:pass@EVIL.COM:8443/p"), "evil.com");
        assert_eq!(extract_host("evil.example.com/path"), "evil.example.com");
        assert_eq!(extract_host("http://[::1]:8080/"), "[::1]");
        assert_eq!(extract_host("api.github.com"), "api.github.com");
        assert_eq!(extract_host(""), "");
    }

    #[test]
    fn url_host_offallowlist_blocks_and_onallowlist_misses() {
        let src = r#"policy "p" {
                       when url_host(action.payload.destination) not in workspace.allowlist
                       then block
                     }
                     policy "ok" { when true then allow }"#;
        let off = serde_json::json!({
            "action": { "payload": { "destination": "https://evil.example.com/x" } },
            "workspace": { "allowlist": ["api.github.com", "internal.example.com"] }
        });
        assert_eq!(fired(src, off).unwrap().verdict, Verdict::Block);

        let on = serde_json::json!({
            "action": { "payload": { "destination": "https://api.github.com/repos" } },
            "workspace": { "allowlist": ["api.github.com", "internal.example.com"] }
        });
        assert_eq!(fired(src, on).unwrap().verdict, Verdict::Allow);
    }

    #[test]
    fn combined_secret_and_offhost_policy_fires() {
        // Mirrors the shipped no_pii_egress.dictum example.
        let src = r#"policy "no_secrets_to_public_http" {
                       when url_host(action.payload.destination) not in workspace.allowlist
                        and secret_ref(action.payload)
                       then block, reason="secret egress"
                     }
                     policy "default_allow" { when true then allow }"#;
        let ctx = serde_json::json!({
            "action": { "payload": {
                "destination": "https://evil.example.com/collect",
                "body": "exfiltrating AKIAIOSFODNN7EXAMPLE off-box"
            }},
            "workspace": { "allowlist": ["api.example.com"] }
        });
        let f = fired(src, ctx).expect("must fire");
        assert_eq!(f.verdict, Verdict::Block);
        assert_eq!(f.policy_name, "no_secrets_to_public_http");
    }

    // ── evaluate_program_traced: fail-closed + budget isolation ───────────────

    fn traced(src: &str, ctx_json: serde_json::Value) -> EvalTrace {
        let program = compile(src).expect("compile");
        let ctx = Context::from_value(ctx_json);
        evaluate_program_traced(&program, &ctx)
    }

    #[test]
    fn when_error_on_block_policy_fails_closed() {
        // `"x" in <int>` is a runtime type error: the `when` of a Block policy
        // must FAIL CLOSED (fire Block), not be silently disabled.
        let t = traced(
            r#"policy "p" { when "x" in action.payload.count then block }"#,
            serde_json::json!({ "action": { "payload": { "count": 5 } } }),
        );
        let f = t.fired.expect("must fail closed");
        assert_eq!(f.verdict, Verdict::Block);
        assert_eq!(f.reason.as_deref(), Some("dictum-eval-error"));
        assert!(t.eval_errored);
        assert_eq!(t.policies_fired, vec!["p".to_string()]);
    }

    #[test]
    fn when_error_on_allow_policy_keeps_scanning() {
        // An erroring Allow policy cannot tighten, so evaluation continues and a
        // later Block still applies (no fail-open on the later guard).
        let t = traced(
            r#"policy "skip" { when "x" in action.payload.count then allow }
               policy "blk"  { when true then block }"#,
            serde_json::json!({ "action": { "payload": { "count": 5 } } }),
        );
        let f = t.fired.expect("later block fires");
        assert_eq!(f.verdict, Verdict::Block);
        assert_eq!(f.policy_name, "blk");
        assert!(t.eval_errored, "the allow policy's error is still recorded");
        assert_eq!(t.policies_evaluated, 2);
    }

    #[test]
    fn evidence_error_keeps_verdict_drops_evidence() {
        // The `when` is true so the policy fires Block; the evidence expr errors,
        // which must NOT downgrade the verdict — it just drops the evidence.
        let t = traced(
            r#"policy "p" { when true then block, evidence=("x" in action.payload.count) }"#,
            serde_json::json!({ "action": { "payload": { "count": 5 } } }),
        );
        let f = t.fired.expect("must fire");
        assert_eq!(f.verdict, Verdict::Block);
        assert!(
            f.evidence.is_none(),
            "evidence error -> None, never downgrade"
        );
        assert!(!t.eval_errored, "a `when` did not error");
    }

    #[test]
    fn evidence_captured_when_it_evaluates() {
        let t = traced(
            r#"policy "p" { when true then review, evidence=action.payload.note }"#,
            serde_json::json!({ "action": { "payload": { "note": "see this" } } }),
        );
        let f = t.fired.expect("must fire");
        assert_eq!(f.verdict, Verdict::Review);
        assert_eq!(f.evidence, Some(Value::Str("see this".into())));
    }

    #[test]
    fn no_fire_reports_evaluated_count() {
        let t = traced(
            r#"policy "a" { when false then block }
               policy "b" { when false then review }"#,
            serde_json::json!({}),
        );
        assert!(t.fired.is_none());
        assert_eq!(t.policies_evaluated, 2);
        assert!(t.policies_fired.is_empty());
        assert!(!t.eval_errored);
    }
}
