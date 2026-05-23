//! Evaluator correctness + determinism tests.

use iaga_sentinel_apl::{compile, evaluate_program, Context, EvalBudget, Value, Verdict};
use serde_json::json;

fn ctx(v: serde_json::Value) -> Context {
    Context::from_value(v)
}

#[test]
fn trivial_true_fires_allow() {
    let prog = compile(r#"policy "p" { when true then allow }"#).unwrap();
    let mut b = EvalBudget::default();
    let fired = evaluate_program(&prog, &ctx(json!({})), &mut b).unwrap();
    let fired = fired.expect("must fire");
    assert_eq!(fired.verdict, Verdict::Allow);
    assert_eq!(fired.policy_name, "p");
}

#[test]
fn false_when_does_not_fire() {
    let prog = compile(r#"policy "p" { when false then block }"#).unwrap();
    let mut b = EvalBudget::default();
    let fired = evaluate_program(&prog, &ctx(json!({})), &mut b).unwrap();
    assert!(fired.is_none());
}

#[test]
fn field_access_on_nested_json() {
    let prog = compile(
        r#"policy "p" {
             when action.url.host == "evil.example.com"
             then block, reason="bad host"
           }"#,
    )
    .unwrap();
    let mut b = EvalBudget::default();
    let c = ctx(json!({
        "action": { "url": { "host": "evil.example.com" } }
    }));
    let fired = evaluate_program(&prog, &c, &mut b).unwrap().unwrap();
    assert_eq!(fired.verdict, Verdict::Block);
    assert_eq!(fired.reason.as_deref(), Some("bad host"));
}

#[test]
fn missing_path_is_null_and_not_truthy() {
    let prog = compile(r#"policy "p" { when action.missing_field then block }"#).unwrap();
    let mut b = EvalBudget::default();
    let fired = evaluate_program(&prog, &ctx(json!({"action": {}})), &mut b).unwrap();
    assert!(fired.is_none(), "null path must not fire");
}

#[test]
fn membership_in_list() {
    let prog = compile(
        r#"policy "p" {
             when action.url.host in workspace.allowlist
             then allow
           }"#,
    )
    .unwrap();
    let mut b = EvalBudget::default();
    let c = ctx(json!({
        "action": { "url": { "host": "ok.com" } },
        "workspace": { "allowlist": ["ok.com", "fine.io"] }
    }));
    assert!(evaluate_program(&prog, &c, &mut b).unwrap().is_some());

    let c2 = ctx(json!({
        "action": { "url": { "host": "bad.com" } },
        "workspace": { "allowlist": ["ok.com"] }
    }));
    let mut b2 = EvalBudget::default();
    assert!(evaluate_program(&prog, &c2, &mut b2).unwrap().is_none());
}

#[test]
fn not_in_list_inverts_membership() {
    let prog = compile(
        r#"policy "p" {
             when action.url.host not in workspace.allowlist
             then block
           }"#,
    )
    .unwrap();
    let mut b = EvalBudget::default();
    let c = ctx(json!({
        "action": { "url": { "host": "bad.com" } },
        "workspace": { "allowlist": ["ok.com"] }
    }));
    assert_eq!(
        evaluate_program(&prog, &c, &mut b)
            .unwrap()
            .unwrap()
            .verdict,
        Verdict::Block
    );
}

#[test]
fn short_circuit_and_does_not_eval_rhs() {
    // rhs is undefined path; with short-circuit on false LHS, no error.
    let prog =
        compile(r#"policy "p" { when false and action.undefined.deeply.nested then block }"#)
            .unwrap();
    let mut b = EvalBudget::default();
    let fired = evaluate_program(&prog, &ctx(json!({})), &mut b).unwrap();
    assert!(fired.is_none());
}

#[test]
fn builtin_contains_on_string() {
    let prog = compile(
        r#"policy "p" {
             when contains(action.payload, "drop table")
             then block, reason="sql injection"
           }"#,
    )
    .unwrap();
    let mut b = EvalBudget::default();
    let c = ctx(json!({"action": {"payload": "please drop table users;"}}));
    let fired = evaluate_program(&prog, &c, &mut b).unwrap().unwrap();
    assert_eq!(fired.verdict, Verdict::Block);
}

#[test]
fn builtin_starts_with_and_ends_with() {
    let prog = compile(
        r#"policy "p" {
             when starts_with(action.url.host, "api.") and ends_with(action.url.host, ".internal")
             then review
           }"#,
    )
    .unwrap();
    let mut b = EvalBudget::default();
    let c = ctx(json!({"action": {"url": {"host": "api.core.internal"}}}));
    assert!(evaluate_program(&prog, &c, &mut b).unwrap().is_some());
}

#[test]
fn numeric_comparison() {
    let prog = compile(r#"policy "p" { when action.risk_score > 80 then block }"#).unwrap();
    let mut b = EvalBudget::default();
    let c1 = ctx(json!({"action": {"risk_score": 95}}));
    let c2 = ctx(json!({"action": {"risk_score": 50}}));
    assert!(evaluate_program(&prog, &c1, &mut b).unwrap().is_some());
    let mut b2 = EvalBudget::default();
    assert!(evaluate_program(&prog, &c2, &mut b2).unwrap().is_none());
}

#[test]
fn evidence_is_captured_when_policy_fires() {
    let prog = compile(
        r#"policy "p" {
             when action.risk_score > 0
             then block, reason="risky", evidence=action.risk_score
           }"#,
    )
    .unwrap();
    let mut b = EvalBudget::default();
    let c = ctx(json!({"action": {"risk_score": 42}}));
    let fired = evaluate_program(&prog, &c, &mut b).unwrap().unwrap();
    assert_eq!(fired.evidence, Some(Value::Int(42)));
}

#[test]
fn first_matching_policy_wins() {
    let prog = compile(
        r#"policy "first"  { when true then review }
           policy "second" { when true then block }"#,
    )
    .unwrap();
    let mut b = EvalBudget::default();
    let fired = evaluate_program(&prog, &ctx(json!({})), &mut b)
        .unwrap()
        .unwrap();
    assert_eq!(fired.policy_name, "first");
    assert_eq!(fired.verdict, Verdict::Review);
}

#[test]
fn eval_is_deterministic() {
    let prog = compile(
        r#"policy "p" {
             when action.url.host not in workspace.allowlist
                and action.risk_score >= 50
             then block
           }"#,
    )
    .unwrap();
    let c = ctx(json!({
        "action": { "url": { "host": "x.com" }, "risk_score": 75 },
        "workspace": { "allowlist": ["ok.com"] }
    }));
    let mut b1 = EvalBudget::default();
    let a = evaluate_program(&prog, &c, &mut b1).unwrap();
    let mut b2 = EvalBudget::default();
    let b = evaluate_program(&prog, &c, &mut b2).unwrap();
    assert_eq!(a, b);
}

#[test]
fn budget_exhaustion_errors_out() {
    let prog =
        compile(r#"policy "p" { when action.x or action.y or action.z then allow }"#).unwrap();
    let mut b = EvalBudget::new(1); // absurdly small
    let res = evaluate_program(&prog, &ctx(json!({"action": {}})), &mut b);
    assert!(res.is_err(), "expected budget exhaustion");
}

#[test]
fn unknown_builtin_is_runtime_error() {
    let prog = compile(r#"policy "p" { when mystery_fn(action.x) then allow }"#).unwrap();
    let mut b = EvalBudget::default();
    let res = evaluate_program(&prog, &ctx(json!({"action": {"x": 1}})), &mut b);
    assert!(res.is_err(), "unknown builtin must error");
}
