//! Parser + validator happy paths and error cases.

use iaga_sentinel_dictum::{compile, parse, BinOp, DictumError, Expr, Lit, UnOp, Verdict};
use pretty_assertions::assert_eq;

#[test]
fn parse_minimal_allow() {
    let src = r#"
        policy "baseline" {
          when true
          then allow
        }
    "#;
    let p = compile(src).expect("parse");
    assert_eq!(p.policies.len(), 1);
    assert_eq!(p.policies[0].name, "baseline");
    assert_eq!(p.policies[0].action.verdict, Verdict::Allow);
    assert_eq!(p.policies[0].when, Expr::Lit(Lit::Bool(true)));
}

#[test]
fn parse_block_with_reason_and_evidence() {
    let src = r#"
        policy "hijack" {
          when action.kind == "shell"
          then block, reason="shell exec", evidence=action.kind
        }
    "#;
    let p = compile(src).expect("parse");
    let action = &p.policies[0].action;
    assert_eq!(action.verdict, Verdict::Block);
    assert_eq!(action.reason.as_deref(), Some("shell exec"));
    assert!(action.evidence.is_some());
}

#[test]
fn parse_compound_and_or_not() {
    let src = r#"
        policy "complex" {
          when (action.kind == "http.request" and not action.trusted)
            or action.risk_score > 80
          then review
        }
    "#;
    let _p = compile(src).expect("parse");
}

#[test]
fn parse_membership_in_and_not_in() {
    let src = r#"
        policy "ws_allowlist" {
          when action.url.host not in workspace.allowlist
          then block, reason="off-allowlist"
        }
    "#;
    let p = compile(src).expect("parse");
    if let Expr::Membership { not, .. } = &p.policies[0].when {
        assert!(*not);
    } else {
        panic!(
            "expected Membership at the root of `when`, got {:?}",
            p.policies[0].when
        );
    }
}

#[test]
fn parse_call_with_args() {
    let src = r#"
        policy "contains_foo" {
          when contains(action.payload, "foo")
          then review
        }
    "#;
    let p = compile(src).expect("parse");
    if let Expr::Call(name, args) = &p.policies[0].when {
        assert_eq!(name, "contains");
        assert_eq!(args.len(), 2);
    } else {
        panic!("expected Call");
    }
}

#[test]
fn parse_rejects_duplicate_policy_names() {
    let src = r#"
        policy "x" { when true then allow }
        policy "x" { when false then block }
    "#;
    let err = compile(src).expect_err("duplicate");
    assert!(matches!(err, DictumError::Type(_)));
}

#[test]
fn parse_rejects_unknown_token() {
    let src = r#"policy "x" { when @ then allow }"#;
    let err = parse(src).expect_err("bad token");
    assert!(matches!(err, DictumError::Parse { .. }));
}

#[test]
fn parse_rejects_missing_verdict() {
    let src = r#"policy "x" { when true then }"#;
    let err = parse(src).expect_err("missing verdict");
    assert!(matches!(err, DictumError::Parse { .. }));
}

#[test]
fn parse_rejects_wrong_builtin_arity() {
    let src = r#"policy "x" { when contains("a") then allow }"#;
    let err = compile(src).expect_err("arity");
    match err {
        DictumError::Type(msg) => assert!(msg.contains("contains"), "msg={}", msg),
        other => panic!("expected Type err, got {:?}", other),
    }
}

#[test]
fn parse_multiple_policies_in_declaration_order() {
    let src = r#"
        policy "first" { when true then review }
        policy "second" { when false then block }
    "#;
    let p = compile(src).expect("parse");
    assert_eq!(p.policies[0].name, "first");
    assert_eq!(p.policies[1].name, "second");
}

#[test]
fn parse_preserves_bin_op_associativity() {
    // `a == b and c == d` should be (a == b) and (c == d), not a == (b and c) == d.
    let src = r#"policy "p" { when action.x == "a" and action.y == "b" then allow }"#;
    let p = compile(src).expect("parse");
    if let Expr::Binary(BinOp::And, _, _) = &p.policies[0].when {
        // good
    } else {
        panic!("expected `and` at root, got {:?}", p.policies[0].when);
    }
}

#[test]
fn parse_handles_unary_not_prefix() {
    let src = r#"policy "p" { when not action.trusted then block }"#;
    let p = compile(src).expect("parse");
    assert!(matches!(p.policies[0].when, Expr::Unary(UnOp::Not, _)));
}

#[test]
fn parse_handles_escaped_strings() {
    let src = r#"policy "p" { when action.msg == "line1\nline2" then review }"#;
    let p = compile(src).expect("parse");
    if let Expr::Binary(BinOp::Eq, _, rhs) = &p.policies[0].when {
        if let Expr::Lit(Lit::Str(s)) = rhs.as_ref() {
            assert_eq!(s, "line1\nline2");
        } else {
            panic!("rhs not a string lit");
        }
    } else {
        panic!("not a binary eq");
    }
}
