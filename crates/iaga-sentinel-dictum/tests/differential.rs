//! Differential tests: tree-walk evaluator vs WASM codegen (1.5.2).
//!
//! Two executors for the same language is a semantics-drift hazard: a policy
//! could fire under one and not the other without anyone noticing. These
//! tests run the SAME program through both paths and assert identical
//! fired-ness, plus a clean, actionable error (and a working tree-walk
//! fallback) for every construct the WASM MVP deliberately rejects.
//!
//! Scope note: the corpus only combines `and`/`or`/`not` over BOOLEAN
//! subexpressions (literals and integer comparisons). That mirrors what the
//! Hindley-Milner checker accepts and sidesteps a known, intentional MVP
//! divergence: WASM lowers `and`/`or` to bitwise `i32.and`/`i32.or`, while
//! the tree-walk evaluator applies logical truthiness, so untyped operands
//! like `2 and 1` would disagree (1 vs true). Int literals stay in i32 range
//! because the MVP codegen truncates i64 → i32.

#![cfg(feature = "dictum-wasm")]

use iaga_sentinel_dictum::{
    compile, compile_to_wasm, evaluate_program, Action, Context, EvalBudget, Expr, Lit, Policy,
    Program, UnOp, Verdict, WasmCompileError,
};
use proptest::prelude::*;

/// Evaluates policy 0 of a compiled WASM program via wasmtime, returning the
/// raw i32 (1 = fires, 0 = does not fire).
fn run_wasm_policy(program: &Program) -> i32 {
    let wasm = compile_to_wasm(program).expect("wasm compile");
    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::new(&engine, wasm.bytes()).expect("valid module");
    let mut store = wasmtime::Store::new(&engine, ());
    let instance = wasmtime::Instance::new(&mut store, &module, &[]).expect("instantiate");
    let export = format!(
        "eval_{}",
        program.policies[0]
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    );
    let func = instance
        .get_typed_func::<(), i32>(&mut store, &export)
        .expect("export present");
    func.call(&mut store, ()).expect("wasm eval")
}

/// Evaluates the program through the canonical tree-walk path against an
/// empty context (the WASM MVP only supports context-free expressions).
fn run_tree_walk(program: &Program) -> bool {
    let ctx = Context::from_value(serde_json::json!({}));
    let mut budget = EvalBudget::default();
    evaluate_program(program, &ctx, &mut budget)
        .expect("tree-walk eval")
        .is_some()
}

fn assert_paths_agree(src: &str) {
    let program = compile(src).expect("compile Dictum source");
    let tree = run_tree_walk(&program);
    let wasm = run_wasm_policy(&program) != 0;
    assert_eq!(
        tree, wasm,
        "evaluator divergence for policy source: {src}\n tree-walk fired={tree}, wasm={wasm}"
    );
}

#[test]
fn fixed_corpus_agrees_across_both_evaluators() {
    let corpus = [
        r#"policy "p" { when true then block }"#,
        r#"policy "p" { when false then block }"#,
        r#"policy "p" { when not true then block }"#,
        r#"policy "p" { when not false then block }"#,
        r#"policy "p" { when 1 == 1 then block }"#,
        r#"policy "p" { when 1 == 2 then block }"#,
        r#"policy "p" { when 1 != 2 then block }"#,
        r#"policy "p" { when 3 > 2 then block }"#,
        r#"policy "p" { when 2 > 3 then block }"#,
        r#"policy "p" { when 2 < 3 then block }"#,
        r#"policy "p" { when 3 <= 3 then block }"#,
        r#"policy "p" { when 4 >= 5 then block }"#,
        r#"policy "p" { when true and true then block }"#,
        r#"policy "p" { when true and false then block }"#,
        r#"policy "p" { when false or true then block }"#,
        r#"policy "p" { when false or false then block }"#,
        r#"policy "p" { when (1 == 1) and (2 < 3) then block }"#,
        r#"policy "p" { when not (1 == 1) or (5 >= 5) then block }"#,
        r#"policy "p" { when -1 < 0 then block }"#,
        r#"policy "p" { when 2147483647 > 0 then block }"#,
        r#"policy "p" { when -2147483648 < 0 then block }"#,
        r#"policy "p" { when not (true and not false) or (1 > 2) then block }"#,
    ];
    for src in corpus {
        assert_paths_agree(src);
    }
}

fn block_policy(when: Expr) -> Program {
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

/// Constructs that need host context are rejected by the WASM MVP with a
/// specific error pointing at the tree-walk fallback — and the tree-walk
/// path must indeed still evaluate the same program.
#[test]
fn unsupported_constructs_reject_cleanly_and_tree_walk_still_works() {
    type ExpectedError = fn(&WasmCompileError) -> bool;
    let cases: Vec<(Expr, ExpectedError)> = vec![
        (
            Expr::Path(vec!["risk".into(), "score".into()]),
            |e| matches!(e, WasmCompileError::UnsupportedPath(p) if p == "risk.score"),
        ),
        (
            Expr::Call("secret_ref".into(), vec![Expr::Lit(Lit::Bool(true))]),
            |e| matches!(e, WasmCompileError::UnsupportedCall(c) if c == "secret_ref"),
        ),
        (
            Expr::Membership {
                not: false,
                needle: Box::new(Expr::Lit(Lit::Str("a".into()))),
                haystack: Box::new(Expr::Path(vec!["allow".into()])),
            },
            |e| matches!(e, WasmCompileError::UnsupportedMembership),
        ),
        (Expr::Lit(Lit::Str("hello".into())), |e| {
            matches!(e, WasmCompileError::TypeMismatch(_))
        }),
    ];

    for (when, matches_expected) in cases {
        let program = block_policy(when);
        let err = compile_to_wasm(&program).expect_err("MVP must reject");
        assert!(
            matches_expected(&err),
            "unexpected rejection variant: {err:?}"
        );
        // The user-facing message must point at the supported fallback.
        assert!(
            err.to_string().contains("use tree-walk evaluator")
                || matches!(err, WasmCompileError::TypeMismatch(_)),
            "error must direct users to the tree-walk fallback: {err}"
        );
        // And the canonical evaluator must still handle the program.
        let ctx = Context::from_value(serde_json::json!({
            "risk": { "score": 10 },
            "allow": ["a", "b"],
        }));
        let mut budget = EvalBudget::default();
        evaluate_program(&program, &ctx, &mut budget)
            .expect("tree-walk must evaluate what WASM rejects");
    }
}

// ── property-based corpus ──
//
// Generates context-free boolean expression trees (bool literals, i32
// comparisons, and/or/not over boolean nodes) and asserts both evaluators
// agree on fired-ness. Arithmetic and untyped logical operands are excluded
// by construction — see the module docs for why.

fn bool_expr() -> impl Strategy<Value = Expr> {
    let cmp = (any::<i32>(), any::<i32>(), 0..6u8).prop_map(|(a, b, op)| {
        use iaga_sentinel_dictum::BinOp;
        let op = match op {
            0 => BinOp::Eq,
            1 => BinOp::Neq,
            2 => BinOp::Lt,
            3 => BinOp::Gt,
            4 => BinOp::Le,
            _ => BinOp::Ge,
        };
        Expr::Binary(
            op,
            Box::new(Expr::Lit(Lit::Int(a as i64))),
            Box::new(Expr::Lit(Lit::Int(b as i64))),
        )
    });
    let leaf = prop_oneof![any::<bool>().prop_map(|b| Expr::Lit(Lit::Bool(b))), cmp];
    leaf.prop_recursive(4, 32, 2, |inner| {
        prop_oneof![
            (inner.clone(), inner.clone()).prop_map(|(l, r)| Expr::Binary(
                iaga_sentinel_dictum::BinOp::And,
                Box::new(l),
                Box::new(r)
            )),
            (inner.clone(), inner.clone()).prop_map(|(l, r)| Expr::Binary(
                iaga_sentinel_dictum::BinOp::Or,
                Box::new(l),
                Box::new(r)
            )),
            inner.prop_map(|e| Expr::Unary(UnOp::Not, Box::new(e))),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn generated_boolean_programs_agree(when in bool_expr()) {
        let program = block_policy(when);
        let tree = run_tree_walk(&program);
        let wasm = run_wasm_policy(&program) != 0;
        prop_assert_eq!(
            tree,
            wasm,
            "evaluator divergence for generated expr: {:?}",
            &program.policies[0].when
        );
    }
}
