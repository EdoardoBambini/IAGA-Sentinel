//! OSS 1.2, Dictum → WebAssembly codegen scaffolding (ADR 0014).
//!
//! **Scope MVP 1.2**: emit a valid WASM module for the subset of
//! Dictum expressions that does not touch host context, literals,
//! boolean / numeric / comparison binary ops, and unary `not`.
//! The resulting module exports an `eval_policy_<n>(): i32` function
//! per policy, returning `1` when the `when` clause evaluates to
//! true (the policy fires) and `0` otherwise.
//!
//! Expressions that depend on the runtime context, `Path(...)`,
//! `Call(name, args)` for any builtin, `Membership`, are
//! **explicitly rejected** by `compile_to_wasm`. Those cases need a
//! host-import ABI (read JSON context from linear memory, call
//! host functions for string ops) that is out of scope for the
//! 1.2 MVP.
//!
//! # NON-CANONICAL: not a proof, not semantically faithful
//!
//! The **tree-walk evaluator in `eval.rs` is the single canonical executor**
//! of Dictum, and the only one the governed verdict and its receipt ever go
//! through. This WASM codegen is an **experimental, non-canonical scaffold**:
//! it does **not** reproduce the tree-walk semantics. Two deliberate
//! divergences in the OSS MVP: integers are **truncated to i32** (the tree-walk
//! keeps i64), so `2^32 == 0` under WASM but not under the canonical evaluator;
//! and `and`/`or` lower to **bitwise** `i32.and`/`i32.or`, not the tree-walk's
//! short-circuit truthiness, so untyped operands like `2 and 1` disagree.
//! Therefore the WASM path must **never** be presented as evidence/proof of a
//! verdict, nor relied on to match a receipt. A semantically faithful,
//! AOT-optimized codegen (i64-correct, cranelift opt-levels, JIT tuning, WASI
//! side-effect policies) lives in IAGA Sentinel Enterprise, see ENTERPRISE.md.

use thiserror::Error;
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, Instruction, Module,
    TypeSection, ValType,
};

use crate::ast::{BinOp, Expr, Lit, Program, UnOp};

/// Opaque WASM module compiled from a [`Program`]. Holds the encoded
/// bytes, host loaders that want to execute it should feed
/// [`WasmProgram::bytes`] into wasmtime / wasmer / browser
/// `WebAssembly.instantiate`.
#[derive(Debug, Clone)]
pub struct WasmProgram {
    bytes: Vec<u8>,
    policy_count: u32,
}

impl WasmProgram {
    /// Encoded WASM module bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Take the bytes by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of `eval_policy_<n>` exports in the module.
    pub fn policy_count(&self) -> u32 {
        self.policy_count
    }
}

/// Failure modes for [`compile_to_wasm`]. Most failures correspond
/// to the MVP scope limitations: anything that needs host context
/// (`Path`, builtin `Call`, `Membership`) is rejected here and must
/// be evaluated via the tree-walk path instead.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WasmCompileError {
    #[error(
        "Dictum → WASM 1.2 MVP does not support path lookups (`{0}`); use tree-walk evaluator"
    )]
    UnsupportedPath(String),
    #[error(
        "Dictum → WASM 1.2 MVP does not support builtin calls (`{0}`); use tree-walk evaluator"
    )]
    UnsupportedCall(String),
    #[error("Dictum → WASM 1.2 MVP does not support membership tests; use tree-walk evaluator")]
    UnsupportedMembership,
    #[error("type mismatch in WASM codegen: {0}")]
    TypeMismatch(String),
}

/// Compile a [`Program`] into a WASM module. Each policy becomes an
/// `eval_policy_<n>(): i32` export returning `1` (fires) or `0`
/// (does not fire).
///
/// Returns [`WasmCompileError::UnsupportedPath`] /
/// [`WasmCompileError::UnsupportedCall`] /
/// [`WasmCompileError::UnsupportedMembership`] for the cases listed
/// in the module docs; callers should fall back to
/// [`crate::evaluate_program`] (tree-walk) for those programs.
pub fn compile_to_wasm(program: &Program) -> Result<WasmProgram, WasmCompileError> {
    let mut module = Module::new();

    // Type section: each policy is `() -> i32`.
    let mut types = TypeSection::new();
    let no_params: [ValType; 0] = [];
    let i32_result: [ValType; 1] = [ValType::I32];
    types.ty().function(no_params, i32_result);
    module.section(&types);

    // Function + Code sections.
    let mut functions = FunctionSection::new();
    let mut codes = CodeSection::new();

    for policy in &program.policies {
        functions.function(0); // type index 0 → () -> i32
        let mut f = Function::new(Vec::<(u32, ValType)>::new());
        emit_expr(&policy.when, &mut f)?;
        f.instruction(&Instruction::End);
        codes.function(&f);
    }

    module.section(&functions);

    // Export section.
    let mut exports = ExportSection::new();
    for (idx, policy) in program.policies.iter().enumerate() {
        let name = format!("eval_{}", sanitize_export(&policy.name));
        exports.export(&name, ExportKind::Func, idx as u32);
    }
    module.section(&exports);
    module.section(&codes);

    let bytes = module.finish();
    Ok(WasmProgram {
        bytes,
        policy_count: program.policies.len() as u32,
    })
}

fn sanitize_export(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Emit instructions for an `Expr` so the value on the WASM stack
/// after evaluation is an `i32` boolean (`0` or `1`) for `when` clauses,
/// or a raw `i32` numeric / encoded boolean for sub-expressions.
fn emit_expr(expr: &Expr, f: &mut Function) -> Result<(), WasmCompileError> {
    match expr {
        Expr::Lit(Lit::Bool(b)) => {
            f.instruction(&Instruction::I32Const(if *b { 1 } else { 0 }));
        }
        Expr::Lit(Lit::Int(n)) => {
            // Non-canonical scaffold (see module docs): integers truncate to
            // i32 here while the canonical tree-walk keeps i64. Intentional, not
            // a TODO; an i64-faithful codegen is Enterprise.
            let n32 = *n as i32;
            f.instruction(&Instruction::I32Const(n32));
        }
        Expr::Lit(Lit::Str(_)) => {
            return Err(WasmCompileError::TypeMismatch(
                "string literals require host import for storage; not in MVP 1.2".into(),
            ));
        }
        Expr::Path(segments) => {
            return Err(WasmCompileError::UnsupportedPath(segments.join(".")));
        }
        Expr::Call(name, _) => {
            return Err(WasmCompileError::UnsupportedCall(name.clone()));
        }
        Expr::Membership { .. } => {
            return Err(WasmCompileError::UnsupportedMembership);
        }
        Expr::Unary(UnOp::Not, inner) => {
            emit_expr(inner, f)?;
            f.instruction(&Instruction::I32Eqz);
        }
        Expr::Binary(op, lhs, rhs) => {
            emit_expr(lhs, f)?;
            emit_expr(rhs, f)?;
            let inst = match op {
                BinOp::Eq => Instruction::I32Eq,
                BinOp::Neq => Instruction::I32Ne,
                BinOp::Lt => Instruction::I32LtS,
                BinOp::Gt => Instruction::I32GtS,
                BinOp::Le => Instruction::I32LeS,
                BinOp::Ge => Instruction::I32GeS,
                // Non-canonical scaffold: bitwise, not the tree-walk's
                // short-circuit truthiness (see module docs). Intentional.
                BinOp::And => Instruction::I32And,
                BinOp::Or => Instruction::I32Or,
            };
            f.instruction(&inst);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Action, Policy, Verdict};

    fn policy(when: Expr) -> Program {
        Program {
            policies: vec![Policy {
                name: "p1".into(),
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
    fn lit_true_compiles_to_valid_module() {
        let p = policy(Expr::Lit(Lit::Bool(true)));
        let m = compile_to_wasm(&p).expect("compile ok");
        // Magic bytes: 0x00 0x61 0x73 0x6d (\0asm) + version 1.
        assert!(m.bytes().starts_with(b"\x00asm\x01\x00\x00\x00"));
        assert_eq!(m.policy_count(), 1);
    }

    #[test]
    fn eq_int_int_compiles() {
        let when = Expr::Binary(
            BinOp::Eq,
            Box::new(Expr::Lit(Lit::Int(42))),
            Box::new(Expr::Lit(Lit::Int(42))),
        );
        let m = compile_to_wasm(&policy(when)).expect("compile ok");
        assert!(m.bytes().len() > 8);
    }

    #[test]
    fn and_or_compile() {
        let when = Expr::Binary(
            BinOp::Or,
            Box::new(Expr::Lit(Lit::Bool(true))),
            Box::new(Expr::Binary(
                BinOp::And,
                Box::new(Expr::Lit(Lit::Bool(false))),
                Box::new(Expr::Lit(Lit::Bool(true))),
            )),
        );
        let m = compile_to_wasm(&policy(when)).expect("compile ok");
        assert!(m.bytes().len() > 8);
    }

    #[test]
    fn not_compiles() {
        let when = Expr::Unary(UnOp::Not, Box::new(Expr::Lit(Lit::Bool(false))));
        let _m = compile_to_wasm(&policy(when)).expect("compile ok");
    }

    #[test]
    fn path_rejected_with_clear_message() {
        let when = Expr::Path(vec!["action".into(), "url".into()]);
        let err = compile_to_wasm(&policy(when)).expect_err("must reject");
        assert!(matches!(err, WasmCompileError::UnsupportedPath(_)));
    }

    #[test]
    fn call_rejected() {
        let when = Expr::Call("contains".into(), vec![]);
        let err = compile_to_wasm(&policy(when)).expect_err("must reject");
        assert!(matches!(err, WasmCompileError::UnsupportedCall(_)));
    }

    #[test]
    fn membership_rejected() {
        let when = Expr::Membership {
            not: false,
            needle: Box::new(Expr::Lit(Lit::Bool(true))),
            haystack: Box::new(Expr::Lit(Lit::Bool(true))),
        };
        let err = compile_to_wasm(&policy(when)).expect_err("must reject");
        assert!(matches!(err, WasmCompileError::UnsupportedMembership));
    }

    #[test]
    fn string_lit_rejected_for_wasm_mvp() {
        let when = Expr::Binary(
            BinOp::Eq,
            Box::new(Expr::Lit(Lit::Str("a".into()))),
            Box::new(Expr::Lit(Lit::Str("a".into()))),
        );
        let err = compile_to_wasm(&policy(when)).expect_err("must reject");
        assert!(matches!(err, WasmCompileError::TypeMismatch(_)));
    }

    #[test]
    fn multiple_policies_get_separate_exports() {
        let p = Program {
            policies: vec![
                Policy {
                    name: "alpha".into(),
                    when: Expr::Lit(Lit::Bool(true)),
                    action: Action {
                        verdict: Verdict::Block,
                        reason: None,
                        evidence: None,
                    },
                },
                Policy {
                    name: "beta".into(),
                    when: Expr::Lit(Lit::Bool(false)),
                    action: Action {
                        verdict: Verdict::Allow,
                        reason: None,
                        evidence: None,
                    },
                },
            ],
        };
        let m = compile_to_wasm(&p).expect("compile ok");
        assert_eq!(m.policy_count(), 2);
        // The bytes contain both export names somewhere.
        let s = String::from_utf8_lossy(m.bytes());
        assert!(s.contains("eval_alpha"));
        assert!(s.contains("eval_beta"));
    }
}
