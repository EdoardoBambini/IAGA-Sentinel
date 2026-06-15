//! Dictum bundle → execpolicy rules compiler (pure logic, no syntax, no I/O).
//!
//! Walks the public Dictum AST and extracts the subset that maps faithfully
//! onto an execpolicy command-prefix rule. The bar is **faithfulness**,
//! not coverage: a static `prefix_rule` is emitted only when the Dictum
//! policy fires *exactly* when a shell command starts with a literal
//! prefix. Anything with a runtime condition (risk score, `contains`,
//! membership, `secret_ref`, ML/usage paths, disjunction) stays
//! runtime-only and is enforced by the `iaga-codex hook` gate instead —
//! emitting a looser-or-tighter static rule would silently change policy
//! semantics, which we refuse to do.
//!
//! The Dictum context the core builds exposes the shell command under
//! `action.payload.*` (see `pipeline/dictum_overlay.rs`); a "command path"
//! here is a path whose last segment is `command`, `cmd`, or `argv`.

use iaga_sentinel_dictum::{BinOp, Expr, Lit, Program, Verdict};

use crate::execpolicy_format::{ExecDecision, PrefixRule};

/// A policy that could not be reduced to a static command prefix, with a
/// human reason for the export report and the `.rules` trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOnly {
    pub policy_name: String,
    pub reason: String,
}

/// Result of compiling a whole bundle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompileReport {
    pub rules: Vec<PrefixRule>,
    pub runtime_only: Vec<RuntimeOnly>,
}

/// Outcome of analysing a single `when` expression.
enum WhenAnalysis {
    /// Reduces to "the shell command starts with these literal tokens".
    Prefix(Vec<String>),
    /// `action.kind == "shell"` — a no-op confirmation for shell rules;
    /// alone it is not a specific command prefix.
    ShellGate,
    /// Not expressible as a single static command prefix; carries why.
    NotCompilable(String),
}

/// Compile every policy in declaration order.
pub fn compile_program(program: &Program) -> CompileReport {
    let mut report = CompileReport::default();
    for policy in &program.policies {
        match analyze(&policy.when) {
            WhenAnalysis::Prefix(tokens) => {
                // `analyze` never returns an empty Prefix, but guard anyway.
                let Some((program_tok, args)) = tokens.split_first() else {
                    report.runtime_only.push(RuntimeOnly {
                        policy_name: policy.name.clone(),
                        reason: "empty command prefix".to_string(),
                    });
                    continue;
                };
                report
                    .rules
                    .push(build_rule(policy, program_tok.clone(), args.to_vec()));
            }
            WhenAnalysis::ShellGate => report.runtime_only.push(RuntimeOnly {
                policy_name: policy.name.clone(),
                reason: "matches all shell actions, not a specific command prefix".to_string(),
            }),
            WhenAnalysis::NotCompilable(reason) => report.runtime_only.push(RuntimeOnly {
                policy_name: policy.name.clone(),
                reason,
            }),
        }
    }
    report
}

/// Build a [`PrefixRule`] from a compilable policy.
fn build_rule(
    policy: &iaga_sentinel_dictum::Policy,
    program: String,
    arg_prefix: Vec<String>,
) -> PrefixRule {
    let decision = match policy.action.verdict {
        Verdict::Block => ExecDecision::Forbidden,
        Verdict::Review => ExecDecision::Prompt,
        Verdict::Allow => ExecDecision::Allow,
    };
    let justification = match &policy.action.reason {
        Some(reason) => format!("IAGA Sentinel: {}. {}", policy.name, reason),
        None => format!("IAGA Sentinel: {}", policy.name),
    };

    // The pattern is the argv prefix as literal positions: program first,
    // then each literal arg token (e.g. ["rm", "-rf"]). Never an empty
    // inner list, which execpolicy rejects.
    let mut pattern = vec![program];
    pattern.extend(arg_prefix);

    // Self-consistent parse-time assertions: the pattern itself matches;
    // a sentinel program that differs does not (`codex execpolicy check`
    // rejects the file if these are wrong).
    let sentinel = if pattern[0] == "true" {
        "false"
    } else {
        "true"
    };

    PrefixRule {
        match_examples: vec![pattern.clone()],
        not_match_examples: vec![vec![sentinel.to_string()]],
        pattern,
        decision,
        justification,
    }
}

/// True when a path's last segment names a shell command.
fn is_command_path(segs: &[String]) -> bool {
    matches!(
        segs.last().map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("command") | Some("cmd") | Some("argv")
    )
}

/// True for `action.kind == "shell"` in either operand order.
fn is_shell_gate(left: &Expr, right: &Expr) -> bool {
    let is_kind =
        |e: &Expr| matches!(e, Expr::Path(p) if p == &["action".to_string(), "kind".to_string()]);
    let is_shell = |e: &Expr| matches!(e, Expr::Lit(Lit::Str(s)) if s == "shell");
    (is_kind(left) && is_shell(right)) || (is_kind(right) && is_shell(left))
}

fn analyze(expr: &Expr) -> WhenAnalysis {
    match expr {
        Expr::Call(name, args) if name == "starts_with" && args.len() == 2 => {
            match (&args[0], &args[1]) {
                (Expr::Path(p), Expr::Lit(Lit::Str(literal))) if is_command_path(p) => {
                    let tokens: Vec<String> =
                        literal.split_whitespace().map(String::from).collect();
                    if tokens.is_empty() {
                        WhenAnalysis::NotCompilable(
                            "starts_with with an empty command literal".to_string(),
                        )
                    } else {
                        WhenAnalysis::Prefix(tokens)
                    }
                }
                (Expr::Path(p), Expr::Lit(Lit::Str(_))) => WhenAnalysis::NotCompilable(format!(
                    "starts_with on non-command path `{}`",
                    path_str(p)
                )),
                _ => WhenAnalysis::NotCompilable(
                    "starts_with with non-literal or dynamic arguments".to_string(),
                ),
            }
        }
        Expr::Binary(BinOp::And, left, right) => combine_and(analyze(left), analyze(right)),
        Expr::Binary(BinOp::Eq, left, right) if is_shell_gate(left, right) => {
            WhenAnalysis::ShellGate
        }
        Expr::Binary(BinOp::Or, _, _) => WhenAnalysis::NotCompilable(
            "disjunction (`or`) is not a single command prefix".to_string(),
        ),
        Expr::Lit(Lit::Bool(true)) => {
            WhenAnalysis::NotCompilable("catch-all `when true` has no command prefix".to_string())
        }
        other => WhenAnalysis::NotCompilable(format!(
            "{} has no command-prefix equivalent",
            describe(other)
        )),
    }
}

/// Combine the two sides of an `and`. A prefix may be ANDed only with a
/// shell-kind gate; two prefixes or any non-compilable side disqualify it.
fn combine_and(left: WhenAnalysis, right: WhenAnalysis) -> WhenAnalysis {
    use WhenAnalysis::*;
    match (left, right) {
        (NotCompilable(reason), _) | (_, NotCompilable(reason)) => NotCompilable(reason),
        (Prefix(p), ShellGate) | (ShellGate, Prefix(p)) => Prefix(p),
        (ShellGate, ShellGate) => ShellGate,
        (Prefix(_), Prefix(_)) => NotCompilable(
            "multiple command-prefix conditions; one prefix per rule in this MVP".to_string(),
        ),
    }
}

fn path_str(segs: &[String]) -> String {
    segs.join(".")
}

/// Short human description of an expression for runtime-only reasons.
fn describe(expr: &Expr) -> String {
    match expr {
        Expr::Lit(_) => "a literal".to_string(),
        Expr::Path(p) => format!("path `{}`", path_str(p)),
        Expr::Call(name, _) => format!("call `{name}(...)`"),
        Expr::Binary(op, _, _) => format!("`{}` comparison", binop_str(*op)),
        Expr::Unary(_, _) => "a negation".to_string(),
        Expr::Membership { not, .. } => {
            if *not {
                "a `not in` membership test".to_string()
            } else {
                "an `in` membership test".to_string()
            }
        }
    }
}

fn binop_str(op: BinOp) -> &'static str {
    match op {
        BinOp::Eq => "==",
        BinOp::Neq => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        BinOp::And => "and",
        BinOp::Or => "or",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iaga_sentinel_dictum::compile;

    fn report_for(src: &str) -> CompileReport {
        let program = compile(src).expect("Dictum fixture must compile");
        compile_program(&program)
    }

    #[test]
    fn starts_with_on_command_compiles_to_a_prefix_rule() {
        let report = report_for(
            r#"policy "block_curl" {
                 when starts_with(action.payload.command, "curl")
                 then block, reason="no external egress"
               }"#,
        );
        assert_eq!(report.rules.len(), 1);
        assert!(report.runtime_only.is_empty());
        let rule = &report.rules[0];
        assert_eq!(rule.pattern, vec!["curl".to_string()]);
        assert_eq!(rule.decision, ExecDecision::Forbidden);
        assert!(rule.justification.contains("block_curl"));
        assert!(rule.justification.contains("no external egress"));
    }

    #[test]
    fn shell_gate_anded_with_prefix_still_compiles() {
        let report = report_for(
            r#"policy "block_rm_rf" {
                 when action.kind == "shell" and starts_with(action.payload.command, "rm -rf")
                 then review
               }"#,
        );
        assert_eq!(report.rules.len(), 1);
        let rule = &report.rules[0];
        assert_eq!(rule.pattern, vec!["rm".to_string(), "-rf".to_string()]);
        assert_eq!(rule.decision, ExecDecision::Prompt);
    }

    #[test]
    fn risk_score_condition_is_runtime_only() {
        let report = report_for(
            r#"policy "halt_high_risk" {
                 when action.kind == "shell" and risk.score > 50
                 then block, reason="elevated risk"
               }"#,
        );
        assert!(report.rules.is_empty());
        assert_eq!(report.runtime_only.len(), 1);
        assert!(report.runtime_only[0].reason.contains('>'));
    }

    #[test]
    fn contains_and_membership_are_runtime_only() {
        let report = report_for(
            r#"policy "p_contains" {
                 when contains(action.payload.command, "evil")
                 then block
               }
               policy "p_member" {
                 when action.tool_name not in workspace.allowlist
                 then block
               }"#,
        );
        assert!(report.rules.is_empty());
        assert_eq!(report.runtime_only.len(), 2);
    }

    #[test]
    fn catch_all_true_is_runtime_only() {
        let report = report_for(r#"policy "default_allow" { when true then allow }"#);
        assert!(report.rules.is_empty());
        assert_eq!(report.runtime_only.len(), 1);
    }

    #[test]
    fn starts_with_on_non_command_path_is_runtime_only() {
        let report = report_for(
            r#"policy "p" {
                 when starts_with(action.tool_name, "sh")
                 then block
               }"#,
        );
        assert!(report.rules.is_empty());
        assert!(report.runtime_only[0].reason.contains("non-command path"));
    }

    #[test]
    fn shell_gate_alone_is_runtime_only() {
        let report =
            report_for(r#"policy "all_shell" { when action.kind == "shell" then review }"#);
        assert!(report.rules.is_empty());
        assert!(report.runtime_only[0].reason.contains("all shell"));
    }
}
