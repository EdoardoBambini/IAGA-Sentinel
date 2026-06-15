//! `iaga-codex export-rules` orchestration: read a Dictum bundle, compile it
//! to execpolicy `.rules`, write the file, and print a coverage report.
//!
//! Thin by design (I/O + glue); the faithful-subset logic lives in
//! [`crate::rules_compiler`] and the syntax in [`crate::execpolicy_format`].

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{execpolicy_format, rules_compiler};

/// Exit codes mirror the workspace CLI convention (0 ok, 2 usage/compile,
/// 3 I/O).
pub const EXIT_OK: i32 = 0;
pub const EXIT_COMPILE: i32 = 2;
pub const EXIT_IO: i32 = 3;

/// Compile `dictum_path` to a `.rules` file at `out_path`. Returns an exit
/// code; all diagnostics go to stderr, the report summary to stdout.
pub fn run_export(dictum_path: &Path, out_path: &Path) -> i32 {
    let src = match std::fs::read_to_string(dictum_path) {
        Ok(src) => src,
        Err(e) => {
            eprintln!(
                "[iaga-codex] cannot read Dictum bundle `{}`: {e}",
                dictum_path.display()
            );
            return EXIT_IO;
        }
    };

    // Hash the exact source bytes so drift between this artifact and the
    // bundle is detectable from the generated file's header.
    let bundle_sha256 = hex::encode(Sha256::digest(src.as_bytes()));

    let program = match iaga_sentinel_dictum::compile(&src) {
        Ok(program) => program,
        Err(e) => {
            eprintln!(
                "[iaga-codex] Dictum compile error in `{}`: {e}",
                dictum_path.display()
            );
            return EXIT_COMPILE;
        }
    };

    let report = rules_compiler::compile_program(&program);
    let text = execpolicy_format::render_rules_file(&bundle_sha256, &report);

    if let Err(e) = std::fs::write(out_path, &text) {
        eprintln!(
            "[iaga-codex] cannot write rules file `{}`: {e}",
            out_path.display()
        );
        return EXIT_IO;
    }

    println!(
        "EXPORTED  rules={}  runtime_only={}  bundle_sha256={}  file={}",
        report.rules.len(),
        report.runtime_only.len(),
        bundle_sha256,
        out_path.display()
    );
    // The runtime-only policies are not a failure: they are enforced by the
    // gate. Surface them so the operator knows what the static layer skips.
    for ro in &report.runtime_only {
        println!("  runtime-only: {} — {}", ro.policy_name, ro.reason);
    }

    EXIT_OK
}
