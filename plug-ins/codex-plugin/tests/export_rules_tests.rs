//! Golden-file + I/O tests for `iaga-codex export-rules`.
//!
//! The golden (`tests/fixtures/sample_bundle.golden.rules`) is the exact
//! output of compiling `tests/fixtures/sample_bundle.dictum`. Regenerate it
//! with:
//!
//! ```text
//! iaga-codex export-rules \
//!   --dictum crates/iaga-sentinel-codex/tests/fixtures/sample_bundle.dictum \
//!   --out crates/iaga-sentinel-codex/tests/fixtures/sample_bundle.golden.rules
//! ```
//!
//! The execpolicy syntax is PROVISIONAL; when the spike confirms it, fix
//! `execpolicy_format.rs` and regenerate this golden.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use iaga_sentinel_codex::execpolicy_format::render_rules_file;
use iaga_sentinel_codex::rules_compiler::compile_program;
use iaga_sentinel_codex::rules_export::{run_export, EXIT_COMPILE, EXIT_IO, EXIT_OK};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("cannot read fixture {name}: {e}"))
        // Normalize CRLF so the test is stable regardless of git autocrlf.
        .replace("\r\n", "\n")
}

#[test]
fn sample_bundle_matches_the_golden_rules() {
    let src = read_fixture("sample_bundle.dictum");
    let bundle_sha256 = hex::encode(Sha256::digest(src.as_bytes()));

    let program = iaga_sentinel_dictum::compile(&src).expect("sample bundle compiles");
    let report = compile_program(&program);
    let rendered = render_rules_file(&bundle_sha256, &report);

    let golden = read_fixture("sample_bundle.golden.rules");
    assert_eq!(
        rendered, golden,
        "export-rules output drifted from the golden; if intended, regenerate \
         tests/fixtures/sample_bundle.golden.rules (see this file's header)"
    );
}

#[test]
fn run_export_writes_a_file_and_reports_ok() {
    let out = std::env::temp_dir().join("iaga_codex_export_rules_test.rules");
    let _ = std::fs::remove_file(&out);

    let code = run_export(&fixture_path("sample_bundle.dictum"), &out);
    assert_eq!(code, EXIT_OK);

    let written = std::fs::read_to_string(&out).expect("output file exists");
    assert!(written.contains("prefix_rule("));
    assert!(written.contains(r#"decision = "forbidden""#));
    assert!(written.contains("Runtime-only policies"));

    let _ = std::fs::remove_file(&out);
}

#[test]
fn missing_bundle_exits_io_error() {
    let out = std::env::temp_dir().join("iaga_codex_export_rules_missing.rules");
    let code = run_export(&fixture_path("does_not_exist.dictum"), &out);
    assert_eq!(code, EXIT_IO);
}

#[test]
fn invalid_dictum_exits_compile_error() {
    let bad = std::env::temp_dir().join("iaga_codex_bad_bundle.dictum");
    std::fs::write(&bad, "policy \"broken\" { when ").expect("write temp bundle");
    let out = std::env::temp_dir().join("iaga_codex_bad_out.rules");

    let code = run_export(&bad, &out);
    assert_eq!(code, EXIT_COMPILE);

    let _ = std::fs::remove_file(&bad);
    let _ = std::fs::remove_file(&out);
}

// ── real round-trip against `codex execpolicy check` ─────────────────────
//
// Requires the Codex CLI on PATH (validated against the version pinned in
// plug-ins/codex-plugin/README.md). Ignored by default so CI without
// Codex stays green:
//
//   cargo test -p iaga-sentinel-codex -- --ignored
//
// Because execpolicy treats `match`/`not_match` as parse-time assertions,
// `check` exiting non-1 already proves the whole generated file parses and
// every example is self-consistent; we additionally assert the curl rule
// resolves to `forbidden`.
#[test]
#[ignore = "requires the Codex CLI (`codex execpolicy check`) on PATH"]
fn generated_rules_pass_codex_execpolicy_check() {
    use std::process::Command;

    // Skip gracefully if Codex is not invocable.
    if Command::new("codex").arg("--version").output().is_err() {
        eprintln!("codex not on PATH; skipping round-trip");
        return;
    }

    let out = std::env::temp_dir().join("iaga_codex_roundtrip.rules");
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        run_export(&fixture_path("sample_bundle.dictum"), &out),
        EXIT_OK
    );

    let output = Command::new("codex")
        .args(["execpolicy", "check", "--rules"])
        .arg(&out)
        .args(["--", "curl", "http://evil.com"])
        .output()
        .expect("run codex execpolicy check");

    // Exit 1 means usage/parse error -> a malformed generated file.
    assert!(
        output.status.success(),
        "codex execpolicy check rejected the generated file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"decision\""),
        "expected a JSON decision in: {stdout}"
    );
    assert!(
        stdout.contains("forbidden"),
        "curl should resolve to forbidden, got: {stdout}"
    );

    let _ = std::fs::remove_file(&out);
}
