//! Ingest behaviour tests — no live sidecar, no Codex binary required.
//!
//! In-process tests drive [`session_ingest::ingest_lines`] against the
//! shared mock `/v1/inspect` (counts, wire contract, fail handling). Two
//! end-to-end tests run the real `iaga-codex` binary against the mock with
//! per-process env (parallel-safe) to cover the file and spawn input modes.

mod common;
use common::{Behavior, MockSidecar, ScriptedVerdict};

use iaga_sentinel_codex::exec_stream::Attestation;
use iaga_sentinel_codex::hook_config::Config;
use iaga_sentinel_codex::session_ingest::{exit_code, ingest_lines, EXIT_GAP, EXIT_OK};
use iaga_sentinel_integrations::GovernanceDecision;

const SESSION_FIXTURE: &str = "exec_stream_session.provisional.jsonl";
const MALFORMED_FIXTURE: &str = "exec_stream_malformed.provisional.jsonl";
/// A real `codex exec --json` stream captured from codex-cli 0.138.0-alpha.7
/// during the stream spike (see ADR 0022). Confirms `exec_stream.rs` parses
/// actual Codex output: `command_execution` + `file_change` are attested,
/// `agent_message` and the lifecycle lines are not.
const REAL_FIXTURE: &str = "exec_stream_real_0.138.jsonl";

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read fixture {path}: {e}"))
}

/// Native-separator path to a fixture. The E2E spawn test passes this to
/// the platform `type`/`cat`, and `cmd`'s `type` rejects forward slashes,
/// so build it with `Path::join` rather than a `/`-joined string.
fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn lines(raw: &str) -> Vec<String> {
    raw.lines().map(str::to_string).collect()
}

fn test_config(base_url: &str) -> Config {
    Config {
        base_url: base_url.trim_end_matches('/').to_string(),
        ..Config::default()
    }
}

fn allow_mock() -> Behavior {
    Behavior::Verdict {
        decision: "allow",
        score: 0,
        reasons: vec![],
    }
}

// ── stream routing & counts ──────────────────────────────────────────────

#[tokio::test]
async fn session_stream_attests_only_completed_actionable_items() {
    let mock = MockSidecar::serve(allow_mock()).await;
    let config = test_config(&mock.base_url());

    let summary = ingest_lines(
        lines(&fixture(SESSION_FIXTURE)),
        &config,
        Attestation::LiveIngest,
    )
    .await;

    // 5 actionable items (2 command_execution, 1 file_change, 1 mcp_tool_call,
    // 1 web_search); reasoning/agent_message/lifecycle lines mint nothing.
    assert_eq!(
        summary.actionable, 5,
        "only completed actionable items count"
    );
    assert_eq!(summary.attested, 5);
    assert_eq!(summary.allow, 5);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.records.len(), 5);
    assert_eq!(exit_code(&summary), EXIT_OK);
    // Exactly one inspect call per actionable item, never per lifecycle line.
    assert_eq!(mock.captured.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn the_wire_body_declares_advisory_attestation_and_session() {
    let mock = MockSidecar::serve(allow_mock()).await;
    let config = test_config(&mock.base_url());

    let _ = ingest_lines(
        lines(&fixture(SESSION_FIXTURE)),
        &config,
        Attestation::LiveIngest,
    )
    .await;

    let captured = mock.captured.lock().unwrap();
    let first = &captured[0];
    // Static registered identity, same as the gate.
    assert_eq!(first["agentId"], "codex");
    assert_eq!(first["framework"], "codex");
    // First actionable item is the benign `cat README.md` shell call.
    assert_eq!(first["action"]["type"], "shell");
    assert_eq!(first["action"]["payload"]["command"], "cat README.md");
    // Advisory tier + provenance + session, declared in metadata.
    assert_eq!(first["metadata"]["enforcement"], "advisory");
    assert_eq!(first["metadata"]["attestation"], "live-ingest");
    assert_eq!(first["metadata"]["source"], "exec-stream");
    assert_eq!(first["metadata"]["threadId"], "0195a3f2-7c41-codex-thread");
    assert_eq!(first["metadata"]["itemId"], "item_1");

    // The MCP call keeps the gate's `<server>:<tool>` naming + protocol tag.
    let mcp = captured
        .iter()
        .find(|b| b["action"]["toolName"] == "github:create_issue")
        .expect("mcp_tool_call attested");
    assert_eq!(mcp["action"]["type"], "custom");
    assert_eq!(mcp["metadata"]["protocol"], "mcp");
}

#[tokio::test]
async fn post_hoc_attestation_is_stamped_for_replayed_captures() {
    let mock = MockSidecar::serve(allow_mock()).await;
    let config = test_config(&mock.base_url());

    let _ = ingest_lines(
        lines(&fixture(SESSION_FIXTURE)),
        &config,
        Attestation::PostHoc,
    )
    .await;

    let captured = mock.captured.lock().unwrap();
    assert_eq!(captured[0]["metadata"]["attestation"], "post-hoc");
}

#[tokio::test]
async fn real_codex_0138_stream_attests_only_completed_actions() {
    // The spike's real capture: echo (command_execution) + write out.txt
    // (file_change), interleaved with two agent_message items.
    let mock = MockSidecar::serve(allow_mock()).await;
    let config = test_config(&mock.base_url());

    let summary = ingest_lines(lines(&fixture(REAL_FIXTURE)), &config, Attestation::PostHoc).await;

    assert_eq!(summary.events, 9, "every real stream line parses");
    assert_eq!(
        summary.actionable, 2,
        "1 command_execution + 1 file_change; agent_message and lifecycle lines mint nothing"
    );
    assert_eq!(summary.attested, 2);
    assert_eq!(mock.captured.lock().unwrap().len(), 2);
    // The real items carry aggregated_output/exit_code/status, forwarded
    // opaquely; the action types still map precisely.
    let captured = mock.captured.lock().unwrap();
    let kinds: Vec<&str> = captured
        .iter()
        .filter_map(|b| b["action"]["type"].as_str())
        .collect();
    assert!(kinds.contains(&"shell"));
    assert!(kinds.contains(&"file_write"));
}

#[tokio::test]
async fn an_empty_stream_is_a_clean_zero() {
    let mock = MockSidecar::serve(allow_mock()).await;
    let config = test_config(&mock.base_url());

    let summary = ingest_lines(Vec::<String>::new(), &config, Attestation::LiveIngest).await;

    assert_eq!(summary.events, 0);
    assert_eq!(summary.actionable, 0);
    assert_eq!(exit_code(&summary), EXIT_OK);
    assert!(mock.captured.lock().unwrap().is_empty());
}

// ── resilience: an evidence plane records as much as it can ───────────────

#[tokio::test]
async fn a_malformed_line_is_skipped_counted_and_does_not_abort() {
    let mock = MockSidecar::serve(allow_mock()).await;
    let config = test_config(&mock.base_url());

    let summary = ingest_lines(
        lines(&fixture(MALFORMED_FIXTURE)),
        &config,
        Attestation::LiveIngest,
    )
    .await;

    // The bad line is counted, but the two real commands either side of it
    // are still attested — the stream keeps flowing.
    assert_eq!(summary.malformed, 1);
    assert_eq!(summary.actionable, 2);
    assert_eq!(summary.attested, 2);
    // A line we could not parse is not, by itself, an attestation gap.
    assert_eq!(summary.failed, 0);
    assert_eq!(exit_code(&summary), EXIT_OK);
}

#[tokio::test]
async fn a_block_verdict_is_recorded_and_the_stream_keeps_flowing() {
    // Advisory tier: the first action is blocked by policy, but the action
    // already ran — the verdict is recorded, never applied, and ingest does
    // not stop. The remaining items allow.
    let mock = MockSidecar::serve(Behavior::Script(vec![
        ScriptedVerdict {
            decision: "block",
            score: 95,
            reasons: vec!["no-external-egress"],
            event_id: "evt_block",
        },
        ScriptedVerdict {
            decision: "allow",
            score: 0,
            reasons: vec![],
            event_id: "evt_ok",
        },
    ]))
    .await;
    let config = test_config(&mock.base_url());

    let summary = ingest_lines(
        lines(&fixture(SESSION_FIXTURE)),
        &config,
        Attestation::LiveIngest,
    )
    .await;

    assert_eq!(summary.actionable, 5);
    assert_eq!(
        summary.attested, 5,
        "advisory attests every item, block included"
    );
    assert_eq!(summary.block, 1);
    assert_eq!(summary.allow, 4);
    assert_eq!(summary.failed, 0);
    // A recorded block is evidence, not a coverage gap.
    assert_eq!(exit_code(&summary), EXIT_OK);

    let first = &summary.records[0];
    assert_eq!(first.decision, GovernanceDecision::Block);
    assert_eq!(first.receipt_id, "evt_block");
    assert_eq!(first.item_type, "command_execution");
}

#[tokio::test]
async fn an_unreachable_sidecar_counts_failures_and_reports_a_gap() {
    // Nothing listens here; every connection is refused immediately.
    let config = test_config("http://127.0.0.1:4999");

    let summary = ingest_lines(
        lines(&fixture(SESSION_FIXTURE)),
        &config,
        Attestation::LiveIngest,
    )
    .await;

    assert_eq!(summary.actionable, 5);
    assert_eq!(summary.attested, 0);
    assert_eq!(summary.failed, 5);
    assert!(
        !summary.aborted,
        "an unreachable sidecar is per-item, not a global abort"
    );
    assert_eq!(exit_code(&summary), EXIT_GAP);
}

#[tokio::test]
async fn an_unregistered_agent_404_aborts_with_the_import_hint() {
    let mock = MockSidecar::serve(Behavior::Status(404)).await;
    let config = test_config(&mock.base_url());

    let summary = ingest_lines(
        lines(&fixture(SESSION_FIXTURE)),
        &config,
        Attestation::LiveIngest,
    )
    .await;

    // Every later call would 404 identically: bail on the first one.
    assert!(summary.aborted);
    assert_eq!(summary.attested, 0);
    assert_eq!(summary.failed, 1);
    assert_eq!(
        mock.captured.lock().unwrap().len(),
        1,
        "aborted after one attempt"
    );
    assert_eq!(exit_code(&summary), EXIT_GAP);
}

// ── end-to-end: the real binary, two input modes ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_ingests_a_file_with_demo_pasteable_output() {
    let mock = MockSidecar::serve(allow_mock()).await;

    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_iaga-codex"))
        .arg("ingest")
        .arg("--from")
        .arg(fixture_path(SESSION_FIXTURE))
        .env("IAGA_BASE_URL", mock.base_url())
        .env_remove("IAGA_API_KEY")
        .output()
        .await
        .expect("run iaga-codex ingest --from");

    assert!(
        output.status.success(),
        "a fully-allowed stream exits 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ATTESTED command_execution allow receipt="),
        "real-time ATTESTED line is emitted; got:\n{stdout}"
    );
    assert!(
        stdout.contains("INGESTED events=14 actionable=5 attested=5"),
        "final summary line is emitted; got:\n{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_spawns_a_producer_and_attests_its_stdout() {
    let mock = MockSidecar::serve(allow_mock()).await;

    // Cross-platform stand-in for `codex exec --json`: a process that prints
    // the captured stream to stdout. The plug-in spawns it after `--`.
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_iaga-codex"));
    command
        .arg("ingest")
        .arg("--")
        .env("IAGA_BASE_URL", mock.base_url())
        .env_remove("IAGA_API_KEY");
    #[cfg(windows)]
    {
        command
            .arg("cmd")
            .arg("/c")
            .arg("type")
            .arg(fixture_path(SESSION_FIXTURE));
    }
    #[cfg(not(windows))]
    {
        command.arg("cat").arg(fixture_path(SESSION_FIXTURE));
    }

    let output = command
        .output()
        .await
        .expect("run iaga-codex ingest -- <emitter>");

    assert!(
        output.status.success(),
        "emitter exits 0 and stream fully attests; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("INGESTED events=14 actionable=5 attested=5"),
        "spawned-stream summary is emitted; got:\n{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_surfaces_a_failed_spawned_command_as_exit_one() {
    let mock = MockSidecar::serve(allow_mock()).await;

    // The spawned command emits nothing and exits non-zero (Codex itself
    // failed). The ingest tally is clean (0 actionable), so the only signal
    // is the child's status: exit 1, below an I/O failure or attestation gap.
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_iaga-codex"));
    command
        .arg("ingest")
        .arg("--")
        .env("IAGA_BASE_URL", mock.base_url())
        .env_remove("IAGA_API_KEY");
    #[cfg(windows)]
    {
        command.arg("cmd").arg("/c").arg("exit").arg("1");
    }
    #[cfg(not(windows))]
    {
        command.arg("sh").arg("-c").arg("exit 1");
    }

    let output = command.output().await.expect("run failing emitter");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a non-zero child surfaces as exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("INGESTED events=0 actionable=0"),
        "an empty stream still reports a summary; got:\n{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_rejects_from_and_spawn_together() {
    // A usage contradiction: it fails before any inspect call, so no sidecar
    // is needed. `cmd` is a placeholder program that is never spawned.
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_iaga-codex"))
        .arg("ingest")
        .arg("--from")
        .arg(fixture_path(SESSION_FIXTURE))
        .arg("--")
        .arg("cmd")
        .env_remove("IAGA_BASE_URL")
        .output()
        .await
        .expect("run with conflicting inputs");

    assert_eq!(
        output.status.code(),
        Some(3),
        "choosing both --from and -- is an I/O/usage error"
    );
}
