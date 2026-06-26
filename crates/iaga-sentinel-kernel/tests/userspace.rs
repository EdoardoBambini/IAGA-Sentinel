//! UserspaceKernel behavior tests. Cross-platform: the spawn target is a
//! trivially-available shell that exits 0 regardless of environment, so the
//! tests stay green under the kernel's environment scrubbing (a tool like
//! `cargo` is a rustup proxy that needs `RUSTUP_HOME` and breaks once the env
//! is scrubbed — that brittleness, not the kernel, is what we avoid here).

use std::sync::Arc;

use iaga_sentinel_kernel::{
    EnforcementKernel, KernelDecision, PolicyCheck, ProcessSpec, UserspaceKernel,
};

/// Program name of the env-independent "exit 0" command, per platform.
#[cfg(windows)]
const OK_PROGRAM: &str = "cmd";
#[cfg(unix)]
const OK_PROGRAM: &str = "sh";

/// A command that spawns and exits 0 with only the scrubbed env allowlist
/// (`cmd` needs `SystemRoot`, `sh` needs `PATH` — both are inherited).
fn spec_ok() -> ProcessSpec {
    #[cfg(windows)]
    let args = vec!["/C".into(), "exit 0".into()];
    #[cfg(unix)]
    let args = vec!["-c".into(), "exit 0".into()];
    ProcessSpec {
        agent_id: "test-agent".into(),
        program: OK_PROGRAM.into(),
        args,
        working_dir: None,
        env: Vec::new(),
    }
}

#[tokio::test]
async fn allow_all_spawns_and_returns_exit_code() {
    let k = UserspaceKernel::allow_all();
    let out = k.launch(&spec_ok()).await.expect("launch ok");
    assert_eq!(out.decision, KernelDecision::Allow);
    assert_eq!(out.backend, "userspace");
    assert!(out.pid.is_some(), "expected pid, got {:?}", out.pid);
    assert_eq!(out.exit_code, Some(0), "the spawned command should exit 0");
}

#[tokio::test]
async fn block_policy_prevents_spawn() {
    let policy: PolicyCheck = Arc::new(|_spec: &ProcessSpec| {
        Box::pin(async { KernelDecision::Block })
            as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
    });
    let k = UserspaceKernel::new(policy);
    let out = k
        .launch(&spec_ok())
        .await
        .expect("launch returns");
    assert_eq!(out.decision, KernelDecision::Block);
    assert!(out.pid.is_none(), "blocked launch must not spawn");
    assert!(out.exit_code.is_none());
    assert!(out.reason.as_deref().unwrap_or("").contains("blocked"));
}

#[tokio::test]
async fn review_policy_holds_launch() {
    let policy: PolicyCheck = Arc::new(|_spec: &ProcessSpec| {
        Box::pin(async { KernelDecision::Review })
            as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
    });
    let k = UserspaceKernel::new(policy);
    let out = k
        .launch(&spec_ok())
        .await
        .expect("launch returns");
    assert_eq!(out.decision, KernelDecision::Review);
    assert!(out.pid.is_none());
    assert!(out.reason.as_deref().unwrap_or("").contains("review"));
}

#[tokio::test]
async fn missing_program_returns_setup_error() {
    let k = UserspaceKernel::allow_all();
    let bad = ProcessSpec {
        agent_id: "test".into(),
        program: "definitely-not-a-real-binary-12345".into(),
        args: vec![],
        working_dir: None,
        env: Vec::new(),
    };
    let result = k.launch(&bad).await;
    assert!(result.is_err(), "missing binary must produce setup error");
}

#[test]
fn userspace_kernel_reports_non_authoritative_posture() {
    let k = UserspaceKernel::allow_all();
    assert_eq!(k.backend_name(), "userspace");
    assert!(
        !k.is_authoritative(),
        "userspace enforces at the process boundary, not in the kernel"
    );
}

#[test]
fn policy_callback_sees_full_spec() {
    use std::sync::Mutex;
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_for_cb = captured.clone();
    let policy: PolicyCheck = Arc::new(move |spec: &ProcessSpec| {
        let captured = captured_for_cb.clone();
        let program = spec.program.clone();
        Box::pin(async move {
            *captured.lock().unwrap() = Some(program);
            KernelDecision::Block
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
    });
    let k = UserspaceKernel::new(policy);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let _ = k.launch(&spec_ok()).await;
    });
    assert_eq!(captured.lock().unwrap().as_deref(), Some(OK_PROGRAM));
}

// ── 1.8 unprivileged process hardening (Unix/Linux) ──
// The child reports its own confinement via exit code: exit 0 means the
// hardening that pre_exec applied before exec is visible in the child.

#[cfg(unix)]
fn spec_sh(script: &str) -> ProcessSpec {
    ProcessSpec {
        agent_id: "test-agent".into(),
        program: "sh".into(),
        args: vec!["-c".into(), script.into()],
        working_dir: None,
        env: Vec::new(),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn hardened_child_has_no_core_dumps() {
    // pre_exec sets RLIMIT_CORE=0 before exec, so the child inherits it.
    let k = UserspaceKernel::allow_all();
    let out = k
        .launch(&spec_sh(r#"[ "$(ulimit -c)" = "0" ]"#))
        .await
        .expect("launch ok");
    assert_eq!(out.decision, KernelDecision::Allow);
    assert_eq!(
        out.exit_code,
        Some(0),
        "governed child should run with RLIMIT_CORE=0 (no core dumps)"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn hardened_child_has_no_new_privs_on_linux() {
    // PR_SET_NO_NEW_PRIVS is set in pre_exec and survives exec; it surfaces as
    // `NoNewPrivs: 1` in /proc/self/status.
    let k = UserspaceKernel::allow_all();
    let out = k
        .launch(&spec_sh(
            r#"grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status"#,
        ))
        .await
        .expect("launch ok");
    assert_eq!(out.decision, KernelDecision::Allow);
    assert_eq!(
        out.exit_code,
        Some(0),
        "governed child on Linux should run with PR_SET_NO_NEW_PRIVS=1"
    );
}
