//! UserspaceKernel behavior tests. Cross-platform: every spawn target
//! is a tool guaranteed to exist in a Rust developer environment.

use std::sync::Arc;

use iaga_sentinel_kernel::{EnforcementKernel, KernelDecision, PolicyCheck, ProcessSpec, UserspaceKernel};

fn spec_cargo_version() -> ProcessSpec {
    ProcessSpec {
        agent_id: "test-agent".into(),
        program: "cargo".into(),
        args: vec!["--version".into()],
        working_dir: None,
        env: Vec::new(),
    }
}

#[tokio::test]
async fn allow_all_spawns_and_returns_exit_code() {
    let k = UserspaceKernel::allow_all();
    let out = k.launch(&spec_cargo_version()).await.expect("launch ok");
    assert_eq!(out.decision, KernelDecision::Allow);
    assert_eq!(out.backend, "userspace");
    assert!(out.pid.is_some(), "expected pid, got {:?}", out.pid);
    assert_eq!(out.exit_code, Some(0), "cargo --version should exit 0");
}

#[tokio::test]
async fn block_policy_prevents_spawn() {
    let policy: PolicyCheck = Arc::new(|_spec: &ProcessSpec| {
        Box::pin(async { KernelDecision::Block })
            as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
    });
    let k = UserspaceKernel::new(policy);
    let out = k
        .launch(&spec_cargo_version())
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
        .launch(&spec_cargo_version())
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
fn userspace_kernel_advertises_soft_enforcement() {
    let k = UserspaceKernel::allow_all();
    assert_eq!(k.backend_name(), "userspace");
    assert!(!k.is_authoritative(), "userspace is soft enforcement");
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
        let _ = k.launch(&spec_cargo_version()).await;
    });
    assert_eq!(captured.lock().unwrap().as_deref(), Some("cargo"));
}
