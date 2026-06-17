//! Live GovernedTool end-to-end against a running sidecar. Ignored by default
//! (no live server in unit CI); run explicitly against a seeded sidecar:
//!
//!   IAGA_SENTINEL_OPEN_MODE=true PORT=4010 iaga serve --seed-demo &
//!   cargo test -p iaga-sentinel-mcp --test live -- --ignored

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use iaga_sentinel_integrations::SentinelError;
use iaga_sentinel_mcp::mcp::GovernedTool;

fn base_url() -> String {
    std::env::var("IAGA_BASE_URL").unwrap_or_else(|_| "http://localhost:4010".to_string())
}

#[tokio::test]
#[ignore = "requires a live sidecar (POST /v1/inspect) + seeded demo"]
async fn governed_tool_blocks_dangerous_shell_and_skips_work() {
    let tool = GovernedTool::new(base_url(), "openclaw-builder-01");
    let ran = Arc::new(AtomicBool::new(false));
    let ran_in = ran.clone();
    let err = tool
        .call(
            "shell_exec",
            serde_json::json!({ "command": "rm -rf /" }),
            async move {
                ran_in.store(true, Ordering::SeqCst);
            },
        )
        .await
        .expect_err("a destructive shell must be blocked by the live pipeline");
    assert!(!ran.load(Ordering::SeqCst), "blocked work must not run");
    assert!(
        matches!(err, SentinelError::Blocked { .. }),
        "expected Blocked from the real pipeline, got {err:?}"
    );
}
