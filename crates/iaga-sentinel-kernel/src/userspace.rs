//! Cross-platform userspace launcher. Always available, "soft" enforcement.
//!
//! What it does:
//! - Runs the policy callback before spawning anything. If the policy
//!   says `Block`, the child never starts.
//! - Spawns the child via `tokio::process::Command` with a scoped
//!   environment (only entries explicitly listed in `ProcessSpec.env`
//!   plus a small allowlist of inherited vars: `PATH`, `HOME`,
//!   `SystemRoot` on Windows). No accidental leakage of secrets the
//!   host happens to have in its env.
//! - Sets the working directory if specified.
//!
//! What it does NOT do (deliberate, deferred to `BpfKernel`):
//! - Restrict syscalls.
//! - Prevent `execve` of arbitrary binaries the child decides to run.
//! - Cap network egress at the kernel layer.
//! - Mediate filesystem access beyond what cwd + env can express.
//!
//! For all of that you want the eBPF LSM backend (M4.1).

use std::collections::HashMap;
use std::process::Stdio;

use async_trait::async_trait;

use crate::decision::{KernelDecision, LaunchOutcome, ProcessSpec};
use crate::engine::{EnforcementKernel, PolicyCheck};
use crate::errors::{KernelError, Result};

/// Environment variables that are inherited from the parent unless the
/// `ProcessSpec.env` explicitly overrides them. Conservatively small
/// so secrets in the parent's env can't leak into the agent's child.
const INHERITED_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "USERNAME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SystemRoot",  // Windows
    "USERPROFILE", // Windows
    "TEMP",        // Windows
    "TMPDIR",      // Unix
];

pub struct UserspaceKernel {
    policy: PolicyCheck,
}

impl UserspaceKernel {
    pub fn new(policy: PolicyCheck) -> Self {
        Self { policy }
    }

    /// Construct with a permissive default policy that always allows.
    /// Useful for tests and for hosts that intentionally want a
    /// no-op kernel (e.g. development).
    pub fn allow_all() -> Self {
        let policy: PolicyCheck = std::sync::Arc::new(|_spec: &ProcessSpec| {
            Box::pin(async { KernelDecision::Allow })
                as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
        });
        Self { policy }
    }

    fn build_env(spec: &ProcessSpec) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = HashMap::new();
        for key in INHERITED_ENV_ALLOWLIST {
            if let Ok(v) = std::env::var(key) {
                env.insert((*key).to_string(), v);
            }
        }
        for (k, v) in &spec.env {
            env.insert(k.clone(), v.clone());
        }
        env
    }
}

#[async_trait]
impl EnforcementKernel for UserspaceKernel {
    async fn launch(&self, spec: &ProcessSpec) -> Result<LaunchOutcome> {
        let decision = (self.policy)(spec).await;
        if matches!(decision, KernelDecision::Block) {
            return Ok(LaunchOutcome {
                decision,
                reason: Some("policy blocked launch".into()),
                pid: None,
                exit_code: None,
                backend: self.backend_name(),
            });
        }
        if matches!(decision, KernelDecision::Review) {
            // The host is responsible for surfacing the review request
            // and either approving or rejecting. The userspace kernel
            // does not hold the launch on its own.
            return Ok(LaunchOutcome {
                decision,
                reason: Some("policy held launch for human review".into()),
                pid: None,
                exit_code: None,
                backend: self.backend_name(),
            });
        }

        let mut cmd = tokio::process::Command::new(&spec.program);
        cmd.args(&spec.args);
        cmd.env_clear();
        for (k, v) in Self::build_env(spec) {
            cmd.env(k, v);
        }
        if let Some(cwd) = &spec.working_dir {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        let mut child = cmd.spawn().map_err(|e| KernelError::Spawn {
            program: spec.program.clone(),
            msg: e.to_string(),
        })?;
        let pid = child.id();

        // For M4 we wait synchronously on the child so the receipt
        // for the launch can record the final exit code. Long-lived
        // detached agents are an M4.1 use case (host owns the handle).
        let status = child.wait().await.map_err(|e| KernelError::Spawn {
            program: spec.program.clone(),
            msg: format!("wait failed: {}", e),
        })?;

        Ok(LaunchOutcome {
            decision,
            reason: None,
            pid,
            exit_code: status.code(),
            backend: self.backend_name(),
        })
    }

    fn backend_name(&self) -> &'static str {
        "userspace"
    }

    fn is_authoritative(&self) -> bool {
        false
    }
}
