//! Cross-platform enforcement kernel trait.
//!
//! Two implementations ship in 1.0:
//!
//! - [`crate::userspace::UserspaceKernel`], always available on every OS.
//!   Enforces at the process boundary: blocks disallowed launches before
//!   they start, scrubs secrets from the child's environment, and confines
//!   the spawned child with unprivileged process controls (no core dumps,
//!   own session/process-group, `PR_SET_NO_NEW_PRIVS` on Linux, reaped on
//!   drop). It does not load kernel hooks, so it cannot mediate syscalls or
//!   network egress in the kernel — that is the Enterprise tier below.
//!
//! - [`crate::bpf::BpfKernel`] (feature `linux-bpf`, `cfg(target_os = "linux")`):
//!   a scaffold today. The authoritative eBPF/LSM program loader and
//!   syscall hooks are an Enterprise implementation (ADR 0010); the trait
//!   surface is wired now so a host can opt into kernel mode at
//!   construction time without changing call sites.
//!
//! Hosts hold an `Arc<dyn EnforcementKernel>` and treat both backends
//! identically. `is_authoritative()` reports the posture truthfully:
//! `false` for the userspace backend (process-boundary enforcement, not
//! kernel-side), `true` only once an authoritative kernel backend is wired.

use async_trait::async_trait;

use crate::decision::{KernelDecision, LaunchOutcome, ProcessSpec};
use crate::errors::Result;

/// Pre-launch policy callback. The host typically wires this to the
/// governance pipeline (`execute_pipeline`); the kernel only knows
/// "allow / review / block", the why is the policy layer's job.
///
/// The callback returns a boxed future so it can run async work
/// (database lookups, ML inference, signed receipt append). The
/// kernel awaits it before deciding to spawn.
pub type PolicyCheck = std::sync::Arc<
    dyn for<'a> Fn(
            &'a ProcessSpec,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = KernelDecision> + Send + 'a>,
        > + Send
        + Sync,
>;

#[async_trait]
pub trait EnforcementKernel: Send + Sync {
    /// Apply the configured policy to `spec` and, if allowed, launch
    /// the child process. Implementations:
    /// - never panic,
    /// - never propagate hot-path errors that the host can't recover
    ///   from (a launch failure is a `LaunchOutcome { decision: Block }`,
    ///   not an `Err`),
    /// - return `Err` only for setup-time problems (missing binary,
    ///   permission denied at the OS level).
    async fn launch(&self, spec: &ProcessSpec) -> Result<LaunchOutcome>;

    /// Backend identifier for telemetry (`userspace`, `linux-bpf`).
    fn backend_name(&self) -> &'static str;

    /// Whether this backend enforces decisions in the kernel. The host
    /// advertises this in `iaga kernel status` so operators know whether
    /// they're in userspace process-boundary mode or authoritative kernel
    /// mode. The userspace backend reports `false` honestly.
    fn is_authoritative(&self) -> bool;
}
