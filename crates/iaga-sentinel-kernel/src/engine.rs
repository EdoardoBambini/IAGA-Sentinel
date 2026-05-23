//! Cross-platform enforcement kernel trait.
//!
//! Two implementations ship in 1.0:
//!
//! - [`crate::userspace::UserspaceKernel`] — always available. Spawns
//!   the child process under the host's existing privileges, with
//!   environment + working-dir scoping. No kernel hooks. This is
//!   "soft" enforcement: it works on macOS, Windows and Linux, but
//!   a determined process can still escape it.
//!
//! - [`crate::bpf::BpfKernel`] (feature `linux-bpf`, `cfg(target_os = "linux")`)
//!   — scaffold today. The actual eBPF LSM program loader and
//!   syscall hooks land in M4.1 (requires bpf-linker + LLVM 18+,
//!   which the build host doesn't ship by default). The trait
//!   surface is wired now so the host can opt into kernel mode at
//!   construction time.
//!
//! Hosts hold an `Arc<dyn EnforcementKernel>` and treat both backends
//! identically. Decisions are advisory in the userspace path and
//! authoritative once `BpfKernel` lands.

use async_trait::async_trait;

use crate::decision::{KernelDecision, LaunchOutcome, ProcessSpec};
use crate::errors::Result;

/// Pre-launch policy callback. The host typically wires this to the
/// governance pipeline (`execute_pipeline`); the kernel only knows
/// "allow / review / block" — the why is the policy layer's job.
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

    /// Whether this backend enforces decisions in the kernel. The
    /// host advertises this in `iaga kernel status` so operators
    /// know whether they're in soft or hard mode.
    fn is_authoritative(&self) -> bool;
}
