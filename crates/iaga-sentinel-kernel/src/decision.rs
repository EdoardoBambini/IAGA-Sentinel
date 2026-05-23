//! Decision types exchanged between the kernel and its consumers.
//!
//! The kernel speaks `KernelDecision`; the host translates that into a
//! `GovernanceDecision` (in `iaga-sentinel-core`) before any user-facing message.

use serde::{Deserialize, Serialize};

/// Outcome of a pre-execution governance check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KernelDecision {
    /// The host may launch the process. May still be sandboxed.
    Allow,
    /// The host must hold the launch and surface a review request.
    Review,
    /// The kernel refused. The host must not launch the process.
    Block,
}

/// Description of a process the host wants to launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSpec {
    /// Agent identity that will own this process for governance purposes.
    pub agent_id: String,
    /// Absolute or PATH-resolvable program name.
    pub program: String,
    /// Arguments, not including argv[0].
    pub args: Vec<String>,
    /// Optional working directory; `None` means inherit.
    pub working_dir: Option<String>,
    /// Optional environment override; entries here replace the
    /// inherited environment for the child.
    pub env: Vec<(String, String)>,
}

/// Result of a governed launch. Kept narrow so it can travel cleanly
/// between userspace and (in M4.1) the eBPF datapath.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchOutcome {
    pub decision: KernelDecision,
    pub reason: Option<String>,
    /// PID of the spawned process, if any. `None` when the kernel
    /// blocked the launch.
    pub pid: Option<u32>,
    /// Exit code of the child. `None` when the launch was blocked,
    /// held for review, or the child was killed by a signal (Unix).
    pub exit_code: Option<i32>,
    /// Backend name (`userspace`, `linux-bpf`, ...) — useful for ops.
    pub backend: &'static str,
}
