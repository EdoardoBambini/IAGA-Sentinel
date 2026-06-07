//! eBPF/LSM enforcement scaffold (Linux-only, feature `linux-bpf`).
//!
//! **Status: scaffold only.** The actual eBPF program loader, LSM hook
//! attachment, and ringbuf-based event delivery are tracked for M4.1.
//! That work needs `bpf-linker` + LLVM 18+ on the build host plus a
//! kernel ≥ 5.13 at runtime, neither is assumed by 1.0-alpha CI.
//!
//! What this file ships today:
//! - The `BpfKernel` type with the same trait surface as
//!   [`crate::userspace::UserspaceKernel`], so the host can construct
//!   either one and pass it through `Arc<dyn EnforcementKernel>` with
//!   no further branching.
//! - A `not_ready` decision policy: every launch returns `Block` with
//!   reason "linux-bpf scaffold; loader pending M4.1". This is honest:
//!   we don't pretend to enforce anything until the loader exists.
//!
//! Why ship the scaffold now: locking the trait shape early lets M4.1
//! be a pure additive change (load programs, attach hooks, deliver
//! events) without touching the host call sites in `iaga-sentinel-core`.

#![cfg(all(feature = "linux-bpf", target_os = "linux"))]

use async_trait::async_trait;

use crate::decision::{KernelDecision, LaunchOutcome, ProcessSpec};
use crate::engine::EnforcementKernel;
use crate::errors::Result;

pub struct BpfKernel {
    _private: (),
}

impl BpfKernel {
    /// Construct the scaffold kernel. In M4.1 this becomes
    /// `BpfKernel::load(program_blob: &[u8])` and attaches LSM hooks.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for BpfKernel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforcementKernel for BpfKernel {
    async fn launch(&self, _spec: &ProcessSpec) -> Result<LaunchOutcome> {
        // Honest scaffold: we say no until the real loader lands.
        Ok(LaunchOutcome {
            decision: KernelDecision::Block,
            reason: Some("linux-bpf scaffold active; LSM loader pending M4.1".into()),
            pid: None,
            exit_code: None,
            backend: self.backend_name(),
        })
    }

    fn backend_name(&self) -> &'static str {
        "linux-bpf"
    }

    fn is_authoritative(&self) -> bool {
        // Will become true once the LSM hooks are attached. Today the
        // honest answer is no: there is no kernel-side enforcement yet.
        false
    }
}
