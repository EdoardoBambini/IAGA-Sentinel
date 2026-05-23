//! # iaga-sentinel-kernel
//!
//! Enforcement kernel for IAGA Sentinel — Pillar 1 of the design.
//!
//! Two backends:
//!
//! - [`UserspaceKernel`] — always available on every platform. Spawns
//!   governed child processes with a scoped environment and a policy
//!   pre-check. "Soft" enforcement: a determined process can still
//!   escape the scoping, so this backend declares
//!   `is_authoritative() == false`.
//! - `BpfKernel` (feature `linux-bpf`, Linux only) — scaffold today.
//!   Same trait surface; the actual eBPF/LSM loader is not part of
//!   this OSS line.
//!
//! Hosts hold an `Arc<dyn EnforcementKernel>` and route process
//! launches through it. The trait is intentionally narrow so the
//! soft-to-hard enforcement swap is a configuration choice, not a
//! refactor.

pub mod decision;
pub mod engine;
pub mod errors;
pub mod userspace;

#[cfg(all(feature = "linux-bpf", target_os = "linux"))]
pub mod bpf;

pub use decision::{KernelDecision, LaunchOutcome, ProcessSpec};
pub use engine::{EnforcementKernel, PolicyCheck};
pub use errors::{KernelError, Result};
pub use userspace::UserspaceKernel;

#[cfg(all(feature = "linux-bpf", target_os = "linux"))]
pub use bpf::BpfKernel;
