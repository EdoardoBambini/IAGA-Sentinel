//! # iaga-sentinel-receipts
//!
//! Ed25519-signed action receipts for IAGA Sentinel 1.0 (M2 "Signed Receipts").
//!
//! Every governance verdict produced by the IAGA Sentinel pipeline is recorded as a
//! `Receipt`: a signed, canonically-serialized JSON object linked to the
//! previous receipt of the same run via `parent_hash`. Together the receipts
//! of a run form an append-only hash chain that can be verified end-to-end
//! with a single public key, and replayed against the current pipeline to
//! detect policy drift.
//!
//! Design notes:
//! - **Crypto**: Ed25519 via `ed25519-dalek`, SHA-256 via `sha2`.
//! - **Determinism**: canonical JSON via struct field order (no HashMaps).
//! - **No dep on `iaga-sentinel-core`**: this crate is a *library*; the core
//!   depends on it, not the other way around.
//! - **Backends**: SQLite and Postgres behind feature flags; the trait is
//!   object-safe so the host passes `Arc<dyn ReceiptStore>`.
//! - **Scope**: single-run linear chain. Cross-run batched Merkle anchors
//!   and KMS integration are 1.1 extensions.

pub mod errors;
pub mod export;
pub mod merkle;
pub mod receipt;
pub mod replay;
pub mod signer;
pub mod store;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

// ── public re-exports ──
pub use errors::{ReceiptError, Result};
pub use export::ChainExport;
pub use merkle::{chain_link, next_parent_hash, verify_chain};
pub use receipt::{
    ChainStatus, DictumEvalTrace, MlInferenceInputs, MlScoreBundle, MlTokenDigest, ModelDigest,
    PipelineInputsCapture, PluginDigest, Receipt, ReceiptBody, RunSummary, Verdict,
};
pub use replay::{replay, verify_only, CurrentOutcome, DriftRecord, ReplayReport};
pub use signer::{verify_receipt, LocalDiskSigner, ReceiptSigner, Signer};
pub use store::ReceiptStore;

// Cost/usage types embedded in `ReceiptBody`, re-exported so consumers can use
// them without depending on `iaga-sentinel-cost` directly.
pub use iaga_sentinel_cost::{CostSource, UsageData, UsageReport};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteReceiptStore;

#[cfg(feature = "postgres")]
pub use postgres::PgReceiptStore;
