//! Persistence trait for receipts.
//!
//! Backends live in `sqlite.rs` (feature `sqlite`) and `postgres.rs`
//! (feature `postgres`). The trait is intentionally thin — a receipt is
//! append-only once signed, so the API surface is small.

use async_trait::async_trait;

use crate::errors::Result;
use crate::receipt::{ChainStatus, Receipt, RunSummary};

#[async_trait]
pub trait ReceiptStore: Send + Sync {
    /// Append a signed receipt to the run. Implementations must reject
    /// out-of-order `seq` values and any duplicate `(run_id, seq)` pair.
    async fn append(&self, receipt: &Receipt) -> Result<()>;

    /// Head (most recent) receipt for a run, if any.
    async fn head(&self, run_id: &str) -> Result<Option<Receipt>>;

    /// Full receipt chain for a run, ordered by `seq` ascending.
    async fn get_run(&self, run_id: &str) -> Result<Vec<Receipt>>;

    /// Verify the chain end-to-end: signatures + parent_hash links.
    /// The implementation is given the verifying key via its construction;
    /// this method does not take a key to keep the trait object-safe.
    async fn verify_chain(&self, run_id: &str) -> Result<ChainStatus>;

    /// List recent runs, newest first.
    async fn list_runs(&self, limit: u32) -> Result<Vec<RunSummary>>;
}
