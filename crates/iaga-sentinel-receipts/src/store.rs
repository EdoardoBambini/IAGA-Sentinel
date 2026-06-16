//! Persistence trait for receipts.
//!
//! Backends live in `sqlite.rs` (feature `sqlite`) and `postgres.rs`
//! (feature `postgres`). The trait is intentionally thin, a receipt is
//! append-only once signed, so the API surface is small.

use async_trait::async_trait;

use crate::errors::{ReceiptError, Result};
use crate::merkle::next_parent_hash;
use crate::receipt::{ChainStatus, Receipt, RunSummary};

/// Assert that `incoming` correctly links the current `head` of a run:
/// its `seq` must be `head.seq + 1` (or 0 for an empty run) and its
/// `parent_hash` must equal the head body hash (or `None` for an empty
/// run). Backends call this inside the append transaction, after reading
/// the head, so the persistence layer enforces the ordering contract this
/// trait documents instead of trusting the caller's convention.
///
/// Returns [`ReceiptError::ChainViolation`] on a mismatch. A duplicate
/// `seq` that *does* link the head correctly is not caught here, that
/// races to the PRIMARY KEY and surfaces as [`ReceiptError::DuplicateSeq`].
pub fn check_append_link(head: Option<&Receipt>, incoming: &Receipt) -> Result<()> {
    let expected_parent = next_parent_hash(head)?;
    let expected_seq = head.map(|r| r.body.seq + 1).unwrap_or(0);
    if incoming.body.seq != expected_seq {
        return Err(ReceiptError::ChainViolation {
            seq: incoming.body.seq,
            reason: format!("expected seq {expected_seq}, got {}", incoming.body.seq),
        });
    }
    if incoming.body.parent_hash != expected_parent {
        return Err(ReceiptError::ChainViolation {
            seq: incoming.body.seq,
            reason: format!(
                "parent_hash mismatch: expected {expected_parent:?}, got {:?}",
                incoming.body.parent_hash
            ),
        });
    }
    Ok(())
}

#[async_trait]
pub trait ReceiptStore: Send + Sync {
    /// Append a signed receipt to the run. Implementations validate the
    /// link against the current head **inside a transaction**: an
    /// out-of-order `seq` or a `parent_hash` that does not bind the head
    /// is rejected with [`ReceiptError::ChainViolation`]
    /// (via [`check_append_link`]); a duplicate `(run_id, seq)` that the
    /// PRIMARY KEY rejects surfaces as [`ReceiptError::DuplicateSeq`] so the
    /// caller can re-read the head and retry.
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
