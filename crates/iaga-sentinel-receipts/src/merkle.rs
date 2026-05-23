//! Append-only hash chain that links receipts within a run.
//!
//! This is not a full Merkle tree — it is a linear hash chain (i.e. a
//! degenerate Merkle list) where each receipt's `parent_hash` is the
//! SHA-256 of the previous receipt's canonical body. Linear chains are
//! sufficient for per-run ordering and tamper detection; a balanced tree
//! per run would add complexity without a concrete 1.0 requirement.
//!
//! A cross-run root (batched tree over all runs for external anchoring) is
//! a 1.1 extension and deliberately out of scope here.

use crate::errors::Result;
use crate::receipt::{ChainStatus, Receipt};
use crate::signer::verify_receipt;
use ed25519_dalek::VerifyingKey;

/// Verify that a chain of receipts for a single run is intact:
/// - every signature validates against `vk`,
/// - every `parent_hash` equals the previous receipt's `body.body_hash()`,
/// - `seq` starts at 0 and is monotonically increasing by 1,
/// - all receipts share the same `run_id`.
pub fn verify_chain(receipts: &[Receipt], vk: &VerifyingKey) -> Result<ChainStatus> {
    if receipts.is_empty() {
        return Ok(ChainStatus::Empty);
    }
    let run_id = &receipts[0].body.run_id;
    let mut expected_parent: Option<String> = None;

    for (i, r) in receipts.iter().enumerate() {
        let seq = r.body.seq;

        if &r.body.run_id != run_id {
            return Ok(ChainStatus::Broken {
                seq,
                reason: format!("run_id mismatch: expected {} got {}", run_id, r.body.run_id),
            });
        }

        if seq != i as u64 {
            return Ok(ChainStatus::Broken {
                seq,
                reason: format!("non-monotonic seq: expected {} got {}", i, seq),
            });
        }

        if r.body.parent_hash != expected_parent {
            return Ok(ChainStatus::Broken {
                seq,
                reason: format!(
                    "parent_hash mismatch: expected {:?} got {:?}",
                    expected_parent, r.body.parent_hash
                ),
            });
        }

        if let Err(e) = verify_receipt(r, vk) {
            return Ok(ChainStatus::Broken {
                seq,
                reason: format!("signature invalid: {}", e),
            });
        }

        let hash = r.body.body_hash()?;
        expected_parent = Some(hex::encode(hash));
    }

    Ok(ChainStatus::Valid {
        receipt_count: receipts.len() as u64,
    })
}

/// Compute the expected `parent_hash` field for the next receipt in a run,
/// given the current head. Returns `None` if the run is empty (first receipt).
pub fn next_parent_hash(head: Option<&Receipt>) -> Result<Option<String>> {
    match head {
        None => Ok(None),
        Some(r) => Ok(Some(hex::encode(r.body.body_hash()?))),
    }
}

/// Convenience: given a head receipt (or None) and the next seq, return a
/// `(parent_hash, seq)` pair ready to be placed into a `ReceiptBody`.
pub fn chain_link(head: Option<&Receipt>) -> Result<(Option<String>, u64)> {
    let parent = next_parent_hash(head)?;
    let next_seq = head.map(|r| r.body.seq + 1).unwrap_or(0);
    Ok((parent, next_seq))
}
