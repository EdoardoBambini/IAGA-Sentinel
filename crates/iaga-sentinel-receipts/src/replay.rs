//! Replay engine — verify a stored receipt chain and (in future milestones)
//! re-execute the pipeline to detect policy drift.
//!
//! For M2 the replay surface is intentionally minimal:
//! - `verify_only`: load the chain and check signatures + parent_hash links.
//! - `drift_check`: accepts a caller-supplied closure that re-runs a single
//!   input through the current pipeline and returns the verdict + reasons;
//!   `replay` compares against the stored body and reports any divergence.
//!
//! Full end-to-end drift replay (with sandboxed pipeline reconstruction)
//! is refined in M5; M2 ships the data primitives.

use serde::Serialize;

use crate::errors::{ReceiptError, Result};
use crate::receipt::{ChainStatus, Receipt, Verdict};
use crate::store::ReceiptStore;

/// Per-receipt drift outcome.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DriftRecord {
    pub seq: u64,
    pub stored_verdict: Verdict,
    pub current_verdict: Verdict,
    pub stored_reasons: Vec<String>,
    pub current_reasons: Vec<String>,
    pub divergent: bool,
}

/// Aggregate replay result.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayReport {
    pub run_id: String,
    pub chain_status: ChainStatus,
    pub drift: Vec<DriftRecord>,
    pub total_divergences: u64,
}

/// Verify the chain for a run and return the `ChainStatus`. No drift check.
pub async fn verify_only(store: &dyn ReceiptStore, run_id: &str) -> Result<ChainStatus> {
    store.verify_chain(run_id).await
}

/// Outcome of re-running a single receipt's input through the current pipeline.
#[derive(Debug, Clone)]
pub struct CurrentOutcome {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

/// Full replay: verify the chain, then let the caller re-evaluate each
/// receipt through the current pipeline. `evaluator` receives the stored
/// receipt and returns the verdict the *current* pipeline would produce
/// for the same input.
pub async fn replay<F>(
    store: &dyn ReceiptStore,
    run_id: &str,
    mut evaluator: F,
) -> Result<ReplayReport>
where
    F: FnMut(&Receipt) -> CurrentOutcome,
{
    let chain_status = store.verify_chain(run_id).await?;
    let receipts = store.get_run(run_id).await?;
    if receipts.is_empty() {
        return Err(ReceiptError::UnknownRun(run_id.to_string()));
    }

    let mut drift = Vec::with_capacity(receipts.len());
    let mut divergences = 0u64;
    for r in &receipts {
        let current = evaluator(r);
        let divergent = current.verdict != r.body.verdict || current.reasons != r.body.reasons;
        if divergent {
            divergences += 1;
        }
        drift.push(DriftRecord {
            seq: r.body.seq,
            stored_verdict: r.body.verdict,
            current_verdict: current.verdict,
            stored_reasons: r.body.reasons.clone(),
            current_reasons: current.reasons,
            divergent,
        });
    }

    Ok(ReplayReport {
        run_id: run_id.to_string(),
        chain_status,
        drift,
        total_divergences: divergences,
    })
}
