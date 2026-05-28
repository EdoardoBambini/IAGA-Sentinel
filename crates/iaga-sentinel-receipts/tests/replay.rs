//! Replay / drift-detection tests against a persisted SQLite chain.

#![cfg(feature = "sqlite")]

use iaga_sentinel_receipts::{
    chain_link, replay, verify_only, ChainStatus, CurrentOutcome, Receipt, ReceiptBody,
    ReceiptSigner, ReceiptStore, SqliteReceiptStore, Verdict,
};

async fn seed(store: &SqliteReceiptStore, signer: &ReceiptSigner, n: u64, run: &str) {
    let mut head = None;
    for i in 0..n {
        let (parent_hash, seq) = chain_link(head.as_ref()).unwrap();
        let body = ReceiptBody {
            run_id: run.into(),
            seq,
            parent_hash,
            input_hash: format!("{:064x}", i),
            policy_hash: "p".repeat(64),
            plugin_digests: vec![],
            model_digests: vec![],
            ml_scores: None,
            verdict: Verdict::Allow,
            reasons: vec![format!("reason-{}", i)],
            risk_score: 10,
            timestamp: format!("2026-04-23T12:00:{:02}Z", i % 60),
            signer_key_id: signer.key_id().into(),
            pipeline_inputs_capture: None,
            apl_eval_trace: None,
            ml_inference_inputs: None,
        };
        let receipt = signer.sign(body).unwrap();
        store.append(&receipt).await.unwrap();
        head = Some(receipt);
    }
}

async fn make() -> (SqliteReceiptStore, ReceiptSigner, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("r.db").display());
    let signer = ReceiptSigner::generate();
    let store = SqliteReceiptStore::new(&url, signer.verifying_key())
        .await
        .unwrap();
    (store, signer, dir)
}

#[tokio::test]
async fn verify_only_returns_valid_on_clean_chain() {
    let (store, signer, _dir) = make().await;
    seed(&store, &signer, 7, "runX").await;
    let status = verify_only(&store, "runX").await.unwrap();
    assert_eq!(status, ChainStatus::Valid { receipt_count: 7 });
}

#[tokio::test]
async fn replay_no_divergence_when_evaluator_matches_stored() {
    let (store, signer, _dir) = make().await;
    seed(&store, &signer, 4, "runY").await;

    let report = replay(&store, "runY", |r: &Receipt| CurrentOutcome {
        verdict: r.body.verdict,
        reasons: r.body.reasons.clone(),
    })
    .await
    .unwrap();

    assert_eq!(report.total_divergences, 0);
    assert_eq!(report.drift.len(), 4);
    for d in &report.drift {
        assert!(!d.divergent);
    }
}

#[tokio::test]
async fn replay_detects_drift_on_divergent_evaluator() {
    let (store, signer, _dir) = make().await;
    seed(&store, &signer, 3, "runZ").await;

    // Simulate "policy drift": current pipeline now blocks everything.
    let report = replay(&store, "runZ", |_r: &Receipt| CurrentOutcome {
        verdict: Verdict::Block,
        reasons: vec!["blocked by new policy".into()],
    })
    .await
    .unwrap();

    assert_eq!(report.total_divergences, 3);
    for d in &report.drift {
        assert!(d.divergent);
        assert_eq!(d.stored_verdict, Verdict::Allow);
        assert_eq!(d.current_verdict, Verdict::Block);
    }
}
