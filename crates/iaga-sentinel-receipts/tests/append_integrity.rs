//! Store-level append integrity (SND-APPEND-NOCHECK / SND-APPEND-RACE).
//!
//! The persistence layer, not just the `SignedReceiptLogger` convention, now
//! enforces the chain contract: an out-of-order `seq` or a `parent_hash` that
//! does not bind the current head is rejected with `ChainViolation` inside the
//! append transaction, and a concurrent `(run_id, seq)` collision surfaces as
//! a distinct `DuplicateSeq` (retryable) instead of corrupting the chain.

#![cfg(feature = "sqlite")]

use std::sync::Arc;

use iaga_sentinel_receipts::{
    chain_link, ChainStatus, Receipt, ReceiptBody, ReceiptError, ReceiptSigner, ReceiptStore,
    SqliteReceiptStore, Verdict,
};

fn signed(signer: &ReceiptSigner, run_id: &str, seq: u64, parent: Option<String>) -> Receipt {
    let body = ReceiptBody {
        run_id: run_id.into(),
        seq,
        parent_hash: parent,
        input_hash: format!("{seq:064x}"),
        policy_hash: "p".repeat(64),
        threat_feed_hash: None,
        plugin_digests: vec![],
        model_digests: vec![],
        ml_scores: None,
        verdict: Verdict::Allow,
        reasons: vec![],
        risk_score: 0,
        timestamp: "2026-06-16T00:00:00Z".into(),
        signer_key_id: signer.key_id().into(),
        pipeline_inputs_capture: None,
        apl_eval_trace: None,
        ml_inference_inputs: None,
        is_authoritative: None,
        usage: None,
    };
    signer.sign(body).expect("sign ok")
}

async fn file_store() -> (Arc<SqliteReceiptStore>, ReceiptSigner, tempfile::TempDir) {
    let signer = ReceiptSigner::generate();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("receipts.db");
    // `sqlite:<path>?mode=rwc` (no `//` authority); forward slashes are
    // accepted by SQLite on every platform, including Windows.
    let url = format!(
        "sqlite:{}?mode=rwc",
        path.to_string_lossy().replace('\\', "/")
    );
    let store = SqliteReceiptStore::new(&url, signer.verifying_key())
        .await
        .expect("open store");
    (Arc::new(store), signer, dir)
}

#[tokio::test]
async fn out_of_order_seq_is_chain_violation() {
    let (store, signer, _dir) = file_store().await;
    store
        .append(&signed(&signer, "run", 0, None))
        .await
        .expect("seq0 ok");

    // Skip seq=1: present a seq=5 with a bogus parent. The store must reject it.
    let err = store
        .append(&signed(&signer, "run", 5, Some("0".repeat(64))))
        .await
        .expect_err("must reject out-of-order seq");
    assert!(
        matches!(err, ReceiptError::ChainViolation { seq: 5, .. }),
        "expected ChainViolation at seq=5, got {err:?}"
    );
}

#[tokio::test]
async fn wrong_parent_hash_is_chain_violation() {
    let (store, signer, _dir) = file_store().await;
    store
        .append(&signed(&signer, "run", 0, None))
        .await
        .expect("seq0 ok");

    // Correct seq (1) but a parent_hash that does not bind head seq0.
    let err = store
        .append(&signed(&signer, "run", 1, Some("f".repeat(64))))
        .await
        .expect_err("must reject bad parent");
    assert!(
        matches!(err, ReceiptError::ChainViolation { seq: 1, .. }),
        "expected ChainViolation at seq=1, got {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_seq_rejects_one_chain_stays_intact() {
    let (store, signer, _dir) = file_store().await;
    store
        .append(&signed(&signer, "run", 0, None))
        .await
        .expect("seq0 ok");

    let head = store.head("run").await.expect("head").expect("some head");
    let (parent, seq) = chain_link(Some(&head)).expect("link");
    assert_eq!(seq, 1);

    // Two writers both try to land seq=1 linking head seq0.
    let a = {
        let store = store.clone();
        let r = signed(&signer, "run", seq, parent.clone());
        tokio::spawn(async move { store.append(&r).await })
    };
    let b = {
        let store = store.clone();
        let r = signed(&signer, "run", seq, parent.clone());
        tokio::spawn(async move { store.append(&r).await })
    };
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());

    // Exactly one wins; the loser is rejected (DuplicateSeq under the race, or
    // ChainViolation if it read the head after the winner committed) — never
    // silently accepted.
    let oks = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1, "exactly one append must win: ra={ra:?} rb={rb:?}");
    let loser = if ra.is_err() { &ra } else { &rb };
    let err = loser.as_ref().unwrap_err();
    assert!(
        matches!(
            err,
            ReceiptError::DuplicateSeq { .. } | ReceiptError::ChainViolation { .. }
        ),
        "loser must be a clean rejection, got {err:?}"
    );

    // The chain is intact: exactly two receipts (seq 0, 1) and verify passes.
    let status = store.verify_chain("run").await.expect("verify");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 2 });
}
