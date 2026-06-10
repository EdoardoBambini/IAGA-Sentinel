//! End-to-end tests against the SQLite-backed `ReceiptStore`.

#![cfg(feature = "sqlite")]

use iaga_sentinel_receipts::{
    chain_link, ChainStatus, ReceiptBody, ReceiptSigner, ReceiptStore, SqliteReceiptStore, Verdict,
};

async fn make_store() -> (SqliteReceiptStore, ReceiptSigner, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("receipts.db");
    // sqlx sqlite url needs the `?mode=rwc` to create if missing on all platforms.
    let url = format!("sqlite://{}?mode=rwc", db_path.display());
    let signer = ReceiptSigner::generate();
    let store = SqliteReceiptStore::new(&url, signer.verifying_key())
        .await
        .expect("open store");
    (store, signer, dir)
}

fn body(signer: &ReceiptSigner, seq: u64, parent: Option<String>) -> ReceiptBody {
    ReceiptBody {
        run_id: "run-sqlite".into(),
        seq,
        parent_hash: parent,
        input_hash: format!("{:064x}", seq),
        policy_hash: "p".repeat(64),
        plugin_digests: vec![],
        model_digests: vec![],
        ml_scores: None,
        verdict: Verdict::Allow,
        reasons: vec![],
        risk_score: 0,
        timestamp: format!("2026-04-23T12:00:{:02}Z", seq % 60),
        signer_key_id: signer.key_id().into(),
        pipeline_inputs_capture: None,
        apl_eval_trace: None,
        ml_inference_inputs: None,
        is_authoritative: None,
        usage: None,
    }
}

#[tokio::test]
async fn append_and_read_back_full_chain() {
    let (store, signer, _dir) = make_store().await;

    let mut head = None;
    for i in 0..10u64 {
        let (parent_hash, seq) = chain_link(head.as_ref()).unwrap();
        assert_eq!(seq, i);
        let receipt = signer.sign(body(&signer, seq, parent_hash)).unwrap();
        store.append(&receipt).await.expect("append");
        head = Some(receipt);
    }

    let chain = store.get_run("run-sqlite").await.expect("get_run");
    assert_eq!(chain.len(), 10);
    for (i, r) in chain.iter().enumerate() {
        assert_eq!(r.body.seq, i as u64);
    }

    let head = store
        .head("run-sqlite")
        .await
        .expect("head")
        .expect("head some");
    assert_eq!(head.body.seq, 9);
}

#[tokio::test]
async fn verify_chain_valid_on_persisted_data() {
    let (store, signer, _dir) = make_store().await;

    let mut head = None;
    for _ in 0..5 {
        let (parent_hash, seq) = chain_link(head.as_ref()).unwrap();
        let receipt = signer.sign(body(&signer, seq, parent_hash)).unwrap();
        store.append(&receipt).await.unwrap();
        head = Some(receipt);
    }

    let status = store.verify_chain("run-sqlite").await.expect("verify");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 5 });
}

#[tokio::test]
async fn verify_chain_detects_tamper_on_persisted_data() {
    let (store, signer, _dir) = make_store().await;

    let mut head = None;
    for _ in 0..5 {
        let (parent_hash, seq) = chain_link(head.as_ref()).unwrap();
        let receipt = signer.sign(body(&signer, seq, parent_hash)).unwrap();
        store.append(&receipt).await.unwrap();
        head = Some(receipt);
    }

    // Tamper directly in the DB: overwrite the verdict of seq=2.
    sqlx::query("UPDATE receipts SET verdict='block' WHERE run_id=? AND seq=2")
        .bind("run-sqlite")
        .execute(store.pool())
        .await
        .expect("tamper update");
    // Also rewrite body_json so deserialize reflects the tamper (simulates a
    // careful attacker who modifies both columns; signatures still won't match).
    sqlx::query(
        "UPDATE receipts SET body_json = REPLACE(body_json, '\"verdict\":\"allow\"', '\"verdict\":\"block\"') \
         WHERE run_id=? AND seq=2",
    )
    .bind("run-sqlite")
    .execute(store.pool())
    .await
    .expect("tamper body_json");

    let status = store
        .verify_chain("run-sqlite")
        .await
        .expect("verify returns");
    match status {
        ChainStatus::Broken { seq, reason: _ } => {
            assert_eq!(seq, 2, "break must be at tampered receipt");
        }
        other => panic!("expected Broken, got {:?}", other),
    }
}

#[tokio::test]
async fn list_runs_returns_summary() {
    let (store, signer, _dir) = make_store().await;

    let mut head = None;
    for _ in 0..3 {
        let (parent_hash, seq) = chain_link(head.as_ref()).unwrap();
        let receipt = signer.sign(body(&signer, seq, parent_hash)).unwrap();
        store.append(&receipt).await.unwrap();
        head = Some(receipt);
    }

    let runs = store.list_runs(10).await.expect("list");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, "run-sqlite");
    assert_eq!(runs[0].receipt_count, 3);
    assert_eq!(runs[0].terminal_verdict, Verdict::Allow);
}

#[tokio::test]
async fn unknown_run_returns_error_on_verify() {
    let (store, _signer, _dir) = make_store().await;
    let err = store
        .verify_chain("does-not-exist")
        .await
        .expect_err("must error");
    let msg = format!("{}", err);
    assert!(msg.contains("unknown run_id"), "unexpected: {}", msg);
}
