//! End-to-end tests against the Postgres-backed `ReceiptStore`.
//!
//! Mirrors `sqlite_store.rs`. These tests need a live Postgres: they run when
//! `IAGA_SENTINEL_TEST_PG_URL` is set (CI provides a postgres:16 service
//! container) and skip cleanly otherwise, so `cargo test --features postgres`
//! still compiles and passes on machines without a database.
//!
//! The suite shares one database, so tests serialize on a lock and clear the
//! `receipts` table before running (the lesson from the 1.5.1 flaky-test fix:
//! shared state in tests must be reset and serialized).

#![cfg(feature = "postgres")]

use std::sync::OnceLock;

use iaga_sentinel_receipts::{
    chain_link, ChainStatus, PgReceiptStore, ReceiptBody, ReceiptSigner, ReceiptStore, Verdict,
};

static TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn test_lock() -> &'static tokio::sync::Mutex<()> {
    TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Opens a store against `IAGA_SENTINEL_TEST_PG_URL`, or `None` to skip.
async fn pg_store() -> Option<(PgReceiptStore, ReceiptSigner)> {
    let url = std::env::var("IAGA_SENTINEL_TEST_PG_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())?;
    let signer = ReceiptSigner::generate();
    let store = PgReceiptStore::new(&url, signer.verifying_key())
        .await
        .expect("open pg store");
    sqlx::query("DELETE FROM receipts")
        .execute(store.pool())
        .await
        .expect("clean receipts table");
    Some((store, signer))
}

fn body(signer: &ReceiptSigner, run_id: &str, seq: u64, parent: Option<String>) -> ReceiptBody {
    ReceiptBody {
        run_id: run_id.into(),
        seq,
        parent_hash: parent,
        input_hash: format!("{:064x}", seq),
        policy_hash: "p".repeat(64),
        threat_feed_hash: None,
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

async fn append_chain(
    store: &PgReceiptStore,
    signer: &ReceiptSigner,
    run_id: &str,
    count: u64,
) -> Option<iaga_sentinel_receipts::Receipt> {
    let mut head = None;
    for _ in 0..count {
        let (parent_hash, seq) = chain_link(head.as_ref()).unwrap();
        let receipt = signer.sign(body(signer, run_id, seq, parent_hash)).unwrap();
        store.append(&receipt).await.expect("append");
        head = Some(receipt);
    }
    head
}

#[tokio::test]
async fn append_and_read_back_full_chain() {
    let _guard = test_lock().lock().await;
    let Some((store, signer)) = pg_store().await else {
        eprintln!("skipped: IAGA_SENTINEL_TEST_PG_URL unset");
        return;
    };

    append_chain(&store, &signer, "run-pg", 10).await;

    let chain = store.get_run("run-pg").await.expect("get_run");
    assert_eq!(chain.len(), 10);
    for (i, r) in chain.iter().enumerate() {
        assert_eq!(r.body.seq, i as u64);
    }

    let head = store
        .head("run-pg")
        .await
        .expect("head")
        .expect("head some");
    assert_eq!(head.body.seq, 9);
}

#[tokio::test]
async fn verify_chain_valid_on_persisted_data() {
    let _guard = test_lock().lock().await;
    let Some((store, signer)) = pg_store().await else {
        eprintln!("skipped: IAGA_SENTINEL_TEST_PG_URL unset");
        return;
    };

    append_chain(&store, &signer, "run-pg-valid", 5).await;

    let status = store.verify_chain("run-pg-valid").await.expect("verify");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 5 });
}

#[tokio::test]
async fn verify_chain_detects_tamper_on_persisted_data() {
    let _guard = test_lock().lock().await;
    let Some((store, signer)) = pg_store().await else {
        eprintln!("skipped: IAGA_SENTINEL_TEST_PG_URL unset");
        return;
    };

    append_chain(&store, &signer, "run-pg-tamper", 5).await;

    // Tamper directly in the DB: overwrite the verdict of seq=2.
    sqlx::query("UPDATE receipts SET verdict='block' WHERE run_id=$1 AND seq=2")
        .bind("run-pg-tamper")
        .execute(store.pool())
        .await
        .expect("tamper update");
    // Also rewrite body_json so deserialize reflects the tamper (simulates a
    // careful attacker who modifies both columns; signatures still won't match).
    sqlx::query(
        "UPDATE receipts SET body_json = REPLACE(body_json, '\"verdict\":\"allow\"', '\"verdict\":\"block\"') \
         WHERE run_id=$1 AND seq=2",
    )
    .bind("run-pg-tamper")
    .execute(store.pool())
    .await
    .expect("tamper body_json");

    let status = store
        .verify_chain("run-pg-tamper")
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
    let _guard = test_lock().lock().await;
    let Some((store, signer)) = pg_store().await else {
        eprintln!("skipped: IAGA_SENTINEL_TEST_PG_URL unset");
        return;
    };

    append_chain(&store, &signer, "run-pg-list", 3).await;

    let runs = store.list_runs(10).await.expect("list");
    let run = runs
        .iter()
        .find(|r| r.run_id == "run-pg-list")
        .expect("run present in listing");
    assert_eq!(run.receipt_count, 3);
    assert_eq!(run.terminal_verdict, Verdict::Allow);
}

#[tokio::test]
async fn unknown_run_returns_error_on_verify() {
    let _guard = test_lock().lock().await;
    let Some((store, _signer)) = pg_store().await else {
        eprintln!("skipped: IAGA_SENTINEL_TEST_PG_URL unset");
        return;
    };

    let err = store
        .verify_chain("does-not-exist")
        .await
        .expect_err("must error");
    let msg = format!("{}", err);
    assert!(msg.contains("unknown run_id"), "unexpected: {}", msg);
}
