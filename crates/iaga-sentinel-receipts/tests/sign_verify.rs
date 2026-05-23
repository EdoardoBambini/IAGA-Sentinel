//! Ed25519 sign + verify happy path + tampering negative cases.

use iaga_sentinel_receipts::{verify_receipt, Receipt, ReceiptBody, ReceiptSigner, Verdict};

fn body_template(signer_key_id: &str) -> ReceiptBody {
    ReceiptBody {
        run_id: "trace-abc".into(),
        seq: 0,
        parent_hash: None,
        input_hash: "a".repeat(64),
        policy_hash: "b".repeat(64),
        plugin_digests: vec![],
        model_digests: vec![],
        ml_scores: None,
        verdict: Verdict::Allow,
        reasons: vec!["ok".into()],
        risk_score: 10,
        timestamp: "2026-04-23T12:00:00Z".into(),
        signer_key_id: signer_key_id.into(),
    }
}

#[test]
fn sign_then_verify_roundtrip() {
    let signer = ReceiptSigner::generate();
    let body = body_template(signer.key_id());
    let receipt = signer.sign(body).expect("sign ok");
    verify_receipt(&receipt, &signer.verifying_key()).expect("verify ok");
}

#[test]
fn tampered_verdict_fails_verification() {
    let signer = ReceiptSigner::generate();
    let body = body_template(signer.key_id());
    let mut receipt = signer.sign(body).expect("sign ok");
    receipt.body.verdict = Verdict::Block; // tamper after signing
    let err =
        verify_receipt(&receipt, &signer.verifying_key()).expect_err("must fail: verdict tampered");
    let msg = format!("{}", err);
    assert!(msg.contains("signature"), "unexpected error: {}", msg);
}

#[test]
fn wrong_key_fails_verification() {
    let signer_a = ReceiptSigner::generate();
    let signer_b = ReceiptSigner::generate();
    let body = body_template(signer_a.key_id());
    let receipt = signer_a.sign(body).expect("sign ok");
    verify_receipt(&receipt, &signer_b.verifying_key()).expect_err("must fail: different key");
}

#[test]
fn sign_rejects_mismatched_key_id_in_body() {
    let signer = ReceiptSigner::generate();
    let body = body_template("ed25519-deadbeef00000000000000000000");
    let err = signer.sign(body).expect_err("mismatched key_id must fail");
    let msg = format!("{}", err);
    assert!(msg.contains("key_id"), "unexpected error: {}", msg);
}

#[test]
fn key_id_is_stable() {
    let signer = ReceiptSigner::generate();
    let id_a = signer.key_id().to_string();
    let id_b = signer.key_id().to_string();
    assert_eq!(id_a, id_b);
    assert!(id_a.starts_with("ed25519-"));
    assert_eq!(id_a.len(), "ed25519-".len() + 32); // 16 bytes hex = 32 chars
}

#[test]
fn receipt_body_hash_is_deterministic() {
    let signer = ReceiptSigner::generate();
    let body = body_template(signer.key_id());
    let h1 = body.body_hash().expect("hash ok");
    let h2 = body.body_hash().expect("hash ok");
    assert_eq!(h1, h2);
}

#[test]
fn persisted_receipt_roundtrips_through_json() {
    let signer = ReceiptSigner::generate();
    let body = body_template(signer.key_id());
    let receipt = signer.sign(body).expect("sign ok");
    let serialized = serde_json::to_string(&receipt).unwrap();
    let parsed: Receipt = serde_json::from_str(&serialized).unwrap();
    verify_receipt(&parsed, &signer.verifying_key()).expect("verify after roundtrip");
}
