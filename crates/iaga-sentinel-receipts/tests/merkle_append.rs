//! Merkle chain construction + verification across many receipts.

use iaga_sentinel_receipts::{
    chain_link, verify_chain, ChainStatus, Receipt, ReceiptBody, ReceiptSigner, Verdict,
};

fn build_chain(signer: &ReceiptSigner, len: u64) -> Vec<Receipt> {
    let mut chain: Vec<Receipt> = Vec::with_capacity(len as usize);
    let mut head: Option<Receipt> = None;
    for i in 0..len {
        let (parent_hash, seq) = chain_link(head.as_ref()).expect("link ok");
        let body = ReceiptBody {
            run_id: "run-merkle".into(),
            seq,
            parent_hash,
            input_hash: format!("{:064x}", i),
            policy_hash: "p".repeat(64),
            plugin_digests: vec![],
            model_digests: vec![],
            ml_scores: None,
            verdict: if i % 3 == 0 {
                Verdict::Allow
            } else if i % 3 == 1 {
                Verdict::Review
            } else {
                Verdict::Block
            },
            reasons: vec![format!("step {}", i)],
            risk_score: (i as u32) % 100,
            timestamp: format!("2026-04-23T12:00:{:02}Z", i % 60),
            signer_key_id: signer.key_id().into(),
            pipeline_inputs_capture: None,
            apl_eval_trace: None,
            ml_inference_inputs: None,
            is_authoritative: None,
        };
        let r = signer.sign(body).expect("sign ok");
        head = Some(r.clone());
        chain.push(r);
    }
    chain
}

#[test]
fn verify_valid_chain_of_100() {
    let signer = ReceiptSigner::generate();
    let chain = build_chain(&signer, 100);
    let status = verify_chain(&chain, &signer.verifying_key()).expect("verify ok");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 100 });
}

#[test]
fn empty_chain_is_empty_status() {
    let signer = ReceiptSigner::generate();
    let chain: Vec<Receipt> = vec![];
    let status = verify_chain(&chain, &signer.verifying_key()).expect("verify ok");
    assert_eq!(status, ChainStatus::Empty);
}

#[test]
fn single_receipt_chain_is_valid() {
    let signer = ReceiptSigner::generate();
    let chain = build_chain(&signer, 1);
    let status = verify_chain(&chain, &signer.verifying_key()).expect("verify ok");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 1 });
}

#[test]
fn tamper_middle_breaks_chain() {
    let signer = ReceiptSigner::generate();
    let mut chain = build_chain(&signer, 50);

    // Tamper: mutate the body of receipt 25 after the fact. Its own
    // signature will invalidate; even if we re-signed it, the next
    // receipt's parent_hash would no longer match.
    chain[25].body.reasons.push("tampered".to_string());

    let status = verify_chain(&chain, &signer.verifying_key()).expect("verify returned");
    match status {
        ChainStatus::Broken { seq, reason: _ } => {
            assert_eq!(seq, 25, "break should be at seq=25");
        }
        other => panic!("expected Broken at seq=25, got {:?}", other),
    }
}

#[test]
fn out_of_order_seq_breaks_chain() {
    let signer = ReceiptSigner::generate();
    let mut chain = build_chain(&signer, 10);
    chain.swap(3, 4);
    let status = verify_chain(&chain, &signer.verifying_key()).expect("verify returned");
    match status {
        ChainStatus::Broken { .. } => {}
        other => panic!("expected Broken, got {:?}", other),
    }
}

#[test]
fn mixed_run_ids_break_chain() {
    let signer = ReceiptSigner::generate();
    let mut chain = build_chain(&signer, 5);
    chain[2].body.run_id = "different-run".into();
    // Re-sign the mutated body so the signature is valid but run_id is wrong.
    let body = chain[2].body.clone();
    chain[2] = signer.sign(body).expect("sign ok");
    let status = verify_chain(&chain, &signer.verifying_key()).expect("verify returned");
    match status {
        ChainStatus::Broken { seq, reason: _ } => {
            assert_eq!(seq, 2);
        }
        other => panic!("expected Broken at seq=2, got {:?}", other),
    }
}
