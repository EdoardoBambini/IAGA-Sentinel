//! Emit a deterministic, signed `ChainExport` as JSON on stdout.
//!
//! This is the cross-language conformance vector: a chain signed by the
//! canonical Rust code, against which non-Rust verifiers (the Python
//! `iaga_verify`, the Node `verify.mjs`) are checked for byte-for-byte
//! parity. A fixed key seed + fixed field values make the output stable, so
//! the committed `sdks/conformance/golden_chain.json` is reproducible:
//!
//!   cargo run -p iaga-sentinel-verify --example emit_golden_export \
//!     > sdks/conformance/golden_chain.json
//!
//! The bodies deliberately exercise the canonicalization edge cases a
//! dependency-free re-serializer must get right:
//!
//! - genesis `parent_hash: null`, Allow/Review/Block verdicts;
//! - empty vs non-empty `reasons`, elided vs present `threat_feed_hash`;
//! - `plugin_digests` / `model_digests` arrays-of-objects, with optional
//!   fields (`attested`, `attestation_issuer`) present and elided;
//! - a nested **camelCase** `apl_eval_trace` object, both with all fields
//!   present and with inner fields elided (`policiesFired` empty,
//!   `evidenceSha256` absent);
//! - `is_authoritative: false` every OSS receipt carries.
//!
//! No floating-point fields (`ml_scores`) — those are the one shape the
//! dependency-free re-serializers refuse rather than risk a divergent verdict.

use ed25519_dalek::{Signer, SigningKey};
use iaga_sentinel_receipts::{
    chain_link, key_id_for_verifying_key, ChainExport, DictumEvalTrace, ModelDigest, PluginDigest,
    Receipt, ReceiptBody, Verdict,
};

fn sign(sk: &SigningKey, body: ReceiptBody) -> Receipt {
    let bytes = body.signing_bytes().expect("signing_bytes");
    let sig = sk.sign(&bytes);
    Receipt {
        body,
        signature: hex::encode(sig.to_bytes()),
    }
}

#[allow(clippy::too_many_arguments)]
fn mk(
    run_id: &str,
    key_id: &str,
    head: Option<&Receipt>,
    i: usize,
    verdict: Verdict,
    reasons: Vec<String>,
    risk_score: u32,
    threat_feed_hash: Option<String>,
    plugin_digests: Vec<PluginDigest>,
    model_digests: Vec<ModelDigest>,
    apl_eval_trace: Option<DictumEvalTrace>,
) -> ReceiptBody {
    let (parent_hash, seq) = chain_link(head).expect("chain link");
    ReceiptBody {
        run_id: run_id.to_string(),
        seq,
        parent_hash,
        input_hash: format!("{:064x}", i),
        policy_hash: "0a".repeat(32),
        threat_feed_hash,
        plugin_digests,
        model_digests,
        ml_scores: None,
        verdict,
        reasons,
        risk_score,
        timestamp: format!("2026-06-16T10:00:{:02}Z", i),
        signer_key_id: key_id.to_string(),
        pipeline_inputs_capture: None,
        apl_eval_trace,
        ml_inference_inputs: None,
        is_authoritative: Some(false),
        usage: None,
    }
}

fn main() {
    // Fixed seed → deterministic key → stable, committable golden vector.
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();
    let key_id = key_id_for_verifying_key(&vk);
    let run_id = "run-golden".to_string();

    let mut receipts: Vec<Receipt> = Vec::new();

    // seq 0 — flat genesis (parent_hash null).
    let b = mk(
        &run_id,
        &key_id,
        None,
        0,
        Verdict::Allow,
        vec![],
        4,
        None,
        vec![],
        vec![],
        None,
    );
    receipts.push(sign(&sk, b));

    // seq 1 — array-of-objects (plugin_digests) with optional fields present + elided.
    let b = mk(
        &run_id,
        &key_id,
        receipts.last(),
        1,
        Verdict::Review,
        vec!["off-hours access".to_string()],
        41,
        Some("ab".repeat(32)),
        vec![
            PluginDigest {
                name: "pii-scan".to_string(),
                sha256: "11".repeat(32),
                attested: Some(true),
                attestation_issuer: None,
            },
            PluginDigest {
                name: "url-host".to_string(),
                sha256: "22".repeat(32),
                attested: None,
                attestation_issuer: None,
            },
        ],
        vec![],
        None,
    );
    receipts.push(sign(&sk, b));

    // seq 2 — nested camelCase object (apl_eval_trace) all-present + model_digests array.
    let b = mk(
        &run_id,
        &key_id,
        receipts.last(),
        2,
        Verdict::Block,
        vec![
            "secret egress detected".to_string(),
            "destination outside workspace allowlist".to_string(),
        ],
        81,
        Some("cd".repeat(32)),
        vec![],
        vec![ModelDigest {
            name: "prompt-injection".to_string(),
            sha256: "33".repeat(32),
        }],
        Some(DictumEvalTrace {
            policy_hash: "44".repeat(32),
            policies_evaluated: 3,
            policies_fired: vec!["no-pii-egress".to_string()],
            evidence_sha256: Some("55".repeat(32)),
        }),
    );
    receipts.push(sign(&sk, b));

    // seq 3 — nested object with INNER elision (policiesFired empty, evidenceSha256 absent).
    let b = mk(
        &run_id,
        &key_id,
        receipts.last(),
        3,
        Verdict::Allow,
        vec![],
        7,
        None,
        vec![],
        vec![],
        Some(DictumEvalTrace {
            policy_hash: "66".repeat(32),
            policies_evaluated: 1,
            policies_fired: vec![],
            evidence_sha256: None,
        }),
    );
    receipts.push(sign(&sk, b));

    let export = ChainExport {
        run_id,
        signer_key_id: key_id,
        signer_verifying_key: hex::encode(vk.to_bytes()),
        receipts,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&export).expect("serialize export")
    );
}
