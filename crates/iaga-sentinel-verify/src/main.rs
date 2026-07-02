//! `iaga-verify`: verify an exported IAGA Sentinel receipt chain offline.
//!
//! Usage:
//!   iaga-verify <chain.json> [--key <hex-ed25519-pubkey>]
//!   iaga-verify --conformance <dir>
//!
//! Where `<chain.json>` is produced by `iaga replay <run_id> --export`.
//! `--conformance <dir>` runs every vector listed in `<dir>/manifest.json`
//! against the expected outcome, printing PASS/FAIL per vector — the receipt
//! conformance suite ("passes the IAGA receipt suite").
//! Exit codes: 0 chain valid / all vectors pass, 1 chain broken or empty /
//! a vector failed, 2 usage error, 3 IO or parse error.

use std::process::ExitCode;

use iaga_sentinel_receipts::{ChainExport, ChainStatus};
use iaga_sentinel_verify::{verify_export, KeySource};

const USAGE: &str =
    "usage: iaga-verify <chain.json> [--key <hex-ed25519-pubkey>] | iaga-verify --conformance <dir>";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut path: Option<String> = None;
    let mut key: Option<String> = None;
    let mut conformance: Option<String> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--conformance" => match args.next() {
                Some(d) => conformance = Some(d),
                None => {
                    eprintln!("iaga-verify: --conformance needs a directory");
                    return ExitCode::from(2);
                }
            },
            "--key" | "-k" => match args.next() {
                Some(k) => key = Some(k),
                None => {
                    eprintln!("iaga-verify: --key needs a hex public key");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                println!(
                    "Verifies the Ed25519 signatures and Merkle links of a signed receipt chain."
                );
                println!(
                    "Pass --key with the expected public key to authenticate authorship; without"
                );
                println!("it the verifier trusts the key embedded in the export (self-asserted).");
                return ExitCode::SUCCESS;
            }
            other if path.is_none() => path = Some(other.to_string()),
            other => {
                eprintln!("iaga-verify: unexpected argument: {other}");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    if let Some(dir) = conformance {
        return run_conformance(&dir);
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga-verify: cannot read {path}: {e}");
            return ExitCode::from(3);
        }
    };
    let export: ChainExport = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("iaga-verify: {path} is not a valid chain export: {e}");
            return ExitCode::from(3);
        }
    };

    let (status, source) = match verify_export(&export, key.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("iaga-verify: {e}");
            return ExitCode::from(3);
        }
    };

    if source == KeySource::Embedded {
        eprintln!(
            "warning: verifying against the key embedded in the export (self-asserted). \
Pass --key with the expected public key to authenticate authorship."
        );
    }
    let key_label = match source {
        KeySource::Pinned => "pinned",
        KeySource::Embedded => "embedded",
    };

    match status {
        ChainStatus::Valid { receipt_count } => {
            // CRYPTO-EXPORT-TRUNC-7: surface the seq range so an auditor holding
            // an external expected count can spot a truncated tail. The chain is
            // genesis-rooted (verify_chain requires seq 0..N-1), so the range is
            // 0..receipt_count-1. "CHAIN OK" proves PREFIX integrity, not
            // completeness — dropping trailing receipts still verifies as a
            // shorter valid chain. Detecting tail truncation offline needs an
            // external anchor (sealed head / archival timestamp), which is
            // Enterprise (see SECURITY.md).
            let last_seq = receipt_count.saturating_sub(1);
            println!(
                "CHAIN OK  run_id={}  receipts={}  seq=0..{}  signer={}  key={}",
                export.run_id, receipt_count, last_seq, export.signer_key_id, key_label
            );
            ExitCode::SUCCESS
        }
        ChainStatus::Broken { seq, reason } => {
            eprintln!(
                "CHAIN BROKEN  run_id={}  seq={}  reason={}",
                export.run_id, seq, reason
            );
            ExitCode::from(1)
        }
        ChainStatus::Empty => {
            eprintln!("CHAIN EMPTY  run_id={}", export.run_id);
            ExitCode::from(1)
        }
    }
}

/// The one-word outcome a `ChainStatus` maps to, matching the `expect` field
/// in a conformance manifest.
fn status_word(status: &ChainStatus) -> &'static str {
    match status {
        ChainStatus::Valid { .. } => "ok",
        ChainStatus::Broken { .. } => "broken",
        ChainStatus::Empty => "empty",
    }
}

/// Run the receipt conformance suite: every vector in `<dir>/manifest.json`
/// is verified with the same `verify_export` the runtime uses and its outcome
/// compared to the manifest's `expect`. Exit 0 iff all vectors pass.
///
/// ponytail: the manifest is read as untyped JSON (no extra serde structs) and
/// each vector reuses the existing verifier — no new verification logic.
fn run_conformance(dir: &str) -> ExitCode {
    let manifest_path = format!("{dir}/manifest.json");
    let raw = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga-verify: cannot read {manifest_path}: {e}");
            return ExitCode::from(3);
        }
    };
    let manifest: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("iaga-verify: {manifest_path} is not valid JSON: {e}");
            return ExitCode::from(3);
        }
    };
    let vectors = match manifest.get("vectors").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => {
            eprintln!("iaga-verify: {manifest_path} has no `vectors` array");
            return ExitCode::from(2);
        }
    };

    let mut failures = 0usize;
    for v in vectors {
        let file = v.get("file").and_then(|f| f.as_str()).unwrap_or("");
        let expect = v.get("expect").and_then(|e| e.as_str()).unwrap_or("");
        let key = v.get("key").and_then(|k| k.as_str());
        if file.is_empty() || expect.is_empty() {
            eprintln!("FAIL  <malformed vector: needs `file` and `expect`>");
            failures += 1;
            continue;
        }

        let vec_path = format!("{dir}/{file}");
        let export: ChainExport = match std::fs::read_to_string(&vec_path)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        {
            Ok(x) => x,
            Err(e) => {
                eprintln!("FAIL  {file}  cannot load: {e}");
                failures += 1;
                continue;
            }
        };

        let got = match verify_export(&export, key) {
            Ok((status, _)) => status_word(&status).to_string(),
            Err(e) => format!("error: {e}"),
        };
        if got == expect {
            println!("PASS  {file}  {got}");
        } else {
            println!("FAIL  {file}  expected={expect}  got={got}");
            failures += 1;
        }
    }

    let total = vectors.len();
    if failures == 0 {
        println!("CONFORMANCE OK  {total}/{total} vectors passed");
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "CONFORMANCE FAILED  {}/{} vectors passed",
            total - failures,
            total
        );
        ExitCode::from(1)
    }
}
