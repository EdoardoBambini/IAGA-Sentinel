//! Offline in-toto / SLSA provenance attestation for plugins.
//!
//! Generates an in-toto **Statement v1** whose subject is the plugin's SHA-256
//! and whose predicate is a minimal **SLSA Provenance v1** document, optionally
//! wrapped in an Ed25519 **DSSE** envelope signed with the local BYOK signer.
//!
//! Honest scope (ADR 0010 / 0013): this is **offline** generation. OSS cannot
//! verify hermeticity, build isolation, or provenance, so the requested SLSA
//! level is recorded as `declaredSlsaLevel` — operator-DECLARED build intent,
//! never an attested guarantee, and the disclaimer travels in-band in the
//! predicate. Verified SLSA (Rekor inclusion proof + Fulcio keyless identity)
//! remains an Enterprise feature; there is no network access here.

use std::path::Path;

use serde::Serialize;

use iaga_sentinel_receipts::LocalDiskSigner;

/// in-toto Statement type URI (v1).
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// SLSA Provenance predicate type URI (v1).
pub const SLSA_PROVENANCE_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
/// DSSE payload type for an in-toto statement.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// Build type URI: an offline, operator-declared provenance (no hermetic build
/// was observed). Distinct from any real SLSA build type on purpose.
pub const OFFLINE_DECLARED_BUILD_TYPE: &str = "https://iaga.tech/slsa/offline-declared/v1";

/// The in-band honesty note embedded in every statement, so a downstream reader
/// of the JSON cannot mistake a declared level for a verified one.
pub const DECLARED_NOTE: &str = "slsaLevel is operator-DECLARED build intent. Offline OSS attest cannot verify hermeticity, provenance, or build isolation: it signs your declaration, it does not certify it. Verified SLSA (Rekor inclusion + Fulcio keyless identity) is an Enterprise feature (ADR 0010/0013).";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    pub predicate_type: String,
    pub predicate: SlsaPredicate,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub name: String,
    pub digest: SubjectDigest,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubjectDigest {
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaPredicate {
    pub build_definition: BuildDefinition,
    pub run_details: RunDetails,
    /// Operator-DECLARED build level (1-4). NOT a verified guarantee.
    pub declared_slsa_level: u8,
    /// In-band disclaimer; see [`DECLARED_NOTE`].
    pub declared_note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDefinition {
    pub build_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetails {
    pub builder: Builder,
}

#[derive(Debug, Clone, Serialize)]
pub struct Builder {
    pub id: String,
}

/// A DSSE envelope wrapping a serialized in-toto statement.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload_type: String,
    /// Base64 of the statement JSON.
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DsseSignature {
    pub keyid: String,
    /// Base64 of the Ed25519 signature over the DSSE PAE.
    pub sig: String,
}

/// Build an in-toto/SLSA statement for `wasm_path`. Reads the plugin bytes to
/// compute the subject digest; performs no network access.
pub fn build_statement(
    wasm_path: &Path,
    name: &str,
    version: &str,
    slsa_level: u8,
) -> std::io::Result<InTotoStatement> {
    let bytes = std::fs::read(wasm_path)?;
    Ok(InTotoStatement {
        type_: INTOTO_STATEMENT_TYPE.to_string(),
        subject: vec![Subject {
            name: format!("{name}@{version}"),
            digest: SubjectDigest {
                sha256: sha256_hex(&bytes),
            },
        }],
        predicate_type: SLSA_PROVENANCE_PREDICATE_TYPE.to_string(),
        predicate: SlsaPredicate {
            build_definition: BuildDefinition {
                build_type: OFFLINE_DECLARED_BUILD_TYPE.to_string(),
            },
            run_details: RunDetails {
                builder: Builder {
                    id: format!("iaga-sentinel-cli@{}", env!("CARGO_PKG_VERSION")),
                },
            },
            declared_slsa_level: slsa_level,
            declared_note: DECLARED_NOTE.to_string(),
        },
    })
}

/// Wrap a statement in a DSSE envelope signed with the local Ed25519 signer.
pub fn wrap_dsse(
    statement: &InTotoStatement,
    signer: &LocalDiskSigner,
) -> Result<DsseEnvelope, serde_json::Error> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let payload = serde_json::to_vec(statement)?;
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE, &payload);
    let sig = signer.sign_detached(&pae);
    Ok(DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        payload: STANDARD.encode(&payload),
        signatures: vec![DsseSignature {
            keyid: signer.key_id().to_string(),
            sig: STANDARD.encode(sig.to_bytes()),
        }],
    })
}

/// DSSE Pre-Authentication Encoding (PAE), per the DSSE spec:
/// `"DSSEv1 " ‖ len(type) ‖ " " ‖ type ‖ " " ‖ len(payload) ‖ " " ‖ payload`.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_plugin(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn statement_shape_and_subject_digest() {
        let dir = tempdir().unwrap();
        let wasm = write_plugin(dir.path(), "p.wasm", b"abc");
        let s = build_statement(&wasm, "myplugin", "1.2.3", 3).unwrap();
        assert_eq!(s.type_, INTOTO_STATEMENT_TYPE);
        assert_eq!(s.predicate_type, SLSA_PROVENANCE_PREDICATE_TYPE);
        assert_eq!(s.subject.len(), 1);
        assert_eq!(s.subject[0].name, "myplugin@1.2.3");
        // sha256("abc") — the FIPS 180-4 vector.
        assert_eq!(
            s.subject[0].digest.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(s.predicate.declared_slsa_level, 3);
    }

    #[test]
    fn statement_json_labels_level_declared_not_verified() {
        let dir = tempdir().unwrap();
        let wasm = write_plugin(dir.path(), "p.wasm", b"x");
        let s = build_statement(&wasm, "p", "0.0.0", 4).unwrap();
        let v = serde_json::to_value(&s).unwrap();
        // The honesty contract: a declared level is present, the note says so,
        // and there is NO field claiming the level is verified.
        assert_eq!(v["predicate"]["declaredSlsaLevel"], 4);
        let note = v["predicate"]["declaredNote"].as_str().unwrap();
        assert!(note.contains("DECLARED"));
        assert!(note.to_lowercase().contains("not") && note.to_lowercase().contains("verif"));
        assert!(v["predicate"].get("verifiedSlsaLevel").is_none());
        assert!(v["predicate"].get("slsaLevelVerified").is_none());
    }

    #[test]
    fn dsse_envelope_roundtrips_signature() {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let dir = tempdir().unwrap();
        let wasm = write_plugin(dir.path(), "p.wasm", b"plugin-bytes");
        let statement = build_statement(&wasm, "p", "1.0.0", 2).unwrap();

        let signer = LocalDiskSigner::generate();
        let env = wrap_dsse(&statement, &signer).unwrap();

        assert_eq!(env.payload_type, DSSE_PAYLOAD_TYPE);
        assert_eq!(env.signatures.len(), 1);
        assert_eq!(env.signatures[0].keyid, signer.key_id());

        // Recompute the PAE over the decoded payload and verify the signature.
        let payload = STANDARD.decode(&env.payload).unwrap();
        let pae = dsse_pae(DSSE_PAYLOAD_TYPE, &payload);
        let sig_bytes = STANDARD.decode(&env.signatures[0].sig).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        use ed25519_dalek::Verifier;
        signer
            .verifying_key()
            .verify(&pae, &sig)
            .expect("DSSE signature must verify over the PAE");

        // The decoded payload is the exact statement we signed.
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["_type"], INTOTO_STATEMENT_TYPE);
    }
}
