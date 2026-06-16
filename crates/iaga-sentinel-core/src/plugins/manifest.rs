//! Ed25519-signed plugin manifests.
//!
//! A plugin can ship a sibling `<wasm>.manifest.json` (the plugin SHA-256
//! plus identity metadata) and a detached `<wasm>.manifest.json.sig` (a
//! hex-encoded Ed25519 signature over the manifest bytes). At verify time
//! the runtime confirms the manifest's `plugin_sha256` matches the actual
//! wasm bytes and the signature verifies against a trusted key.
//!
//! Scope: this proves payload integrity and signer identity against a
//! caller-provided trusted-key list. It does NOT establish key provenance
//! or a PKI; binding a key to an organization is Enterprise work. It is
//! orthogonal to the Sigstore/SBOM attestation in `attestation.rs`: either
//! or both can be used.
//!
//! Graceful degradation: a missing or malformed manifest yields
//! `verified = false` with a reason, never a hard error, so an unsigned
//! plugin is simply "not signed" rather than a load failure.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use iaga_sentinel_receipts::{key_id_for_verifying_key, LocalDiskSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The signed payload: what the manifest commits to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifestPayload {
    pub name: String,
    pub version: String,
    /// Hex-encoded SHA-256 of the plugin wasm bytes the manifest covers.
    pub plugin_sha256: String,
    pub created_at: String,
    /// Stable id of the signing key, `ed25519-<hex16>`.
    pub signer_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Result of checking a plugin's signed manifest. Always returned (never an
/// error) so callers treat "no or invalid manifest" as "not verified".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPluginManifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<PluginManifestPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    /// True iff the manifest parsed, the plugin sha256 matched, and the
    /// signature verified against one of the trusted keys.
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Hard errors for signing and low-level signature checks.
#[derive(Debug)]
pub enum ManifestError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
    /// The signature hex was not 64 bytes of valid hex.
    BadSignature,
    /// The signature did not verify against the given key.
    SignatureInvalid,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Io(e) => write!(f, "manifest io: {e}"),
            ManifestError::Serialize(e) => write!(f, "manifest serialize: {e}"),
            ManifestError::BadSignature => write!(f, "signature is not 64 bytes of hex"),
            ManifestError::SignatureInvalid => write!(f, "signature did not verify"),
        }
    }
}

impl std::error::Error for ManifestError {}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Build `<file_name>.<suffix>` next to the plugin (no existence check).
fn sibling_path(wasm_path: &Path, suffix: &str) -> Option<PathBuf> {
    let mut p = PathBuf::from(wasm_path);
    let file_name = wasm_path.file_name()?.to_string_lossy().into_owned();
    p.set_file_name(format!("{file_name}.{suffix}"));
    Some(p)
}

/// Verify a detached Ed25519 signature (hex) over `manifest_bytes`.
pub fn verify_manifest_signature(
    manifest_bytes: &[u8],
    sig_hex: &str,
    vk: &VerifyingKey,
) -> Result<(), ManifestError> {
    let raw = hex::decode(sig_hex.trim()).map_err(|_| ManifestError::BadSignature)?;
    let arr: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| ManifestError::BadSignature)?;
    let sig = Signature::from_bytes(&arr);
    vk.verify(manifest_bytes, &sig)
        .map_err(|_| ManifestError::SignatureInvalid)
}

/// Produce a signed manifest for `wasm_path`, writing the sibling
/// `<wasm>.manifest.json` and `<wasm>.manifest.json.sig` files. Returns the
/// two paths written.
pub fn sign_manifest(
    wasm_path: &Path,
    signer: &LocalDiskSigner,
    name: &str,
    version: &str,
    created_at: &str,
) -> Result<(PathBuf, PathBuf), ManifestError> {
    let bytes = std::fs::read(wasm_path).map_err(ManifestError::Io)?;
    let payload = PluginManifestPayload {
        name: name.to_string(),
        version: version.to_string(),
        plugin_sha256: sha256_hex(&bytes),
        created_at: created_at.to_string(),
        signer_key_id: signer.key_id().to_string(),
        metadata: None,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&payload).map_err(ManifestError::Serialize)?;
    let sig = signer.sign_detached(&manifest_bytes);
    let sig_hex = hex::encode(sig.to_bytes());

    let manifest_path =
        sibling_path(wasm_path, "manifest.json").ok_or(ManifestError::BadSignature)?;
    let sig_path =
        sibling_path(wasm_path, "manifest.json.sig").ok_or(ManifestError::BadSignature)?;
    std::fs::write(&manifest_path, &manifest_bytes).map_err(ManifestError::Io)?;
    std::fs::write(&sig_path, sig_hex.as_bytes()).map_err(ManifestError::Io)?;
    Ok((manifest_path, sig_path))
}

/// Verify the signed manifest sitting next to `wasm_path` against a set of
/// trusted public keys. Never errors: a missing, malformed, mismatched, or
/// untrusted manifest yields `verified = false` with a `reason`.
pub fn verify_signed_manifest(
    wasm_path: &Path,
    trusted_keys: &[VerifyingKey],
) -> SignedPluginManifest {
    let mut out = SignedPluginManifest {
        manifest: None,
        signer_key_id: None,
        verified: false,
        reason: None,
    };

    let (Some(mpath), Some(spath)) = (
        sibling_path(wasm_path, "manifest.json").filter(|p| p.exists()),
        sibling_path(wasm_path, "manifest.json.sig").filter(|p| p.exists()),
    ) else {
        out.reason = Some("no signed manifest present".into());
        return out;
    };

    let Ok(manifest_bytes) = std::fs::read(&mpath) else {
        out.reason = Some("manifest unreadable".into());
        return out;
    };
    let Ok(payload) = serde_json::from_slice::<PluginManifestPayload>(&manifest_bytes) else {
        out.reason = Some("manifest malformed".into());
        return out;
    };
    out.signer_key_id = Some(payload.signer_key_id.clone());

    let Ok(wasm_bytes) = std::fs::read(wasm_path) else {
        out.reason = Some("plugin unreadable".into());
        out.manifest = Some(payload);
        return out;
    };
    if sha256_hex(&wasm_bytes) != payload.plugin_sha256 {
        out.reason = Some("plugin sha256 does not match manifest".into());
        out.manifest = Some(payload);
        return out;
    }

    let Ok(sig_hex) = std::fs::read_to_string(&spath) else {
        out.reason = Some("signature unreadable".into());
        out.manifest = Some(payload);
        return out;
    };

    // CRYPTO-MANIFEST-1: find the trusted key that actually verifies the
    // signature, then require its derived id to equal the manifest's *declared*
    // `signer_key_id`. The old `.any()` reported the declared id without binding
    // it to the verifying key, so with more than one trusted key a manifest
    // signed by B could declare signer=A and be reported as A.
    let verifying_key = trusted_keys
        .iter()
        .find(|vk| verify_manifest_signature(&manifest_bytes, sig_hex.trim(), vk).is_ok());

    let (verified, reason) = match verifying_key {
        None if trusted_keys.is_empty() => (false, "no trusted keys provided"),
        None => (false, "signature did not match any trusted key"),
        Some(vk) if key_id_for_verifying_key(vk) == payload.signer_key_id => {
            (true, "signature verified against the declared trusted key")
        }
        Some(_) => (
            false,
            "signature verifies but signer_key_id does not match the verifying key",
        ),
    };

    out.reason = Some(reason.into());
    out.verified = verified;
    out.manifest = Some(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use iaga_sentinel_receipts::ReceiptSigner;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_wasm(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[test]
    fn sign_then_verify_against_trusted_key() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "p.wasm", b"\x00asm\x01\x00\x00\x00");
        let signer = ReceiptSigner::generate();
        sign_manifest(&wasm, &signer, "p", "1.0.0", "2026-06-06T00:00:00Z").expect("sign");

        let result = verify_signed_manifest(&wasm, &[signer.verifying_key()]);
        assert!(result.verified, "reason: {:?}", result.reason);
        assert_eq!(result.signer_key_id.as_deref(), Some(signer.key_id()));
    }

    #[test]
    fn tampered_plugin_fails_digest_check() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "p.wasm", b"original");
        let signer = ReceiptSigner::generate();
        sign_manifest(&wasm, &signer, "p", "1.0.0", "t").expect("sign");
        // Mutate the wasm after signing.
        write_wasm(dir.path(), "p.wasm", b"tampered-bytes");
        let result = verify_signed_manifest(&wasm, &[signer.verifying_key()]);
        assert!(!result.verified);
        assert_eq!(
            result.reason.as_deref(),
            Some("plugin sha256 does not match manifest")
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "p.wasm", b"bytes");
        let signer = ReceiptSigner::generate();
        let attacker = ReceiptSigner::generate();
        sign_manifest(&wasm, &signer, "p", "1.0.0", "t").expect("sign");
        let result = verify_signed_manifest(&wasm, &[attacker.verifying_key()]);
        assert!(!result.verified);
        assert_eq!(
            result.reason.as_deref(),
            Some("signature did not match any trusted key")
        );
    }

    #[test]
    fn no_manifest_is_not_signed_gracefully() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "bare.wasm", b"bytes");
        let signer = ReceiptSigner::generate();
        let result = verify_signed_manifest(&wasm, &[signer.verifying_key()]);
        assert!(!result.verified);
        assert_eq!(result.reason.as_deref(), Some("no signed manifest present"));
    }

    #[test]
    fn empty_trusted_keys_does_not_verify() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "p.wasm", b"bytes");
        let signer = ReceiptSigner::generate();
        sign_manifest(&wasm, &signer, "p", "1.0.0", "t").expect("sign");
        let result = verify_signed_manifest(&wasm, &[]);
        assert!(!result.verified);
        assert_eq!(result.reason.as_deref(), Some("no trusted keys provided"));
    }

    #[test]
    fn spoofed_signer_key_id_is_rejected() {
        // CRYPTO-MANIFEST-1: attacker key B (also trusted) signs a manifest that
        // DECLARES victim key A's id. The signature verifies under B, but the
        // declared `signer_key_id` is bound to the verifying key, so this is
        // rejected rather than reported as signed by A.
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "p.wasm", b"\x00asm\x01\x00\x00\x00");
        let victim = ReceiptSigner::generate();
        let attacker = ReceiptSigner::generate();

        // Build a payload that lies about the signer, then sign the *lying*
        // bytes with the attacker key.
        let bytes = std::fs::read(&wasm).unwrap();
        let payload = PluginManifestPayload {
            name: "p".into(),
            version: "1.0.0".into(),
            plugin_sha256: sha256_hex(&bytes),
            created_at: "t".into(),
            signer_key_id: victim.key_id().to_string(), // the lie
            metadata: None,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&payload).unwrap();
        let sig = attacker.sign_detached(&manifest_bytes);
        std::fs::write(
            sibling_path(&wasm, "manifest.json").unwrap(),
            &manifest_bytes,
        )
        .unwrap();
        std::fs::write(
            sibling_path(&wasm, "manifest.json.sig").unwrap(),
            hex::encode(sig.to_bytes()),
        )
        .unwrap();

        // Both keys are trusted; the spoof must still be rejected.
        let result =
            verify_signed_manifest(&wasm, &[victim.verifying_key(), attacker.verifying_key()]);
        assert!(!result.verified, "spoofed signer_key_id must not verify");
        assert_eq!(
            result.reason.as_deref(),
            Some("signature verifies but signer_key_id does not match the verifying key")
        );
    }

    #[test]
    fn malformed_signature_hex_rejected() {
        let signer = ReceiptSigner::generate();
        let err = verify_manifest_signature(b"abc", "zz-not-hex", &signer.verifying_key())
            .expect_err("must reject");
        assert!(matches!(err, ManifestError::BadSignature));
    }
}
