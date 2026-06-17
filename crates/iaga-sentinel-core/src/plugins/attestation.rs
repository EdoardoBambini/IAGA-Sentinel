//! OSS 1.2, offline Sigstore bundle + CycloneDX SBOM attestation
//! primitive for plugin supply-chain integrity.
//!
//! Scope (ADR 0013, ADR 0010 §3):
//!
//! - Detect attestation **presence**: sibling `<wasm>.sigstore.json`
//!   and `<wasm>.cdx.json` files are searched alongside each plugin.
//! - **Offline structural verification**: the Sigstore bundle JSON is
//!   parsed for well-formedness and the embedded payload digest is
//!   compared bit-exact to the SHA-256 of the WASM file.
//! - **CycloneDX 1.5 SBOM**: the `components[]` array is counted and
//!   the `specVersion` is exposed.
//!
//! Explicitly **not in scope** (Enterprise differentiation per ADR 0010):
//!
//! - Online Rekor inclusion-proof verification (network).
//! - Fulcio root CA chain validation (would require X.509 parsing).
//! - Issuer / SAN extraction from cert (X.509 parsing).
//! - Hosted plugin marketplace API.
//! - Supply-chain SLA telemetry, threat-intel correlation, signed
//!   threat-feed integration.
//!
//! For full chain-of-trust verification (Rekor proof + Fulcio root
//! attestation + cert identity binding) the host should run `cosign
//! verify` out-of-band, or upgrade to IAGA Sentinel Enterprise which
//! ships the hosted marketplace with curated supply-chain SLA.

use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Result of an offline attestation check on a single plugin file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginAttestation {
    /// Hex-encoded SHA-256 of the plugin bytes (always populated when
    /// the wasm file is readable).
    pub plugin_sha256: String,
    /// Path to the sibling `<wasm>.sigstore.json` bundle file, if found.
    pub bundle_path: Option<PathBuf>,
    /// Path to the sibling `<wasm>.cdx.json` CycloneDX SBOM, if found.
    pub sbom_path: Option<PathBuf>,
    /// `true` iff the bundle is a well-formed Sigstore JSON envelope
    /// (we recognize either the v0.3 schema or the legacy cosign
    /// bundle v0.1 schema).
    pub bundle_well_formed: bool,
    /// `true` iff the payload digest embedded in the bundle matches
    /// the SHA-256 of the plugin file bit-exact. Always `false` when
    /// `bundle_well_formed` is `false`.
    pub payload_digest_match: bool,
    /// Rekor log index extracted from the bundle (no online lookup).
    pub rekor_log_index: Option<u64>,
    /// Optional CycloneDX SBOM summary.
    pub sbom: Option<SbomReport>,
    /// `true` iff an operator-pinned Ed25519 public key
    /// (`IAGA_SENTINEL_PLUGIN_PUBKEY`) cryptographically verified the bundle
    /// signature over the plugin bytes. Always `false` on the default OSS path
    /// (digest-only). CRYPTO-ATTEST-1: managed *keyless* identity verification
    /// (Fulcio cert chain + Rekor inclusion) is intentionally an Enterprise
    /// feature and is NOT performed here.
    #[serde(default)]
    pub signature_verified: bool,
    /// `true` iff a pinned key was configured AND a signature check was actually
    /// attempted, so a `false` `signature_verified` with `signature_checked ==
    /// true` means the signature did NOT validate (as opposed to "no key pinned").
    #[serde(default)]
    pub signature_checked: bool,
}

impl PluginAttestation {
    /// The bundle exists, parses cleanly, and its embedded payload digest matches
    /// the plugin bytes bit-exact. This is a useful integrity check but **not** a
    /// signature verification: anyone who can write the sibling sidecar file can
    /// embed a matching digest. For cryptographic authorship use
    /// [`PluginAttestation::offline_verified`].
    pub fn digest_attested(&self) -> bool {
        self.bundle_path.is_some() && self.bundle_well_formed && self.payload_digest_match
    }

    /// `true` only when a signature was **cryptographically verified** offline:
    /// the digest matches AND a pinned operator key validated the bundle
    /// signature.
    ///
    /// CRYPTO-ATTEST-1: this previously returned `true` on a mere digest match,
    /// presenting a forgeable self-certifying check as "verified" (anyone who
    /// could write the sidecar passed). It now requires a real signature check,
    /// so an attacker who only controls the sidecar file cannot satisfy it.
    pub fn offline_verified(&self) -> bool {
        self.digest_attested() && self.signature_verified
    }

    /// Human-readable attestation strength: `"none"`, `"digest-only"`, or
    /// `"key-verified"`.
    pub fn attestation_level(&self) -> &'static str {
        if self.offline_verified() {
            "key-verified"
        } else if self.digest_attested() {
            "digest-only"
        } else {
            "none"
        }
    }
}

/// Summary of a CycloneDX 1.5 SBOM document. Stored compactly so the
/// pipeline can attach a snapshot to plugin manifests / receipts
/// without serializing the entire SBOM blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbomReport {
    pub spec_version: String,
    pub component_count: u32,
}

/// Failure modes for `verify_plugin`. Most failures degrade to
/// `PluginAttestation::bundle_well_formed = false` rather than an
/// error: callers should treat a missing-or-malformed attestation as
/// "no attestation" (the safe default) rather than a hard failure.
#[derive(Debug)]
pub enum AttestationError {
    /// The plugin file itself could not be read.
    PluginIo(std::io::Error),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PluginIo(e) => write!(f, "plugin file read failed: {e}"),
        }
    }
}

impl std::error::Error for AttestationError {}

impl From<std::io::Error> for AttestationError {
    fn from(value: std::io::Error) -> Self {
        Self::PluginIo(value)
    }
}

/// Run an offline attestation check on `wasm_path`.
///
/// Looks for `<wasm>.sigstore.json` and `<wasm>.cdx.json` next to the
/// plugin. Both are optional; missing or malformed bundles degrade
/// gracefully (the corresponding fields stay `None` / `false`).
///
/// Only `PluginIo` is a real error, meaning the plugin file itself
/// could not be read. Bundle / SBOM parse failures are *not* errors:
/// the function returns a `PluginAttestation` with the relevant fields
/// flagged "absent / malformed".
pub fn verify_plugin(wasm_path: &Path) -> Result<PluginAttestation, AttestationError> {
    let pinned = std::env::var("IAGA_SENTINEL_PLUGIN_PUBKEY").ok();
    verify_plugin_with_pinned_key(wasm_path, pinned.as_deref())
}

/// Like [`verify_plugin`] but takes the operator-pinned Ed25519 public key (hex)
/// explicitly instead of reading `IAGA_SENTINEL_PLUGIN_PUBKEY`. `None` ⇒
/// digest-only (no signature check). Exposed so callers/tests can pin a key
/// without mutating process-global environment.
pub fn verify_plugin_with_pinned_key(
    wasm_path: &Path,
    pinned_pubkey_hex: Option<&str>,
) -> Result<PluginAttestation, AttestationError> {
    let bytes = std::fs::read(wasm_path)?;
    let plugin_sha256 = sha256_hex(&bytes);

    let bundle_path = sibling(wasm_path, "sigstore.json");
    // Accept either a CycloneDX (`<wasm>.cdx.json`) or an SPDX
    // (`<wasm>.spdx.json`) SBOM sibling; the format is auto-detected on parse.
    let sbom_path = sibling(wasm_path, "cdx.json").or_else(|| sibling(wasm_path, "spdx.json"));

    let (bundle_well_formed, payload_digest_match, rekor_log_index) =
        verify_bundle(bundle_path.as_deref(), &bytes);

    // CRYPTO-ATTEST-1 workaround: optional signature verification against an
    // operator-pinned Ed25519 key. No-op (false, false) unless a key is pinned;
    // keyless Fulcio/Rekor identity verification stays an Enterprise feature.
    let (signature_verified, signature_checked) =
        verify_bundle_signature(bundle_path.as_deref(), &bytes, pinned_pubkey_hex);

    let sbom = sbom_path.as_deref().and_then(parse_sbom_path);

    Ok(PluginAttestation {
        plugin_sha256,
        bundle_path,
        sbom_path,
        bundle_well_formed,
        payload_digest_match,
        rekor_log_index,
        sbom,
        signature_verified,
        signature_checked,
    })
}

/// Parse a CycloneDX 1.5 SBOM file into a compact `SbomReport`.
///
/// Returns `Err` on IO failure or when the JSON does not look like a
/// CycloneDX document (`bomFormat != "CycloneDX"`). Other malformed
/// content yields a best-effort summary (component_count = 0).
pub fn parse_sbom_cyclonedx(path: &Path) -> Result<SbomReport, SbomError> {
    let bytes = std::fs::read(path).map_err(SbomError::Io)?;
    parse_sbom_cyclonedx_bytes(&bytes)
}

/// Same as [`parse_sbom_cyclonedx`] but takes raw bytes.
pub fn parse_sbom_cyclonedx_bytes(bytes: &[u8]) -> Result<SbomReport, SbomError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(SbomError::Parse)?;
    let bom_format = value
        .get("bomFormat")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !bom_format.eq_ignore_ascii_case("CycloneDX") {
        return Err(SbomError::NotCycloneDx);
    }
    let spec_version = value
        .get("specVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let component_count = value
        .get("components")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len() as u32)
        .unwrap_or(0);
    Ok(SbomReport {
        spec_version,
        component_count,
    })
}

/// Errors when parsing a CycloneDX SBOM. `verify_plugin` consumes
/// these silently (returns `sbom: None`); the standalone
/// `parse_sbom_cyclonedx` returns them to the caller.
#[derive(Debug)]
pub enum SbomError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    NotCycloneDx,
    NotSpdx,
    /// Valid JSON, but neither a CycloneDX nor an SPDX document.
    Unrecognized,
}

impl fmt::Display for SbomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "sbom read failed: {e}"),
            Self::Parse(e) => write!(f, "sbom parse failed: {e}"),
            Self::NotCycloneDx => write!(f, "not a CycloneDX document"),
            Self::NotSpdx => write!(f, "not an SPDX document"),
            Self::Unrecognized => write!(f, "not a recognized SBOM (CycloneDX or SPDX)"),
        }
    }
}

impl std::error::Error for SbomError {}

/// Parse an SPDX 2.x JSON SBOM file into a compact `SbomReport`.
pub fn parse_sbom_spdx(path: &Path) -> Result<SbomReport, SbomError> {
    let bytes = std::fs::read(path).map_err(SbomError::Io)?;
    parse_sbom_spdx_bytes(&bytes)
}

/// Same as [`parse_sbom_spdx`] but takes raw bytes. SPDX JSON is identified by a
/// top-level `spdxVersion` (e.g. `SPDX-2.3`); the package count is `packages[]`.
pub fn parse_sbom_spdx_bytes(bytes: &[u8]) -> Result<SbomReport, SbomError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(SbomError::Parse)?;
    let Some(spec_version) = value.get("spdxVersion").and_then(|v| v.as_str()) else {
        return Err(SbomError::NotSpdx);
    };
    let component_count = value
        .get("packages")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len() as u32)
        .unwrap_or(0);
    Ok(SbomReport {
        spec_version: spec_version.to_string(),
        component_count,
    })
}

/// Parse an SBOM in either CycloneDX or SPDX JSON, auto-detecting the format.
/// `spec_version` carries the format's own version string (`1.5` for CycloneDX,
/// `SPDX-2.3` for SPDX), so callers can tell which format was bound.
pub fn parse_sbom_bytes(bytes: &[u8]) -> Result<SbomReport, SbomError> {
    match parse_sbom_cyclonedx_bytes(bytes) {
        Ok(report) => Ok(report),
        // Valid JSON but not CycloneDX: try SPDX before giving up.
        Err(SbomError::NotCycloneDx) => match parse_sbom_spdx_bytes(bytes) {
            Ok(report) => Ok(report),
            Err(SbomError::NotSpdx) => Err(SbomError::Unrecognized),
            Err(other) => Err(other),
        },
        Err(other) => Err(other),
    }
}

fn parse_sbom_path(path: &Path) -> Option<SbomReport> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| parse_sbom_bytes(&bytes).ok())
}

fn sibling(wasm_path: &Path, suffix: &str) -> Option<PathBuf> {
    let mut p = PathBuf::from(wasm_path);
    let file_name = wasm_path.file_name()?.to_string_lossy().into_owned();
    let candidate = format!("{file_name}.{suffix}");
    p.set_file_name(candidate);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn verify_bundle(bundle_path: Option<&Path>, wasm_bytes: &[u8]) -> (bool, bool, Option<u64>) {
    let Some(path) = bundle_path else {
        return (false, false, None);
    };
    let Ok(raw) = std::fs::read(path) else {
        return (false, false, None);
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return (false, false, None);
    };

    // Sigstore Bundle v0.3 schema (mediaType
    // application/vnd.dev.sigstore.bundle.v0.3+json).
    // Look for messageSignature.messageDigest.digest (base64 SHA-256).
    let v03_digest_b64 = json
        .get("messageSignature")
        .and_then(|m| m.get("messageDigest"))
        .and_then(|d| d.get("digest"))
        .and_then(|v| v.as_str());

    // Cosign bundle v0.1 legacy schema: base64Signature + cert + payload.
    // Here payload (if present) is the in-toto/dsse statement; the
    // digest is in payload.subject[0].digest.sha256 (hex).
    let v01_digest_hex = json
        .pointer("/Payload/Body/IntotoObj/payload/subject/0/digest/sha256")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let actual_sha256_hex = sha256_hex(wasm_bytes);

    let payload_match = if let Some(d) = v03_digest_b64 {
        decode_b64_to_hex(d)
            .map(|h| h == actual_sha256_hex)
            .unwrap_or(false)
    } else if let Some(ref h) = v01_digest_hex {
        h.eq_ignore_ascii_case(&actual_sha256_hex)
    } else {
        false
    };

    let rekor_log_index = json
        .pointer("/verificationMaterial/tlogEntries/0/logIndex")
        .and_then(|v| match v {
            serde_json::Value::String(s) => s.parse::<u64>().ok(),
            serde_json::Value::Number(n) => n.as_u64(),
            _ => None,
        });

    // "Well-formed" = we recognized either schema and could extract a
    // digest field. Payload-match is a separate, stricter check.
    let well_formed = v03_digest_b64.is_some() || v01_digest_hex.is_some();

    (well_formed, payload_match, rekor_log_index)
}

fn decode_b64_to_hex(s: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    Some(hex::encode(bytes))
}

/// CRYPTO-ATTEST-1 workaround — optional, operator-pinned signature verification.
///
/// If a pinned Ed25519 public key (hex) is provided, verify the bundle's
/// `messageSignature.signature` (base64) over the **plugin bytes** with that key.
/// This mirrors the BYOK / `iaga-verify --key` pinning pattern and the cosign
/// `sign-blob --key <ed25519>` convention (Ed25519 signs the artifact directly).
/// It deliberately does NOT parse the bundle's X.509 cert, validate a Fulcio
/// root, or query Rekor — that managed keyless chain-of-trust is an Enterprise
/// feature (ADR 0010/0013). Returns `(signature_verified, signature_checked)`:
/// `checked` is `true` only when a key was pinned AND a bundle was present.
fn verify_bundle_signature(
    bundle_path: Option<&Path>,
    wasm_bytes: &[u8],
    pinned_pubkey_hex: Option<&str>,
) -> (bool, bool) {
    let Some(pubkey_hex) = pinned_pubkey_hex else {
        return (false, false);
    };
    let Some(path) = bundle_path else {
        return (false, false);
    };
    let verified = verify_pinned_ed25519(pubkey_hex, path, wasm_bytes).unwrap_or(false);
    (verified, true)
}

/// Inner helper: `Some(valid)` once the signature was actually checked, or `None`
/// when the key / bundle / signature could not be parsed (treated as not
/// verified by the caller).
fn verify_pinned_ed25519(pubkey_hex: &str, bundle_path: &Path, wasm_bytes: &[u8]) -> Option<bool> {
    let key_bytes = hex::decode(pubkey_hex.trim()).ok()?;
    let key_arr: [u8; 32] = key_bytes.as_slice().try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&key_arr).ok()?;

    let raw = std::fs::read(bundle_path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let sig_b64 = json
        .get("messageSignature")
        .and_then(|m| m.get("signature"))
        .and_then(|v| v.as_str())?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .ok()?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().ok()?;
    let sig = Signature::from_bytes(&sig_arr);

    Some(vk.verify(wasm_bytes, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_wasm(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[test]
    fn no_attestation_files_means_no_bundle_no_sbom() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "plain.wasm", b"\x00asm\x01\x00\x00\x00");
        let att = verify_plugin(&wasm).expect("verify ok");
        assert!(att.bundle_path.is_none());
        assert!(att.sbom_path.is_none());
        assert!(!att.bundle_well_formed);
        assert!(!att.payload_digest_match);
        assert!(att.sbom.is_none());
        assert!(!att.offline_verified());
        // SHA-256 of the wasm magic bytes is well-known.
        assert_eq!(att.plugin_sha256.len(), 64);
    }

    #[test]
    fn malformed_bundle_degrades_to_not_well_formed() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "p.wasm", b"contents");
        let bundle_path = dir.path().join("p.wasm.sigstore.json");
        std::fs::write(&bundle_path, b"not json {{").unwrap();
        let att = verify_plugin(&wasm).expect("verify ok");
        assert_eq!(att.bundle_path.as_deref(), Some(bundle_path.as_path()));
        assert!(!att.bundle_well_formed);
        assert!(!att.payload_digest_match);
    }

    #[test]
    fn v03_bundle_well_formed_but_digest_mismatch() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "q.wasm", b"contents-q");
        let fake_digest = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": fake_digest,
                },
                "signature": "deadbeef",
            },
            "verificationMaterial": {
                "tlogEntries": [{ "logIndex": "12345678" }],
            },
        });
        std::fs::write(
            dir.path().join("q.wasm.sigstore.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();
        let att = verify_plugin(&wasm).expect("verify ok");
        assert!(att.bundle_well_formed);
        assert!(!att.payload_digest_match);
        assert_eq!(att.rekor_log_index, Some(12345678));
        assert!(!att.offline_verified());
    }

    #[test]
    fn v03_bundle_matching_digest_is_digest_only_not_verified() {
        let dir = tempdir().unwrap();
        let payload = b"matching-content-here";
        let wasm = write_wasm(dir.path(), "good.wasm", payload);
        let mut h = Sha256::new();
        h.update(payload);
        let real_digest_b64 = base64::engine::general_purpose::STANDARD.encode(h.finalize());
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": real_digest_b64,
                },
                "signature": "ababab",
            },
        });
        std::fs::write(
            dir.path().join("good.wasm.sigstore.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();
        // CRYPTO-ATTEST-1: a matching digest with no verified signature is
        // "digest-only", NOT "verified" (the old behavior called this verified,
        // which anyone who could write the sidecar could forge).
        let att = verify_plugin_with_pinned_key(&wasm, None).expect("verify ok");
        assert!(att.bundle_well_formed);
        assert!(att.payload_digest_match);
        assert!(att.digest_attested());
        assert!(!att.signature_verified);
        assert!(
            !att.offline_verified(),
            "a digest match alone is not cryptographic verification"
        );
        assert_eq!(att.attestation_level(), "digest-only");
        assert_eq!(att.rekor_log_index, None); // not present in this fixture
    }

    #[test]
    fn cyclonedx_sbom_components_counted() {
        let dir = tempdir().unwrap();
        let _wasm = write_wasm(dir.path(), "r.wasm", b"r");
        let sbom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                { "name": "wasmtime", "version": "36.0.8" },
                { "name": "anyhow", "version": "1.0" },
                { "name": "serde", "version": "1.0" },
            ]
        });
        std::fs::write(
            dir.path().join("r.wasm.cdx.json"),
            serde_json::to_vec(&sbom).unwrap(),
        )
        .unwrap();
        let att = verify_plugin(&dir.path().join("r.wasm")).expect("verify ok");
        let report = att.sbom.expect("sbom report present");
        assert_eq!(report.spec_version, "1.5");
        assert_eq!(report.component_count, 3);
    }

    #[test]
    fn sbom_rejects_non_cyclonedx() {
        let bytes = b"{\"bomFormat\":\"SPDX\",\"specVersion\":\"2.3\"}";
        let err = parse_sbom_cyclonedx_bytes(bytes).expect_err("must reject");
        assert!(matches!(err, SbomError::NotCycloneDx));
    }

    #[test]
    fn spdx_sbom_packages_counted() {
        let dir = tempdir().unwrap();
        let _wasm = write_wasm(dir.path(), "s.wasm", b"s");
        let sbom = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "s",
            "packages": [
                { "name": "wasmtime", "SPDXID": "SPDXRef-Package-wasmtime" },
                { "name": "serde", "SPDXID": "SPDXRef-Package-serde" },
            ]
        });
        std::fs::write(
            dir.path().join("s.wasm.spdx.json"),
            serde_json::to_vec(&sbom).unwrap(),
        )
        .unwrap();
        let att = verify_plugin(&dir.path().join("s.wasm")).expect("verify ok");
        let report = att.sbom.expect("spdx sbom report present");
        assert_eq!(report.spec_version, "SPDX-2.3");
        assert_eq!(report.component_count, 2);
    }

    #[test]
    fn parse_sbom_spdx_bytes_rejects_cyclonedx() {
        let bytes = br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#;
        let err = parse_sbom_spdx_bytes(bytes).expect_err("must reject");
        assert!(matches!(err, SbomError::NotSpdx));
    }

    #[test]
    fn parse_sbom_bytes_auto_detects_both_formats() {
        let cdx = br#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}"#;
        let r = parse_sbom_bytes(cdx).expect("cyclonedx");
        assert_eq!(r.spec_version, "1.6");
        assert_eq!(r.component_count, 1);

        let spdx = br#"{"spdxVersion":"SPDX-2.3","packages":[{"name":"a"},{"name":"b"}]}"#;
        let r = parse_sbom_bytes(spdx).expect("spdx");
        assert_eq!(r.spec_version, "SPDX-2.3");
        assert_eq!(r.component_count, 2);

        let neither = br#"{"hello":"world"}"#;
        assert!(matches!(
            parse_sbom_bytes(neither).expect_err("unrecognized"),
            SbomError::Unrecognized
        ));
    }

    #[test]
    fn sbom_missing_components_yields_zero() {
        let bytes = br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#;
        let r = parse_sbom_cyclonedx_bytes(bytes).expect("parse ok");
        assert_eq!(r.component_count, 0);
        assert_eq!(r.spec_version, "1.5");
    }

    #[test]
    fn digest_attested_requires_bundle_present_and_match_and_verified_adds_signature() {
        let mut a = PluginAttestation {
            plugin_sha256: "00".repeat(32),
            bundle_path: None,
            sbom_path: None,
            bundle_well_formed: true,
            payload_digest_match: true,
            rekor_log_index: None,
            sbom: None,
            signature_verified: false,
            signature_checked: false,
        };
        assert!(!a.digest_attested(), "bundle_path None fails");
        a.bundle_path = Some(PathBuf::from("x"));
        a.bundle_well_formed = false;
        assert!(!a.digest_attested(), "not well-formed fails");
        a.bundle_well_formed = true;
        a.payload_digest_match = false;
        assert!(!a.digest_attested(), "digest mismatch fails");
        a.payload_digest_match = true;
        assert!(
            a.digest_attested(),
            "all three required for digest attestation"
        );

        // CRYPTO-ATTEST-1: digest-only must NOT count as verified; that needs a
        // cryptographically verified signature on top.
        assert!(
            !a.offline_verified(),
            "offline_verified requires a verified signature, not just a digest"
        );
        assert_eq!(a.attestation_level(), "digest-only");
        a.signature_verified = true;
        assert!(
            a.offline_verified(),
            "digest + verified signature ⇒ verified"
        );
        assert_eq!(a.attestation_level(), "key-verified");
    }

    #[test]
    fn pinned_key_signature_verification_end_to_end() {
        use ed25519_dalek::{Signer, SigningKey};

        let dir = tempdir().unwrap();
        let payload = b"signed-plugin-bytes";
        let wasm = write_wasm(dir.path(), "signed.wasm", payload);

        // Operator's Ed25519 keypair (deterministic seed for the test).
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey_hex = hex::encode(sk.verifying_key().as_bytes());

        // cosign `sign-blob`-style: Ed25519 signature over the artifact bytes,
        // with the digest also present in the bundle.
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sk.sign(payload).to_bytes());
        let mut h = Sha256::new();
        h.update(payload);
        let digest_b64 = base64::engine::general_purpose::STANDARD.encode(h.finalize());
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": { "algorithm": "SHA2_256", "digest": digest_b64 },
                "signature": sig_b64,
            },
        });
        std::fs::write(
            dir.path().join("signed.wasm.sigstore.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();

        // Correct pinned key ⇒ key-verified.
        let ok = verify_plugin_with_pinned_key(&wasm, Some(&pubkey_hex)).expect("verify ok");
        assert!(ok.payload_digest_match);
        assert!(ok.signature_checked);
        assert!(
            ok.signature_verified,
            "the pinned key must verify the signature"
        );
        assert!(ok.offline_verified());
        assert_eq!(ok.attestation_level(), "key-verified");

        // Wrong pinned key ⇒ checked but not verified; never "verified".
        let wrong_hex = hex::encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let bad = verify_plugin_with_pinned_key(&wasm, Some(&wrong_hex)).expect("verify ok");
        assert!(bad.signature_checked);
        assert!(!bad.signature_verified);
        assert!(!bad.offline_verified());
        assert!(bad.digest_attested());
        assert_eq!(bad.attestation_level(), "digest-only");
    }

    #[test]
    fn rekor_log_index_accepts_string_or_number() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "z.wasm", b"z");
        let bundle = serde_json::json!({
            "messageSignature": { "messageDigest": { "digest": "" } },
            "verificationMaterial": {
                "tlogEntries": [{ "logIndex": 99 }],
            },
        });
        std::fs::write(
            dir.path().join("z.wasm.sigstore.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();
        let att = verify_plugin(&wasm).expect("verify ok");
        assert_eq!(att.rekor_log_index, Some(99));
    }

    #[test]
    fn sibling_search_uses_full_wasm_filename_with_suffix() {
        let dir = tempdir().unwrap();
        let wasm = write_wasm(dir.path(), "my-plugin.wasm", b"x");
        std::fs::write(
            dir.path().join("my-plugin.wasm.sigstore.json"),
            b"{\"messageSignature\":{\"messageDigest\":{\"digest\":\"\"}}}",
        )
        .unwrap();
        let att = verify_plugin(&wasm).expect("verify ok");
        assert!(att.bundle_path.is_some());
        assert!(att.bundle_well_formed); // recognized v03 shape
    }
}
