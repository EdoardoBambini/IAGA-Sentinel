//! Ed25519 signer for receipts, `Signer` trait + `LocalDiskSigner`
//! reference impl (OSS 1.2 refactor, ADR 0011).
//!
//! The `Signer` trait is the public abstraction every governance
//! pipeline consumes through `Arc<dyn Signer>`. The default impl,
//! [`LocalDiskSigner`], holds a single 32-byte Ed25519 seed on disk
//! at a path chosen by the host (typically
//! `~/.iaga-sentinel/keys/receipt_signer.ed25519`), created with mode
//! `0600` on Unix. That filesystem-mount pattern is the BYOK contract
//! kept in OSS forever.
//!
//! Native KMS SDK backends (AWS KMS / Azure Key Vault / HashiCorp
//! Vault / PKCS#11 HSM) live in IAGA Sentinel Enterprise as separate
//! `impl Signer for ...` implementations, plugged in behind the same
//! trait without OSS leaking a discovery / factory mechanism. See
//! [`ENTERPRISE.md`] and ADR 0010 §2.20.
//!
//! `ReceiptSigner` remains as a type alias for [`LocalDiskSigner`] to
//! preserve every callsite from the 1.0 / 1.1 line.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::errors::{ReceiptError, Result};
use crate::receipt::{Receipt, ReceiptBody};

/// Object-safe abstraction over a receipt signing backend.
///
/// Implementations sign a [`ReceiptBody`] producing a full
/// [`Receipt`] with a hex-encoded Ed25519 signature over the
/// canonical signing bytes. Implementations must be both `Send` and
/// `Sync` so the pipeline can hold them inside `Arc<dyn Signer>` and
/// share them across async tasks.
///
/// The default reference impl is [`LocalDiskSigner`]. Enterprise
/// builds plug in native KMS-backed implementations behind this same
/// trait.
#[async_trait]
pub trait Signer: Send + Sync {
    /// Stable public identifier for the active key, of the form
    /// `ed25519-<hex16>` for the [`LocalDiskSigner`] impl. The exact
    /// shape is impl-specific but must be stable across restarts so
    /// `ReceiptBody::signer_key_id` can be verified by external
    /// consumers.
    fn key_id(&self) -> &str;

    /// Public verifying key matching the active signing key. Used by
    /// receipt stores to register the trust anchor and by external
    /// verifiers to validate signatures.
    fn verifying_key(&self) -> VerifyingKey;

    /// Sign a receipt body, returning the full [`Receipt`] with a
    /// hex-encoded signature over `body.signing_bytes()`.
    ///
    /// Implementations must reject bodies whose `signer_key_id` does
    /// not match `self.key_id()` to catch misuse early.
    async fn sign_body(&self, body: ReceiptBody) -> Result<Receipt>;
}

/// Reference [`Signer`] implementation backed by a single Ed25519
/// signing key on local disk. This is the BYOK filesystem-mount
/// pattern kept in OSS forever, the public verifying key is
/// identified by a stable `key_id` derived from
/// `SHA-256(pubkey)[0..16]`, hex-encoded.
pub struct LocalDiskSigner {
    signing_key: SigningKey,
    key_id: String,
    source_path: Option<PathBuf>,
}

/// Backward-compatible alias preserved for OSS 1.0 / 1.1 callers. New
/// code should prefer [`LocalDiskSigner`] (concrete impl) or
/// `Arc<dyn Signer>` (trait object).
pub type ReceiptSigner = LocalDiskSigner;

impl LocalDiskSigner {
    /// Generate a fresh ephemeral signer (tests, in-memory runs).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let key_id = Self::derive_key_id(&signing_key.verifying_key());
        Self {
            signing_key,
            key_id,
            source_path: None,
        }
    }

    /// Load a signer from a 32-byte seed file. If the file does not exist,
    /// generate a fresh key, write it with 0600 permissions on Unix, and
    /// return the new signer.
    ///
    /// 1.5.2 permission posture: on Unix a freshly written key is re-checked
    /// post-write and creation fails if it is group/world accessible; loading
    /// a pre-existing loose seed only warns (hard-failing would lock existing
    /// deployments out of their own ledger). On Windows the key relies on
    /// default NTFS ACLs and a warning reminds the operator to restrict them.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            warn_if_key_permissions_loose(path);
            let bytes = std::fs::read(path)?;
            if bytes.len() != 32 {
                return Err(ReceiptError::Key(format!(
                    "expected 32-byte seed at {}, got {}",
                    path.display(),
                    bytes.len()
                )));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let signing_key = SigningKey::from_bytes(&seed);
            let key_id = Self::derive_key_id(&signing_key.verifying_key());
            Ok(Self {
                signing_key,
                key_id,
                source_path: Some(path.to_path_buf()),
            })
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let signing_key = SigningKey::generate(&mut OsRng);
            let seed = signing_key.to_bytes();
            write_private_key(path, &seed)?;
            verify_created_key_permissions(path)?;
            let key_id = Self::derive_key_id(&signing_key.verifying_key());
            Ok(Self {
                signing_key,
                key_id,
                source_path: Some(path.to_path_buf()),
            })
        }
    }

    /// Stable public identifier for this key: `ed25519-<hex16>` where the
    /// 16 bytes are the first 16 of SHA-256(public key).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Return the public verifying key so verifiers off-machine can check signatures.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a receipt body synchronously, returning the full Receipt
    /// with hex-encoded signature. Preserved for 1.0 / 1.1 callers
    /// holding a concrete [`LocalDiskSigner`]; pipeline code that
    /// holds an `Arc<dyn Signer>` should call
    /// [`Signer::sign_body`] instead.
    pub fn sign(&self, body: ReceiptBody) -> Result<Receipt> {
        if body.signer_key_id != self.key_id {
            return Err(ReceiptError::Key(format!(
                "body.signer_key_id={} does not match signer key_id={}",
                body.signer_key_id, self.key_id
            )));
        }
        let bytes = body.signing_bytes()?;
        let sig: Signature = self.signing_key.sign(&bytes);
        Ok(Receipt {
            body,
            signature: hex::encode(sig.to_bytes()),
        })
    }

    /// Sign arbitrary bytes with this key, returning the detached Ed25519
    /// signature. Used for signing plugin manifests; the receipt path uses
    /// `sign` and `sign_body`.
    pub fn sign_detached(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Path on disk if this signer was loaded from / written to a file.
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    fn derive_key_id(vk: &VerifyingKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(vk.as_bytes());
        let digest = hasher.finalize();
        format!("ed25519-{}", hex::encode(&digest[..16]))
    }
}

#[async_trait]
impl Signer for LocalDiskSigner {
    fn key_id(&self) -> &str {
        LocalDiskSigner::key_id(self)
    }

    fn verifying_key(&self) -> VerifyingKey {
        LocalDiskSigner::verifying_key(self)
    }

    async fn sign_body(&self, body: ReceiptBody) -> Result<Receipt> {
        // Ed25519 signing is microseconds; no need to off-thread.
        LocalDiskSigner::sign(self, body)
    }
}

/// Verify the signature of a single receipt against the provided public key.
pub fn verify_receipt(receipt: &Receipt, vk: &VerifyingKey) -> Result<()> {
    let sig_bytes = hex::decode(&receipt.signature)?;
    if sig_bytes.len() != 64 {
        return Err(ReceiptError::SignatureInvalid {
            seq: receipt.body.seq,
        });
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    let msg = receipt.body.signing_bytes()?;
    vk.verify(&msg, &sig)
        .map_err(|_| ReceiptError::SignatureInvalid {
            seq: receipt.body.seq,
        })
}

#[cfg(unix)]
fn write_private_key(path: &Path, seed: &[u8; 32]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(seed)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, seed: &[u8; 32]) -> Result<()> {
    // Windows: rely on default ACLs of the user's profile directory.
    std::fs::write(path, seed)?;
    Ok(())
}

/// Post-write check for a key this process just created: the requested mode
/// could have been widened by umask quirks or an exotic filesystem, so trust
/// the filesystem's answer, not the request (1.5.2).
#[cfg(unix)]
fn verify_created_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(ReceiptError::Key(format!(
            "signing key {} was created group/world accessible (mode {:o}); \
             refusing to use it — fix the filesystem and retry",
            path.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_created_key_permissions(path: &Path) -> Result<()> {
    tracing::warn!(
        path = %path.display(),
        "receipt signing key relies on default NTFS ACLs; restrict access to this file"
    );
    Ok(())
}

/// Loading a pre-existing seed with loose permissions warns instead of
/// failing: operators upgrading from older releases must not be locked out
/// of their own receipt ledger.
#[cfg(unix)]
fn warn_if_key_permissions_loose(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode & 0o777),
                "receipt signing key is group/world accessible; chmod 600 it"
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_key_permissions_loose(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::Verdict;
    use std::sync::Arc;

    fn make_body(signer_key_id: &str) -> ReceiptBody {
        ReceiptBody {
            run_id: "run-test".into(),
            seq: 0,
            parent_hash: None,
            input_hash: "00".repeat(32),
            policy_hash: "11".repeat(32),
            plugin_digests: vec![],
            model_digests: vec![],
            ml_scores: None,
            verdict: Verdict::Allow,
            reasons: vec![],
            risk_score: 0,
            timestamp: "2026-01-01T00:00:00Z".into(),
            signer_key_id: signer_key_id.into(),
            pipeline_inputs_capture: None,
            apl_eval_trace: None,
            ml_inference_inputs: None,
            is_authoritative: None,
            usage: None,
        }
    }

    // Compile-time assertion that the trait is object-safe.
    #[allow(dead_code)]
    fn assert_object_safe(_: Arc<dyn Signer>) {}

    #[tokio::test]
    async fn local_disk_signer_implements_signer_trait() {
        let signer = LocalDiskSigner::generate();
        let body = make_body(signer.key_id());
        let r: Arc<dyn Signer> = Arc::new(signer);
        let receipt = r.sign_body(body).await.expect("sign_body");
        assert_eq!(receipt.body.signer_key_id, r.key_id());
        verify_receipt(&receipt, &r.verifying_key()).expect("verify");
    }

    #[tokio::test]
    async fn sync_sign_and_trait_sign_body_are_equivalent() {
        let signer = LocalDiskSigner::generate();
        let body_sync = make_body(signer.key_id());
        let body_async = body_sync.clone();
        let sync_receipt = signer.sign(body_sync).expect("sync sign");
        let async_receipt = signer.sign_body(body_async).await.expect("async sign");
        assert_eq!(sync_receipt.signature, async_receipt.signature);
    }

    #[test]
    fn receipt_signer_alias_resolves_to_local_disk_signer() {
        // Pure compile-time check: ReceiptSigner must be usable wherever
        // LocalDiskSigner is, ensuring callsites from 1.0 / 1.1 stay valid.
        let s: ReceiptSigner = LocalDiskSigner::generate();
        assert!(s.key_id().starts_with("ed25519-"));
    }

    #[tokio::test]
    async fn sign_body_rejects_mismatched_key_id() {
        let signer = LocalDiskSigner::generate();
        let mut body = make_body("ed25519-deadbeef");
        body.signer_key_id = "ed25519-deadbeef".into();
        let err = signer.sign_body(body).await.unwrap_err();
        match err {
            ReceiptError::Key(_) => {}
            other => panic!("expected Key error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn key_id_is_stable_across_clones_of_arc() {
        let signer: Arc<dyn Signer> = Arc::new(LocalDiskSigner::generate());
        let clone = signer.clone();
        assert_eq!(signer.key_id(), clone.key_id());
        assert_eq!(
            signer.verifying_key().as_bytes(),
            clone.verifying_key().as_bytes()
        );
    }

    #[test]
    fn key_id_format_is_ed25519_hex16() {
        let s = LocalDiskSigner::generate();
        // ed25519-<32 hex chars>
        let kid = s.key_id();
        assert!(kid.starts_with("ed25519-"));
        let hex = &kid["ed25519-".len()..];
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 1.5.2: a freshly created key file must be owner-only on Unix; the
    /// post-write verification rejects anything group/world accessible.
    #[cfg(unix)]
    #[test]
    fn created_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("receipt-signing.key");
        let signer = LocalDiskSigner::load_or_create(&path).expect("create signer");
        assert_eq!(signer.source_path(), Some(path.as_path()));

        let mode = std::fs::metadata(&path)
            .expect("stat key file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "key must not be group/world accessible");

        // Loading a deliberately loosened seed must still succeed (warn-only
        // posture for pre-existing deployments).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen perms");
        let reloaded = LocalDiskSigner::load_or_create(&path).expect("reload signer");
        assert_eq!(reloaded.key_id(), signer.key_id());
    }
}
