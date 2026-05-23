//! Ed25519 signer for receipts.
//!
//! Single signer key on disk at a path chosen by the host
//! (typically `~/.iaga-sentinel/keys/receipt_signer.ed25519`). The file
//! stores the 32-byte seed (raw, no password) and is created with
//! mode 0600 on Unix. This is the BYOK filesystem-mount pattern,
//! kept in OSS forever. A `Signer` trait + `LocalDiskSigner`
//! refactor is on the OSS 1.2 roadmap (additive, no breaking
//! change). Native KMS SDK backends (AWS KMS / Azure Key Vault /
//! HashiCorp Vault / PKCS#11 HSM) live in IAGA Sentinel Enterprise;
//! see ENTERPRISE.md.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::errors::{ReceiptError, Result};
use crate::receipt::{Receipt, ReceiptBody};

/// Signs receipts with a single Ed25519 key. The public key is identified
/// by a stable `key_id` derived from SHA-256(pubkey)[0..16], hex-encoded.
pub struct ReceiptSigner {
    signing_key: SigningKey,
    key_id: String,
    source_path: Option<PathBuf>,
}

impl ReceiptSigner {
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
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
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

    /// Sign a receipt body, returning the full Receipt with hex-encoded signature.
    /// Note: the `signer_key_id` field of the body must already be set to
    /// this signer's key_id — we verify that here to catch misuse.
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
