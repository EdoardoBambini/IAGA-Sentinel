//! Portable export of a run's signed receipt chain for offline verification.

use serde::{Deserialize, Serialize};

use crate::receipt::Receipt;

/// A self-describing export of a single run's signed receipt chain. It
/// carries the receipts, the signer key id, and the hex-encoded Ed25519
/// public key, so a third party can verify the chain offline with the
/// standalone `iaga-verify` tool and nothing else.
///
/// The embedded `signer_verifying_key` is self-asserted. It lets a verifier
/// run with zero configuration, but an auditor who needs assurance of
/// authorship pins the expected key out of band and verifies against that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainExport {
    pub run_id: String,
    pub signer_key_id: String,
    /// Hex-encoded 32-byte Ed25519 public key the receipts were signed with.
    pub signer_verifying_key: String,
    pub receipts: Vec<Receipt>,
}
