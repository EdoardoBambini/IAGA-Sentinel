//! Integration point between the governance pipeline and `iaga-sentinel-receipts`.
//!
//! Design (M2, dual-write transition):
//! - The pipeline keeps writing to `audit_store` exactly as in 0.4.0.
//! - In addition, if a `ReceiptLogger` is configured on `AppState`, every
//!   stored verdict is translated into a signed `Receipt` appended to the
//!   Merkle chain of the corresponding `run_id` (mapped from `trace_id` /
//!   `event_id`). A failure in the receipt path must never fail the
//!   governance decision — errors are logged at warn level and swallowed.
//! - The trait is defined here so callers can remain feature-agnostic:
//!   `state.receipts: Option<Arc<dyn ReceiptLogger>>` is `None` when the
//!   `receipts` cargo feature is disabled and the concrete impl is absent.
//!
//! The concrete `SignedReceiptLogger` (feature `receipts`) lives at the
//! bottom of this file and is gated so the core still compiles without
//! the `iaga-sentinel-receipts` crate in the dependency graph.

use async_trait::async_trait;

use crate::core::types::StoredAuditEvent;
use crate::pipeline::reasoning::ReasoningOutcome;

#[async_trait]
pub trait ReceiptLogger: Send + Sync {
    /// Append a signed receipt for the given audit event. Must not panic
    /// and must not propagate errors into the hot path: implementations
    /// log internally and return. The optional `evidence` carries ML
    /// scores and model digests from the reasoning plane (M3.5); when
    /// `None`, the receipt body records empty `model_digests` and
    /// `ml_scores: None` (legacy M2 behavior).
    async fn record(&self, event: &StoredAuditEvent, evidence: Option<&ReasoningOutcome>);

    /// 1.0 read surface for the dashboard / HTTP API. Implementations
    /// return JSON-shaped data; defaults return empty so non-receipt
    /// loggers (the `receipts` feature off path) still satisfy the
    /// trait without forcing JSON construction.
    async fn list_runs_json(&self, _limit: u32) -> serde_json::Value {
        serde_json::Value::Array(Vec::new())
    }

    async fn get_run_json(&self, _run_id: &str) -> serde_json::Value {
        serde_json::json!({ "receipts": [], "verify": null })
    }

    fn signer_key_id(&self) -> Option<String> {
        None
    }

    fn policy_hash(&self) -> Option<String> {
        None
    }
}

/// Best-effort construction of a signed receipt logger. Returns `None` when:
/// - the `receipts` feature is disabled at compile time, or
/// - the host cannot resolve a signer key path (e.g. no `HOME` on a
///   restricted environment), or
/// - the SQLite/Postgres receipt store fails to open (errors are
///   logged and swallowed — receipts must never break the pipeline
///   startup path).
///
/// `policy_hash` is the SHA-256 hex digest of the active policy
/// bundle. When the host has an APL overlay loaded (M6) it should
/// pass `Some(overlay.policy_hash().to_string())` so receipts can
/// be replayed against the exact policy that produced them. Pass
/// `None` for the default placeholder (M2 behavior preserved).
pub async fn try_build_receipt_logger(
    database_url: &str,
    policy_hash: Option<String>,
) -> Option<std::sync::Arc<dyn ReceiptLogger>> {
    #[cfg(feature = "receipts")]
    {
        signed::try_build(database_url, policy_hash).await
    }
    #[cfg(not(feature = "receipts"))]
    {
        let _ = database_url;
        let _ = policy_hash;
        None
    }
}

#[cfg(feature = "receipts")]
pub use signed::SignedReceiptLogger;

#[cfg(feature = "receipts")]
mod signed {
    use std::sync::Arc;

    use iaga_sentinel_receipts::{
        chain_link, MlScoreBundle, ReceiptBody, ReceiptSigner, ReceiptStore, Verdict,
    };
    use async_trait::async_trait;
    use sha2::{Digest, Sha256};
    use tokio::sync::Mutex;
    use tracing::warn;

    use super::ReceiptLogger;
    use crate::core::types::{GovernanceDecision, StoredAuditEvent};

    /// Concrete `ReceiptLogger` that signs and appends receipts via an
    /// `iaga_sentinel_receipts::ReceiptStore`.
    ///
    /// Head tracking is delegated to the store (`store.head(run_id)`),
    /// avoiding drift from an in-memory cache that could get out of sync
    /// across process restarts.
    pub struct SignedReceiptLogger {
        store: Arc<dyn ReceiptStore>,
        signer: ReceiptSigner,
        policy_hash: String,
        /// Serializes append operations so concurrent writes to the same
        /// run_id can't race on `head()`/`append()`. A per-run_id mutex map
        /// would be lower contention; a single global lock is simpler and
        /// adequate for M2 throughput.
        append_guard: Mutex<()>,
    }

    impl SignedReceiptLogger {
        pub fn new(
            store: Arc<dyn ReceiptStore>,
            signer: ReceiptSigner,
            policy_hash: String,
        ) -> Self {
            Self {
                store,
                signer,
                policy_hash,
                append_guard: Mutex::new(()),
            }
        }

        fn input_hash(event: &StoredAuditEvent) -> String {
            let mut hasher = Sha256::new();
            hasher.update(event.event_id.as_bytes());
            hasher.update(event.agent_id.as_bytes());
            hasher.update(event.tool_name.as_bytes());
            hex::encode(hasher.finalize())
        }

        fn map_verdict(d: GovernanceDecision) -> Verdict {
            match d {
                GovernanceDecision::Allow => Verdict::Allow,
                GovernanceDecision::Review => Verdict::Review,
                GovernanceDecision::Block => Verdict::Block,
            }
        }

        fn run_id(event: &StoredAuditEvent) -> String {
            // For M2 we use the event_id as run_id: every verdict is its
            // own run. Multi-step runs grouped by a shared trace_id land
            // in M3 when APL exposes session identity formally.
            event.event_id.clone()
        }
    }

    #[async_trait]
    impl ReceiptLogger for SignedReceiptLogger {
        async fn record(
            &self,
            event: &StoredAuditEvent,
            evidence: Option<&super::ReasoningOutcome>,
        ) {
            let run_id = Self::run_id(event);

            // Serialize append within this logger instance.
            let _guard = self.append_guard.lock().await;

            let head = match self.store.head(&run_id).await {
                Ok(h) => h,
                Err(e) => {
                    warn!(run_id = %run_id, error = %e, "receipt head lookup failed");
                    return;
                }
            };
            let (parent_hash, seq) = match chain_link(head.as_ref()) {
                Ok(v) => v,
                Err(e) => {
                    warn!(run_id = %run_id, error = %e, "receipt chain_link failed");
                    return;
                }
            };

            // M3.5: lift ML evidence (model digests + scores) into the
            // receipt body. Empty / None when no reasoning engine is
            // wired or the engine produced no evidence — receipt stays
            // bit-identical to M2 in that case.
            let (model_digests, ml_scores) = match evidence {
                Some(ev)
                    if !ev.model_digests.is_empty()
                        || ev
                            .scores
                            .as_object()
                            .map(|o| !o.is_empty())
                            .unwrap_or(false) =>
                {
                    let digests: Vec<iaga_sentinel_receipts::ModelDigest> = ev
                        .model_digests
                        .iter()
                        .map(|(name, sha)| iaga_sentinel_receipts::ModelDigest {
                            name: name.clone(),
                            sha256: sha.clone(),
                        })
                        .collect();
                    (digests, Some(MlScoreBundle(ev.scores.clone())))
                }
                _ => (vec![], None::<MlScoreBundle>),
            };

            let body = ReceiptBody {
                run_id: run_id.clone(),
                seq,
                parent_hash,
                input_hash: Self::input_hash(event),
                policy_hash: self.policy_hash.clone(),
                plugin_digests: vec![],
                model_digests,
                ml_scores,
                verdict: Self::map_verdict(event.decision),
                reasons: event.reasons.clone(),
                risk_score: event.risk_score,
                timestamp: event.timestamp.clone(),
                signer_key_id: self.signer.key_id().to_string(),
            };

            let receipt = match self.signer.sign(body) {
                Ok(r) => r,
                Err(e) => {
                    warn!(run_id = %run_id, error = %e, "receipt signing failed");
                    return;
                }
            };
            if let Err(e) = self.store.append(&receipt).await {
                warn!(run_id = %run_id, error = %e, "receipt append failed");
            }
        }

        async fn list_runs_json(&self, limit: u32) -> serde_json::Value {
            match self.store.list_runs(limit).await {
                Ok(runs) => serde_json::to_value(&runs).unwrap_or(serde_json::Value::Null),
                Err(e) => {
                    warn!(error = %e, "receipt list_runs failed");
                    serde_json::json!({ "error": e.to_string() })
                }
            }
        }

        async fn get_run_json(&self, run_id: &str) -> serde_json::Value {
            let receipts = match self.store.get_run(run_id).await {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({
                        "error": e.to_string(),
                        "receipts": [],
                        "verify": null,
                    });
                }
            };
            let verify = match self.store.verify_chain(run_id).await {
                Ok(status) => serde_json::to_value(&status).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            };
            serde_json::json!({
                "runId": run_id,
                "receipts": serde_json::to_value(&receipts).unwrap_or(serde_json::Value::Null),
                "verify": verify,
                "signerKeyId": self.signer.key_id(),
                "policyHash": self.policy_hash,
            })
        }

        fn signer_key_id(&self) -> Option<String> {
            Some(self.signer.key_id().to_string())
        }

        fn policy_hash(&self) -> Option<String> {
            Some(self.policy_hash.clone())
        }
    }

    /// Default policy hash placeholder for M2. In M3 APL will replace this
    /// with the SHA-256 of the compiled policy bundle.
    pub fn default_policy_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"iaga-sentinel-policy-v0");
        hex::encode(hasher.finalize())
    }

    /// Resolve the signer key path: env override `IAGA_SENTINEL_SIGNER_KEY_PATH`
    /// wins; otherwise `<HOME>/.iaga-sentinel/keys/receipt_signer.ed25519`.
    fn signer_key_path() -> Option<std::path::PathBuf> {
        if let Ok(p) = std::env::var("IAGA_SENTINEL_SIGNER_KEY_PATH") {
            return Some(std::path::PathBuf::from(p));
        }
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
        let mut p = std::path::PathBuf::from(home);
        p.push(".iaga-sentinel");
        p.push("keys");
        p.push("receipt_signer.ed25519");
        Some(p)
    }

    /// Public helper called from `pipeline::receipts::try_build_receipt_logger`.
    /// M5: supports `sqlite:` and `postgres://`/`postgresql://` URLs.
    /// M6: accepts an optional `policy_hash` override so APL-loaded
    /// hosts can embed the bundle digest in every receipt body.
    pub(super) async fn try_build(
        database_url: &str,
        policy_hash: Option<String>,
    ) -> Option<Arc<dyn super::ReceiptLogger>> {
        let key_path = match signer_key_path() {
            Some(p) => p,
            None => {
                tracing::warn!("receipts: cannot resolve signer key path; receipts disabled");
                return None;
            }
        };
        let signer = match ReceiptSigner::load_or_create(&key_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, path = %key_path.display(), "receipts: signer load failed; receipts disabled");
                return None;
            }
        };

        let store: Arc<dyn ReceiptStore> = if database_url.starts_with("sqlite:") {
            #[cfg(feature = "sqlite")]
            {
                use iaga_sentinel_receipts::SqliteReceiptStore;
                match SqliteReceiptStore::new(database_url, signer.verifying_key()).await {
                    Ok(s) => Arc::new(s) as Arc<dyn ReceiptStore>,
                    Err(e) => {
                        tracing::warn!(error = %e, "receipts: sqlite store open failed; receipts disabled");
                        return None;
                    }
                }
            }
            #[cfg(not(feature = "sqlite"))]
            {
                tracing::info!("receipts: sqlite URL but core built without `sqlite` feature; receipts disabled");
                return None;
            }
        } else if database_url.starts_with("postgres://")
            || database_url.starts_with("postgresql://")
        {
            #[cfg(feature = "postgres")]
            {
                use iaga_sentinel_receipts::PgReceiptStore;
                match PgReceiptStore::new(database_url, signer.verifying_key()).await {
                    Ok(s) => Arc::new(s) as Arc<dyn ReceiptStore>,
                    Err(e) => {
                        tracing::warn!(error = %e, "receipts: postgres store open failed; receipts disabled");
                        return None;
                    }
                }
            }
            #[cfg(not(feature = "postgres"))]
            {
                tracing::info!("receipts: postgres URL but core built without `postgres` feature; receipts disabled");
                return None;
            }
        } else {
            tracing::info!("receipts: unrecognized database_url scheme; receipts disabled");
            return None;
        };

        let resolved_policy_hash = policy_hash.unwrap_or_else(default_policy_hash);
        tracing::info!(
            key_id = signer.key_id(),
            path = %key_path.display(),
            policy_hash = %resolved_policy_hash,
            "receipts: signed action receipts enabled"
        );
        let logger = SignedReceiptLogger::new(store, signer, resolved_policy_hash);
        Some(Arc::new(logger) as Arc<dyn super::ReceiptLogger>)
    }
}
