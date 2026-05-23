use std::sync::Arc;

use crate::config::env::AppEnv;
use crate::events::bus::EventBus;
use crate::events::webhooks::WebhookManager;
use crate::modules::fingerprint::behavioral::BehavioralEngine;
use crate::modules::rate_limit::limiter::RateLimiter;
use crate::modules::threat_intel::feed::ThreatFeed;
#[cfg(feature = "apl")]
use crate::pipeline::apl_overlay::AplOverlay;
use crate::pipeline::reasoning::ReasoningHandle;
use crate::pipeline::receipts::ReceiptLogger;
use crate::plugins::PluginRegistry;
use crate::storage::traits::*;

pub struct AppState {
    pub audit_store: Arc<dyn AuditStore>,
    pub review_store: Arc<dyn ReviewStore>,
    pub policy_store: Arc<dyn PolicyStore>,
    pub api_key_store: Arc<dyn ApiKeyStore>,
    pub tenant_store: Arc<dyn TenantStore>,
    // v0.4.0 — Durable State stores
    pub nhi_store: Arc<dyn NhiStore>,
    pub session_store: Arc<dyn SessionStore>,
    pub taint_store: Arc<dyn TaintStore>,
    pub fingerprint_store: Arc<dyn FingerprintStore>,
    pub rate_limit_store: Arc<dyn RateLimitStore>,
    pub event_bus: EventBus,
    pub webhook_manager: Arc<WebhookManager>,
    pub behavioral_engine: Arc<BehavioralEngine>,
    pub rate_limiter: Arc<RateLimiter>,
    pub threat_feed: Arc<ThreatFeed>,
    pub plugin_registry: Arc<PluginRegistry>,
    pub storage_backend: StorageBackend,
    pub env: AppEnv,
    /// 1.0 M2 — signed action receipts (optional; `None` when the
    /// `receipts` feature is disabled or the host hasn't wired it).
    pub receipts: Option<Arc<dyn ReceiptLogger>>,
    /// 1.0 M3.5 — probabilistic reasoning plane (optional; `None`
    /// when the `reasoning` feature is disabled or no engine wired).
    pub reasoning: Option<Arc<dyn ReasoningHandle>>,
    /// 1.0 M6 — APL live policy overlay (optional). When present,
    /// the pipeline consults it after the YAML risk score and merges
    /// with stricter-wins. See `pipeline::apl_overlay`.
    #[cfg(feature = "apl")]
    pub apl_overlay: Option<Arc<AplOverlay>>,
}
