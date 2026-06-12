use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::core::errors::SentinelError;
use crate::server::app_state::AppState;
use crate::storage::traits::KeyScope;

/// Returns true if the IAGA_SENTINEL_OPEN_MODE env var is explicitly set to "true".
pub fn is_open_mode_enabled() -> bool {
    std::env::var("IAGA_SENTINEL_OPEN_MODE")
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Identity attached to every authenticated request by [`auth_middleware`].
/// Handlers read it via the [`RequireAdmin`] extractor (or directly from
/// request extensions when they only need the key id).
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub scope: KeyScope,
    /// `None` in open mode and for keys verified through a legacy
    /// [`crate::storage::traits::ApiKeyStore`] implementation.
    pub key_id: Option<String>,
}

/// Extractor that rejects with `403 admin_scope_required` unless the request
/// authenticated with an `admin`-scoped key (or open mode, which is implicit
/// admin). Fails closed when the auth middleware did not run.
pub struct RequireAdmin;

impl<S> FromRequestParts<S> for RequireAdmin
where
    S: Send + Sync,
{
    type Rejection = SentinelError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthContext>() {
            Some(ctx) if ctx.scope == KeyScope::Admin => Ok(RequireAdmin),
            // Agent-scoped key, or middleware never ran (fail closed).
            _ => Err(SentinelError::AdminScopeRequired),
        }
    }
}

/// Auth middleware: extracts the Bearer token and verifies it against stored
/// Argon2 hashes, consulting the per-instance [`crate::auth::cache::AuthCache`]
/// first so the hot path skips the DB query + Argon2 work (1.5.2).
///
/// Open mode (no auth when no keys exist) requires explicit opt-in via
/// IAGA_SENTINEL_OPEN_MODE=true. Without that env var, requests are rejected
/// with 401 if no API keys have been generated yet.
///
/// Staleness: the cached "any keys exist" flag can lag out-of-process key
/// creation/deletion by at most the cache TTL. A presented token is always
/// verified for real on cache miss, so a key created by another process works
/// immediately; set IAGA_SENTINEL_AUTH_CACHE_TTL_MS=0 to disable caching.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract the Bearer token up front (owned, so we can mutate extensions).
    let token: Option<String> = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string);

    // "Any keys configured?" — cached; one list_keys() round-trip on miss.
    let keys_exist = match state.auth_cache.keys_exist() {
        Some(v) => v,
        None => {
            let exist = !state
                .api_key_store
                .list_keys()
                .await
                .unwrap_or_default()
                .is_empty();
            state.auth_cache.set_keys_exist(exist);
            exist
        }
    };

    // No keys yet and no token presented: open mode allows (as implicit
    // admin, the historical behavior), otherwise reject.
    if !keys_exist && token.is_none() {
        if is_open_mode_enabled() {
            request.extensions_mut().insert(AuthContext {
                scope: KeyScope::Admin,
                key_id: None,
            });
            return Ok(next.run(request).await);
        }
        tracing::warn!("no API keys configured and IAGA_SENTINEL_OPEN_MODE is not enabled, rejecting request. Run `iaga gen-key` to create your first key.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Keys exist (or the flag is stale and a token was presented anyway):
    // a Bearer token is required from here on.
    let token = match token {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Hot path: previously verified key, no DB query, no Argon2.
    if let Some((key_id, scope)) = state.auth_cache.lookup(&token) {
        request
            .extensions_mut()
            .insert(AuthContext { scope, key_id });
        return Ok(next.run(request).await);
    }

    // Cold path: verify against stored Argon2 hashes.
    match state.api_key_store.verify_raw_key_scoped(&token).await {
        Ok(Some(verified)) => {
            state
                .auth_cache
                .insert(&token, verified.key_id.clone(), verified.scope);
            state.auth_cache.set_keys_exist(true);
            request.extensions_mut().insert(AuthContext {
                scope: verified.scope,
                key_id: verified.key_id,
            });
            Ok(next.run(request).await)
        }
        _ => {
            // Preserve pre-1.5.2 open-mode semantics: with open mode on and
            // genuinely zero keys configured, any request is allowed even if
            // it carried a (stale/bogus) token. Fresh recheck, never cached.
            if is_open_mode_enabled() {
                let fresh_empty = state
                    .api_key_store
                    .list_keys()
                    .await
                    .map(|k| k.is_empty())
                    .unwrap_or(false);
                state.auth_cache.set_keys_exist(!fresh_empty);
                if fresh_empty {
                    request.extensions_mut().insert(AuthContext {
                        scope: KeyScope::Admin,
                        key_id: None,
                    });
                    return Ok(next.run(request).await);
                }
            }
            state.auth_cache.remove(&token);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
