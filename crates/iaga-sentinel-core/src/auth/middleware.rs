use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::server::app_state::AppState;

/// Returns true if the IAGA_SENTINEL_OPEN_MODE env var is explicitly set to "true".
pub fn is_open_mode_enabled() -> bool {
    std::env::var("IAGA_SENTINEL_OPEN_MODE")
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Auth middleware: extracts Bearer token and verifies against stored Argon2 hashes.
/// Open mode (no auth when no keys exist) requires explicit opt-in via
/// IAGA_SENTINEL_OPEN_MODE=true. Without that env var, requests are rejected
/// with 401 if no API keys have been generated yet.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check if any keys exist
    let keys = state.api_key_store.list_keys().await.unwrap_or_default();
    if keys.is_empty() {
        if is_open_mode_enabled() {
            return Ok(next.run(request).await);
        }
        tracing::warn!("no API keys configured and IAGA_SENTINEL_OPEN_MODE is not enabled, rejecting request. Run `iaga gen-key` to create your first key.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract Bearer token
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // Verify the raw key against stored Argon2 hashes
    match state.api_key_store.verify_raw_key(token).await {
        Ok(true) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
