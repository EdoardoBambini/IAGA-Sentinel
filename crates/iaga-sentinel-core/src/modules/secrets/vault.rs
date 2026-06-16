//! Demo secret-reference allowlist (CRYPTO-SECRETS-1).
//!
//! **This is NOT a secret store and resolves no real secrets.** It is a tiny
//! hardcoded allowlist of `secretref://…` identifiers that exists only to make
//! the secret-injection governance flow demonstrable end to end: the pipeline
//! can show an *approved* vs *denied* secret reference without any real
//! credential material ever being present.
//!
//! Resolving and protecting real secrets is deliberately out of scope for the
//! open build: bring your own resolver (env, file, or your platform's secret
//! manager) behind [`secret_exists`], or use a managed vault integration, which
//! is part of IAGA Sentinel Enterprise (ADR 0010). The name `DEMO_VAULT` is
//! load-bearing — keep it explicit so nobody mistakes this for a real vault.

use once_cell::sync::Lazy;
use std::collections::HashSet;

/// Hardcoded demo allowlist. Two illustrative refs, no real secrets behind them.
static DEMO_VAULT: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s = HashSet::new();
    s.insert("secretref://prod/github/token");
    s.insert("secretref://prod/slack/webhook");
    s
});

/// Whether `secret_ref` is a known (demo) secret reference. Demo-only: a real
/// deployment replaces this with a BYO resolver or a managed vault (Enterprise).
pub fn secret_exists(secret_ref: &str) -> bool {
    DEMO_VAULT.contains(secret_ref)
}
