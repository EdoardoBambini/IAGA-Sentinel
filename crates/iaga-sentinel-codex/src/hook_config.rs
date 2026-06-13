//! Environment-driven configuration for the Codex gate.
//!
//! Shared knobs reuse the names every other integration already uses
//! (`IAGA_BASE_URL`, `IAGA_API_KEY`, see the claude-code hook); the
//! Codex-specific ones are namespaced `IAGA_CODEX_*`. Tests build
//! [`Config`] directly instead of mutating process env, so they can run
//! in parallel safely.

use std::time::Duration;

/// Default sidecar base URL, same as every other integration.
pub const DEFAULT_BASE_URL: &str = "http://localhost:4010";

/// Static agent identity for Codex sessions. `/v1/inspect` returns 404
/// for unregistered agents, so the id must match a registered profile
/// (`examples/integrations/codex/codex.policy.yaml`). The Codex
/// `session_id` rides in the request metadata instead — never in the
/// agent id.
pub const DEFAULT_AGENT_ID: &str = "codex";

/// Framework label stamped on every inspect request and receipt.
pub const FRAMEWORK: &str = "codex";

/// Hard timeout for the inspect round-trip. The hook runs synchronously
/// inside Codex's loop, so an unbounded call would hang the agent.
pub const DEFAULT_TIMEOUT_MS: u64 = 1_000;

/// Transport-failure policy.
///
/// The Codex gate is **fail-closed by default** — deliberately the
/// opposite of the observation-only adapters (claude-code hook, SDKs),
/// which fail open. This integration is an enforcement point: an
/// unreachable sidecar must not silently widen what the agent may do.
/// `IAGA_CODEX_FAIL=open` opts into availability over enforcement; the
/// coverage gap is then declared on stderr instead of being attested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPolicy {
    Closed,
    Open,
}

/// Runtime configuration for the gate, resolved once per hook invocation.
#[derive(Debug, Clone)]
pub struct Config {
    /// Sidecar base URL without trailing slash (`IAGA_BASE_URL`).
    pub base_url: String,
    /// Bearer token for `/v1/inspect`, if the sidecar requires auth
    /// (`IAGA_API_KEY`; an `agent`-scoped key is sufficient).
    pub api_key: Option<String>,
    /// Registered agent identity (`IAGA_CODEX_AGENT_ID`).
    pub agent_id: String,
    /// What to do when no verdict can be obtained (`IAGA_CODEX_FAIL`).
    pub fail_policy: FailPolicy,
    /// Hard inspect timeout (`IAGA_CODEX_TIMEOUT_MS`).
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: None,
            agent_id: DEFAULT_AGENT_ID.to_string(),
            fail_policy: FailPolicy::Closed,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl Config {
    /// Resolve the configuration from process environment variables,
    /// falling back to the documented defaults on unset or invalid values
    /// (an invalid value never widens the fail policy).
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(url) = std::env::var("IAGA_BASE_URL") {
            let trimmed = url.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                config.base_url = trimmed.to_string();
            }
        }
        if let Ok(key) = std::env::var("IAGA_API_KEY") {
            if !key.trim().is_empty() {
                config.api_key = Some(key.trim().to_string());
            }
        }
        if let Ok(agent_id) = std::env::var("IAGA_CODEX_AGENT_ID") {
            if !agent_id.trim().is_empty() {
                config.agent_id = agent_id.trim().to_string();
            }
        }
        if let Ok(policy) = std::env::var("IAGA_CODEX_FAIL") {
            match policy.trim().to_ascii_lowercase().as_str() {
                "open" => config.fail_policy = FailPolicy::Open,
                "closed" | "" => config.fail_policy = FailPolicy::Closed,
                other => {
                    // Unknown value: keep the safe default, say so once.
                    eprintln!(
                        "[iaga-codex] unknown IAGA_CODEX_FAIL value '{other}', \
                         keeping fail-closed (expected 'closed' or 'open')"
                    );
                }
            }
        }
        if let Ok(raw_ms) = std::env::var("IAGA_CODEX_TIMEOUT_MS") {
            match raw_ms.trim().parse::<u64>() {
                Ok(ms) if ms > 0 => config.timeout = Duration::from_millis(ms),
                _ => {
                    eprintln!(
                        "[iaga-codex] invalid IAGA_CODEX_TIMEOUT_MS '{raw_ms}', \
                         keeping default {DEFAULT_TIMEOUT_MS} ms"
                    );
                }
            }
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // from_env() reads process-global env, which is unsafe to mutate in
    // parallel tests; defaults are asserted here, env overrides are
    // exercised end-to-end by the gate tests via explicit Config values.
    #[test]
    fn defaults_are_fail_closed_with_1s_timeout() {
        let config = Config::default();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.agent_id, DEFAULT_AGENT_ID);
        assert_eq!(config.api_key, None);
        assert_eq!(config.fail_policy, FailPolicy::Closed);
        assert_eq!(config.timeout, Duration::from_millis(1_000));
    }
}
