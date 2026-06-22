//! Thin HTTP client for `POST /v1/inspect` with a hard timeout.
//!
//! Exists because the gate runs synchronously inside Codex's loop: the
//! shared `SentinelClient` in `iaga-sentinel-integrations` does not expose
//! a timeout, and an unbounded inspect call would hang the agent. The wire
//! types are reused from that crate, so the contract stays single-source.

use thiserror::Error;

use iaga_sentinel_integrations::{GovernanceResult, InspectRequest};

use crate::hook_config::Config;

/// Failures the gate maps onto its fail policy.
#[derive(Debug, Error)]
pub enum InspectError {
    /// HTTP 404: the agent profile is not registered server-side. Called
    /// out separately so the gate can print the exact fix.
    #[error("agent '{agent_id}' is not registered at {base_url} (HTTP 404)")]
    AgentNotRegistered { agent_id: String, base_url: String },
    /// Any other non-success status (401/403 bad key, 5xx, ...).
    #[error("IAGA Sentinel returned HTTP {status}")]
    Http { status: u16 },
    /// Transport-level failure: connection refused, hard timeout, or an
    /// unparseable response body.
    #[error("IAGA Sentinel unreachable: {0}")]
    Transport(#[from] reqwest::Error),
}

/// One-shot inspect client; built per hook invocation.
#[derive(Debug)]
pub struct InspectClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    agent_id: String,
}

impl InspectClient {
    /// Build a client with the hard timeout from [`Config`] applied to the
    /// whole request (connect + read).
    pub fn new(config: &Config) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder().timeout(config.timeout).build()?;
        Ok(Self {
            http,
            base_url: config.base_url.clone(),
            api_key: config.api_key.clone(),
            agent_id: config.agent_id.clone(),
        })
    }

    /// Ask the sidecar for a verdict on one pending tool call.
    pub async fn inspect(
        &self,
        request: &InspectRequest,
    ) -> Result<GovernanceResult, InspectError> {
        let mut builder = self
            .http
            .post(format!("{}/v1/inspect", self.base_url))
            .json(request);
        if let Some(key) = &self.api_key {
            builder = builder.bearer_auth(key);
        }

        let response = builder.send().await?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(InspectError::AgentNotRegistered {
                agent_id: self.agent_id.clone(),
                base_url: self.base_url.clone(),
            });
        }
        if !status.is_success() {
            return Err(InspectError::Http {
                status: status.as_u16(),
            });
        }
        Ok(response.json::<GovernanceResult>().await?)
    }
}
