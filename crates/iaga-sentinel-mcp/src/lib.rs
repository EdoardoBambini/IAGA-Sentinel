//! `iaga::mcp::GovernedTool` — cooperative MCP `tools/call` governance for Rust.
//!
//! A thin wrapper over the public [`iaga_sentinel_integrations`] client: it maps
//! an MCP `tools/call` (tool name + arguments) into the public `InspectRequest`,
//! POSTs it to `/v1/inspect`, and runs the wrapped work **only if** the verdict
//! is Allow — the same contract as the Python and TypeScript `GovernedTool`. It
//! is cooperative and fail-open by default; it does **not** depend on the core
//! pipeline crate, and every receipt the sidecar writes for these calls is
//! `is_authoritative:false`.
//!
//! ```no_run
//! use iaga_sentinel_mcp::mcp::GovernedTool;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let tool = GovernedTool::new("http://localhost:4010", "my-agent");
//! // The work future is only polled if governance allows the call.
//! let governed = tool
//!     .call("read_file", serde_json::json!({ "path": "/etc/hostname" }), async {
//!         std::fs::read_to_string("/etc/hostname").unwrap_or_default()
//!     })
//!     .await?;
//! println!("{} (authoritative={})", governed.value, governed.is_authoritative);
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;

use iaga_sentinel_integrations::{
    ActionDetail, ActionType, GovernanceResult, InspectRequest, SentinelClient, SentinelError,
};

/// Cooperative governance wrapper for MCP tool calls.
pub struct GovernedTool {
    client: SentinelClient,
    agent_id: String,
    fail_closed: bool,
}

impl GovernedTool {
    /// Point at the sidecar base URL (e.g. `http://localhost:4010`) and the
    /// agent the calls are attributed to. Fail-open by default.
    pub fn new(base_url: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            client: SentinelClient::new(base_url),
            agent_id: agent_id.into(),
            fail_closed: false,
        }
    }

    /// Attach a bearer token used on every `/v1/inspect` call.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.client = self.client.with_api_key(key);
        self
    }

    /// Treat a sidecar that is unreachable (or 5xx) as a Block instead of
    /// failing open. Off by default, matching the SDK contract.
    pub fn fail_closed(mut self, yes: bool) -> Self {
        self.fail_closed = yes;
        self
    }

    /// Inspect an MCP `tools/call` and return the raw verdict. Performs no
    /// side-effecting work — use [`GovernedTool::call`] to gate work on Allow.
    pub async fn inspect(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<GovernanceResult, SentinelError> {
        let request = self.build_request(tool_name, arguments);
        self.client
            .inspect_with_policy(&request, self.fail_closed)
            .await
    }

    /// Inspect the call, then await `work` **iff** the verdict is Allow. A
    /// Block or Review returns `Err` and the `work` future is dropped unpolled,
    /// so a blocked tool's side effects never happen. Pass `work` as an
    /// `async { .. }` block: a future is lazy, so its body does not run until
    /// this method awaits it.
    pub async fn call<T, Fut>(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        work: Fut,
    ) -> Result<Governed<T>, SentinelError>
    where
        Fut: std::future::Future<Output = T>,
    {
        let request = self.build_request(tool_name, arguments);
        let result = self.client.enforce(&request, self.fail_closed).await?;
        let event_id = event_id_of(&result);
        Ok(Governed {
            value: work.await,
            trace_id: result.trace_id,
            event_id,
            // OSS governance is cooperative; the sidecar's receipt is advisory.
            is_authoritative: false,
        })
    }

    fn build_request(&self, tool_name: &str, arguments: serde_json::Value) -> InspectRequest {
        let payload: HashMap<String, serde_json::Value> = match arguments {
            serde_json::Value::Object(map) => map.into_iter().collect(),
            // A non-object argument is wrapped so the wire `payload` stays an
            // object, as the server expects.
            other => HashMap::from([("value".to_string(), other)]),
        };
        InspectRequest::new(
            self.agent_id.clone(),
            "mcp",
            ActionDetail::new(infer_action_type(tool_name), tool_name, payload),
        )
        .with_protocol("mcp")
    }
}

/// Result of an allowed governed call.
#[derive(Debug, Clone)]
pub struct Governed<T> {
    /// The value produced by the wrapped work.
    pub value: T,
    /// Trace id of the governance decision.
    pub trace_id: String,
    /// The audit event id. Equals the receipt `run_id` only when a `sessionId`
    /// is threaded through `metadata`; otherwise it is the per-call event id,
    /// resolvable under `GET /v1/receipts/{event_id}`.
    pub event_id: String,
    /// Always `false`: OSS governance is cooperative, never authoritative.
    pub is_authoritative: bool,
}

fn event_id_of(result: &GovernanceResult) -> String {
    result
        .audit_event
        .get("eventId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Infer an action category from an MCP tool name. Mirrors the proxy/SDK
/// heuristic so a Rust caller gets the same mapping as the rest of the stack.
fn infer_action_type(tool_name: &str) -> ActionType {
    let lower = tool_name.to_lowercase();
    if lower.contains("read")
        || lower.contains("get")
        || lower.contains("list")
        || lower.contains("search")
    {
        ActionType::FileRead
    } else if lower.contains("write")
        || lower.contains("create")
        || lower.contains("update")
        || lower.contains("edit")
    {
        ActionType::FileWrite
    } else if lower.contains("exec")
        || lower.contains("run")
        || lower.contains("shell")
        || lower.contains("bash")
        || lower.contains("command")
    {
        ActionType::Shell
    } else if lower.contains("http")
        || lower.contains("fetch")
        || lower.contains("request")
        || lower.contains("curl")
    {
        ActionType::Http
    } else if lower.contains("query")
        || lower.contains("sql")
        || lower.contains("db")
        || lower.contains("database")
    {
        ActionType::DbQuery
    } else if lower.contains("email") || lower.contains("mail") || lower.contains("send") {
        ActionType::Email
    } else {
        ActionType::Custom
    }
}

/// Re-export so the roadmap's `iaga::mcp::GovernedTool` path resolves as
/// `iaga_sentinel_mcp::mcp::GovernedTool`.
pub mod mcp {
    pub use crate::{Governed, GovernedTool};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn infers_action_type_from_tool_name() {
        assert_eq!(infer_action_type("read_file"), ActionType::FileRead);
        assert_eq!(infer_action_type("shell.exec"), ActionType::Shell);
        assert_eq!(infer_action_type("http_fetch"), ActionType::Http);
        assert_eq!(infer_action_type("send_email"), ActionType::Email);
        assert_eq!(infer_action_type("frobnicate"), ActionType::Custom);
    }

    /// Minimal axum mock of `/v1/inspect`: one canned verdict, captures bodies.
    mod mock_server {
        use std::net::SocketAddr;
        use std::sync::{Arc, Mutex};

        pub(super) struct MockSentinel {
            pub addr: SocketAddr,
            pub captured: Arc<Mutex<Vec<serde_json::Value>>>,
            handle: tokio::task::JoinHandle<()>,
        }

        impl MockSentinel {
            pub(super) async fn serve(decision: &'static str, score: u32) -> Self {
                use axum::{routing::post, Json, Router};

                let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
                let captured_in = captured.clone();
                let app = Router::new().route(
                    "/v1/inspect",
                    post(move |Json(body): Json<serde_json::Value>| {
                        let captured = captured_in.clone();
                        async move {
                            captured.lock().unwrap().push(body);
                            Json(serde_json::json!({
                                "traceId": "mock-trace",
                                "decision": decision,
                                "risk": { "score": score, "decision": decision, "reasons": ["mock reason"] },
                                "auditEvent": { "eventId": "mock-event" }
                            }))
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind mock listener");
                let addr = listener.local_addr().expect("mock addr");
                let handle = tokio::spawn(async move {
                    axum::serve(listener, app).await.expect("mock server runs");
                });
                Self {
                    addr,
                    captured,
                    handle,
                }
            }

            pub(super) fn base_url(&self) -> String {
                format!("http://{}", self.addr)
            }
        }

        impl Drop for MockSentinel {
            fn drop(&mut self) {
                self.handle.abort();
            }
        }
    }

    #[tokio::test]
    async fn allow_runs_work_and_sends_mcp_wire_body() {
        let server = mock_server::MockSentinel::serve("allow", 5).await;
        let tool = GovernedTool::new(server.base_url(), "demo-agent").with_api_key("iaga_test");

        let ran = Arc::new(AtomicBool::new(false));
        let ran_in = ran.clone();
        let governed = tool
            .call(
                "read_file",
                serde_json::json!({ "path": "/etc/hostname" }),
                async move {
                    ran_in.store(true, Ordering::SeqCst);
                    "host-x".to_string()
                },
            )
            .await
            .expect("allow verdict runs the work");

        assert!(ran.load(Ordering::SeqCst), "work must run on allow");
        assert_eq!(governed.value, "host-x");
        assert_eq!(governed.event_id, "mock-event");
        assert!(!governed.is_authoritative, "OSS is never authoritative");

        // The body on the wire is the MCP-shaped public contract.
        let captured = server.captured.lock().unwrap();
        let body = &captured[0];
        assert_eq!(body["agentId"], "demo-agent");
        assert_eq!(body["framework"], "mcp");
        assert_eq!(body["protocol"], "mcp");
        assert_eq!(body["action"]["toolName"], "read_file");
        assert_eq!(body["action"]["type"], "file_read");
        assert_eq!(body["action"]["payload"]["path"], "/etc/hostname");
    }

    #[tokio::test]
    async fn block_returns_error_and_does_not_run_work() {
        let server = mock_server::MockSentinel::serve("block", 95).await;
        let tool = GovernedTool::new(server.base_url(), "demo-agent");

        let ran = Arc::new(AtomicBool::new(false));
        let ran_in = ran.clone();
        let err = tool
            .call("delete_everything", serde_json::json!({}), async move {
                ran_in.store(true, Ordering::SeqCst);
            })
            .await
            .expect_err("block must surface an error");

        assert!(!ran.load(Ordering::SeqCst), "blocked work must NOT run");
        assert!(matches!(err, SentinelError::Blocked { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn review_returns_error() {
        let server = mock_server::MockSentinel::serve("review", 60).await;
        let tool = GovernedTool::new(server.base_url(), "demo-agent");
        let err = tool
            .call("update_record", serde_json::json!({}), async {})
            .await
            .expect_err("review must surface an error");
        assert!(matches!(err, SentinelError::Review { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn fail_open_by_default_runs_work_when_sidecar_down() {
        // Nothing is listening on this port.
        let tool = GovernedTool::new("http://127.0.0.1:4999", "demo-agent");
        let governed = tool
            .call("read_file", serde_json::json!({}), async { 42 })
            .await
            .expect("fail-open runs the work");
        assert_eq!(governed.value, 42);
        assert!(!governed.is_authoritative);
    }

    #[tokio::test]
    async fn fail_closed_errors_when_sidecar_down() {
        let tool = GovernedTool::new("http://127.0.0.1:4999", "demo-agent").fail_closed(true);
        let err = tool
            .call("read_file", serde_json::json!({}), async {})
            .await
            .expect_err("fail-closed surfaces an error");
        assert!(
            matches!(err, SentinelError::Unreachable { .. }),
            "got {err:?}"
        );
    }
}
