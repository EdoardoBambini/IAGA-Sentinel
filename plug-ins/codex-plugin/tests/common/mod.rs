//! Shared test harness: an in-process mock `/v1/inspect` sidecar.
//!
//! Same pattern as the MockSentinel in `iaga-sentinel-integrations`, shared
//! by the gate tests and the ingest tests so the wire contract is exercised
//! against one server. No live sidecar and no Codex binary required.
//!
//! Each integration-test binary compiles this module and uses a different
//! subset of [`Behavior`] (the gate never scripts verdicts; the ingest
//! never delays), so unused-variant warnings here are expected.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{routing::post, Json, Router};

/// How the mock answers one `/v1/inspect` call.
#[derive(Clone)]
pub enum Behavior {
    /// Respond with a canned verdict.
    Verdict {
        decision: &'static str,
        score: u32,
        reasons: Vec<&'static str>,
    },
    /// Respond with a bare HTTP status (e.g. 404 unregistered agent).
    Status(u16),
    /// Sleep first, then answer "allow" — exercises the hard timeout.
    Delayed(Duration),
    /// Answer each call from a script of verdicts, in order; once the
    /// script is exhausted, keep replaying the last entry. Lets one server
    /// hand different verdicts to a multi-event ingest stream.
    Script(Vec<ScriptedVerdict>),
}

/// One entry in a [`Behavior::Script`].
#[derive(Clone)]
pub struct ScriptedVerdict {
    pub decision: &'static str,
    pub score: u32,
    pub reasons: Vec<&'static str>,
    pub event_id: &'static str,
}

/// Serves one `/v1/inspect` behaviour; captures every request body.
pub struct MockSidecar {
    pub addr: SocketAddr,
    pub captured: Arc<Mutex<Vec<serde_json::Value>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockSidecar {
    pub async fn serve(behavior: Behavior) -> Self {
        let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
        let captured_in = captured.clone();
        // Per-server call counter so Script can advance through its entries.
        let calls = Arc::new(Mutex::new(0usize));
        let app = Router::new().route(
            "/v1/inspect",
            post(move |Json(body): Json<serde_json::Value>| {
                let captured = captured_in.clone();
                let behavior = behavior.clone();
                let calls = calls.clone();
                async move {
                    let nth = {
                        let mut guard = calls.lock().unwrap();
                        let n = *guard;
                        *guard += 1;
                        n
                    };
                    captured.lock().unwrap().push(body);
                    match behavior {
                        Behavior::Verdict {
                            decision,
                            score,
                            reasons,
                        } => {
                            verdict_json(decision, score, &reasons, "mock-event-1").into_response()
                        }
                        Behavior::Status(code) => StatusCode::from_u16(code)
                            .expect("valid status")
                            .into_response(),
                        Behavior::Delayed(delay) => {
                            tokio::time::sleep(delay).await;
                            verdict_json("allow", 0, &[], "mock-event-1").into_response()
                        }
                        Behavior::Script(entries) => {
                            let idx = nth.min(entries.len().saturating_sub(1));
                            let entry = &entries[idx];
                            verdict_json(
                                entry.decision,
                                entry.score,
                                &entry.reasons,
                                entry.event_id,
                            )
                            .into_response()
                        }
                    }
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

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

fn verdict_json(
    decision: &str,
    score: u32,
    reasons: &[&str],
    event_id: &str,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "traceId": "mock-trace",
        "decision": decision,
        "risk": { "score": score, "decision": decision, "reasons": reasons },
        "auditEvent": { "eventId": event_id }
    }))
}

impl Drop for MockSidecar {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
