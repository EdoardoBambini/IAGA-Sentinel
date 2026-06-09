use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "plugins")]
#[path = "support/plugin_test_support.rs"]
mod plugin_test_support;

use iaga_sentinel::auth::api_keys::generate_api_key;
use iaga_sentinel::config::env::{AppEnv, NodeEnv, ServiceMode};
use iaga_sentinel::core::types::RateLimitConfig;
use iaga_sentinel::demo::scenarios::{demo_profiles, demo_workspace_policies};
use iaga_sentinel::events::bus::EventBus;
use iaga_sentinel::events::webhooks::{DeadLetterQueue, WebhookManager};
use iaga_sentinel::modules::fingerprint::behavioral::BehavioralEngine;
use iaga_sentinel::modules::rate_limit::limiter::RateLimiter;
use iaga_sentinel::modules::threat_intel::feed::ThreatFeed;
use iaga_sentinel::plugins::PluginRegistry;
use iaga_sentinel::server::app_state::AppState;
use iaga_sentinel::server::create_server::create_router;
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::{ApiKeyStore, PolicyStore, StorageBackend};
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

struct TestServer {
    address: SocketAddr,
    api_key: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_test_server() -> TestServer {
    spawn_test_server_with_plugin_registry(Arc::new(PluginRegistry::default())).await
}

async fn spawn_test_server_with_plugin_registry(
    plugin_registry: Arc<PluginRegistry>,
) -> TestServer {
    let db_url = format!(
        "sqlite:file:e2e-http-{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );
    let storage = SqliteStorage::new(&db_url)
        .await
        .expect("failed to create in-memory SQLite");
    let storage = Arc::new(storage);

    for profile in demo_profiles() {
        storage
            .upsert_profile(&profile)
            .await
            .expect("failed to seed profile");
    }
    for workspace in demo_workspace_policies() {
        storage
            .upsert_workspace(&workspace)
            .await
            .expect("failed to seed workspace policy");
    }

    let (raw_key, key_hash) = generate_api_key();
    storage
        .store_key("seeded-key", &key_hash, "e2e", &raw_key)
        .await
        .expect("failed to seed api key");

    let state = Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        tenant_store: storage.clone(),
        nhi_store: storage.clone(),
        session_store: storage.clone(),
        taint_store: storage.clone(),
        fingerprint_store: storage.clone(),
        rate_limit_store: storage.clone(),
        event_bus: EventBus::new(64),
        webhook_manager: Arc::new(WebhookManager::new(Arc::new(DeadLetterQueue::new()))),
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: Arc::new(ThreatFeed::with_builtin_indicators()),
        plugin_registry,
        storage_backend: StorageBackend::Sqlite,
        env: AppEnv {
            port: 0,
            node_env: NodeEnv::Test,
            default_mode: ServiceMode::Gateway,
        },
        receipts: None,
        reasoning: None,
        #[cfg(feature = "apl")]
        apl_overlay: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test listener");
    let address = listener
        .local_addr()
        .expect("failed to read listener address");

    let router = create_router(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("test server should run");
    });

    TestServer {
        address,
        api_key: raw_key,
        task,
    }
}

fn auth_client(api_key: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {api_key}")
            .parse()
            .expect("valid auth header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("failed to build reqwest client")
}

fn safe_inspect_body() -> Value {
    serde_json::json!({
        "agentId": "openclaw-builder-01",
        "tenantId": null,
        "workspaceId": "ws-demo",
        "framework": "openclaw",
        "protocol": "mcp",
        "action": {
            "type": "file_read",
            "toolName": "filesystem.read",
            "payload": {
                "path": "README.md",
                "intent": "read repository documentation"
            }
        },
        "requestedSecrets": null,
        "metadata": null
    })
}

fn blocked_inspect_body() -> Value {
    serde_json::json!({
        "agentId": "openclaw-builder-01",
        "tenantId": null,
        "workspaceId": "ws-demo",
        "framework": "openclaw",
        "protocol": "mcp",
        "action": {
            "type": "shell",
            "toolName": "terminal.exec",
            "payload": {
                "command": "rm -rf /",
                "intent": "cleanup"
            }
        },
        "requestedSecrets": null,
        "metadata": {
            "sessionId": "e2e-session-1"
        }
    })
}

fn session_sequence_file_read_body(session_id: &str) -> Value {
    serde_json::json!({
        "agentId": "openclaw-builder-01",
        "tenantId": null,
        "workspaceId": "ws-demo",
        "framework": "openclaw",
        "protocol": "mcp",
        "action": {
            "type": "file_read",
            "toolName": "filesystem.read",
            "payload": {
                "path": "README.md",
                "intent": "inspect repository docs"
            }
        },
        "requestedSecrets": null,
        "metadata": {
            "sessionId": session_id
        }
    })
}

fn session_sequence_http_body(session_id: &str) -> Value {
    serde_json::json!({
        "agentId": "openclaw-builder-01",
        "tenantId": null,
        "workspaceId": "ws-demo",
        "framework": "openclaw",
        "protocol": "mcp",
        "action": {
            "type": "http",
            "toolName": "http.fetch",
            "payload": {
                "method": "POST",
                "destination": "api.github.com",
                "intent": "send repository summary"
            }
        },
        "requestedSecrets": null,
        "metadata": {
            "sessionId": session_id
        }
    })
}

#[tokio::test]
async fn test_http_end_to_end_governance_flow() {
    let server = spawn_test_server().await;
    let client = auth_client(&server.api_key);

    let health = client
        .get(format!("{}/health", server.base_url()))
        .send()
        .await
        .expect("health request should succeed");
    assert_eq!(health.status(), StatusCode::OK);
    assert!(
        health.headers().contains_key("x-request-id"),
        "health response should include x-request-id"
    );

    let inspect = client
        .post(format!("{}/v1/inspect", server.base_url()))
        .json(&safe_inspect_body())
        .send()
        .await
        .expect("inspect request should succeed");
    assert_eq!(inspect.status(), StatusCode::OK);
    assert!(
        inspect.headers().contains_key("x-request-id"),
        "inspect response should include x-request-id"
    );
    let inspect_json: Value = inspect
        .json()
        .await
        .expect("inspect response should be JSON");
    assert_eq!(inspect_json["decision"], "allow");
    assert!(
        inspect_json["risk"]["score"].as_u64().unwrap_or_default() <= 10,
        "safe inspect should stay low risk, got {:?}",
        inspect_json["risk"]["score"]
    );
    assert!(
        inspect_json["traceId"].as_str().is_some(),
        "inspect response should include traceId"
    );

    let blocked = client
        .post(format!("{}/v1/inspect", server.base_url()))
        .json(&blocked_inspect_body())
        .send()
        .await
        .expect("blocked inspect request should succeed");
    assert_eq!(blocked.status(), StatusCode::OK);
    let blocked_json: Value = blocked
        .json()
        .await
        .expect("blocked response should be JSON");
    assert_eq!(blocked_json["decision"], "block");
    assert!(
        blocked_json["risk"]["score"].as_u64().unwrap_or_default() >= 70,
        "blocked response should carry a high risk score"
    );

    let demo_card = format!("{}{}", "4111 1111 ", "1111 1111");
    let scan_body = serde_json::json!({
        "requestId": "scan-e2e-1",
        "agentId": "openclaw-builder-01",
        "toolName": "terminal.exec",
        "responsePayload": {
            "card": demo_card,
            "message": "test payment data"
        },
        "metadata": null
    });
    let scan = client
        .post(format!("{}/v1/response/scan", server.base_url()))
        .json(&scan_body)
        .send()
        .await
        .expect("response scan should succeed");
    assert_eq!(scan.status(), StatusCode::OK);
    let scan_json: Value = scan.json().await.expect("response scan should return JSON");
    assert_eq!(scan_json["decision"], "review");
    assert!(
        scan_json["riskScore"].as_u64().unwrap_or_default() >= 50,
        "response scan should surface elevated risk"
    );

    let audit = client
        .get(format!("{}/v1/audit", server.base_url()))
        .send()
        .await
        .expect("audit request should succeed");
    assert_eq!(audit.status(), StatusCode::OK);
    let audit_json: Value = audit.json().await.expect("audit response should be JSON");
    let audit_events = audit_json.as_array().expect("audit should return an array");
    assert_eq!(
        audit_events.len(),
        2,
        "two inspect requests should be audited"
    );

    let export = client
        .get(format!("{}/v1/audit/export?format=csv", server.base_url()))
        .send()
        .await
        .expect("audit export should succeed");
    assert_eq!(export.status(), StatusCode::OK);
    let csv = export.text().await.expect("csv export should be readable");
    assert!(
        csv.starts_with("event_id,agent_id,framework,action_type,tool_name,decision,risk_score,review_status,timestamp"),
        "csv export should include the header row"
    );
}

#[tokio::test]
async fn test_http_same_session_double_call_is_correlated() {
    let server = spawn_test_server().await;
    let client = auth_client(&server.api_key);
    let session_id = "e2e-sequence-double-1";

    let first = client
        .post(format!("{}/v1/inspect", server.base_url()))
        .json(&session_sequence_file_read_body(session_id))
        .send()
        .await
        .expect("first inspect should succeed");
    assert_eq!(first.status(), StatusCode::OK);
    let first_json: Value = first.json().await.expect("first inspect should be JSON");
    assert_eq!(first_json["decision"], "allow");

    let second = client
        .post(format!("{}/v1/inspect", server.base_url()))
        .json(&session_sequence_http_body(session_id))
        .send()
        .await
        .expect("second inspect should succeed");
    assert_eq!(second.status(), StatusCode::OK);
    let second_json: Value = second.json().await.expect("second inspect should be JSON");
    assert_eq!(
        second_json["decision"], "block",
        "same-session read -> http should block, got {second_json:?}"
    );
    assert!(
        second_json["risk"]["score"].as_u64().unwrap_or_default() >= 70,
        "same-session sequence should score high risk, got {:?}",
        second_json["risk"]["score"]
    );
    assert_eq!(second_json["sessionGraph"]["transitionAllowed"], false);
    assert!(
        second_json["sessionGraph"]["attacksDetected"]
            .as_array()
            .is_some_and(|attacks| attacks
                .iter()
                .any(|attack| attack["name"] == "data_exfiltration")),
        "expected data_exfiltration attack in session graph, got {:?}",
        second_json["sessionGraph"]
    );

    let audit = client
        .get(format!("{}/v1/audit", server.base_url()))
        .send()
        .await
        .expect("audit request should succeed");
    assert_eq!(audit.status(), StatusCode::OK);
    let audit_json: Value = audit.json().await.expect("audit response should be JSON");
    let audit_events = audit_json.as_array().expect("audit should return an array");
    assert_eq!(
        audit_events.len(),
        2,
        "two same-session inspect requests should both be audited"
    );
}

#[tokio::test]
async fn test_http_plugin_endpoints_are_available() {
    let server = spawn_test_server().await;
    let client = auth_client(&server.api_key);

    let list = client
        .get(format!("{}/v1/plugins", server.base_url()))
        .send()
        .await
        .expect("plugin list should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list_json: Value = list.json().await.expect("plugin list should be JSON");
    assert!(list_json["pluginDir"].is_string());
    assert!(list_json["plugins"].is_array());
    assert!(list_json["loadErrors"].is_array());
    assert!(list_json["loadedCount"].is_u64());

    let reload = client
        .post(format!("{}/v1/plugins/reload", server.base_url()))
        .send()
        .await
        .expect("plugin reload should succeed");
    assert_eq!(reload.status(), StatusCode::OK);
    let reload_json: Value = reload.json().await.expect("plugin reload should be JSON");
    assert!(reload_json["pluginDir"].is_string());
    assert!(reload_json["plugins"].is_array());
    assert!(reload_json["loadErrors"].is_array());
    assert!(reload_json["loadedCount"].is_u64());
}

#[tokio::test]
async fn test_http_workspace_rules_persist_and_affect_pipeline() {
    let server = spawn_test_server().await;
    let client = auth_client(&server.api_key);

    let rule_body = serde_json::json!({
        "id": "review-readme-1",
        "name": "review-readme-access",
        "priority": 1,
        "matchCriteria": {
            "actionType": ["file_read"],
            "toolName": ["filesystem.read"]
        },
        "conditions": {
            "payloadContains": ["README.md"]
        },
        "decision": "review",
        "reason": "README access requires manual review",
        "enabled": true
    });

    let create_rule = client
        .post(format!("{}/v1/workspaces/ws-demo/rules", server.base_url()))
        .json(&rule_body)
        .send()
        .await
        .expect("create rule request should succeed");
    assert_eq!(create_rule.status(), StatusCode::CREATED);
    let create_rule_json: Value = create_rule
        .json()
        .await
        .expect("create rule response should be JSON");
    assert_eq!(create_rule_json["status"], "persisted");
    assert_eq!(create_rule_json["rule"]["id"], "review-readme-1");

    let list_rules = client
        .get(format!("{}/v1/workspaces/ws-demo/rules", server.base_url()))
        .send()
        .await
        .expect("list rules request should succeed");
    assert_eq!(list_rules.status(), StatusCode::OK);
    let list_rules_json: Value = list_rules.json().await.expect("list rules should be JSON");
    assert_eq!(list_rules_json["count"], 1);
    assert_eq!(list_rules_json["rules"][0]["id"], "review-readme-1");
    assert_eq!(list_rules_json["rules"][0]["decision"], "review");

    let inspect = client
        .post(format!("{}/v1/inspect", server.base_url()))
        .json(&safe_inspect_body())
        .send()
        .await
        .expect("inspect with persisted rule should succeed");
    assert_eq!(inspect.status(), StatusCode::OK);
    let inspect_json: Value = inspect
        .json()
        .await
        .expect("inspect response should be JSON");
    assert_eq!(
        inspect_json["decision"], "review",
        "persisted workspace rule should elevate the otherwise-safe request, got {inspect_json:?}"
    );
    assert!(
        inspect_json["policyFindings"]
            .as_array()
            .is_some_and(|findings| findings.iter().any(|finding| {
                finding
                    .as_str()
                    .is_some_and(|finding| finding.contains("README access requires manual review"))
            })),
        "expected persisted rule reason in policy findings, got {:?}",
        inspect_json["policyFindings"]
    );
}

#[cfg(feature = "plugins")]
#[tokio::test]
async fn test_http_real_wasm_plugin_dir_populates_plugin_results() {
    let plugin_dir = plugin_test_support::TempPluginDir::new("e2e-http");
    let plugin_path = plugin_dir.write_review_plugin();
    let plugin_registry = Arc::new(PluginRegistry::new(plugin_dir.path().to_path_buf()));
    let snapshot = plugin_registry.reload();

    assert_eq!(snapshot.loaded_count, 1);
    assert!(
        snapshot.load_errors.is_empty(),
        "unexpected plugin load errors: {:?}",
        snapshot.load_errors
    );

    let server = spawn_test_server_with_plugin_registry(plugin_registry).await;
    let client = auth_client(&server.api_key);

    let list = client
        .get(format!("{}/v1/plugins", server.base_url()))
        .send()
        .await
        .expect("plugin list should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list_json: Value = list.json().await.expect("plugin list should be JSON");
    assert_eq!(list_json["loadedCount"], 1);
    assert_eq!(
        list_json["plugins"][0]["name"],
        plugin_test_support::PLUGIN_NAME
    );
    assert_eq!(
        list_json["plugins"][0]["version"],
        plugin_test_support::PLUGIN_VERSION
    );
    assert_eq!(
        list_json["plugins"][0]["path"],
        plugin_path.display().to_string()
    );

    let inspect = client
        .post(format!("{}/v1/inspect", server.base_url()))
        .json(&safe_inspect_body())
        .send()
        .await
        .expect("inspect with real WASM plugin should succeed");
    assert_eq!(inspect.status(), StatusCode::OK);
    let inspect_json: Value = inspect
        .json()
        .await
        .expect("inspect response should be JSON");

    assert_eq!(
        inspect_json["decision"], "review",
        "plugin decision hint should elevate inspect response, got {inspect_json:?}"
    );
    assert_eq!(
        inspect_json["pluginResults"][0]["pluginName"],
        plugin_test_support::PLUGIN_NAME
    );
    assert_eq!(
        inspect_json["pluginResults"][0]["pluginVersion"],
        plugin_test_support::PLUGIN_VERSION
    );
    assert_eq!(
        inspect_json["pluginResults"][0]["result"]["riskScore"],
        plugin_test_support::PLUGIN_RISK_SCORE
    );
    assert_eq!(
        inspect_json["pluginResults"][0]["result"]["decisionHint"],
        plugin_test_support::PLUGIN_DECISION_HINT
    );
    assert!(
        inspect_json["pluginResults"][0]["result"]["findings"]
            .as_array()
            .is_some_and(|findings| findings
                .iter()
                .any(|finding| finding == plugin_test_support::PLUGIN_FINDING)),
        "expected concrete plugin finding in response, got {:?}",
        inspect_json["pluginResults"]
    );
    assert!(
        inspect_json["policyFindings"]
            .as_array()
            .is_some_and(|findings| findings.iter().any(|finding| {
                finding
                    .as_str()
                    .is_some_and(|finding| finding.contains(plugin_test_support::PLUGIN_FINDING))
            })),
        "pipeline should merge plugin findings into policy findings, got {:?}",
        inspect_json["policyFindings"]
    );
}

#[tokio::test]
async fn test_dashboard_root_and_public_context_are_available() {
    let server = spawn_test_server().await;
    let client = reqwest::Client::new();

    let dashboard = client
        .get(server.base_url())
        .send()
        .await
        .expect("dashboard request should succeed");
    assert_eq!(dashboard.status(), StatusCode::OK);
    let dashboard_html = dashboard
        .text()
        .await
        .expect("dashboard response should be text");
    assert!(
        dashboard_html.contains("Operator Console"),
        "dashboard should expose the live operator console"
    );
    assert!(
        dashboard_html.contains("/dashboard/context"),
        "dashboard should load public runtime context"
    );

    let context = client
        .get(format!("{}/dashboard/context", server.base_url()))
        .send()
        .await
        .expect("dashboard context request should succeed");
    assert_eq!(context.status(), StatusCode::OK);
    let context_json: Value = context
        .json()
        .await
        .expect("dashboard context should be JSON");
    assert_eq!(context_json["service"], "iaga-sentinel");
    assert_eq!(context_json["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(context_json["apiKeysConfigured"], true);
    assert_eq!(context_json["openMode"], false);
}

#[tokio::test]
async fn test_http_authenticated_key_management_and_demo_routes() {
    let server = spawn_test_server().await;
    let client = auth_client(&server.api_key);

    let profiles = client
        .get(format!("{}/v1/profiles", server.base_url()))
        .send()
        .await
        .expect("profiles request should succeed");
    assert_eq!(profiles.status(), StatusCode::OK);
    let profiles_json: Value = profiles.json().await.expect("profiles should be JSON");
    assert_eq!(profiles_json.as_array().map(|v| v.len()), Some(2));

    let create_key = client
        .post(format!("{}/v1/auth/keys", server.base_url()))
        .json(&serde_json::json!({ "label": "e2e-second-key" }))
        .send()
        .await
        .expect("create key request should succeed");
    assert_eq!(create_key.status(), StatusCode::CREATED);
    let create_key_json: Value = create_key
        .json()
        .await
        .expect("create key should return JSON");
    assert_eq!(create_key_json["label"], "e2e-second-key");
    assert!(
        create_key_json["key"]
            .as_str()
            .map(|key| key.starts_with("iaga_"))
            .unwrap_or(false),
        "new API key should be returned once"
    );

    let demo = client
        .post(format!("{}/v1/demo/run-adapter", server.base_url()))
        .send()
        .await
        .expect("demo adapter request should succeed");
    assert_eq!(demo.status(), StatusCode::OK);
    let demo_json: Value = demo.json().await.expect("demo response should be JSON");
    let scenarios = demo_json
        .as_array()
        .expect("demo response should be an array");
    assert_eq!(scenarios.len(), 4);
    assert!(
        scenarios
            .iter()
            .any(|scenario| scenario["decision"] == "block"),
        "demo scenarios should include at least one blocked action"
    );
}

#[tokio::test]
async fn test_http_requires_valid_bearer_token() {
    let server = spawn_test_server().await;

    let unauthorized = reqwest::Client::new()
        .get(format!("{}/v1/audit", server.base_url()))
        .send()
        .await
        .expect("unauthorized request should complete");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let invalid = reqwest::Client::new()
        .get(format!("{}/v1/audit", server.base_url()))
        .header(reqwest::header::AUTHORIZATION, "Bearer invalid-key")
        .send()
        .await
        .expect("invalid-key request should complete");
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
}
