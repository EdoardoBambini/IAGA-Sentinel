use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::core::errors::SentinelError;
use crate::server::app_state::AppState;

use super::protocol::*;
use super::tool_interceptor::{intercept_tool_call, InterceptResult};

/// MCP Proxy Server configuration.
pub struct McpProxyConfig {
    /// Agent ID to use for governance checks.
    pub agent_id: String,
    /// Command to launch the downstream MCP server.
    pub downstream_command: String,
    /// Arguments for the downstream command.
    pub downstream_args: Vec<String>,
    /// Environment variables for the downstream process.
    pub downstream_env: HashMap<String, String>,
}

/// Run the MCP proxy: reads JSON-RPC from stdin, governs tools/call,
/// forwards to downstream MCP server, returns responses to stdout.
pub async fn run_mcp_proxy(
    config: McpProxyConfig,
    state: Arc<AppState>,
) -> Result<(), SentinelError> {
    tracing::info!(
        agent_id = %config.agent_id,
        downstream = %config.downstream_command,
        "Starting MCP proxy mode"
    );

    // Spawn downstream MCP server
    let mut downstream = spawn_downstream(&config)?;
    let downstream_stdin = downstream
        .stdin
        .take()
        .ok_or_else(|| SentinelError::Proxy("Failed to capture downstream stdin".into()))?;
    let downstream_stdout = downstream
        .stdout
        .take()
        .ok_or_else(|| SentinelError::Proxy("Failed to capture downstream stdout".into()))?;

    let mut downstream_writer = downstream_stdin;
    let mut downstream_reader = BufReader::new(downstream_stdout).lines();

    // Read from our stdin (client → proxy)
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut client_reader = BufReader::new(stdin).lines();

    loop {
        tokio::select! {
            // Client → Proxy
            line = client_reader.next_line() => {
                match line {
                    Ok(Some(line)) if !line.trim().is_empty() => {
                        let request: JsonRpcRequest = match serde_json::from_str(&line) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::warn!(error = %e, "Invalid JSON-RPC from client");
                                continue;
                            }
                        };

                        match request.method.as_str() {
                            "tools/call" => {
                                let response = handle_tool_call(&request, &config, &state, &mut downstream_writer, &mut downstream_reader).await;
                                let out = match serde_json::to_string(&response) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::error!(error = %e, "Failed to serialize MCP response");
                                        continue;
                                    }
                                };
                                let _ = stdout.write_all(out.as_bytes()).await;
                                let _ = stdout.write_all(b"\n").await;
                                let _ = stdout.flush().await;
                            }
                            _ => {
                                // Pass-through: forward to downstream and relay response
                                let response = forward_and_relay(&request, &mut downstream_writer, &mut downstream_reader).await;
                                let out = match serde_json::to_string(&response) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::error!(error = %e, "Failed to serialize MCP response");
                                        continue;
                                    }
                                };
                                let _ = stdout.write_all(out.as_bytes()).await;
                                let _ = stdout.write_all(b"\n").await;
                                let _ = stdout.flush().await;
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::info!("Client stdin closed, shutting down proxy");
                        break;
                    }
                    Ok(Some(_)) => continue, // empty line
                    Err(e) => {
                        tracing::error!(error = %e, "Error reading from client stdin");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    let _ = downstream.kill().await;
    Ok(())
}

fn spawn_downstream(config: &McpProxyConfig) -> Result<Child, SentinelError> {
    let mut cmd = Command::new(&config.downstream_command);
    cmd.args(&config.downstream_args)
        .envs(&config.downstream_env)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    cmd.spawn().map_err(|e| {
        SentinelError::Proxy(format!(
            "Failed to spawn downstream MCP server '{}': {e}",
            config.downstream_command
        ))
    })
}

async fn handle_tool_call(
    request: &JsonRpcRequest,
    config: &McpProxyConfig,
    state: &Arc<AppState>,
    downstream_writer: &mut tokio::process::ChildStdin,
    downstream_reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) -> JsonRpcResponse {
    // Parse tool call params
    let tool_call: McpToolCallParams = match serde_json::from_value(request.params.clone()) {
        Ok(tc) => tc,
        Err(e) => {
            return JsonRpcResponse::error(
                request.id.clone(),
                -32602,
                format!("Invalid tools/call params: {e}"),
            );
        }
    };

    tracing::info!(
        tool = %tool_call.name,
        agent_id = %config.agent_id,
        "Intercepting MCP tool call"
    );

    // Run governance pipeline
    let intercept = intercept_tool_call(state, &config.agent_id, &tool_call).await;

    match intercept {
        InterceptResult::Allow => {
            tracing::info!(tool = %tool_call.name, "ALLOW, forwarding to downstream");
            // Forward original request to downstream
            forward_and_relay(request, downstream_writer, downstream_reader).await
        }
        InterceptResult::Review {
            review_id,
            risk_score,
        } => {
            tracing::warn!(
                tool = %tool_call.name,
                review_id = %review_id,
                risk_score = risk_score,
                "REVIEW, tool call held for human review"
            );
            JsonRpcResponse::error_with_data(
                request.id.clone(),
                -32001,
                format!(
                    "Tool '{}' requires human review (risk score: {})",
                    tool_call.name, risk_score
                ),
                serde_json::json!({
                    "governance": "review",
                    "reviewId": review_id,
                    "riskScore": risk_score,
                    "tool": tool_call.name,
                }),
            )
        }
        InterceptResult::Block {
            reasons,
            risk_score,
        } => {
            tracing::warn!(
                tool = %tool_call.name,
                risk_score = risk_score,
                reasons = ?reasons,
                "BLOCK, tool call denied by governance"
            );
            JsonRpcResponse::error_with_data(
                request.id.clone(),
                -32000,
                format!(
                    "Tool '{}' blocked by IAGA Sentinel governance (risk score: {})",
                    tool_call.name, risk_score
                ),
                serde_json::json!({
                    "governance": "block",
                    "riskScore": risk_score,
                    "reasons": reasons,
                    "tool": tool_call.name,
                }),
            )
        }
    }
}

async fn forward_and_relay(
    request: &JsonRpcRequest,
    downstream_writer: &mut tokio::process::ChildStdin,
    downstream_reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) -> JsonRpcResponse {
    // Send to downstream
    let line = match serde_json::to_string(request) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize MCP request");
            return JsonRpcResponse::error(
                request.id.clone(),
                -32603,
                format!("Failed to serialize request: {e}"),
            );
        }
    };
    if let Err(e) = downstream_writer.write_all(line.as_bytes()).await {
        return JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            format!("Failed to write to downstream: {e}"),
        );
    }
    if let Err(e) = downstream_writer.write_all(b"\n").await {
        return JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            format!("Failed to write to downstream: {e}"),
        );
    }
    let _ = downstream_writer.flush().await;

    // Read response from downstream
    match downstream_reader.next_line().await {
        Ok(Some(resp_line)) => match serde_json::from_str::<JsonRpcResponse>(&resp_line) {
            Ok(resp) => resp,
            Err(e) => JsonRpcResponse::error(
                request.id.clone(),
                -32603,
                format!("Invalid JSON-RPC from downstream: {e}"),
            ),
        },
        Ok(None) => JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            "Downstream server closed connection".to_string(),
        ),
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            format!("Error reading from downstream: {e}"),
        ),
    }
}
