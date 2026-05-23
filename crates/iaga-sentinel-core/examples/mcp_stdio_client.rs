use std::process::Stdio;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut child, db_path) = spawn_server()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("failed to capture MCP server stdin")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("failed to capture MCP server stdout")?;
    let mut stdout = BufReader::new(stdout).lines();

    let initialize = rpc_request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "iaga-sentinel-mcp-example",
                "version": env!("CARGO_PKG_VERSION")
            }
        }),
    );
    let initialize_response = send_request(&mut stdin, &mut stdout, &initialize).await?;
    println!(
        "initialize -> {}",
        serde_json::to_string_pretty(&initialize_response)?
    );

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    write_message(&mut stdin, &initialized).await?;

    let tools_list = rpc_request(2, "tools/list", json!({}));
    let tools_response = send_request(&mut stdin, &mut stdout, &tools_list).await?;
    println!(
        "tools/list -> {}",
        serde_json::to_string_pretty(&tools_response)?
    );

    let inspect = rpc_request(
        3,
        "tools/call",
        json!({
            "name": "iaga.inspect",
            "arguments": {
                "agentId": "openclaw-builder-01",
                "workspaceId": "ws-demo",
                "framework": "openclaw",
                "protocol": "mcp",
                "action": {
                    "type": "file_read",
                    "toolName": "filesystem.read",
                    "payload": {
                        "path": "README.md",
                        "intent": "inspect repository documentation"
                    }
                }
            }
        }),
    );
    let inspect_response = send_request(&mut stdin, &mut stdout, &inspect).await?;
    println!(
        "tools/call inspect -> {}",
        serde_json::to_string_pretty(&inspect_response)?
    );

    let response_scan = rpc_request(
        4,
        "tools/call",
        json!({
            "name": "iaga.response_scan",
            "arguments": {
                "requestId": "scan-example-1",
                "agentId": "openclaw-builder-01",
                "toolName": "terminal.exec",
                "responsePayload": {
                    "secret": "AKIA1234567890ABCDEF",
                    "message": "temporary credential"
                }
            }
        }),
    );
    let response_scan_response = send_request(&mut stdin, &mut stdout, &response_scan).await?;
    println!(
        "tools/call response_scan -> {}",
        serde_json::to_string_pretty(&response_scan_response)?
    );

    let _ = child.kill().await;
    let _ = std::fs::remove_file(db_path);
    Ok(())
}

fn spawn_server() -> Result<(Child, String), Box<dyn std::error::Error>> {
    let db_path = format!("mcp_stdio_example_{}.db", Uuid::new_v4());
    let db_url = format!("sqlite:{db_path}?mode=rwc");

    let mut command = Command::new("cargo");
    command
        .arg("run")
        .arg("--quiet")
        .arg("--")
        .arg("--db")
        .arg(&db_url)
        .arg("mcp-server")
        .arg("--seed-demo")
        .env("IAGA_SENTINEL_LOG_LEVEL", "error")
        .env("RUST_LOG", "error")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    Ok((command.spawn()?, db_path))
}

fn rpc_request(id: u64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    })
}

async fn send_request(
    stdin: &mut ChildStdin,
    stdout: &mut tokio::io::Lines<BufReader<ChildStdout>>,
    request: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    write_message(stdin, request).await?;
    read_jsonrpc_response(stdout).await
}

async fn write_message(
    stdin: &mut ChildStdin,
    message: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let line = serde_json::to_string(message)?;
    stdin.write_all(line.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    Ok(())
}

async fn read_jsonrpc_response(
    stdout: &mut tokio::io::Lines<BufReader<ChildStdout>>,
) -> Result<Value, Box<dyn std::error::Error>> {
    loop {
        let line = stdout
            .next_line()
            .await?
            .ok_or("MCP server closed stdout")?;

        match serde_json::from_str::<Value>(&line) {
            Ok(value) if value.get("jsonrpc") == Some(&json!("2.0")) => return Ok(value),
            Ok(value) => eprintln!("Skipping non-JSON-RPC stdout line: {value}"),
            Err(_) => eprintln!("Skipping non-JSON stdout line: {line}"),
        }
    }
}
