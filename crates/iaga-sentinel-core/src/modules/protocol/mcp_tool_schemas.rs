use serde_json::Value;
use std::collections::HashMap;

/// Validates payload fields against known MCP tool schemas.
/// Returns (valid, findings).
pub fn validate_schema(tool_name: &str, payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    match tool_name {
        "filesystem.read" => validate_filesystem_read(payload),
        "terminal.exec" => validate_terminal_exec(payload),
        "http.fetch" => validate_http_fetch(payload),
        _ => (
            false,
            vec![format!("no MCP schema registered for tool {tool_name}")],
        ),
    }
}

fn validate_filesystem_read(payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    let mut findings = Vec::new();

    match payload.get("path") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => findings.push("path: Required".to_string()),
    }

    match payload.get("intent") {
        Some(Value::String(s)) if s.len() >= 3 => {}
        _ => findings.push("intent: String must contain at least 3 character(s)".to_string()),
    }

    if findings.is_empty() {
        (true, vec!["payload matched MCP tool schema".to_string()])
    } else {
        (false, findings)
    }
}

fn validate_terminal_exec(payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    let mut findings = Vec::new();

    match payload.get("command") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => findings.push("command: Required".to_string()),
    }

    match payload.get("intent") {
        Some(Value::String(s)) if s.len() >= 3 => {}
        _ => findings.push("intent: String must contain at least 3 character(s)".to_string()),
    }

    // destination is optional
    if let Some(val) = payload.get("destination") {
        if !val.is_string() {
            findings.push("destination: Expected string".to_string());
        }
    }

    if findings.is_empty() {
        (true, vec!["payload matched MCP tool schema".to_string()])
    } else {
        (false, findings)
    }
}

fn validate_http_fetch(payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    let mut findings = Vec::new();

    match payload.get("method") {
        Some(Value::String(s))
            if matches!(s.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") => {}
        _ => findings.push("method: Expected one of GET, POST, PUT, PATCH, DELETE".to_string()),
    }

    match payload.get("destination") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => findings.push("destination: Required".to_string()),
    }

    match payload.get("intent") {
        Some(Value::String(s)) if s.len() >= 3 => {}
        _ => findings.push("intent: String must contain at least 3 character(s)".to_string()),
    }

    if findings.is_empty() {
        (true, vec!["payload matched MCP tool schema".to_string()])
    } else {
        (false, findings)
    }
}
