use std::collections::HashMap;

use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::core::types::{InspectRequest, ProtocolKind, SchemaValidation};

use super::mcp_parser::normalize_mcp_payload;
use super::validate_mcp_tool::validate_mcp_tool;

const A2A_METHODS: &[&str] = &[
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "ListTasks",
    "CancelTask",
    "SubscribeToTask",
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/list",
    "tasks/cancel",
    "tasks/subscribe",
];

const A2A_SEND_METHODS: &[&str] = &[
    "SendMessage",
    "SendStreamingMessage",
    "message/send",
    "message/stream",
];

const A2A_TASK_LOOKUP_METHODS: &[&str] = &[
    "GetTask",
    "CancelTask",
    "SubscribeToTask",
    "tasks/get",
    "tasks/cancel",
    "tasks/subscribe",
];

const ACP_MODES: &[&str] = &["sync", "async", "stream"];
const ACP_ENCODINGS: &[&str] = &["plain", "base64"];

pub fn normalize_protocol_payload(
    input: &InspectRequest,
    protocol: ProtocolKind,
) -> HashMap<String, Value> {
    match protocol {
        ProtocolKind::Mcp => normalize_mcp_payload(input),
        ProtocolKind::A2a => normalize_a2a_payload(input),
        ProtocolKind::Acp => normalize_acp_payload(input),
        ProtocolKind::HttpFunction | ProtocolKind::Unknown => input.action.payload.clone(),
    }
}

pub fn validate_protocol_payload(
    input: &InspectRequest,
    protocol: ProtocolKind,
) -> SchemaValidation {
    match protocol {
        ProtocolKind::Mcp => validate_mcp_tool(input),
        ProtocolKind::A2a => validate_a2a_payload(input),
        ProtocolKind::Acp => validate_acp_payload(input),
        ProtocolKind::HttpFunction | ProtocolKind::Unknown => SchemaValidation {
            tool_name: input.action.tool_name.clone(),
            valid: true,
            findings: vec![format!(
                "built-in protocol validation skipped for {}",
                protocol_label(protocol)
            )],
        },
    }
}

pub fn looks_like_mcp_payload(payload: &HashMap<String, Value>) -> bool {
    let root = root_object(payload);
    root.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && root
            .get("method")
            .and_then(Value::as_str)
            .map(|method| {
                method == "initialize"
                    || method == "ping"
                    || method.starts_with("tools/")
                    || method.starts_with("resources/")
            })
            .unwrap_or(false)
}

pub fn looks_like_a2a_payload(payload: &HashMap<String, Value>) -> bool {
    let root = root_object(payload);

    if root.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && root
            .get("method")
            .and_then(Value::as_str)
            .map(is_supported_a2a_method)
            .unwrap_or(false)
    {
        return true;
    }

    if root.get("message").and_then(Value::as_object).is_some() {
        return true;
    }

    if root.get("task").and_then(Value::as_object).is_some() {
        return true;
    }

    root.contains_key("taskId")
        || root.contains_key("contextId")
        || root.contains_key("skill")
        || root.contains_key("parts")
}

pub fn looks_like_acp_payload(payload: &HashMap<String, Value>) -> bool {
    let root = root_object(payload);
    let body = root.get("body").and_then(Value::as_object).unwrap_or(&root);

    route_from_acp_root(&root)
        .map(|route| route == "/ping" || route.starts_with("/runs") || route.starts_with("/agents"))
        .unwrap_or(false)
        || (body.contains_key("agent_name") && body.contains_key("input"))
        || body.contains_key("run_id")
        || body.contains_key("session_id")
}

fn normalize_a2a_payload(input: &InspectRequest) -> HashMap<String, Value> {
    let root = root_object(&input.action.payload);
    let mut normalized = HashMap::new();
    let (body, method) = a2a_body_and_method(&root, &mut Vec::new());
    let message = body
        .get("message")
        .and_then(Value::as_object)
        .unwrap_or(body);

    normalized.insert(
        "toolName".into(),
        Value::String(input.action.tool_name.clone()),
    );

    if let Some(method) = method {
        normalized.insert("method".into(), Value::String(method.to_string()));
    }

    for (source, target) in [
        ("taskId", "taskId"),
        ("contextId", "contextId"),
        ("messageId", "messageId"),
        ("skill", "skill"),
    ] {
        if let Some(value) =
            message_string_field(message, source).or_else(|| message_string_field(body, source))
        {
            normalized.insert(target.into(), Value::String(value.to_string()));
        }
    }

    if let Some(role) = message_string_field(message, "role") {
        normalized.insert("role".into(), Value::String(role.to_string()));
    }

    if let Some(parts) = message.get("parts").and_then(Value::as_array) {
        normalized.insert("parts".into(), Value::Array(parts.clone()));
        normalized.insert("partCount".into(), json!(parts.len()));

        let text = collect_a2a_text(parts);
        if !text.is_empty() {
            normalized.insert("messageText".into(), Value::String(text));
        }
    }

    if let Some(configuration) = body.get("configuration") {
        normalized.insert("configuration".into(), configuration.clone());
    }

    if let Some(metadata) = body.get("metadata") {
        normalized.insert("metadata".into(), metadata.clone());
    }

    if let Some(task) = body.get("task") {
        normalized.insert("task".into(), task.clone());
    }

    normalized
}

fn normalize_acp_payload(input: &InspectRequest) -> HashMap<String, Value> {
    let root = root_object(&input.action.payload);
    let body = root.get("body").and_then(Value::as_object).unwrap_or(&root);
    let mut normalized = HashMap::new();

    normalized.insert(
        "toolName".into(),
        Value::String(input.action.tool_name.clone()),
    );

    if let Some(route) = route_from_acp_root(&root) {
        normalized.insert("route".into(), Value::String(route.to_string()));
    }

    if let Some(method) = root.get("method").and_then(Value::as_str) {
        normalized.insert("method".into(), Value::String(method.to_string()));
    }

    for (source, target) in [
        ("agent_name", "agentName"),
        ("mode", "mode"),
        ("session_id", "sessionId"),
        ("run_id", "runId"),
    ] {
        if let Some(value) = body
            .get(source)
            .cloned()
            .or_else(|| root.get(source).cloned())
        {
            normalized.insert(target.into(), value);
        }
    }

    if let Some(messages) = body.get("input").and_then(Value::as_array) {
        normalized.insert("input".into(), Value::Array(messages.clone()));
        normalized.insert("messageCount".into(), json!(messages.len()));

        let part_count: usize = messages
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|message| message.get("parts").and_then(Value::as_array))
            .map(Vec::len)
            .sum();
        normalized.insert("partCount".into(), json!(part_count));

        if let Some(first_role) = messages
            .iter()
            .filter_map(Value::as_object)
            .find_map(|message| message_string_field(message, "role"))
        {
            normalized.insert("firstRole".into(), Value::String(first_role.to_string()));
        }
    }

    normalized
}

fn validate_a2a_payload(input: &InspectRequest) -> SchemaValidation {
    let root = root_object(&input.action.payload);
    let mut findings = Vec::new();
    let (body, method) = a2a_body_and_method(&root, &mut findings);
    let mut matched_shape = false;

    if method.map(is_send_message_method).unwrap_or(false)
        || body.contains_key("message")
        || body.contains_key("parts")
    {
        matched_shape = true;
        validate_a2a_message(body, &mut findings);
    }

    if method.map(is_task_lookup_method).unwrap_or(false) {
        matched_shape = true;
        let task_id = body
            .get("taskId")
            .and_then(Value::as_str)
            .or_else(|| body.get("id").and_then(Value::as_str));
        match task_id {
            Some(task_id) if !task_id.trim().is_empty() => {}
            _ => findings.push("taskId: Required for A2A task lookup methods".to_string()),
        }
    }

    if method == Some("ListTasks") || method == Some("tasks/list") {
        matched_shape = true;
    }

    if let Some(task) = body.get("task").and_then(Value::as_object) {
        matched_shape = true;
        validate_a2a_task(task, &mut findings);
    }

    if !matched_shape {
        findings.push("payload did not match a supported A2A envelope".to_string());
    }

    schema_result(
        &input.action.tool_name,
        findings,
        "payload matched A2A protocol schema",
    )
}

fn validate_a2a_message(body: &Map<String, Value>, findings: &mut Vec<String>) {
    let message = body
        .get("message")
        .and_then(Value::as_object)
        .unwrap_or(body);

    match message.get("role").and_then(Value::as_str) {
        Some(role) if is_supported_a2a_role(role) => {}
        Some(role) => findings.push(format!("message.role: Unsupported value {role}")),
        None => findings.push("message.role: Required".to_string()),
    }

    let parts = message.get("parts").and_then(Value::as_array);
    match parts {
        Some(parts) if !parts.is_empty() => {
            for (index, part) in parts.iter().enumerate() {
                validate_a2a_part(part, index, findings);
            }
        }
        _ => findings.push("message.parts: Required non-empty array".to_string()),
    }
}

fn validate_a2a_part(part: &Value, index: usize, findings: &mut Vec<String>) {
    let Some(part) = part.as_object() else {
        findings.push(format!("message.parts[{index}]: Expected object"));
        return;
    };

    let content_forms = ["text", "data", "raw", "url"]
        .iter()
        .filter(|key| part.contains_key(**key))
        .count();
    let kind = part.get("kind").and_then(Value::as_str);

    if content_forms == 0 && kind.is_none() {
        findings.push(format!(
            "message.parts[{index}]: Required one of text, data, raw, url or kind"
        ));
    }

    if content_forms > 1 {
        findings.push(format!(
            "message.parts[{index}]: Expected exactly one content form"
        ));
    }

    if let Some(kind) = kind {
        match kind {
            "text" => {
                if part.get("text").and_then(Value::as_str).is_none() {
                    findings.push(format!("message.parts[{index}]: kind=text requires text"));
                }
            }
            "file" => {
                if part.get("url").and_then(Value::as_str).is_none() && !part.contains_key("data") {
                    findings.push(format!(
                        "message.parts[{index}]: kind=file requires url or data"
                    ));
                }
            }
            "data" => {
                if !part.contains_key("data") {
                    findings.push(format!("message.parts[{index}]: kind=data requires data"));
                }
            }
            other => findings.push(format!("message.parts[{index}]: unsupported kind {other}")),
        }
    }
}

fn validate_a2a_task(task: &Map<String, Value>, findings: &mut Vec<String>) {
    match task.get("id").and_then(Value::as_str) {
        Some(id) if !id.trim().is_empty() => {}
        _ => findings.push("task.id: Required".to_string()),
    }

    match task
        .get("status")
        .and_then(Value::as_object)
        .and_then(|status| status.get("state"))
        .and_then(Value::as_str)
    {
        Some(state) if is_supported_a2a_task_state(state) => {}
        Some(state) => findings.push(format!("task.status.state: Unsupported value {state}")),
        None => findings.push("task.status.state: Required".to_string()),
    }
}

fn validate_acp_payload(input: &InspectRequest) -> SchemaValidation {
    let root = root_object(&input.action.payload);
    let body = root.get("body").and_then(Value::as_object).unwrap_or(&root);
    let route = route_from_acp_root(&root);
    let mut findings = Vec::new();
    let mut matched_shape = false;

    if route == Some("/ping")
        || route
            .map(|value| value.starts_with("/agents"))
            .unwrap_or(false)
    {
        matched_shape = true;
    }

    if route == Some("/runs") || (body.contains_key("agent_name") && body.contains_key("input")) {
        matched_shape = true;
        validate_acp_run_create(body, &mut findings);
    }

    if route
        .map(|value| value.starts_with("/runs/"))
        .unwrap_or(false)
        || body.contains_key("run_id")
        || root.contains_key("run_id")
    {
        matched_shape = true;
        let run_id = body
            .get("run_id")
            .and_then(Value::as_str)
            .or_else(|| root.get("run_id").and_then(Value::as_str))
            .or_else(|| route.and_then(extract_acp_run_id));
        validate_uuid_field("run_id", run_id, &mut findings);
    }

    if !matched_shape {
        findings.push("payload did not match a supported ACP envelope".to_string());
    }

    schema_result(
        &input.action.tool_name,
        findings,
        "payload matched ACP protocol schema",
    )
}

fn validate_acp_run_create(body: &Map<String, Value>, findings: &mut Vec<String>) {
    match body.get("agent_name").and_then(Value::as_str) {
        Some(agent_name) if !agent_name.trim().is_empty() => {}
        _ => findings.push("agent_name: Required".to_string()),
    }

    match body.get("mode").and_then(Value::as_str) {
        Some(mode) if ACP_MODES.contains(&mode) => {}
        Some(mode) => findings.push(format!("mode: Unsupported value {mode}")),
        None => {}
    }

    validate_uuid_field(
        "session_id",
        body.get("session_id").and_then(Value::as_str),
        findings,
    );

    match body.get("input").and_then(Value::as_array) {
        Some(messages) if !messages.is_empty() => {
            for (index, message) in messages.iter().enumerate() {
                validate_acp_message(message, index, findings);
            }
        }
        _ => findings.push("input: Required non-empty array".to_string()),
    }
}

fn validate_acp_message(message: &Value, index: usize, findings: &mut Vec<String>) {
    let Some(message) = message.as_object() else {
        findings.push(format!("input[{index}]: Expected object"));
        return;
    };

    match message.get("role").and_then(Value::as_str) {
        Some(role) if role == "user" || role.starts_with("agent") => {}
        Some(role) => findings.push(format!("input[{index}].role: Unsupported value {role}")),
        None => findings.push(format!("input[{index}].role: Required")),
    }

    match message.get("parts").and_then(Value::as_array) {
        Some(parts) if !parts.is_empty() => {
            for (part_index, part) in parts.iter().enumerate() {
                validate_acp_part(part, index, part_index, findings);
            }
        }
        _ => findings.push(format!("input[{index}].parts: Required non-empty array")),
    }
}

fn validate_acp_part(
    part: &Value,
    message_index: usize,
    part_index: usize,
    findings: &mut Vec<String>,
) {
    let Some(part) = part.as_object() else {
        findings.push(format!(
            "input[{message_index}].parts[{part_index}]: Expected object"
        ));
        return;
    };

    if part.get("content_type").and_then(Value::as_str).is_none() {
        findings.push(format!(
            "input[{message_index}].parts[{part_index}].content_type: Required"
        ));
    }

    let has_content = part.contains_key("content");
    let has_url = part
        .get("content_url")
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);

    if has_content == has_url {
        findings.push(format!(
            "input[{message_index}].parts[{part_index}]: Expected exactly one of content or content_url"
        ));
    }

    if let Some(encoding) = part.get("content_encoding").and_then(Value::as_str) {
        if !ACP_ENCODINGS.contains(&encoding) {
            findings.push(format!(
                "input[{message_index}].parts[{part_index}].content_encoding: Unsupported value {encoding}"
            ));
        }
    }
}

fn a2a_body_and_method<'a>(
    root: &'a Map<String, Value>,
    findings: &mut Vec<String>,
) -> (&'a Map<String, Value>, Option<&'a str>) {
    let method = root.get("method").and_then(Value::as_str);
    let is_jsonrpc = root.contains_key("jsonrpc") || root.contains_key("method");

    if is_jsonrpc {
        if root.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            findings.push("jsonrpc: Expected 2.0".to_string());
        }

        match method {
            Some(method) if is_supported_a2a_method(method) => {}
            Some(method) => findings.push(format!("method: Unsupported A2A method {method}")),
            None => findings.push("method: Required".to_string()),
        }

        match root.get("params").and_then(Value::as_object) {
            Some(params) => return (params, method),
            None => findings.push("params: Expected object".to_string()),
        }
    }

    (root, method)
}

fn root_object(payload: &HashMap<String, Value>) -> Map<String, Value> {
    payload
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn message_string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn collect_a2a_text(parts: &[Value]) -> String {
    parts
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|part| {
            part.get("text")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn schema_result(tool_name: &str, findings: Vec<String>, ok_message: &str) -> SchemaValidation {
    let valid = findings.is_empty();
    SchemaValidation {
        tool_name: tool_name.to_string(),
        valid,
        findings: if valid {
            vec![ok_message.to_string()]
        } else {
            findings
        },
    }
}

fn validate_uuid_field(field: &str, value: Option<&str>, findings: &mut Vec<String>) {
    if let Some(value) = value {
        if Uuid::parse_str(value).is_err() {
            findings.push(format!("{field}: Expected UUID"));
        }
    }
}

fn route_from_acp_root(root: &Map<String, Value>) -> Option<&str> {
    root.get("route")
        .and_then(Value::as_str)
        .or_else(|| root.get("path").and_then(Value::as_str))
        .or_else(|| root.get("endpoint").and_then(Value::as_str))
}

fn extract_acp_run_id(route: &str) -> Option<&str> {
    let trimmed = route.trim_matches('/');
    let mut segments = trimmed.split('/');

    while let Some(segment) = segments.next() {
        if segment == "runs" {
            return segments.next();
        }
    }

    None
}

fn protocol_label(protocol: ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::Mcp => "mcp",
        ProtocolKind::Acp => "acp",
        ProtocolKind::A2a => "a2a",
        ProtocolKind::HttpFunction => "http-function",
        ProtocolKind::Unknown => "unknown",
    }
}

fn is_supported_a2a_method(method: &str) -> bool {
    A2A_METHODS.contains(&method)
}

fn is_send_message_method(method: &str) -> bool {
    A2A_SEND_METHODS.contains(&method)
}

fn is_task_lookup_method(method: &str) -> bool {
    A2A_TASK_LOOKUP_METHODS.contains(&method)
}

fn is_supported_a2a_role(role: &str) -> bool {
    matches!(
        role,
        "ROLE_USER" | "ROLE_AGENT" | "ROLE_SYSTEM" | "user" | "agent" | "system"
    )
}

fn is_supported_a2a_task_state(state: &str) -> bool {
    state.starts_with("TASK_STATE_")
        || matches!(
            state,
            "working" | "completed" | "input_required" | "failed" | "canceled" | "cancelled"
        )
}
