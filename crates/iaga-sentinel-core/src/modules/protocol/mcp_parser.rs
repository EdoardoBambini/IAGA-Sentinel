use crate::core::types::InspectRequest;
use std::collections::HashMap;

pub fn normalize_mcp_payload(input: &InspectRequest) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    map.insert(
        "toolName".to_string(),
        serde_json::Value::String(input.action.tool_name.clone()),
    );
    map.insert(
        "actionType".to_string(),
        serde_json::to_value(input.action.action_type).unwrap_or_default(),
    );
    map.insert(
        "payload".to_string(),
        serde_json::to_value(&input.action.payload).unwrap_or_default(),
    );
    map.insert(
        "requestedSecrets".to_string(),
        serde_json::to_value(input.requested_secrets.as_deref().unwrap_or(&[])).unwrap_or_default(),
    );
    map
}
