//! Plugin system types for the WASM plugin interface.

use serde::{Deserialize, Serialize};

/// Metadata about a loaded plugin, derived from its exported `name()` and `version()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub path: String,
    pub loaded: bool,
}

/// The result returned by a single plugin's `on_inspect()` call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginResult {
    /// Risk contribution from this plugin (0-100).
    pub risk_score: u32,
    /// Human-readable findings from this plugin.
    pub findings: Vec<String>,
    /// Optional hint for the governance decision ("allow", "review", "block").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_hint: Option<String>,
}

/// Combined output from a plugin evaluation, including manifest info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginOutput {
    pub plugin_name: String,
    pub plugin_version: String,
    pub result: PluginResult,
    pub execution_ms: u64,
}

/// Request payload serialized to JSON and passed to `on_inspect()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInspectRequest {
    pub agent_id: String,
    pub tool_name: String,
    pub action_type: String,
    pub framework: String,
    pub payload: serde_json::Value,
    pub risk_score: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_result_default() {
        let r = PluginResult::default();
        assert_eq!(r.risk_score, 0);
        assert!(r.findings.is_empty());
        assert!(r.decision_hint.is_none());
    }

    #[test]
    fn test_plugin_result_serialization() {
        let r = PluginResult {
            risk_score: 75,
            findings: vec!["suspicious pattern detected".into()],
            decision_hint: Some("review".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("riskScore"));
        assert!(json.contains("75"));
        let back: PluginResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.risk_score, 75);
    }

    #[test]
    fn test_plugin_output_serialization() {
        let output = PluginOutput {
            plugin_name: "test-plugin".into(),
            plugin_version: "1.0.0".into(),
            result: PluginResult::default(),
            execution_ms: 5,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("test-plugin"));
        assert!(json.contains("executionMs"));
    }

    #[test]
    fn test_plugin_manifest_serialization() {
        let m = PluginManifest {
            name: "my-plugin".into(),
            version: "0.1.0".into(),
            path: "/plugins/my-plugin.wasm".into(),
            loaded: true,
        };
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["name"], "my-plugin");
        assert_eq!(json["loaded"], true);
    }

    #[test]
    fn test_inspect_request_serialization() {
        let req = PluginInspectRequest {
            agent_id: "agent-1".into(),
            tool_name: "shell.exec".into(),
            action_type: "shell".into(),
            framework: "mcp".into(),
            payload: serde_json::json!({"cmd": "ls"}),
            risk_score: 42,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("agent-1"));
        assert!(json.contains("42"));
    }
}
