use std::collections::HashMap;

use crate::core::types::*;

pub fn demo_profiles() -> Vec<AgentProfile> {
    vec![
        AgentProfile {
            agent_id: "openclaw-builder-01".into(),
            tenant_id: None,
            workspace_id: "ws-demo".into(),
            framework: "openclaw".into(),
            role: AgentRole::Builder,
            approved_tools: vec![
                "filesystem.read".into(),
                "http.fetch".into(),
                "terminal.exec".into(),
            ],
            approved_secrets: vec![
                "secretref://prod/github/token".into(),
                "secretref://prod/slack/webhook".into(),
            ],
            baseline_action_types: vec![ActionType::FileRead, ActionType::Http, ActionType::Shell],
            tool_trust: 0.7,
        },
        AgentProfile {
            agent_id: "openclaw-research-01".into(),
            tenant_id: None,
            workspace_id: "ws-demo".into(),
            framework: "openclaw".into(),
            role: AgentRole::Researcher,
            approved_tools: vec!["filesystem.read".into(), "http.fetch".into()],
            approved_secrets: vec![],
            baseline_action_types: vec![ActionType::Http],
            tool_trust: 0.7,
        },
    ]
}

pub fn demo_workspace_policies() -> Vec<WorkspacePolicy> {
    vec![WorkspacePolicy {
        workspace_id: "ws-demo".into(),
        tenant_id: None,
        allowed_protocols: vec![ProtocolKind::Mcp, ProtocolKind::HttpFunction],
        allowed_domains: vec!["api.github.com".into(), "hooks.slack.com".into()],
        tools: vec![
            ToolPolicy {
                tool_name: "filesystem.read".into(),
                allowed_action_types: vec![ActionType::FileRead],
                max_decision: GovernanceDecision::Allow,
                requires_human_review: false,
            },
            ToolPolicy {
                tool_name: "http.fetch".into(),
                allowed_action_types: vec![ActionType::Http],
                max_decision: GovernanceDecision::Allow,
                requires_human_review: false,
            },
            ToolPolicy {
                tool_name: "terminal.exec".into(),
                allowed_action_types: vec![ActionType::Shell],
                max_decision: GovernanceDecision::Review,
                requires_human_review: true,
            },
        ],
        threshold_block: 70,
        threshold_review: 35,
    }]
}

fn payload(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

pub fn demo_scenarios() -> Vec<DemoScenario> {
    vec![
        DemoScenario {
            step: "Step 1".into(),
            title: "Safe MCP-aligned repository inspection".into(),
            request: InspectRequest {
                agent_id: "openclaw-builder-01".into(),
                tenant_id: None,
                workspace_id: Some("ws-demo".into()),
                framework: "openclaw".into(),
                protocol: Some(ProtocolKind::Mcp),
                action: ActionDetail {
                    action_type: ActionType::FileRead,
                    tool_name: "filesystem.read".into(),
                    payload: payload(&[
                        ("path", serde_json::json!("/workspace/README.md")),
                        (
                            "intent",
                            serde_json::json!("inspect repository documentation"),
                        ),
                    ]),
                },
                requested_secrets: None,
                metadata: None,
            },
        },
        DemoScenario {
            step: "Step 2".into(),
            title: "Controlled shell execution with secret injection".into(),
            request: InspectRequest {
                agent_id: "openclaw-builder-01".into(),
                tenant_id: None,
                workspace_id: Some("ws-demo".into()),
                framework: "openclaw".into(),
                protocol: Some(ProtocolKind::Mcp),
                action: ActionDetail {
                    action_type: ActionType::Shell,
                    tool_name: "terminal.exec".into(),
                    payload: payload(&[
                        (
                            "command",
                            serde_json::json!("git push origin feature/iaga-sentinel-demo"),
                        ),
                        ("destination", serde_json::json!("api.github.com")),
                        ("intent", serde_json::json!("publish vetted branch")),
                    ]),
                },
                requested_secrets: Some(vec!["secretref://prod/github/token".into()]),
                metadata: None,
            },
        },
        DemoScenario {
            step: "Step 3".into(),
            title: "Destructive shell command blocked".into(),
            request: InspectRequest {
                agent_id: "openclaw-builder-01".into(),
                tenant_id: None,
                workspace_id: Some("ws-demo".into()),
                framework: "openclaw".into(),
                protocol: Some(ProtocolKind::Mcp),
                action: ActionDetail {
                    action_type: ActionType::Shell,
                    tool_name: "terminal.exec".into(),
                    payload: payload(&[
                        (
                            "command",
                            serde_json::json!("rm -rf /var/lib/postgresql/data"),
                        ),
                        ("intent", serde_json::json!("cleanup old data")),
                    ]),
                },
                requested_secrets: Some(vec!["secretref://prod/github/token".into()]),
                metadata: None,
            },
        },
        DemoScenario {
            step: "Step 4".into(),
            title: "Unknown secret reference denied".into(),
            request: InspectRequest {
                agent_id: "openclaw-research-01".into(),
                tenant_id: None,
                workspace_id: Some("ws-demo".into()),
                framework: "openclaw".into(),
                protocol: Some(ProtocolKind::Mcp),
                action: ActionDetail {
                    action_type: ActionType::Http,
                    tool_name: "http.fetch".into(),
                    payload: payload(&[
                        ("method", serde_json::json!("POST")),
                        ("destination", serde_json::json!("hooks.slack.com")),
                        ("intent", serde_json::json!("send external summary")),
                    ]),
                },
                requested_secrets: Some(vec!["secretref://prod/root/aws-admin".into()]),
                metadata: None,
            },
        },
    ]
}
