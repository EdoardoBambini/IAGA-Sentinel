use crate::core::types::{InspectRequest, ProtocolKind};

use super::protocol_envelope::{
    looks_like_a2a_payload, looks_like_acp_payload, looks_like_mcp_payload,
};

pub fn detect_protocol(input: &InspectRequest) -> ProtocolKind {
    if let Some(p) = input.protocol {
        return p;
    }

    let tool = input.action.tool_name.to_lowercase();
    let framework = input.framework.to_lowercase();

    // MCP
    if tool.contains("mcp")
        || framework.contains("mcp")
        || looks_like_mcp_payload(&input.action.payload)
    {
        return ProtocolKind::Mcp;
    }

    // A2A (Google Agent-to-Agent protocol)
    if framework.contains("a2a")
        || tool.contains("a2a")
        || looks_like_a2a_payload(&input.action.payload)
    {
        return ProtocolKind::A2a;
    }

    // ACP
    if tool.contains("acp")
        || framework.contains("acp")
        || looks_like_acp_payload(&input.action.payload)
    {
        return ProtocolKind::Acp;
    }

    if !framework.is_empty() {
        return ProtocolKind::HttpFunction;
    }

    ProtocolKind::Unknown
}
