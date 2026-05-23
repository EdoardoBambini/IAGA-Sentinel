use super::mcp_tool_schemas::validate_schema;
use crate::core::types::{InspectRequest, SchemaValidation};

pub fn validate_mcp_tool(input: &InspectRequest) -> SchemaValidation {
    let (valid, findings) = validate_schema(&input.action.tool_name, &input.action.payload);
    SchemaValidation {
        tool_name: input.action.tool_name.clone(),
        valid,
        findings,
    }
}
