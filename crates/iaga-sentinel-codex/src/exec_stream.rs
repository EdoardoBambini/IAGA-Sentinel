//! THE single place that knows the shape of the `codex exec --json` stream.
//!
//! CONTRACT STATUS (stream spike, `docs/adr/0022-codex-integration.md`):
//! the line shapes are **confirmed against a real `codex exec --json` run on
//! codex-cli 0.138.0-alpha.7** (`tests/fixtures/exec_stream_real_0.138.jsonl`):
//! `thread.started`+`thread_id`, `turn.started`/`turn.completed`,
//! `item.started`/`item.completed`, and the `command_execution` (string
//! `command` + `aggregated_output`/`exit_code`/`status`), `file_change`
//! (`changes:[{path,kind}]`), and `agent_message` items. Still PROVISIONAL,
//! not yet observed in a capture: the `mcp_tool_call` and `web_search` item
//! shapes. All stream field-name knowledge stays in THIS module; nothing
//! outside it may assume them.
//!
//! Security invariant: the stream narrates what an attacker-influenced
//! model did (commands and arguments are composed from repository
//! content). This module never interprets, interpolates or logs item
//! payloads — it forwards them as opaque JSON to `/v1/inspect`, where the
//! firewall and policies examine them.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value as Json;

use iaga_sentinel_integrations::{ActionDetail, ActionType, InspectRequest};

use crate::codex_event;
use crate::hook_config::{Config, FRAMEWORK};

/// Provenance of the stream being ingested, declared on every receipt as
/// `metadata.attestation`. This is our taxonomy, not Codex's, and is NOT
/// provisional: live ingest proves what was observed as it happened;
/// post-hoc proves only what was logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attestation {
    /// Events consumed as they are produced (stdin pipe or spawned
    /// `codex exec --json`).
    LiveIngest,
    /// A captured stream re-processed after the fact (`--from <file>`).
    PostHoc,
}

impl Attestation {
    pub fn as_str(self) -> &'static str {
        match self {
            Attestation::LiveIngest => "live-ingest",
            Attestation::PostHoc => "post-hoc",
        }
    }
}

/// One parsed line of the newline-delimited stream.
///
/// Every field is optional so a drifted stream still parses; absence is
/// handled explicitly by [`classify`] instead of failing deep inside
/// serde. Unknown fields are ignored by construction (serde default).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StreamEvent {
    /// PROVISIONAL — line discriminator, e.g. `"thread.started"`,
    /// `"turn.completed"`, `"item.completed"`.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// PROVISIONAL — session/thread identifier carried by
    /// `"thread.started"` lines.
    pub thread_id: Option<String>,
    /// PROVISIONAL — the item payload of `"item.*"` lines.
    pub item: Option<StreamItem>,
}

/// PROVISIONAL — one work item narrated by the stream.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StreamItem {
    /// PROVISIONAL — item identifier, e.g. `"item_3"`.
    pub id: Option<String>,
    /// PROVISIONAL — item discriminator. Expected actionable kinds:
    /// `command_execution`, `file_change`, `mcp_tool_call`, `web_search`.
    /// Expected narrative kinds (never attested): `agent_message`,
    /// `reasoning`, `todo_list`, `error`.
    #[serde(rename = "type", alias = "item_type")]
    pub kind: Option<String>,
    /// PROVISIONAL — `mcp_tool_call`: server half of the tool identity.
    pub server: Option<String>,
    /// PROVISIONAL — `mcp_tool_call`: tool half of the tool identity.
    pub tool: Option<String>,
    /// Everything else the item carries (`command`, `exit_code`,
    /// `changes`, `query`, ...). Kept opaque and forwarded as the inspect
    /// payload — never interpreted here.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Json>,
}

/// PROVISIONAL — item kinds that narrate the run without performing an
/// external action; they mint no receipt.
const NARRATIVE_ITEM_KINDS: &[&str] = &["agent_message", "reasoning", "todo_list", "error"];

/// What the ingest loop should do with one parsed line.
#[derive(Debug, Clone)]
pub enum LineAction {
    /// A completed, payload-bearing item: attest it with one inspect call.
    Attest(StreamItem),
    /// A recognized lifecycle or narrative line: skip silently.
    Skip,
    /// Parsed JSON without a recognizable discriminator. Skipped loudly —
    /// an evidence plane must not silently drop lines it cannot read.
    Unrecognized,
}

/// Parse one raw stream line.
pub fn parse_line(raw: &str) -> Result<StreamEvent, serde_json::Error> {
    serde_json::from_str(raw)
}

/// Route one parsed line.
///
/// Only `item.completed` mints receipts: `item.started`/`item.updated`
/// describe the same item in flight and would duplicate evidence. Unknown
/// *item* kinds on a completed item are attested defensively (as
/// `custom`): if Codex grows a new action kind, the evidence plane must
/// record it, not drop it.
pub fn classify(event: StreamEvent) -> LineAction {
    match event.kind.as_deref() {
        // PROVISIONAL — completed-item discriminator.
        Some("item.completed") => match event.item {
            Some(item) => {
                let narrative = item
                    .kind
                    .as_deref()
                    .is_some_and(|k| NARRATIVE_ITEM_KINDS.contains(&k));
                if narrative {
                    LineAction::Skip
                } else {
                    LineAction::Attest(item)
                }
            }
            None => LineAction::Unrecognized,
        },
        Some(_) => LineAction::Skip,
        None => LineAction::Unrecognized,
    }
}

/// The tool identity recorded on the receipt. MCP calls reuse the gate's
/// `<server>:<tool>` namespacing so one policy file governs both planes;
/// every other item is named by its stream kind.
pub fn tool_name(item: &StreamItem) -> String {
    if item.kind.as_deref() == Some("mcp_tool_call") {
        if let (Some(server), Some(tool)) = (&item.server, &item.tool) {
            return format!("{server}:{tool}");
        }
    }
    item.kind.clone().unwrap_or_else(|| "unknown".to_string())
}

/// Map one completed item onto the public `/v1/inspect` wire contract.
///
/// Fixed mapping decisions (these are ours, not Codex's, and are NOT
/// provisional):
/// - `agentId` is the static registered identity from [`Config`], same as
///   the gate.
/// - `metadata.enforcement = "advisory"` — the ingest observes; the verdict
///   is recorded, never applied (the action has already run).
/// - `metadata.attestation` declares the stream's provenance
///   ([`Attestation`]).
/// - The item payload is forwarded as-is; unknown item kinds degrade
///   through the same name heuristic as the gate
///   ([`codex_event::infer_action_type`]).
pub fn to_inspect_request(
    item: &StreamItem,
    thread_id: Option<&str>,
    attestation: Attestation,
    config: &Config,
) -> InspectRequest {
    let name = tool_name(item);

    let mut payload: HashMap<String, Json> = item.rest.clone().into_iter().collect();
    // Same flattening as the gate: give substring policies a string command
    // even when an item carries the command as an argv array.
    codex_event::add_command_line(&mut payload);

    let mut metadata: HashMap<String, Json> = HashMap::from([
        ("enforcement".to_string(), Json::from("advisory")),
        ("attestation".to_string(), Json::from(attestation.as_str())),
        ("source".to_string(), Json::from("exec-stream")),
    ]);
    if let Some(thread_id) = thread_id {
        metadata.insert("threadId".to_string(), Json::from(thread_id));
    }
    if let Some(id) = &item.id {
        metadata.insert("itemId".to_string(), Json::from(id.clone()));
    }
    if item.kind.as_deref() == Some("mcp_tool_call") {
        metadata.insert("protocol".to_string(), Json::from("mcp"));
    }

    let action_type = action_type_for(item.kind.as_deref().unwrap_or("unknown"));
    let mut request = InspectRequest::new(
        config.agent_id.clone(),
        FRAMEWORK,
        ActionDetail::new(action_type, name, payload),
    );
    request.metadata = Some(metadata);
    request
}

/// Map a stream item kind onto the wire's action categories.
/// PROVISIONAL — expected Codex item kinds; unknown kinds fall back to the
/// gate's shared name heuristic so both planes degrade identically.
fn action_type_for(kind: &str) -> ActionType {
    match kind {
        "command_execution" => ActionType::Shell,
        "file_change" => ActionType::FileWrite,
        "web_search" => ActionType::Http,
        "mcp_tool_call" => ActionType::Custom,
        other => codex_event::infer_action_type(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_item_kinds_map_to_precise_categories() {
        assert_eq!(action_type_for("command_execution"), ActionType::Shell);
        assert_eq!(action_type_for("file_change"), ActionType::FileWrite);
        assert_eq!(action_type_for("web_search"), ActionType::Http);
        assert_eq!(action_type_for("mcp_tool_call"), ActionType::Custom);
    }

    #[test]
    fn unknown_item_kinds_fall_back_to_the_gate_heuristic() {
        // Same degrade path as the gate: name keywords, then custom.
        assert_eq!(action_type_for("fetch_url"), ActionType::Http);
        assert_eq!(action_type_for("database_thing"), ActionType::Custom);
    }

    #[test]
    fn mcp_items_are_named_server_colon_tool() {
        let item: StreamItem = serde_json::from_str(
            r#"{"type":"mcp_tool_call","server":"github","tool":"create_issue"}"#,
        )
        .unwrap();
        assert_eq!(tool_name(&item), "github:create_issue");

        // Missing halves fall back to the kind, never to a bogus name.
        let bare: StreamItem = serde_json::from_str(r#"{"type":"mcp_tool_call"}"#).unwrap();
        assert_eq!(tool_name(&bare), "mcp_tool_call");
    }

    #[test]
    fn only_completed_actionable_items_are_attested() {
        let attest =
            |raw: &str| matches!(classify(parse_line(raw).unwrap()), LineAction::Attest(_));

        assert!(attest(
            r#"{"type":"item.completed","item":{"type":"command_execution","command":"ls"}}"#
        ));
        // In-flight phases of the same item must not duplicate evidence.
        assert!(!attest(
            r#"{"type":"item.started","item":{"type":"command_execution","command":"ls"}}"#
        ));
        assert!(!attest(
            r#"{"type":"item.updated","item":{"type":"command_execution","command":"ls"}}"#
        ));
        // Narrative items mint no receipt.
        assert!(!attest(
            r#"{"type":"item.completed","item":{"type":"agent_message","text":"done"}}"#
        ));
        // Lifecycle lines are recognized no-ops.
        assert!(!attest(
            r#"{"type":"turn.completed","usage":{"input_tokens":1}}"#
        ));
    }

    #[test]
    fn unknown_completed_item_kinds_are_attested_defensively() {
        let action = classify(
            parse_line(r#"{"type":"item.completed","item":{"type":"novel_action","x":1}}"#)
                .unwrap(),
        );
        assert!(matches!(action, LineAction::Attest(_)));
    }

    #[test]
    fn undiscriminated_lines_are_unrecognized_not_dropped() {
        assert!(matches!(
            classify(parse_line(r#"{"foo":"bar"}"#).unwrap()),
            LineAction::Unrecognized
        ));
        assert!(matches!(
            classify(parse_line(r#"{"type":"item.completed"}"#).unwrap()),
            LineAction::Unrecognized
        ));
    }
}
