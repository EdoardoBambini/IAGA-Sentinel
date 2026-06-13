# Codex fixtures — spike status

Two fixture families, each isolated behind exactly one module. Status as of
the spike against **codex-cli 0.138.0-alpha.7** (see ADR 0022):

## Exec-stream lines — `*.jsonl` — CONFIRMED

`exec_stream_real_0.138.jsonl` is a **real `codex exec --json` capture** from
0.138: it confirms `thread.started`+`thread_id`, `turn.*`, `item.started`/
`item.completed`, and the `command_execution` (string `command` +
`aggregated_output`/`exit_code`/`status`), `file_change` (`changes:[{path,
kind}]`), and `agent_message` shapes. `exec_stream.rs` parses it with no
changes. The synthetic `exec_stream_session.provisional.jsonl` stays for
broad coverage (it also exercises `mcp_tool_call` and `web_search`, whose
shapes are **not yet captured**); `exec_stream_malformed.provisional.jsonl`
proves a non-JSON line is skipped, not fatal. Field-name knowledge lives in
`src/exec_stream.rs`.

## Hook payloads — `*.provisional.json` — field names confirmed, literal payload pending

One-per-event hook payloads for the gate. The **field names are confirmed**
against the 0.138 binary (and Codex's Claude-Code hook compatibility): the
discriminator is `hook_event_name` (not `event`), with `tool_name`/
`tool_input`/`tool_response`/`session_id`/`transcript_path`/`cwd`/
`permission_mode`/`stop_hook_active`. `src/codex_event.rs` is reconciled to
those names (the `event` alias keeps these synthetic fixtures parsing). A
**literal** payload echo is still worth capturing — `codex exec` did not fire
hooks in the spike; the interactive TUI does. When it lands, replace these
with the real payloads and drop `.provisional`. Field-name knowledge lives in
`src/codex_event.rs`.

## Open hook finding

Codex supports a structured hook response with
`hookSpecificOutput.permissionDecision = allow | deny | ask` (Claude-Code
contract). So the gate's `review` verdict could map to a real **ask**
(human-in-the-loop) instead of today's conservative exit-2 block — deferred,
documented in ADR 0022.

Nothing outside the two owner modules may assume Codex field names.
