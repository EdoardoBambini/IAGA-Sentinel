# IAGA Sentinel — Claude Agent SDK

Govern tool calls made by an agent built on the **Claude Agent SDK**. Two
entry points, both inspect each tool call through `POST /v1/inspect` first:

| File | SDK | Hook |
|---|---|---|
| `canUseTool.ts` | TypeScript (`@anthropic-ai/claude-agent-sdk`) | `query({ options: { canUseTool } })` |
| `hooks_example.py` | Python (`claude-agent-sdk`) | `ClaudeAgentOptions(hooks={"PreToolUse": ...})` |

`block`/`review` → the tool is denied (`canUseTool` has only allow/deny, so both
map to deny); `allow` → the call proceeds and a signed receipt is produced.
Transport errors fail open by default.

> If you use Claude **Code** (the CLI) rather than the SDK, use the
> `PreToolUse` command hook in `../claude-code/` instead.

## Setup

```bash
cargo build --release --workspace
IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

Register the agent so its tool names are known (unregistered agents return 404):

```bash
./target/release/iaga import examples/integrations/claude-agent-sdk/claude-agent-sdk.policy.yaml
```

## Run

- **TypeScript:** `npx tsx canUseTool.ts`
- **Python:** `python hooks_example.py`

The injection firewall blocks dangerous payloads (e.g. `curl … | sh`) regardless
of the policy decision. Verify a receipt with `iaga replay <run_id> --export` +
`iaga-verify` (`is_authoritative: false`).
