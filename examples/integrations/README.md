# IAGA Sentinel — Agent & framework integrations

Put IAGA Sentinel **in the loop** of any AI agent: intercept each tool call,
ask IAGA for a verdict (`POST /v1/inspect`), enforce it, and let IAGA sign an
offline-verifiable receipt. Adapters are thin and **cooperative** — they observe
and gate; they never reimplement the schema or crypto, and every receipt records
`is_authoritative = false` (kernel-level, unbypassable enforcement is the
Enterprise roadmap).

Enforcement is identical everywhere: **allow** → run; **review** → don't run,
surface for approval; **block** → don't run. Transport errors fail **open** by
default (configurable to fail-closed). One signed receipt per tool call.

## Quick start (every integration)

```bash
cargo build --release --workspace
IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo   # port 4010
./target/release/iaga import examples/integrations/<framework>/<framework>.policy.yaml
```

Then run the example in that folder. Verify any receipt:

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```

## Supported frameworks

| Framework | Lang | Adapter / entry point | Folder |
|---|---|---|---|
| Custom agent | Python | `@governed` | [`custom/`](custom/) |
| LangChain | Python | `SentinelCallbackHandler` (on_tool_start) | [`langchain/`](langchain/) |
| LangGraph | Python / JS | `GovernedToolNode` / `governedToolNode` | [`langgraph/`](langgraph/) |
| LlamaIndex | Python | `IagaCallbackHandler` (FUNCTION_CALL) | [`llamaindex/`](llamaindex/) |
| Pydantic AI | Python | `governed_tool` | [`pydantic-ai/`](pydantic-ai/) |
| OpenAI Agents SDK | Python | `iaga_tool_guardrail` + `governed_tool` | [`openai-agents/`](openai-agents/) |
| CrewAI | Python | `SentinelGuardrail` | [`crewai/`](crewai/) |
| AutoGen / AG2 | Python | `AutoGenSentinelHook` | [`autogen/`](autogen/) |
| Microsoft Agent Framework | Python | `sentinel_middleware` | [`microsoft-agent-framework/`](microsoft-agent-framework/) |
| OpenAI | Python | `sentinel_wrap_openai` | [`openai/`](openai/) |
| OpenAI | TypeScript | `sentinelWrapOpenAI` | [`openai-ts/`](openai-ts/) |
| Vercel AI SDK | TypeScript | `sentinelMiddleware` | [`vercel-ai/`](vercel-ai/) |
| MCP servers | Python / TS | `govern_tool` / `governMcpTool` (+ `iaga proxy`) | [`mcp/`](mcp/) |
| Claude Code | CLI | `PreToolUse` hook | [`claude-code/`](claude-code/) |
| Claude Agent SDK | TS / Python | `canUseTool` / `PreToolUse` hook | [`claude-agent-sdk/`](claude-agent-sdk/) |
| OpenAI Codex CLI | CLI / Rust | `iaga-codex hook` (PreToolUse, fail-closed) | [`codex/`](codex/) |

## Tests

- **Fake (CI):** `sdks/python/tests/` and `sdks/typescript/smoke.cjs` drive each
  adapter against the live sidecar with dependency-free duck-typed inputs — no
  framework libraries required.
- **Real E2E:** `sdks/python/tests/e2e/` drives the adapters against the **real**
  framework types (LangChain, LangGraph, LlamaIndex, Pydantic AI, MCP/FastMCP,
  OpenAI Agents, CrewAI, AutoGen). Each test `importorskip`s its library, so it
  auto-skips when absent; run it in a venv that has the framework installed.
