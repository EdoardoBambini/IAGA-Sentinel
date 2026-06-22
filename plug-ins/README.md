# IAGA Sentinel plug-ins — put governance in your agent's loop

This folder holds everything that wires IAGA Sentinel **into an agent framework's
tool-call path**: ask a local Sentinel sidecar for an `allow` / `review` / `block`
verdict before a tool runs, enforce it, and turn each verdict into an
Ed25519-signed, offline-verifiable receipt.

Two kinds live here:

- **Plugins** (`*-plugin/`) — complete, self-contained, **released** packages you
  drop into a framework: [`codex-plugin/`](codex-plugin) (crate `iaga-sentinel-codex`,
  bin `iaga-codex`), [`voltagent-plugin/`](voltagent-plugin) (npm `@iaga-sentinel/voltagent`).
- **Adapters** (`*-adapter/`) — thin, copy-paste integrations that gate tool calls
  but aren't yet packaged as standalone, deployable plugins. One per framework
  (LangChain, LangGraph, CrewAI, Claude Code, …). The reusable client libraries they
  build on are in [`sdks/`](../sdks).

> Promotion path: an `*-adapter/` graduates to `*-plugin/` once it is a
> self-contained, tested, deployable package like `codex-plugin/`.

---

## Tutorial: govern any agent in 4 steps

### 1. Run the Sentinel sidecar

Pull the pinned image and run it in open mode (no auth — for local dev/demos):

```bash
docker pull ghcr.io/edoardobambini/iaga-sentinel:v1.7.1
docker run -p 4010:4010 -e IAGA_SENTINEL_OPEN_MODE=true \
  ghcr.io/edoardobambini/iaga-sentinel:v1.7.1 serve --seed-demo
```

The REST API and operator dashboard are now at <http://localhost:4010/>. (In
production, drop open mode and pass an API key via `IAGA_SENTINEL_API_KEY`.)

### 2. Pick your integration

- A released **plugin**? Install it: e.g. `npm i @iaga-sentinel/voltagent` for
  VoltAgent, or build the `iaga-codex` binary for OpenAI Codex.
- Only an **adapter** for your framework? Copy the folder's snippet into your app.
- Nothing yet? Follow the same recipe with the SDK client
  ([`sdks/typescript`](../sdks/typescript), [`sdks/python`](../sdks/python)) and
  consider contributing it back as a new `*-adapter/`.

### 3. Wire it into the tool-call path

Every integration does the same three things at the framework's interception
point (a hook, a callback, a middleware, a tool wrapper):

1. Map the tool call to an `InspectRequest` and `POST /v1/inspect`.
2. Enforce the verdict: **allow** → run; **review** → don't run (default), or pass
   through if configured; **block** → don't run.
3. Surface the policy reason into the framework's own error/flow.

The VoltAgent plugin, end to end:

```ts
import { Agent } from "@voltagent/core";
import { createSentinelHooks } from "@iaga-sentinel/voltagent";

const agent = new Agent({
  name: "governed-agent",
  model: /* your model */,
  tools: [/* your tools */],
  hooks: createSentinelHooks({ agentId: "my-agent", sessionId: "run-1" }),
});
// A blocked tool throws ToolDeniedError before execute() runs.
```

### 4. Verify the evidence offline

Every governed action appends a signed receipt under `run_id = <agentId>:<sessionId>`.
Verify the whole chain with no network and no trust in the sidecar:

```bash
iaga replay <agentId>:<sessionId> --verify-only      # -> CHAIN OK  receipts=N  signer=ed25519-…
# or export + verify with the standalone tool:
iaga replay <agentId>:<sessionId> --export chain.json
iaga-verify chain.json                               # -> CHAIN OK
```

---

## Shared posture: enforces softly, certifies hard

Everything here is **cooperative agent-loop tier**, not kernel enforcement:

- **Fail-closed by default** — when the sidecar is unreachable, the gate denies.
- **Bypassable** — if the host strips the integration (or calls the tool outside
  the framework), nothing stops execution. The block is cooperative.
- Every OSS receipt carries **`isAuthoritative: false`** — the community build
  ships no authoritative kernel.
- The **hard guarantee is the evidence**: a tamper-evident, signed, Merkle-chained
  receipt log that verifies offline.

---

## Inventory

### Plugins (released)

| Plugin | Framework | Interception |
| --- | --- | --- |
| [`codex-plugin/`](codex-plugin) | OpenAI Codex CLI | `PreToolUse` hook → `/v1/inspect` (+ rules compiler, ingest) |
| [`voltagent-plugin/`](voltagent-plugin) | VoltAgent (`@voltagent/core`) | `onToolStart` / `onToolEnd` hooks |

### Adapters (copy-paste, not yet packaged)

`claude-code-adapter` · `claude-agent-sdk-adapter` · `langchain-adapter` ·
`langgraph-adapter` · `llamaindex-adapter` · `pydantic-ai-adapter` ·
`openai-agents-adapter` · `microsoft-agent-framework-adapter` · `openai-adapter` ·
`openai-ts-adapter` · `vercel-ai-adapter` · `mcp-adapter` · `crewai-adapter` ·
`autogen-adapter` · `custom-adapter`
