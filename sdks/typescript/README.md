# IAGA Sentinel TypeScript SDK

The TypeScript SDK wraps the IAGA Sentinel HTTP API and adds lightweight helpers
for OpenAI and Vercel AI style integrations.

## Highlights

- `SentinelClient` covers governance, policy, plugin, audit, telemetry, and threat
  intel endpoints exposed by the runtime
- `InspectRequest.sessionId` is normalized into `metadata.sessionId` so sequence
  aware governance survives across repeated tool calls
- adapter helpers are dependency-light and keep the package buildable without
  forcing framework installs

## Quick start

```ts
import { SentinelClient } from "@iaga-sentinel/sdk";

const client = new SentinelClient({ apiKey: "ak-local" });

const result = await client.inspect({
  agentId: "builder-01",
  workspaceId: "ws-demo",
  framework: "openai",
  sessionId: "session-123",
  action: {
    type: "http",
    toolName: "openai.responses.create",
    payload: { model: "gpt-5.4-mini" },
  },
});

console.log(result.decision, result.traceId);
```

## Adapters

```ts
import OpenAI from "openai";
import { sentinelMiddleware, sentinelWrapOpenAI } from "@iaga-sentinel/sdk";

const openai = sentinelWrapOpenAI(new OpenAI(), {
  agentId: "builder-01",
  apiKey: "ak-local",
});

const middleware = sentinelMiddleware({
  agentId: "builder-01",
  apiKey: "ak-local",
  toolName: "vercel-ai.generate",
});
```
