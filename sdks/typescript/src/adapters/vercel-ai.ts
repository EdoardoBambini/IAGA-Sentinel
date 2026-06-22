import {
  SentinelBlockedError,
  SentinelClient,
  SentinelReviewError,
  inspectWithPolicy,
} from "../client";
import type { SentinelMiddlewareOptions, InspectRequest, JsonObject } from "../types";

function buildInspectRequest(
  options: SentinelMiddlewareOptions,
  payload: JsonObject
): InspectRequest {
  return {
    agentId: options.agentId,
    tenantId: options.tenantId,
    workspaceId: options.workspaceId,
    framework: options.framework ?? "vercel-ai",
    sessionId: options.sessionId,
    metadata: options.metadata,
    action: {
      type: options.actionType ?? "http",
      toolName: options.toolName ?? "vercel-ai.generate",
      payload,
    },
  };
}

async function inspectPayload(
  client: SentinelClient,
  options: SentinelMiddlewareOptions,
  payload: JsonObject
): Promise<void> {
  const result = await inspectWithPolicy(
    client,
    buildInspectRequest(options, payload),
    { failClosed: options.failClosed }
  );
  if (result.decision === "block") {
    throw new SentinelBlockedError(result);
  }
  if (result.decision === "review") {
    throw new SentinelReviewError(result);
  }
}

// The Vercel AI SDK calls a middleware's wrapGenerate/wrapStream with a single
// options object `{ doGenerate, doStream, params, model }` (params holds the
// prompt, tools, etc.). Extract a JSON-safe governance payload from it so the
// firewall can scan the prompt the model is about to run.
function paramsToPayload(params: unknown): JsonObject {
  if (!params || typeof params !== "object") return {};
  const p = params as Record<string, unknown>;
  try {
    return JSON.parse(
      JSON.stringify({ prompt: p.prompt, tools: p.tools, toolChoice: p.toolChoice })
    ) as JsonObject;
  } catch {
    return { prompt: String(p.prompt ?? "") };
  }
}

/**
 * IAGA Sentinel middleware for the Vercel AI SDK.
 *
 * It is a real `LanguageModelMiddleware`: pass it to `wrapLanguageModel`, and
 * every `generateText` / `streamText` call is inspected (prompt + tools) before
 * the model runs. A `block` raises `SentinelBlockedError`, a `review` raises
 * `SentinelReviewError`; transport errors fail open by default (`failClosed`).
 *
 * The returned object is dependency-light (it does not import `ai`); it is
 * duck-typed against the SDK's middleware contract. `inspect(payload)` is also
 * exposed as a standalone escape hatch for governing an arbitrary payload.
 *
 * See plug-ins/vercel-ai-adapter/ for a runnable example.
 */
export function sentinelMiddleware(options: SentinelMiddlewareOptions) {
  const client = new SentinelClient(options);
  const inspect = (payload: JsonObject) => inspectPayload(client, options, payload);

  return {
    middlewareVersion: "v2" as const,
    name: "iaga-sentinel",
    async wrapGenerate(opts: {
      doGenerate: () => unknown;
      params?: unknown;
    }): Promise<unknown> {
      await inspect(paramsToPayload(opts?.params));
      return opts.doGenerate();
    },
    async wrapStream(opts: {
      doStream: () => unknown;
      params?: unknown;
    }): Promise<unknown> {
      await inspect(paramsToPayload(opts?.params));
      return opts.doStream();
    },
    /** Standalone escape hatch: inspect an arbitrary payload yourself. */
    inspect,
  };
}
