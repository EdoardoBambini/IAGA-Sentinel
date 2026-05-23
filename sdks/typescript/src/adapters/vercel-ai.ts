import { SentinelBlockedError, SentinelClient, SentinelReviewError } from "../client";
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
  const result = await client.inspect(buildInspectRequest(options, payload));
  if (result.decision === "block") {
    throw new SentinelBlockedError(result);
  }
  if (result.decision === "review") {
    throw new SentinelReviewError(result);
  }
}

export function sentinelMiddleware(options: SentinelMiddlewareOptions) {
  const client = new SentinelClient(options);

  return {
    name: "iaga-sentinel",
    async inspect(payload: JsonObject): Promise<void> {
      await inspectPayload(client, options, payload);
    },
    async wrapGenerate<T>(
      next: (payload: JsonObject) => Promise<T>,
      payload: JsonObject
    ): Promise<T> {
      await inspectPayload(client, options, payload);
      return next(payload);
    },
    async wrapStream<T>(
      next: (payload: JsonObject) => Promise<T>,
      payload: JsonObject
    ): Promise<T> {
      await inspectPayload(client, options, payload);
      return next(payload);
    },
  };
}
