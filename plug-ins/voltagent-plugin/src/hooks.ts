import { createHooks, ToolDeniedError } from "@voltagent/core";
import type {
  AgentHooks,
  OnToolEndHookArgs,
  OnToolEndHookResult,
  OnToolStartHookArgs,
} from "@voltagent/core";
import { SentinelClient } from "./client.js";
import { resolveOptions, type ResolvedConfig } from "./config.js";
import type {
  GovernanceResult,
  InspectRequest,
  ResponseScanRequest,
  SentinelOptions,
} from "./types.js";

function reasonOf(verdict: GovernanceResult): string {
  if (verdict.risk?.reasons?.length) return verdict.risk.reasons.join("; ");
  if (verdict.policyFindings?.length) return verdict.policyFindings.join("; ");
  return "blocked by IAGA Sentinel";
}

function toPayload(args: unknown): Record<string, unknown> {
  if (args && typeof args === "object" && !Array.isArray(args)) {
    return args as Record<string, unknown>;
  }
  return { value: args };
}

function stringifyArgs(args: unknown): string {
  if (typeof args === "string") return args;
  try {
    return JSON.stringify(args ?? {});
  } catch {
    return String(args);
  }
}

function buildInspectRequest(
  cfg: ResolvedConfig,
  toolName: string,
  args: unknown,
): InspectRequest {
  const metadata: Record<string, unknown> = { enforcement: "agent-loop" };
  if (cfg.sessionId) metadata.sessionId = cfg.sessionId;
  const request: InspectRequest = {
    agentId: cfg.agentId,
    framework: cfg.framework,
    action: {
      type: cfg.inferActionType(toolName, args),
      toolName,
      payload: toPayload(args),
    },
    metadata,
  };
  if (cfg.workspaceId) request.workspaceId = cfg.workspaceId;
  return request;
}

function newRequestId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  return c?.randomUUID ? c.randomUUID() : `req-${Date.now()}-${process.pid ?? 0}`;
}

function buildResponseScanRequest(
  cfg: ResolvedConfig,
  toolName: string,
  output: unknown,
): ResponseScanRequest {
  const request: ResponseScanRequest = {
    requestId: newRequestId(),
    agentId: cfg.agentId,
    toolName,
    responsePayload: output,
  };
  if (cfg.sessionId) request.metadata = { sessionId: cfg.sessionId };
  return request;
}

/**
 * Build VoltAgent hooks that govern every tool call through an IAGA Sentinel
 * sidecar. Pass the result to `new Agent({ hooks })` or to a per-call
 * `generateText`/`streamText`.
 *
 * Posture: cooperative agent-loop tier. Blocking happens by throwing a
 * `ToolDeniedError` from `onToolStart` (the tool's `execute` never runs), which
 * VoltAgent turns into a hard operation abort. It is bypassable if the host
 * strips the hook; every receipt the sidecar signs is `isAuthoritative: false`.
 * The hard guarantee is the signed, offline-verifiable receipt chain.
 */
export function createSentinelHooks(options: SentinelOptions = {}): AgentHooks {
  const cfg = resolveOptions(options);
  const client = new SentinelClient({
    baseUrl: cfg.baseUrl,
    apiKey: cfg.apiKey,
    timeoutMs: cfg.timeoutMs,
    fetch: cfg.fetch,
  });

  const onToolStart = async ({ tool, args }: OnToolStartHookArgs): Promise<void> => {
    const toolName = tool?.name ?? "unknown";

    // Optional pre-inspect prompt-injection scan of the tool input.
    if (cfg.scanInput) {
      let blocked = false;
      let summary = "prompt injection detected";
      try {
        const fw = await client.firewallScan(stringifyArgs(args));
        blocked = fw.blocked === true;
        if (fw.summary) summary = fw.summary;
      } catch (err) {
        cfg.logger?.warn?.(`[iaga-sentinel] firewall scan failed for ${toolName}: ${String(err)}`);
        if (cfg.failClosed) {
          throw new ToolDeniedError({
            toolName,
            message: `IAGA Sentinel unreachable, failing closed: ${String(err)}`,
            code: "IAGA_UNREACHABLE",
            httpStatus: 424,
          });
        }
      }
      if (blocked) {
        throw new ToolDeniedError({
          toolName,
          message: `IAGA Sentinel firewall blocked the input: ${summary}`,
          code: "IAGA_FIREWALL_BLOCK",
          httpStatus: 403,
        });
      }
    }

    // Core verdict.
    let verdict: GovernanceResult;
    try {
      verdict = await client.inspect(buildInspectRequest(cfg, toolName, args));
    } catch (err) {
      cfg.logger?.warn?.(`[iaga-sentinel] inspect failed for ${toolName}: ${String(err)}`);
      if (cfg.failClosed) {
        throw new ToolDeniedError({
          toolName,
          message: `IAGA Sentinel unreachable, failing closed: ${String(err)}`,
          code: "IAGA_UNREACHABLE",
          httpStatus: 424,
        });
      }
      cfg.logger?.warn?.(`[iaga-sentinel] failing open: ${toolName} allowed without a verdict`);
      return;
    }

    if (verdict.decision === "allow") {
      cfg.logger?.debug?.(`[iaga-sentinel] allow ${toolName} (risk=${verdict.risk?.score})`);
      return;
    }

    if (verdict.decision === "block") {
      throw new ToolDeniedError({
        toolName,
        message: reasonOf(verdict),
        code: "IAGA_BLOCK",
        httpStatus: 403,
      });
    }

    // review
    if (cfg.onReview === "allow") {
      cfg.logger?.info?.(
        `[iaga-sentinel] review ${toolName} passed through (onReview=allow, receipt recorded)`,
      );
      return;
    }
    throw new ToolDeniedError({
      toolName,
      message: `IAGA Sentinel requires review: ${reasonOf(verdict)}`,
      code: "IAGA_REVIEW",
      httpStatus: 403,
    });
  };

  if (!cfg.scanOutput) {
    return createHooks({ onToolStart });
  }

  const onToolEnd = async ({
    tool,
    output,
    error,
  }: OnToolEndHookArgs): Promise<OnToolEndHookResult | undefined> => {
    if (error || output === undefined) return undefined;
    const toolName = tool?.name ?? "unknown";
    try {
      const scan = await client.responseScan(buildResponseScanRequest(cfg, toolName, output));
      if (scan.findings?.length) {
        cfg.logger?.warn?.(
          `[iaga-sentinel] response scan ${toolName} (${scan.decision}): ${scan.findings.join("; ")}`,
        );
      }
      if (
        cfg.redactOutput &&
        scan.decision !== "allow" &&
        scan.redactedPayload !== undefined
      ) {
        return { output: scan.redactedPayload };
      }
    } catch (err) {
      // Output scanning is best-effort; a scan failure never rewrites a result.
      cfg.logger?.warn?.(`[iaga-sentinel] response scan failed for ${toolName}: ${String(err)}`);
    }
    return undefined;
  };

  return createHooks({ onToolStart, onToolEnd });
}
