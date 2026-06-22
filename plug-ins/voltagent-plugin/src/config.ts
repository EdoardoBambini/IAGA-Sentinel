import type { ActionType, SentinelLogger, SentinelOptions } from "./types.js";

export interface ResolvedConfig {
  baseUrl: string;
  apiKey?: string;
  agentId: string;
  framework: string;
  sessionId?: string;
  workspaceId?: string;
  failClosed: boolean;
  onReview: "block" | "allow";
  scanInput: boolean;
  scanOutput: boolean;
  redactOutput: boolean;
  timeoutMs: number;
  fetch?: typeof fetch;
  logger?: SentinelLogger;
  inferActionType: (toolName: string, args: unknown) => ActionType;
}

function env(name: string): string | undefined {
  return typeof process !== "undefined" ? process.env?.[name] : undefined;
}

/**
 * Best-effort tool-name -> ActionType so the sidecar can risk-score the right
 * category. Defaults to "custom" (the safe, generic bucket) when nothing matches.
 */
export function defaultInferActionType(toolName: string): ActionType {
  const n = (toolName || "").toLowerCase();
  if (/(^|[_:.\- ])(shell|exec|bash|sh|cmd|command|terminal|run|spawn)([_:.\- ]|$)/.test(n)) {
    return "shell";
  }
  if (/(write|create|edit|save|patch|append|delete|remove|rm|mkdir|put|upload)/.test(n)) {
    return "file_write";
  }
  if (/(read|cat|view|open|load|ls|list|glob|grep|get_file|download)/.test(n)) {
    return "file_read";
  }
  if (/(sql|query|db|database|select|insert|mongo|postgres|mysql|redis)/.test(n)) {
    return "db_query";
  }
  if (/(http|fetch|request|url|web|api|curl|browse|crawl|scrape)/.test(n)) {
    return "http";
  }
  if (/(email|smtp|mail|sendgrid|mailgun)/.test(n)) {
    return "email";
  }
  return "custom";
}

export function resolveOptions(options: SentinelOptions = {}): ResolvedConfig {
  return {
    baseUrl: options.baseUrl ?? env("IAGA_SENTINEL_URL") ?? "http://localhost:4010",
    apiKey: options.apiKey ?? env("IAGA_SENTINEL_API_KEY"),
    agentId: options.agentId ?? env("IAGA_SENTINEL_AGENT_ID") ?? "voltagent-agent",
    framework: options.framework ?? "voltagent",
    sessionId: options.sessionId,
    workspaceId: options.workspaceId,
    failClosed: options.failClosed ?? true,
    onReview: options.onReview ?? "block",
    scanInput: options.scanInput ?? false,
    scanOutput: options.scanOutput ?? false,
    redactOutput: options.redactOutput ?? false,
    timeoutMs: options.timeoutMs ?? 5000,
    fetch: options.fetch,
    logger: options.logger,
    inferActionType: options.inferActionType ?? defaultInferActionType,
  };
}
