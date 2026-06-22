// Wire types for the IAGA Sentinel sidecar, transcribed from the real Rust
// handlers (serde camelCase) in crates/iaga-sentinel-core/src/core/types.rs and
// modules/injection_firewall/prompt_firewall.rs. Only the fields this plugin
// uses are modelled; the sidecar may return more (ignored).

export type GovernanceDecision = "allow" | "review" | "block";

export type ActionType =
  | "shell"
  | "file_read"
  | "file_write"
  | "http"
  | "db_query"
  | "email"
  | "custom";

export interface ActionDetail {
  type: ActionType;
  toolName: string;
  payload: Record<string, unknown>;
}

/** POST /v1/inspect request body. */
export interface InspectRequest {
  agentId: string;
  framework: string;
  action: ActionDetail;
  tenantId?: string;
  workspaceId?: string;
  /** `metadata.sessionId` becomes the signed-receipt run_id (chains a run). */
  metadata?: Record<string, unknown>;
}

export interface RiskScore {
  score: number;
  decision: GovernanceDecision;
  reasons: string[];
}

/** POST /v1/inspect response (subset of GovernanceResult). */
export interface GovernanceResult {
  traceId: string;
  decision: GovernanceDecision;
  risk: RiskScore;
  reviewStatus?: string;
  reviewRequestId?: string;
  policyFindings?: string[];
  auditEvent?: { eventId?: string } & Record<string, unknown>;
}

/** POST /v1/firewall/scan response (subset of FirewallResult). */
export interface FirewallResult {
  blocked: boolean;
  riskScore?: number;
  summary?: string;
}

/** POST /v1/response/scan request body. */
export interface ResponseScanRequest {
  requestId: string;
  agentId: string;
  toolName: string;
  responsePayload: unknown;
  metadata?: Record<string, unknown>;
}

/** POST /v1/response/scan response body. */
export interface ResponseScanResult {
  requestId: string;
  decision: GovernanceDecision;
  riskScore: number;
  findings: string[];
  redactedPayload?: unknown;
}

/** Minimal structural logger; VoltAgent's logger satisfies it. */
export interface SentinelLogger {
  debug?(message: string, ...rest: unknown[]): void;
  info?(message: string, ...rest: unknown[]): void;
  warn?(message: string, ...rest: unknown[]): void;
  error?(message: string, ...rest: unknown[]): void;
}

export interface SentinelOptions {
  /** Sidecar REST base. Env: IAGA_SENTINEL_URL. Default http://localhost:4010 */
  baseUrl?: string;
  /** Bearer key, omitted in open mode. Env: IAGA_SENTINEL_API_KEY */
  apiKey?: string;
  /** Registered agent id. Env: IAGA_SENTINEL_AGENT_ID. Default "voltagent-agent" */
  agentId?: string;
  /** Reported framework. Default "voltagent". */
  framework?: string;
  /** Maps to metadata.sessionId = receipt run_id (chains a verifiable run). */
  sessionId?: string;
  workspaceId?: string;
  /** Deny when the sidecar is unreachable. Default true. */
  failClosed?: boolean;
  /** What a "review" verdict does. Default "block". */
  onReview?: "block" | "allow";
  /** Scan tool input through /v1/firewall/scan before inspect. Default false. */
  scanInput?: boolean;
  /** Scan tool output through /v1/response/scan in onToolEnd. Default false. */
  scanOutput?: boolean;
  /** Substitute redactedPayload into the result the model sees. Default false. */
  redactOutput?: boolean;
  /** Per-request timeout in ms. Default 5000. */
  timeoutMs?: number;
  /** Injectable fetch for runtimes without a global one. */
  fetch?: typeof fetch;
  /** Optional logger (e.g. VoltAgent's). */
  logger?: SentinelLogger;
  /** Override the tool-name -> ActionType heuristic. */
  inferActionType?: (toolName: string, args: unknown) => ActionType;
}
