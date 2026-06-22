export { createSentinelHooks } from "./hooks.js";
export { SentinelClient, SentinelApiError } from "./client.js";
export { resolveOptions, defaultInferActionType } from "./config.js";
export type { ResolvedConfig } from "./config.js";
export type {
  ActionDetail,
  ActionType,
  FirewallResult,
  GovernanceDecision,
  GovernanceResult,
  InspectRequest,
  ResponseScanRequest,
  ResponseScanResult,
  RiskScore,
  SentinelLogger,
  SentinelOptions,
} from "./types.js";
