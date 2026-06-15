# ADR 0020: Cost Control (observability + budget enforcement)

- **Status:** Accepted
- **Date:** 2026-06-09

## Context

Operators need to see where their agents' LLM spend goes and to cap it, without
shipping evidence to a third party. IAGA Sentinel governs actions at decision
time (before an action runs); it does **not** sit on the LLM network path and
cannot observe token usage on its own. Cost must therefore be *reported* to
Sentinel by an instrumented caller, not *discovered* by it. Anthropic and OpenAI
return exact `usage` (input/output tokens) in their responses, which the agent
SDKs already see.

## Decision

Add **cost control** to the open build behind a `cost-control` cargo feature
(default **off**, so the default build stays byte-identical to 1.4.0).

- New leaf crate `crates/iaga-sentinel-cost`: `UsageReport` (the wire shape a
  caller reports, with human-USD `costUsd`) resolves to `UsageData` (the
  canonical, signed form). Money in `UsageData` is integer **micro-USD**
  (`costMicros`), not `f64` — the ledger stays exact under summation and the
  type stays `Eq`, which `ReceiptBody` requires.
- Local pricing only: a `PricingTable` (dated built-in list, overridable via
  `IAGA_SENTINEL_PRICING_FILE`, YAML or JSON) converts tokens to micro-USD. A
  caller-supplied cost always wins over the table. No external billing API is
  ever called.
- `usage: Option<UsageData>` is appended to `ReceiptBody` (elided when `None`,
  so pre-1.5 receipts stay byte-identical and verify unchanged — same additive
  contract as the 1.2 capture fields and the 1.3.1 `is_authoritative` flag) and
  mirrored on `StoredAuditEvent` with denormalized audit columns (migration
  0004) for fast aggregation.
- **Capture** flows from the `/v1/inspect` body and the agent SDKs (a new
  optional `usage` field on the public wire contract). MCP proxy calls are
  governed and, when read-only, served from the deterministic response cache
  (ADR 0021); recording their per-call token cost into the audit ledger from the
  proxy is a follow-up — the SDK and `/v1/inspect` channels are the supported
  cost-capture paths.
- **Observability**: `AuditStore::cost_summary / cost_by_{agent,model,tool} /
  cost_over_time`, surfaced at `/v1/cost/*`, a "Cost Control" dashboard panel,
  and an `iaga cost` CLI. Endpoints report `{ "enabled": false }` when the
  feature is compiled out.
- **Budget enforcement**: a process-global, session-scoped `SpendStore`
  (cumulative micro-USD per `(agent_id, session_id)`, mirroring the
  session-graph state model) is read at decision time. The current spend and the
  configured limit (`IAGA_SENTINEL_SESSION_BUDGET_USD`) are injected into the Dictum
  context as `usage.session_cost_usd` and `budget.limit`, so a policy can write
  `when usage.session_cost_usd > budget.limit then block`. A non-Dictum fallback
  enforces the same limit even with no policy loaded. Both follow the existing
  stricter-wins merge: cost can only tighten a verdict. Semantics are
  "block-next": a session's prior cumulative spend is checked before the action,
  and the action's own cost is added after it is recorded.

## Consequences

Cost is only as complete as the callers that report it; the SDKs and
`/v1/inspect` are the supported channels. token-to-USD conversion is local and
indicative, not an invoice — list prices drift, so operators override the table
and a caller-supplied cost is treated as ground truth. The 1.5 `SpendStore` is
in-memory and session-scoped; durable spend (the `agent_spend` table is created
but not yet hydrated), time-windowed (hourly/daily) budgets, and per-agent /
per-workspace budget config are follow-ups. Network-layer or eBPF cost
interception remains out of the open build (ADR 0010).
