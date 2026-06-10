# ADR 0021: Response Cache — deterministic in OSS, semantic in Enterprise

- **Status:** Accepted
- **Date:** 2026-06-09

## Context

1.5 ships cost **control** in the open build (ADR 0020). The adjacent cost
**reduction** primitive is a response cache: return a prior result instead of
paying for the call again. It comes in two flavors — **deterministic**
(exact/normalized-argument key) and **semantic** (prompt-similarity matching).
Which belong in the open build?

## Decision

**The deterministic response cache ships in the open build** (under the
`cost-control` feature). **Semantic caching is an Enterprise feature.**

Deterministic cache (open build):

- Lives in the MCP proxy. After governance allows a `tools/call`, an identical,
  safe, read-only call is served from cache instead of being forwarded
  downstream — the real saving is the avoided downstream/LLM call.
- Key is `(agent_id, tool_name, sha256(canonical_args))`; argument key-order is
  normalized so it never changes the key. Entries are TTL'd (5 min) and
  size-capped with oldest-eviction. Process-global and in-memory, mirroring the
  session-graph / spend-store model (lost on restart).
- **Safe by construction**: gated to read-only actions only (`ActionType::FileRead`
  via the proxy's tool-name inference — never `Shell`/`FileWrite`/`DbQuery`/
  `Email`), skipped when the agent's session is tainted, and isolated per agent.
  Broadening to safe HTTP GETs is a follow-up.
- Savings are surfaced through the cost **summary** (a process-global hit/savings
  counter folded into `/v1/cost/summary`), deliberately **not** as audit rows, so
  a cache hit never double-counts the governance event already recorded for the
  same call.

Semantic cache (Enterprise, not in the open build):

- Similarity matching needs a real sentence-embedding model plus a vector index.
  The open build's reasoning backend (`TractEngine`) is a hash-bag-of-n-grams
  scalar scorer, not an embedding model, so it cannot back semantic similarity.
- It also carries a materially higher false-hit / correctness surface (returning
  a "close enough" answer) that wants the Enterprise isolation and review posture
  reserved by ADR 0010.

## Consequences

Open-build users get real call-avoidance and savings visibility on safe,
read-only tool calls, on top of the spend visibility and budget caps from
ADR 0020. The cache is conservative (read-only, per-agent, untainted, TTL'd) by
default. The `UsageData.cache_hit` / `savings_micros` fields and the matching
audit columns remain part of the shared schema (an Enterprise build, or a future
per-call cache receipt, can populate them) — keeping receipts byte-verifiable
across the OSS↔Enterprise boundary. Semantic caching, durable cache state, and a
broader cacheability gate are future / Enterprise work.
