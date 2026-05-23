# IAGA Sentinel v0.4.0 — Roadmap

> **Codename:** *Azzurra*
> **Target:** Community Edition — open source, game-changing release
> **Status:** In development
> **Date:** April 2026

---

## Context

v0.3.0 shipped a solid 8-layer governance pipeline with 48 HTTP endpoints, SQLite/PostgreSQL storage, MCP proxy/server modes, Python + TypeScript SDKs, and 120 tests. But several critical modules (`nhi`, `session_graph`, `taint`, `fingerprint`, `rate_limit`) still use `static Lazy<Mutex<HashMap>>` in-memory state that vanishes on restart. The policy engine is flat (no conditionals, no hierarchy). There are no framework adapters beyond MCP. The SDKs cover ~5 of 48 endpoints. And there's no way for the community to extend the pipeline with custom rules.

v0.4.0 closes these gaps with **6 pillars** that transform IAGA Sentinel from a demo-ready runtime into a **production-grade, extensible governance platform**.

> **Hardening note (April 2026):** Session correlation is being tightened so multi-call arcs like `file_read -> file_read -> http` feed the adaptive scorer with real session depth/timestamps instead of relying on per-call scoring alone.

## Reality Check (April 17, 2026)

This document still describes the intended `0.4.0` target shape, but the repo is **not fully at roadmap completion yet**. The current state is:

### Closed And Verified In Repo

- Version bump to `0.4.0` landed in `community` and `enterprise`.
- Session-aware hardening landed in:
  - `community/src/modules/session_graph/session_dag.rs`
  - `community/src/pipeline/execute_pipeline.rs`
  - `community/src/modules/risk/adaptive_scorer.rs`
- Real same-session sequence tests now cover `file_read -> http` in both integration and HTTP e2e paths; the second call is blocked when the `sessionId` is shared.
- WASM plugin runtime is wired through the server and pipeline:
  - `PluginRegistry` / `PluginHost`
  - `GET /v1/plugins`
  - `POST /v1/plugins/reload`
  - `GovernanceResult.pluginResults`
- Plugin CLI commands are now implemented and tested:
  - `iaga-sentinel plugins list`
  - `iaga-sentinel plugins validate <path.wasm>`
- Real feature-gated WASM tests now exist and are passing with `--features plugins`:
  - a `.wasm` module generated via `wat::parse_str`
  - loaded from a temporary plugin directory
  - verified through direct pipeline execution, HTTP e2e, and CLI invocation
  - asserts concrete plugin findings and a `decisionHint`
- The repo now includes a real example plugin tree:
  - `community/examples/plugins/review_hint.wat`
  - `community/tests/plugin_example_tests.rs`
  - CI validates the example plugin path explicitly
- Workspace policy rules are now persisted and exercised end-to-end:
  - `POST /v1/workspaces/{workspace_id}/rules` persists rules in storage
  - `GET /v1/workspaces/{workspace_id}/rules` returns persisted rules
  - the pipeline evaluates persisted rules during inspection
  - tests cover both HTTP persistence and runtime decision impact
- Framework adapter scaffolding is now materially present:
  - `sdks/python/iaga_sentinel/adapters/`
  - `sdks/typescript/src/adapters/`
- SDK coverage is no longer limited to ~5 endpoints:
  - both SDKs now cover governance, policy, plugin, audit, telemetry, review,
    threat intel, NHI, response, fingerprint, and rate-limit routes
  - both SDKs now expose `sessionId`, which is encoded into `metadata.sessionId`
- Root docs were updated to match the repo's real `0.4.0` state:
  - `README.md`
  - `docs/ARCHITECTURE.md`
- Durable-state scaffolding is partially landed:
  - new storage traits
  - migration `0003`
  - write-behind persistence hooks in the pipeline

### Partial / Still Open

- Durable state is **not fully closed as a restart story** yet. The new traits, migrations, and write-behind hooks are present, but startup hydration / background sync / restart validation still need tighter end-to-end proof before this pillar can be called done.
- Policy v2 is more real now, but still not fully closed:
  - built-in templates and rule persistence exist
  - persisted workspace rules are evaluated by the pipeline
  - template inheritance / hierarchy exists in code, but the full authoring and management story is still incomplete
- The WASM plugin slice is materially real now, but still not fully polished:
  - the example plugin is WAT-based for zero-toolchain readability rather than a richer Rust plugin crate
  - there is still no marketplace/distribution story beyond local plugin directories
- SDK parity is much closer, but not perfectly closed:
  - many methods exist now
  - some responses are still intentionally left as generic JSON objects instead of exhaustive typed SDK models

### Not Done Yet

- Enhanced CLI from Pillar 5 is not implemented beyond the current inspect/validate-oriented paths:
  - no `watch`
  - no `replay`
  - no `benchmark`
  - no `policy-test`
- Full durable-state restart proof remains the biggest architecture gap.

### Practical Read On `0.4.0`

The repo now has a real and tested sequence-aware hardening slice plus a real and tested WASM plugin runtime slice. That is meaningful progress, but it is **not honest yet** to call the full `0.4.0` roadmap complete.

---

## Pillar 1: Durable State — Persist All Layers

### Why

The #1 architectural debt. Restart the server and all NHI identities, session graphs, taint labels, behavioral fingerprints, and rate limit counters vanish. No one runs a security runtime in production with ephemeral state.

### What

Add 5 new storage traits + SQLite/PostgreSQL implementations. Migrate the 5 in-memory modules to persist their state behind `StorageBackend`.

### New Storage Traits

```rust
pub trait NhiStore: Send + Sync {
    async fn store_identity(&self, identity: &AgentIdentity, secret_key_hex: &str) -> Result<()>;
    async fn get_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>>;
    async fn get_secret_key_hex(&self, agent_id: &str) -> Result<Option<String>>;
    async fn list_identities(&self) -> Result<Vec<AgentIdentity>>;
    async fn update_trust(&self, agent_id: &str, trust_score: f64) -> Result<()>;
    async fn store_challenge(&self, challenge: &PendingChallenge) -> Result<()>;
    async fn get_challenge(&self, challenge_id: &str) -> Result<Option<PendingChallenge>>;
    async fn delete_challenge(&self, challenge_id: &str) -> Result<()>;
    async fn prune_expired_challenges(&self) -> Result<usize>;
}

pub trait SessionStore: Send + Sync {
    async fn store_session(&self, session: &SessionDAG) -> Result<()>;
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionDAG>>;
    async fn list_sessions(&self) -> Result<Vec<SessionDAG>>;
    async fn delete_session(&self, session_id: &str) -> Result<()>;
    async fn prune_stale_sessions(&self, max_age_ms: u64) -> Result<usize>;
}

pub trait TaintStore: Send + Sync {
    async fn get_session_taint(&self, session_id: &str) -> Result<HashSet<String>>;
    async fn update_session_taint(&self, session_id: &str, labels: &HashSet<String>) -> Result<()>;
    async fn prune_stale_sessions(&self, max_age_secs: u64) -> Result<usize>;
}

pub trait FingerprintStore: Send + Sync {
    async fn get_fingerprint(&self, agent_id: &str) -> Result<Option<AgentFingerprint>>;
    async fn upsert_fingerprint(&self, fp: &AgentFingerprint) -> Result<()>;
    async fn list_fingerprints(&self) -> Result<Vec<AgentFingerprint>>;
    async fn delete_fingerprint(&self, agent_id: &str) -> Result<()>;
}

pub trait RateLimitStore: Send + Sync {
    async fn load_config(&self) -> Result<Option<RateLimitConfig>>;
    async fn save_config(&self, config: &RateLimitConfig) -> Result<()>;
}
```

### Architecture Decision: Hybrid In-Memory + Persistent

The modules keep their fast in-memory data structures for zero-latency hot-path execution. Persistence happens via:

1. **Load from DB on startup** — hydrate in-memory state
2. **In-memory operation during runtime** — fast path unchanged
3. **Write-behind persistence** — async flush to DB after pipeline runs
4. **Periodic background sync** — every 30s, flush dirty state
5. **Graceful shutdown flush** — ensure no data loss

This gives us **zero performance regression** + **durable state across restarts**.

### New Database Tables (migration 0003)

- `nhi_identities` — agent SPIFFE identities, keys, trust scores
- `nhi_challenges` — pending attestation challenges (TTL)
- `session_graphs` — serialized session DAGs (JSON blob)
- `taint_sessions` — per-session taint label sets
- `fingerprints` — agent behavioral fingerprints (JSON)
- `rate_limit_config` — persisted rate limit configuration

### Files Modified

- `community/src/storage/traits.rs` — 5 new traits (**DONE**)
- `community/src/storage/sqlite.rs` — SQLite implementations
- `community/src/storage/postgres.rs` — PostgreSQL implementations
- `community/migrations/sqlite/0003_durable_state.sql`
- `community/migrations/postgres/0003_durable_state.sql`
- `community/src/server/app_state.rs` — new `Arc<dyn XxxStore>` fields
- `community/src/pipeline/execute_pipeline.rs` — persistence hooks
- `community/src/main.rs` — startup hydration, background sync, StorageBundle

---

## Pillar 2: WASM Plugin System

### Why

The community can't extend the pipeline today. Custom detection rules, custom risk scorers, custom protocol parsers — all require forking the crate. A WASM plugin system lets anyone write a plugin in Rust/Go/C/AssemblyScript, compile to `.wasm`, and drop it into IAGA Sentinel.

### What

A `PluginHost` that loads `.wasm` modules via `wasmtime`, calls them at a defined point in the pipeline, and merges their risk contributions into the final decision.

### Plugin Interface

```rust
// Each WASM plugin exports:
fn name() -> String
fn version() -> String
fn on_inspect(request_json: &str) -> PluginResultJson
// Where PluginResult = { risk_score: u32, findings: Vec<String>, decision_hint: Option<String> }
```

### Integration Points

- New Cargo feature: `plugins = ["wasmtime"]` (opt-in, doesn't bloat default builds)
- Pipeline step between Layer 6 (Policy) and Layer 7 (Firewall): "Plugin Evaluation"
- `GovernanceResult.plugin_results: Option<Vec<PluginOutput>>`
- HTTP endpoints: `GET /v1/plugins`, `POST /v1/plugins/reload`
- CLI: `iaga-sentinel plugins list`, `iaga-sentinel plugins validate <path.wasm>`

### New Files

- `community/src/plugins/mod.rs`
- `community/src/plugins/host.rs` — `PluginHost`: load, instantiate, call
- `community/src/plugins/types.rs` — `PluginResult`, `PluginManifest`, `PluginOutput`
- `community/src/plugins/registry.rs` — loaded plugin tracking, hot-reload
- `community/examples/plugins/` — example Rust plugin → wasm32-wasi

---

## Pillar 3: Policy-as-Code v2

### Why

Current policy is flat — a workspace has a list of tools with allowed action types. No conditionals, no time windows, no hierarchy, no templates. Real deployments need:
- "Allow shell only during business hours"
- "If agent is builder AND risk < 30, auto-allow"
- "Production workspace inherits from base-secure but overrides thresholds"

### What

A richer policy DSL in YAML with conditional rules, time windows, template inheritance, and a gallery of pre-built templates.

### New Policy YAML Structure

```yaml
extends: "base-secure"          # template inheritance
workspace_id: "production"

rules:
  - name: "shell-business-hours"
    match:
      action_type: shell
      agent_role: [operator]
    conditions:
      time_window: { start: "09:00", end: "18:00", timezone: "UTC" }
      max_risk_score: 40
    decision: allow

  - name: "block-all-email"
    match:
      action_type: email
    decision: block
    reason: "Email sending disabled in production"

  - name: "review-http-egress"
    match:
      action_type: http
    conditions:
      payload_contains: ["external-api.com"]
    decision: review

defaults:
  threshold_block: 60
  threshold_review: 30
  requires_human_review: true
```

### Built-in Policy Templates

| Template | Use Case |
|----------|----------|
| `strict-production` | Block by default, whitelist tools, low thresholds |
| `permissive-dev` | Allow most, review risky, high thresholds |
| `compliance-hipaa` | Healthcare: block PII egress, audit everything |
| `compliance-soc2` | Enterprise: review all writes, enforce encryption |
| `ml-pipeline` | ML workflows: allow data ops, block shell |

### New Files

- `community/src/modules/policy/rules_engine.rs` — Rule, ConditionSet, MatchCriteria, evaluation
- `community/src/modules/policy/templates.rs` — built-in templates
- `community/src/modules/policy/time_window.rs` — time-based conditions
- `community/src/modules/policy/hierarchy.rs` — `extends` resolution, cascading merge

### HTTP Endpoints

- `GET /v1/templates` — list available templates
- `GET /v1/templates/{name}` — get template details
- `POST /v1/workspaces/{id}/rules` — add rules to workspace

---

## Pillar 4: Framework Adapters

### Why

Without adapters, users must manually construct `InspectRequest` JSON and call the HTTP API. Framework adapters let LangChain/OpenAI/CrewAI users add governance with **2 lines of code**.

### Python Adapters (`sdks/python/iaga_sentinel/adapters/`)

```python
# LangChain — one-liner governance
from iaga_sentinel.adapters.langchain import SentinelCallbackHandler
chain = my_chain | SentinelCallbackHandler(api_key="ak-...")

# OpenAI — wrap the client
from iaga_sentinel.adapters.openai import sentinel_wrap_openai
client = sentinel_wrap_openai(OpenAI(), api_key="ak-...")

# CrewAI — guardrail
from iaga_sentinel.adapters.crewai import SentinelGuardrail
crew = Crew(agents=[...], guardrails=[SentinelGuardrail(api_key="ak-...")])
```

### TypeScript Adapters (`sdks/typescript/src/adapters/`)

```typescript
// Vercel AI SDK middleware
import { sentinelMiddleware } from 'iaga-sentinel/adapters/vercel-ai';
const result = await generateText({ ...opts, middleware: sentinelMiddleware({ apiKey }) });

// OpenAI wrapper
import { sentinelWrapOpenAI } from 'iaga-sentinel/adapters/openai';
const client = sentinelWrapOpenAI(new OpenAI(), { apiKey });
```

### New Files

- `sdks/python/iaga_sentinel/adapters/__init__.py`
- `sdks/python/iaga_sentinel/adapters/langchain.py`
- `sdks/python/iaga_sentinel/adapters/openai.py`
- `sdks/python/iaga_sentinel/adapters/crewai.py`
- `sdks/python/iaga_sentinel/adapters/autogen.py`
- `sdks/typescript/src/adapters/vercel-ai.ts`
- `sdks/typescript/src/adapters/openai.ts`

---

## Pillar 5: Enhanced CLI

### Why

Operators need real-time visibility and debugging tools beyond the embedded dashboard.

### New Commands

| Command | Description |
|---------|-------------|
| `iaga-sentinel watch` | Live tail of governance decisions via SSE. Colored output: green=allow, yellow=review, red=block. Filters: `--agent`, `--tool`, `--decision` |
| `iaga-sentinel replay <event-id>` | Fetch audit event, reconstruct InspectRequest, re-run through pipeline, show side-by-side diff. Debug "why was this blocked?" |
| `iaga-sentinel benchmark` | Generate N random payloads, fire at `/v1/inspect`, report p50/p95/p99 latency, decisions distribution, throughput |
| `iaga-sentinel policy-test <policy.yaml> <scenario.json>` | Dry-run a policy against scenarios without a running server. Pure local evaluation |

### New Files

- `community/src/cli/mod.rs`
- `community/src/cli/watch.rs`
- `community/src/cli/replay.rs`
- `community/src/cli/benchmark.rs`
- `community/src/cli/policy_test.rs`

---

## Pillar 6: SDK Feature Parity

### Why

Current SDKs cover ~5 of 48 endpoints. Community contributors need full API access from Python/TypeScript.

### Coverage (Python + TypeScript)

| Category | Methods |
|----------|---------|
| **Profiles** | `create_profile()`, `get_profile()`, `update_profile()`, `delete_profile()`, `list_profiles()` |
| **Workspaces** | `create_workspace()`, `get_workspace()`, `update_workspace()`, `delete_workspace()`, `list_workspaces()` |
| **Response** | `scan_response()`, `get_patterns()` |
| **NHI** | `register_identity()`, `attest()`, `create_challenge()`, `verify_attestation()`, `list_identities()` |
| **Risk** | `get_risk_weights()`, `submit_feedback()` |
| **Fingerprint** | `get_fingerprint()`, `list_fingerprints()` |
| **Rate Limit** | `get_config()`, `set_config()`, `get_status()` |
| **Threat Intel** | `list_indicators()`, `add_indicator()` |
| **Telemetry** | `list_spans()`, `get_metrics()`, `export_telemetry()` |
| **Webhooks** | `register_webhook()`, `list_webhooks()`, `get_dlq()` |
| **Auth** | `create_key()`, `list_keys()`, `delete_key()` |
| **Audit** | `export_csv()`, `get_stats()`, `get_analytics()` |
| **Templates** | `list_templates()`, `get_template()` |
| **Plugins** | `list_plugins()`, `reload_plugins()` |

---

## Implementation Order

```
1. Pillar 1: Durable State        ← foundation, everything builds on this
2. Pillar 3: Policy v2            ← enriches the core value proposition
3. Pillar 2: WASM Plugins         ← extensibility play for community
4. Pillar 4: Framework Adapters   ← adoption driver
5. Pillar 5: Enhanced CLI         ← operator experience
6. Pillar 6: SDK Parity           ← done last (covers new endpoints from 1-3)
```

## Testing Strategy

- **Unit tests:** Each new trait impl gets >= 5 tests. Rules engine, time windows, template resolution all get dedicated tests.
- **Property tests:** Extend `property_tests.rs`: durable state round-trips, plugin risk scores in [0,100], policy hierarchy is deterministic.
- **Integration tests:** Full pipeline with durable storage, plugin chain, policy v2 rules.
- **E2E HTTP tests:** New endpoints (plugins, templates, rules) get HTTP-level tests.
- **Plugin tests:** Example WASM plugin compiled and tested in CI.

## Version Bump

- `community/Cargo.toml`: `version = "0.4.0"`
- `enterprise/Cargo.toml`: bump dependency
- Update `README.md` with new features
- Update `docs/ARCHITECTURE.md`
- Tag: `v0.4.0`

---

*Generated: April 2026 | IAGA Sentinel Community Edition*
