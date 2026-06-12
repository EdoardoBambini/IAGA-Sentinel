# Changelog

All notable changes to IAGA Sentinel are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

For architectural rationale, see the ADRs under [docs/adr/](docs/adr/).

This changelog tracks the **open-source build** of IAGA Sentinel,
licensed under BUSL-1.1 with Change License: Apache-2.0 baked in.
IAGA Sentinel Enterprise is a separate commercial product built on the
same governance kernel; see [`ENTERPRISE.md`](ENTERPRISE.md) for the
Enterprise overview.

---

## [1.5.2], 2026-06-12

Technical-debt remediation across the whole open build: hardening of existing
features, test-coverage closure, and CI/workspace hygiene. No new product
surface beyond minimal API-key scopes; signed receipts produced by any prior
release verify unchanged (now enforced by golden-vector tests), and every new
tunable defaults to the previous hardcoded behavior.

### Added

- **Verified-API-key cache**: the auth middleware no longer pays one
  `list_keys()` query plus an Argon2 verification on *every* request — verified
  keys (stored as SHA-256, never raw) are cached per server instance with a TTL
  (`IAGA_SENTINEL_AUTH_CACHE_TTL_MS`, default 60 s; `0` restores
  verify-every-request). Key deletion invalidates the cache immediately.
- **API-key scopes** (minimal, single-tenant): `admin` (default — identical to
  pre-1.5.2 keys; all existing keys stay admin via migration 0005) and `agent`
  (governance surface only). `iaga gen-key --scope agent`, `scope` on
  `POST /v1/auth/keys`, and admin-only enforcement (403 `admin_scope_required`)
  on key/webhook/DLQ management, rate-limit config, threat-intel mutations, and
  plugin reloads. Multi-tenant/SSO/SIEM remain Enterprise (ADR 0010).
- **Network configuration**: `IAGA_SENTINEL_HOST` (bind interface, default
  `0.0.0.0`) and `IAGA_SENTINEL_CORS_ORIGINS` (comma-separated allowlist;
  unset keeps the permissive `Any` of previous releases).
- **Tunables for previously hardcoded constants** (defaults unchanged):
  session-graph cap/TTL/cooldown/strikes, background-cleanup cadence/age, and
  response-cache TTL/size (see README → Environment variables).
- **`POST /v1/risk/weights/reset`** (admin): drop feedback-learned adaptive-risk
  weight adjustments; the process-global weight behavior is now documented.
- **Strict env-denylist mode**: `IAGA_SENTINEL_ENV_DENYLIST_STRICT=1` makes
  `iaga run` fail closed (launch blocked) when the denylist TOML extension is
  unreadable or malformed, instead of silently degrading to the built-in list.
- **Pricing freshness**: the built-in price list now carries
  `BUILTIN_PRICING_EFFECTIVE_DATE` (also surfaced as `builtinEffectiveDate` on
  `/v1/cost/pricing`) and the server warns when it is older than 90 days.
- **ML failure visibility**: per-model inference failures are logged and
  recorded in a new additive `MlEvidence.failed_models` (elided when empty —
  serialized shape and receipts unchanged in the no-failure case).
- **Signer key permission posture**: on Unix a freshly created receipt signing
  key is re-checked post-write and creation fails if group/world accessible;
  loading a pre-existing loose key warns (`chmod 600` hint). Windows warns to
  restrict NTFS ACLs.
- **Test-coverage closure**: golden-vector tests freezing `signing_bytes()` for
  every receipt shape since 1.1; a live-Postgres receipts suite mirroring the
  SQLite one; APL tree-walk ↔ WASM differential tests (fixed corpus + 256
  property-based cases) plus clean-rejection checks for unsupported constructs;
  a mock-HTTP client suite for `iaga-sentinel-integrations` (verdict mapping +
  wire shape, no live sidecar needed); `iaga-verify` CLI smoke tests pinning
  the documented exit codes 0/1/2/3.
- **CI**: postgres:16 service container with real `--features postgres` test
  runs (receipts + core), a `cargo test --workspace --all-features` job, a
  `linux-bpf` scaffold compile check, and the cross-platform compile-sanity job
  promoted to a blocking status.
- **SDK e2e smoke in CI**: the test job now boots a real sidecar and runs the
  Python SDK adapter suite (previously auto-skipped without a server) plus the
  TypeScript `smoke.cjs` checks against it; a new
  `sdks/typescript/register-smoke-agents.cjs` helper provisions the fresh
  agent pool the smoke needs. The framework-heavy `tests/e2e` suites stay
  local-only.
- **Workspace hygiene**: declared MSRV (`rust-version = "1.88"`),
  `[workspace.lints]` shared by every crate (`unsafe_code = "deny"` among
  others), centralized `wasmtime` version and tokio dev-dependencies.

### Changed

- Raw IO failures now map to a dedicated `SentinelError::Io` and an `io_error`
  HTTP error body; previously they surfaced as `config_error`.
- The `linux-bpf` scaffold's block reason is now machine-readable
  (`bpf-loader-not-implemented: …`) so audit consumers can distinguish
  "loader not implemented" from a policy-driven block. Posture unchanged:
  `is_authoritative()` stays `false`; authoritative kernel enforcement is
  Enterprise (ADR 0010).
- `cargo audit` ignores consolidated into a single `.cargo/audit.toml` at the
  repo root (previously duplicated as CI flags).
- `ApiKeyRecord` gains a `scope` field (serde-defaulted to `admin` for old
  records); the `ApiKeyStore` trait gains `store_key_scoped` /
  `verify_raw_key_scoped` with backward-compatible default implementations.

### Fixed

- Corrupt JSON in storage rows (audit reasons/usage, workspace policies, rules,
  tenant metadata, NHI capabilities, sessions, taint labels, fingerprints) is
  no longer silently replaced by defaults: the same fallback now logs a warning
  naming the column, on both SQLite and Postgres backends.
- The background TTL-cleanup task now derives the durable taint-store prune age
  from the configured TTL instead of a hardcoded 3600 s.
- `docs/openapi.yaml` was three releases stale (frozen at 1.3.0): now at
  1.5.2 with every served route documented (receipts, cost API, audit
  export/stats, analytics, webhook DLQ, NHI challenge/verify, templates,
  workspace rules, plugins, policy overlay / reasoning / kernel status,
  risk-weights reset), admin-scope operations marked with their 403, and the
  `RiskWeights` / `HealthResponse` / error-code schemas corrected to match the
  actual wire shapes.
- The Python SDK `__version__` was stale at 1.4.0 while `pyproject.toml` said
  1.5.x; both now track the release version.

## [1.5.1], 2026-06-10

Patch release: a test-determinism fix only — no change to the open build's
runtime behavior, the public wire contract, or the receipt/cost schema.

### Fixed

- Deterministic adaptive-risk weight tests. The adaptive-risk weights are a
  process-global that `apply_feedback` mutates and `calculate_adaptive_risk`
  reads; in the test binary a parallel feedback test could lower the weight
  feeding a borderline assertion (`test_risk_high_risk_shell_rm_rf`) and fail CI
  nondeterministically. The risk-weight tests now serialize and reset to default
  weights via a new `reset_weights()` helper. Production behavior unchanged.

## [1.5.0], 2026-06-09

Cost control: meter, attribute, and cap LLM spend from the open build, fully
self-hosted (no external billing API), plus a deterministic response cache that
reduces spend on safe, repeated read-only tool calls. All additive and behind a
default-off `cost-control` feature — the default build is byte-identical to 1.4.0
and pre-1.5 signed receipts verify unchanged.

### Added

- **`iaga-sentinel-cost` crate**: canonical cost/usage types + a self-hosted
  pricing engine. `UsageReport` (wire, human USD) resolves to `UsageData` (the
  signed form; money is an integer micro-USD ledger). Local `PricingTable` (dated
  built-in, overridable via `IAGA_SENTINEL_PRICING_FILE`); a caller-supplied cost
  always wins (ADR 0020).
- **Cost on receipts + audit**: optional `usage` on the signed `ReceiptBody`
  (elided when absent, so pre-1.5 receipts stay byte-identical) and on audit
  events, with denormalized columns for fast aggregation (migration 0004).
- **Capture** of usage from `POST /v1/inspect` and the agent SDKs — a new optional
  `usage` field on the public wire contract, plus `with_usage` on the Rust client.
- **Observability**: `/v1/cost/{summary,by-agent,by-model,by-tool,over-time,budget,pricing}`,
  a "Cost Control" dashboard panel, and an `iaga cost` CLI.
- **Budget enforcement**: per-session cumulative spend (`IAGA_SENTINEL_SESSION_BUDGET_USD`)
  injected into the APL context as `usage.session_cost_usd` / `budget.limit`, so a
  policy can `when usage.session_cost_usd > budget.limit then block`; a non-APL
  fallback enforces the same cap. Stricter-wins: cost can only tighten a verdict
  (ADR 0020).
- **Deterministic response cache**: the MCP proxy serves an identical, safe,
  read-only tool call from cache instead of forwarding it; savings surface in the
  cost summary. Semantic caching is an Enterprise feature (ADR 0021).

### Notes

- The default build is unchanged; enable cost control with `--features cost-control`.
- Cost is reported by instrumented callers and priced locally — indicative, not an
  invoice. Session budgets are in-memory; durable spend, time-windowed budgets, and
  network/eBPF cost interception are Enterprise / follow-up work (ADR 0010).

## [1.4.0], 2026-06-09

Agent & framework integrations: put IAGA Sentinel in the loop of any agent stack,
one signed receipt per tool call. Cooperative governance (`allow` / `review` /
`block`, fail-open-by-default transport); every receipt still records
`is_authoritative: false`. All additive — no change to the receipt schema or the
existing public wire contract.

### Added

- **Python adapters** (`sdks/python/iaga_sentinel/adapters/`): `@governed` (custom),
  LangChain (`SentinelCallbackHandler`), LangGraph (`GovernedToolNode`), LlamaIndex
  (`IagaCallbackHandler`), Pydantic AI (`governed_tool`), OpenAI Agents SDK
  (`iaga_tool_guardrail` + `governed_tool`), CrewAI (`SentinelGuardrail`), AutoGen
  (`AutoGenSentinelHook`), Microsoft Agent Framework (`sentinel_middleware`), OpenAI
  (`sentinel_wrap_openai`), and MCP (`govern_tool`). Shared transport helper
  `_common.py`, fail-open by default (configurable via `fail_closed`).
- **TypeScript adapters** (`sdks/typescript/src/adapters/`): OpenAI
  (`sentinelWrapOpenAI`), Vercel AI SDK (`sentinelMiddleware`), LangGraph
  (`governedToolNode`), and MCP (`governMcpTool`); `failClosed` opt-in.
- **Claude Code** `PreToolUse` hook example (zero-dependency Python + Bash variants)
  and **Claude Agent SDK** examples (`canUseTool` for TS, `PreToolUse` hook for
  Python).
- **MCP `GovernedTool`** wrapper (Python + TS) for MCP servers you author;
  complements the existing `iaga proxy` transparent interception.
- **`iaga-sentinel-integrations` Rust crate**: a lightweight standalone async client
  (`SentinelClient` over `reqwest`) mirroring the public camelCase wire contract,
  decoupled from the pipeline internals (ADR 0019).
- **Examples** for all 15 framework integrations under `examples/integrations/`
  (runnable code + `*.policy.yaml` + README + an index and support matrix).
- **Tests**: dependency-free fakes drive every adapter against the live sidecar in
  CI (`sdks/python/tests/`, `sdks/typescript/smoke.cjs`), plus **real end-to-end
  tests** against the actual framework libraries (`sdks/python/tests/e2e/`,
  `importorskip`-guarded so CI stays green without them).

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in.

---

## [1.3.1], 2026-06-08

The 1.3 conformity-closure patch: reconciles the shipped open build with the
1.3 roadmap's "verifier sovereignty" OSS track (ADR 0018). All changes are
additive, no breaking changes against 1.3.0. Receipts produced before 1.3.1
verify unchanged, the new optional field is elided when absent.

### Added

- ADR 0018: receipt honesty flag. `ReceiptBody` gains an optional
  `is_authoritative` field, populated `false` on every open-build receipt
  because OSS enforcement is soft (no authoritative kernel ships in the
  community edition; `UserspaceKernel::is_authoritative()` is `false`).
  Elided from `signing_bytes` when absent, so 1.3.0 receipts stay
  byte-identical and verify unchanged.
- OpenTelemetry receipt span now also carries the roadmap-named keys
  `iaga.receipt.id` (`run_id:seq`), `iaga.chain.head` (the receipt body
  hash) and `iaga.policy.verdict`, plus `iaga.is_authoritative`, alongside
  the existing `receipt.*` aliases. Full `gen_ai.*` GenAI semantic-convention
  alignment remains a 1.4 deliverable.
- Sensitive-environment scrub on `UserspaceKernel`: a denylist of 23 known
  secret-bearing variables (cloud and model-provider credentials, registry
  tokens, the receipt signing-key path) is stripped from every governed
  child environment, even when passed explicitly via `ProcessSpec.env`, and
  is extendable at runtime via a TOML file at `IAGA_SENTINEL_ENV_DENYLIST`.
- `verify-only` cargo feature on `iaga-sentinel-verify` (default-on), so the
  documented reproducible build
  `cargo build --release --no-default-features --features verify-only` is
  valid and stable across releases.
- CI now exercises the `otel-receipts` and `plugin-manifest-signing`
  features, 1.3 primitives that previously had no CI coverage.

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in.

---

## [1.3.0], 2026-06-07

The conformity-evidence release: three additive, opt-in primitives that strengthen the trusted-evidence substrate, plus a repositioning of the public narrative around the EU AI Act conformity evidence layer. All changes are additive, no breaking changes against 1.2.0. Default behaviour and receipt bytes are unchanged with the new features off.

### Added

- ADR 0015: standalone receipt verifier. A new slim crate `iaga-sentinel-verify` (binary `iaga-verify`, no database, no async runtime, about 3 MB) verifies a signed receipt chain offline by reusing `verify_chain`. New CLI flag `iaga replay <run_id> --export <file.json>` writes a run as `{ run_id, signer_verifying_key, receipts }` for the verifier to consume. The expected public key is pinned with `--key`; the embedded key is a self-asserted fallback with a loud warning.
- ADR 0016: OpenTelemetry receipt export, behind the default-off `otel-receipts` feature, no new dependency. Each signed receipt also surfaces as an OTel span `iaga_sentinel.receipt` (run id, seq, verdict, input and policy hashes, risk score, signer key id) in the existing telemetry feed, visible via `GET /v1/telemetry/spans` and `/v1/telemetry/export`.
- ADR 0017: Ed25519-signed plugin manifests, behind the default-off `plugin-manifest-signing` feature, orthogonal to `plugin-attestation`. A plugin ships `<plugin>.manifest.json` plus a detached `.sig`; verification checks the plugin SHA-256 and the signature against a trusted-key list. New CLI `iaga plugins sign-manifest` and `iaga plugins verify-manifest --trusted-keys`.
- Data-handling and security documentation: `DATA_HANDLING.md` covering what a receipt contains, the default hashes-only PII posture, where data lives, the absence of call-home, and offline verification; plus a signing section in `SECURITY.md`. Both are linked from the README.

### Changed

- Public narrative repositioned from "zero-trust governance kernel" to the EU AI Act conformity evidence layer for AI agents. README, ENTERPRISE.md, the operator dashboard, contacts, and the project docs are reconciled to that frame and to the honest posture: soft enforcement today, authoritative eBPF/LSM on the Enterprise roadmap. The operator dashboard at `/` is restyled to a minimal theme.

### Removed

- The unwired `ui/` React visualization (the deferred Visual Plane scaffold), the `ui-embed` Cargo feature, and the optional `rust-embed` dependency are removed. The operator dashboard served at `/` is unaffected; it was never part of the `ui-embed` path. This drops the dead TypeScript and React surface and keeps the repository Rust-first.

---

## [1.2.0], 2026-05-28

The **primitive evolution release**: ships the 4 primitives that
ADR 0010 §3 reinstated to the OSS 1.2 roadmap. All changes are
**additive**; no breaking changes against 1.1.0. The
`IAGA Sentinel Enterprise` boundary (ADR 0010 §2, 20 categories)
is reaffirmed, see [`ENTERPRISE.md`](ENTERPRISE.md).

### Added

- [`docs/adr/0011-signer-trait-and-local-disk.md`](docs/adr/0011-signer-trait-and-local-disk.md) -
  `Signer` trait (async, object-safe) + `LocalDiskSigner` reference impl.
  `ReceiptSigner` becomes a type alias so every 1.0 / 1.1 callsite -
  production and test, compiles unchanged. `SignedReceiptLogger` now
  holds `Arc<dyn Signer>`, giving Enterprise builds a clean injection
  point for KMS-backed signers without ricompiling the OSS core.
- [`docs/adr/0012-drift-replay-additive.md`](docs/adr/0012-drift-replay-additive.md) -
  three new optional fields on `ReceiptBody` (`pipeline_inputs_capture`,
  `apl_eval_trace`, `ml_inference_inputs`), opt-in via host env
  `IAGA_SENTINEL_RECEIPT_CAPTURE=1`. New CLI flag
  `iaga replay --re-execute` surfaces per-receipt capture availability.
  Receipts produced with capture disabled are **byte-identical** to
  1.1, chain hashes and signatures stay stable.
- [`docs/adr/0013-plugin-attestation.md`](docs/adr/0013-plugin-attestation.md) -
  new Cargo feature `plugin-attestation` (default off) gates offline
  Sigstore bundle + CycloneDX 1.5 SBOM verification. Looks for sibling
  `<plugin>.sigstore.json` and `<plugin>.cdx.json` next to each WASM
  plugin; validates bundle well-formedness and confirms the payload
  digest matches the plugin bytes. New CLI subcmd
  `iaga plugin verify <path>`.
- [`docs/adr/0014-apl-wasm-and-types.md`](docs/adr/0014-apl-wasm-and-types.md) -
  Hindley-Milner type checker (Algorithm W) over the existing APL AST,
  always-available via `compile_with_types(src)` and the CLI
  `iaga policy check <file.apl>`. New Cargo feature `apl-wasm`
  (default off) adds a WASM codegen scaffolding for literal +
  boolean / numeric / comparison operations; `iaga policy compile`
  emits the module. The tree-walk evaluator remains canonical for the
  full APL surface, Path / Call / Membership are rejected by the WASM
  MVP with clear errors.
- New CLI subcmds (additive): `iaga replay --re-execute`,
  `iaga plugin verify <path>`, `iaga policy check <file.apl>`,
  `iaga policy compile <file.apl> [--output bundle.wasm]`.

### Changed

- Workspace version bumped to `1.2.0`. License **unchanged**
  (BUSL-1.1 + Change License Apache-2.0 baked-in).
- `ReceiptBody` gains three optional capture fields, elided from
  serialization when `None` (1.1 byte-equality preserved).
- `PluginManifest` gains three cfg-gated optional fields under
  `plugin-attestation` (`attestation`, `sbom`,
  `attestation_offline_verified`). All `None`/`false` by default.
- `PluginDigest` (in the receipt body) gains optional `attested`
  and `attestation_issuer`. Elided when `None`.
- `SignedReceiptLogger` now accepts `Arc<dyn Signer>` rather than
  the concrete struct. `ReceiptSigner` preserved as a type alias -
  zero breaking change for existing callers.

### Deferred (still OSS-eligible, no schedule)

- `iaga policy migrate` (YAML → APL converter), debt closure for
  ADR 0008, not a primitive evolution. Lands in 1.2.x or 1.3.
- Address the 3 RUSTSEC ignores in CI (`RUSTSEC-2023-0071`,
  `-2025-0057`, `-2024-0436`) via dependency hardening pass.
- APL WASM codegen full support for Path / Call / Membership +
  parity proptest tree-walk vs WASM. The 1.2 MVP ships scaffolding
  (literal + ops only); full coverage is 1.3.
- Postgres + macOS / Windows full CI matrix (1.2 adds compile
  sanity best-effort; promotion to required CI status is 1.3).

### Still Enterprise (boundary reaffirmed, see [`ENTERPRISE.md`](ENTERPRISE.md))

The OSS 1.2 primitive scope is intentionally narrow. The full
chain-of-trust / production-grade implementations remain in
IAGA Sentinel Enterprise per ADR 0010 §2 (20 categories), including:

- Native KMS SDK backends (AWS KMS / Azure Key Vault / HashiCorp
  Vault / PKCS#11 HSM) plug behind the new `Signer` trait but ship
  Enterprise-only.
- Forensic time-travel replay (event sourcing + DB-state-per-verdict
  temporal queries) vs OSS's input-capture-only drift replay.
- Hosted plugin marketplace + supply-chain SLA + signed threat-intel
  feed integration vs OSS's offline-only Sigstore / SBOM primitive.
- APL AOT optimized codegen (cranelift opt-levels, WASI side-effects)
  + curated rule library + LSP / language server.
- All other ADR 0010 §2 categories: eIDAS qualified signature, managed
  key lifecycle, mesh tier-2, multi-tenant, Enterprise SSO, SIEM
  connectors, air-gap distro, EU AI Act + GDPR + DORA compliance pack,
  DPO dashboard, curated ML library, curated eBPF/LSM library,
  confidential-computing receipts, commercial support,
  conformity assessment notified-body, real eBPF/LSM loader,
  cross-platform kernel macOS/Windows, mesh single-cluster baseline,
  curated ONNX models + HF tokenizers.

---

## [1.1.0], 2026-05-23

A consolidation + rebrand release. 1.1.0 keeps 1.0.0's runtime
behaviour and API contract, but **renames the project Agent Armor →
IAGA Sentinel** across binary, crates, env vars, paths, and
identifiers (breaking for CLI / ops / crate consumers), and pins **how the OSS line is
positioned** relative to the IAGA Sentinel Enterprise commercial
product.

The 1.0 GA shipped the full governance kernel concept: enforcement
kernel scaffold + `UserspaceKernel` cross-platform, signed Merkle
receipts, APL DSL with live overlay, probabilistic reasoning
framework, audit pipeline. That is the OSS contract preserved by
the **never retroactively remove** covenant in `ENTERPRISE.md`.

1.1 holds that line, no new runtime capabilities, and clarifies
the OSS↔Enterprise boundary in the public docs so that users and
would-be contributors know what to expect from the open-source
line going forward.

**Boundary clarification (canonical: [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md)).**
Capabilities originally listed under "Deferred to 1.0.x" or
"Deferred to 1.1" in the 1.0.0 entry below have been re-scoped:

- **Reinstated to OSS 1.2 roadmap** (no fixed date; ships when
  ready, no breaking changes): APL WASM codegen + Hindley-Milner
  type checker (was 1.0.3), Sigstore + SBOM CycloneDX plugin
  attestation primitive (was 1.1), drift replay additivo + `iaga
  replay --re-execute` (was 1.1), `Signer` trait +
  `LocalDiskSigner` refactor (was implicit). These are primitive
  evolutions with no scale/UX value beyond what OSS already
  provides; keeping them OSS reinforces the open-core covenant
  without diminishing Enterprise.
- **Migrated to IAGA Sentinel Enterprise** (separate commercial
  product): real Aya-rs eBPF/LSM loader on Linux
  (was 1.0.1), macOS Endpoint Security backend + Windows ETW/WFP
  backend (was 1.1), governance mesh single-cluster baseline + the
  pre-existing tier-2 multi-region active-active (was 1.1),
  curated ONNX reference models (intent-drift / prompt-injection
  / anomaly-seq) + HuggingFace tokenizer integration + calibration
  framework (was 1.0.2 + 1.1), four native KMS SDK signer backends
  AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 (was 1.1).
  These require specialist engineering at scale and ship with
  contractual support, managed lifecycle, and threat-intel feed.
  None shipped in 1.0 GA, the **never retroactively remove**
  covenant is preserved.

The Enterprise edition is where the EU AI Act + GDPR + DORA
compliance pack, DPO Dashboard, multi-tenant isolation, Enterprise
SSO, eIDAS qualified signature pipeline, native SIEM connectors,
air-gapped distribution, commercial support, confidential-computing
receipts, forensic time-travel replay, conformity assessment
notified-body workflow, and the curated AI-specific eBPF/LSM
program library also live. See [`ENTERPRISE.md`](ENTERPRISE.md) for
the concise Enterprise overview.

### Changed

- Workspace version bumped to `1.1.0`.
- [`CHANGELOG.md`](CHANGELOG.md), [`ENTERPRISE.md`](ENTERPRISE.md), and
  [`README.md`](README.md)
  updated to reflect the OSS↔Enterprise boundary clarification.
- ADR 0010 committed as the canonical public boundary note.

### Renamed (breaking)

- Complete rebrand **Agent Armor → IAGA Sentinel**: primary binary
  `agent-armor` → `iaga-sentinel` (short alias `armor` → `iaga`);
  crates `armor-*` → `iaga-sentinel-*`; library imports `agent_armor`
  / `armor_*` → `iaga_sentinel` / `iaga_sentinel_*`; env vars
  `AGENT_ARMOR_*` and `ARMOR_*` → `IAGA_SENTINEL_*` (clean break, no
  fallback); signer key dir `~/.armor/` → `~/.iaga-sentinel/`; default
  DB `agent_armor.db` → `iaga_sentinel.db`; API-key prefix `aa_` →
  `iaga_` (newly generated keys only, existing keys still validate);
  webhook headers `X-Armor-*` → `X-Iaga-Sentinel-*`; MCP tools
  `agentarmor.*` → `iaga.*`; public types `Armor*` → `Sentinel*`. The GitHub repository is now
  `EdoardoBambini/IAGA-Sentinel`.

### Added

- [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md):
  canonical ADR documenting the 20-category Enterprise boundary +
  the 4 primitives reinstated to OSS 1.2 roadmap.

### Unchanged

- Runtime behaviour, verdict logic, receipt format (Ed25519 +
  Merkle), on-disk schema, APL/policy formats, feature flags, and
  the HTTP API contract (endpoints, camelCase JSON, Bearer auth) are
  identical to 1.0.0; existing API keys still validate. **Only
  identifiers were renamed (see Renamed above), behaviour did not
  change.**
- The covenant in `ENTERPRISE.md`: *Enterprise will never
  retroactively remove features from OSS. If something works in
  OSS today, it works in OSS forever.*

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in. Each
release converts automatically and irrevocably to Apache-2.0 four
years after publication.

---

## [1.0.0], 2026-04-26 ("Fortezza")

Architectural leap from 0.4.0. The 0.4.0 sidecar HTTP gate becomes a
distributed, attested, replayable, probabilistically aware kernel for
autonomous AI agents. Every governance decision is now signed,
chained, and verifiable offline. Policy moves from YAML templates to
a typed deterministic DSL. ML is opt-in and produces evidence the
deterministic policy decides on.

### Fixed (GA pre-flight, after E2E smoke)

- **Dockerfile** rewritten for the workspace layout. Previous version
  pointed at the pre-M1 `community/` paths and shipped a stub binary
  that exited immediately. New Dockerfile builds the real binary
  single-shot and `docker compose up` is healthy on first attempt.
- CLI banner: "8 Layers ARMED" → "12 Layers ARMED" (consistent with
  the 1.0 marketing surface; M3.5 + M4 add 4 layers on top of the
  original 8).
- `iaga-sentinel-core` crate description: "(Community Edition)" →
  "(open-source edition)" for consistency with the new
  Community vs Enterprise docs.

### Added

- **Workspace split** into 5 crates under `crates/`: `iaga-sentinel-core`,
  `iaga-sentinel-receipts`, `iaga-sentinel-apl`, `iaga-sentinel-reasoning`, `iaga-sentinel-kernel`.
  Single workspace `Cargo.toml` at the root.
- **M2, Signed Action Receipts.** Ed25519-signed records of every
  governance verdict, hash-chained per `run_id` (Merkle append-log).
  SQLite and Postgres backends. New CLI: `iaga replay --list`,
  `iaga replay <run_id>`, `iaga replay <run_id> --verify-only`.
  Signer key auto-generated at `~/.iaga-sentinel/keys/receipt_signer.ed25519`
  on first run, override via `IAGA_SENTINEL_SIGNER_KEY_PATH`.
- **M3, Agent Policy Language (APL).** Typed DSL with deterministic
  tree-walk evaluator, instruction budget, short-circuit boolean
  evaluation, hash-linked replay safety. New crate `iaga-sentinel-apl`. CLI:
  `iaga policy test <file.apl>` and `iaga policy lint <file.apl>`.
  WASM codegen for APL is tracked for 1.0.3.
- **M3.5, Probabilistic Reasoning Plane.** New crate `iaga-sentinel-reasoning`
  with always-available `NoopEngine` plus `TractEngine` (pure-Rust
  ONNX via `tract-onnx`) behind opt-in `ml` feature. Model SHA-256
  digests embedded in every receipt. CLI: `iaga reasoning info`.
  Pre-trained models ship in 1.0.2. *(See [1.1.0] entry for
  re-scoping: curated ONNX library lives in IAGA Sentinel Enterprise.)*
- **M4, Enforcement Kernel scaffold.** New crate `iaga-sentinel-kernel` with
  cross-platform `UserspaceKernel` (soft enforcement, every OS) and
  Linux `BpfKernel` scaffold under `linux-bpf` feature. New CLI:
  `iaga run [--agent-id ...] [--cwd ...] -- <cmd>` and
  `iaga kernel status`. The real eBPF/LSM loader lands in 1.0.1.
  *(See [1.1.0] entry: real Aya-rs loader re-scoped to IAGA Sentinel
  Enterprise; the OSS scaffold + honest posture continue in 1.x.)*
- **M5, `iaga run` traverses the full governance pipeline.** Every
  governed launch produces a signed receipt. Postgres receipt backend
  is wired automatically based on the `DATABASE_URL` scheme.
  Cargo feature composition: `iaga-sentinel-core/sqlite|postgres` transitively
  enables the matching `iaga-sentinel-receipts` feature.
- **M6, APL as live policy engine.** `iaga serve --policy <file.apl>`
  loads an overlay merged stricter-wins with the YAML profile system.
  Receipts embed the SHA-256 of the active APL bundle in
  `policy_hash`. New CLI `iaga policy lint`.
- **UI embedded** in the binary via `rust-embed` behind `ui-embed`
  feature.
- **8 ADRs** documenting every architectural decision (`docs/adr/0001`
  through `0008`).
- **`iaga` short alias binary** alongside `iaga-sentinel`. Same entry
  point.

### Changed

- **Crate renamed**: package `iaga-sentinel` → `iaga-sentinel-core`. Binary
  name `iaga-sentinel` preserved for backward compatibility.
- **License**: stays on BUSL-1.1 with **Change License: Apache-2.0**
  baked into the licence. Each release converts automatically and
  irrevocably to Apache-2.0 four years after publication. See
  [ADR 0002](docs/adr/0002-open-source-license-and-scope.md) for the
  rationale and [`LICENSE`](LICENSE) for the legal text.
- **Defense-in-depth model**: 8 layers → 12 layers. The original 8 are
  hardened in M2-M5; M3.5 + M4 add supply chain attestation /
  blast radius enforcement / behavioral baseline / counterparty trust
  scaffolding.
- **All paths** `community/` → `crates/iaga-sentinel-core/`.
- **Cargo `default` features** for `iaga-sentinel-core`:
  `["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]`.

### Re-scoped after 1.0 GA (boundary clarification, see 1.1.0 entry above)

> The lists below preserved verbatim from the 1.0 GA changelog for
> historical fidelity. The **2026-05-08 OSS↔Enterprise boundary
> clarification** re-scopes these capabilities, see the [1.1.0]
> entry above and [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).
> None of the items below shipped in 1.0 GA, so the **never
> retroactively remove** covenant is preserved.

#### Originally deferred to 1.0.x patch releases

- ~~**1.0.1**~~: real eBPF/LSM loader via `aya-rs` + LLVM 18. LSM
  hooks on `execve`, `openat`, `connect`, `sendto`. Landlock
  fallback. Cgroup jailing. Long-lived detached child handle
  ownership. **Re-scoped → IAGA Sentinel Enterprise.**
- ~~**1.0.2**~~: pre-trained ONNX models for intent-drift /
  prompt-injection / anomaly-seq, plus pluggable tokenizers shipped
  alongside model files. **Re-scoped → Enterprise** (curated ML
  model library with threat-intel feed + GPU acceleration).
- ~~**1.0.3**~~: WASM codegen for APL via `wasm-encoder`; full
  Hindley-Milner type checker. **Reinstated → OSS 1.2 roadmap.**

#### Originally deferred to 1.1

- Governance mesh (gRPC gossip, federated rate budgets, CRDT on
  receipt log). **Re-scoped → Enterprise** (single-cluster
  baseline + tier-2 multi-region active-active).
- macOS Endpoint Security + Windows ETW kernel backends.
  **Re-scoped → Enterprise** (signed/notarized turnkey).
- KMS / HSM signer backends for receipts. **OSS keeps the BYOK
  pattern** (filesystem-mount via `IAGA_SENTINEL_SIGNER_KEY_PATH`) and the
  `Signer` trait + `LocalDiskSigner` refactor (reinstated → OSS
  1.2 roadmap). **Re-scoped → Enterprise**: four native KMS SDK
  backends (AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11
  HSM) + managed key lifecycle + eIDAS qualified signatures.
- GPU acceleration ML + native ONNX Runtime backend (`ort`).
  **Re-scoped → Enterprise** (curated ML model library).
- Drift replay with full pipeline re-execution against historical
  receipts (requires receipt schema change). **Reinstated → OSS
  1.2 roadmap** as additive (`iaga replay --re-execute`,
  schema-additive); the forensic *time-travel* variant (event
  sourcing + temporal queries DB-state-per-verdict) lives in
  Enterprise.
- Stateful cross-run anomaly detection. **Re-scoped → Enterprise**
  (curated ML model library `anomaly-seq`).
- HuggingFace tokenizers in `iaga-sentinel-reasoning`. **Re-scoped →
  Enterprise** (curated ML model library, paired with the curated
  ONNX models).
- `iaga policy migrate` (YAML → APL converter). **OSS-eligible**
  (small utility, debt closure for ADR 0008); not yet scheduled.

### Newly added to OSS 1.2 roadmap (reinstated primitives)

- Sigstore + SBOM CycloneDX plugin attestation primitive (closes
  Pillar 4). The hosted private marketplace + supply-chain SLA
  contractual layer remains Enterprise.

---

## [0.4.0], 2026-04-19 ("Azzurra")

The community runtime that proved the thesis. 8-layer defense in depth
behind a single `/v1/inspect` HTTP gate. Policy as YAML + templates.
SDKs in Python and TypeScript. SQLite + Postgres durable state.

See git history for the full 0.4.0 changelog.
