# Changelog

All notable changes to IAGA Sentinel are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

For path renames and migration steps, see [MIGRATION.md](MIGRATION.md).
For architectural rationale, see the ADRs under [docs/adr/](docs/adr/).

This changelog tracks the **open-source build** of IAGA Sentinel,
licensed under BUSL-1.1 with Change License: Apache-2.0 baked in.
IAGA Sentinel Enterprise is a separate commercial product built on the
same governance kernel; see [`ENTERPRISE.md`](ENTERPRISE.md) for the
Enterprise pitch and the EU AI Act + GDPR + DORA compliance pack mapping.

---

## [1.2.0] — Unreleased

The **primitive evolution release**: ships the 4 primitives that
ADR 0010 §3 reinstated to the OSS 1.2 roadmap. All changes are
**additive**; no breaking changes against 1.1.0. The
`IAGA Sentinel Enterprise` boundary (ADR 0010 §2, 20 categories)
is reaffirmed — see [`ENTERPRISE.md`](ENTERPRISE.md).

### Added

- [`docs/adr/0011-signer-trait-and-local-disk.md`](docs/adr/0011-signer-trait-and-local-disk.md) —
  `Signer` trait (async, object-safe) + `LocalDiskSigner` reference impl.
  `ReceiptSigner` becomes a type alias so every 1.0 / 1.1 callsite —
  production and test — compiles unchanged. `SignedReceiptLogger` now
  holds `Arc<dyn Signer>`, giving Enterprise builds a clean injection
  point for KMS-backed signers without ricompiling the OSS core.
- [`docs/adr/0012-drift-replay-additive.md`](docs/adr/0012-drift-replay-additive.md) —
  three new optional fields on `ReceiptBody` (`pipeline_inputs_capture`,
  `apl_eval_trace`, `ml_inference_inputs`), opt-in via host env
  `IAGA_SENTINEL_RECEIPT_CAPTURE=1`. New CLI flag
  `iaga replay --re-execute` surfaces per-receipt capture availability.
  Receipts produced with capture disabled are **byte-identical** to
  1.1 — chain hashes and signatures stay stable.
- [`docs/adr/0013-plugin-attestation.md`](docs/adr/0013-plugin-attestation.md) —
  new Cargo feature `plugin-attestation` (default off) gates offline
  Sigstore bundle + CycloneDX 1.5 SBOM verification. Looks for sibling
  `<plugin>.sigstore.json` and `<plugin>.cdx.json` next to each WASM
  plugin; validates bundle well-formedness and confirms the payload
  digest matches the plugin bytes. New CLI subcmd
  `iaga plugin verify <path>`.
- [`docs/adr/0014-apl-wasm-and-types.md`](docs/adr/0014-apl-wasm-and-types.md) —
  Hindley-Milner type checker (Algorithm W) over the existing APL AST,
  always-available via `compile_with_types(src)` and the CLI
  `iaga policy check <file.apl>`. New Cargo feature `apl-wasm`
  (default off) adds a WASM codegen scaffolding for literal +
  boolean / numeric / comparison operations; `iaga policy compile`
  emits the module. The tree-walk evaluator remains canonical for the
  full APL surface — Path / Call / Membership are rejected by the WASM
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
  the concrete struct. `ReceiptSigner` preserved as a type alias —
  zero breaking change for existing callers.

### Deferred (still OSS-eligible, no schedule)

- `iaga policy migrate` (YAML → APL converter) — debt closure for
  ADR 0008, not a primitive evolution. Lands in 1.2.x or 1.3.
- Address the 3 RUSTSEC ignores in CI (`RUSTSEC-2023-0071`,
  `-2025-0057`, `-2024-0436`) via dependency hardening pass.
- APL WASM codegen full support for Path / Call / Membership +
  parity proptest tree-walk vs WASM. The 1.2 MVP ships scaffolding
  (literal + ops only); full coverage is 1.3.
- Postgres + macOS / Windows full CI matrix (1.2 adds compile
  sanity best-effort; promotion to required CI status is 1.3).

### Still Enterprise (boundary reaffirmed — see [`ENTERPRISE.md`](ENTERPRISE.md))

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
  confidential-computing receipts, founder-led contractual support,
  conformity assessment notified-body, real eBPF/LSM loader,
  cross-platform kernel macOS/Windows, mesh single-cluster baseline,
  curated ONNX models + HF tokenizers.

---

## [1.1.0] — 2026-05-23

A consolidation + rebrand release. 1.1.0 keeps 1.0.0's runtime
behaviour and API contract, but **renames the project Agent Armor →
IAGA Sentinel** across binary, crates, env vars, paths, and
identifiers (breaking for CLI / ops / crate consumers — see
[`MIGRATION.md`](MIGRATION.md)), and pins **how the OSS line is
positioned** relative to the IAGA Sentinel Enterprise commercial
product.

The 1.0 GA shipped the full governance kernel concept: enforcement
kernel scaffold + `UserspaceKernel` cross-platform, signed Merkle
receipts, APL DSL with live overlay, probabilistic reasoning
framework, audit pipeline. That is the OSS contract preserved by
the **never retroactively remove** covenant in `ENTERPRISE.md`.

1.1 holds that line — no new runtime capabilities — and clarifies
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
  product, private repo): real Aya-rs eBPF/LSM loader on Linux
  (was 1.0.1), macOS Endpoint Security backend + Windows ETW/WFP
  backend (was 1.1), governance mesh single-cluster baseline + the
  pre-existing tier-2 multi-region active-active (was 1.1),
  curated ONNX reference models (intent-drift / prompt-injection
  / anomaly-seq) + HuggingFace tokenizer integration + calibration
  framework (was 1.0.2 + 1.1), four native KMS SDK signer backends
  AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 (was 1.1).
  These require specialist engineering at scale and ship with
  contractual support, managed lifecycle, and threat-intel feed.
  None shipped in 1.0 GA — the **never retroactively remove**
  covenant is preserved.

The Enterprise edition is where the EU AI Act + GDPR + DORA
compliance pack, DPO Dashboard, multi-tenant isolation, Enterprise
SSO, eIDAS qualified signature pipeline, native SIEM connectors,
air-gapped distribution, founder-led 24/7 SLA, confidential-computing
receipts, forensic time-travel replay, conformity assessment
notified-body workflow, and the curated AI-specific eBPF/LSM
program library also live. See [`ENTERPRISE.md`](ENTERPRISE.md) for
the full pitch and EU AI Act article-by-article mapping.

### Changed

- Workspace version bumped to `1.1.0`.
- [`CHANGELOG.md`](CHANGELOG.md), [`MIGRATION.md`](MIGRATION.md),
  [`ENTERPRISE.md`](ENTERPRISE.md), [`README.md`](README.md), and
  [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md) §9 updated to reflect
  the OSS↔Enterprise boundary clarification.
- New [`IAGA_SENTINEL_1.1.md`](IAGA_SENTINEL_1.1.md) committed as the
  canonical 1.1 design note.

### Renamed (breaking — see [`MIGRATION.md`](MIGRATION.md))

- Complete rebrand **Agent Armor → IAGA Sentinel**: primary binary
  `agent-armor` → `iaga-sentinel` (short alias `armor` → `iaga`);
  crates `armor-*` → `iaga-sentinel-*`; library imports `agent_armor`
  / `armor_*` → `iaga_sentinel` / `iaga_sentinel_*`; env vars
  `AGENT_ARMOR_*` and `ARMOR_*` → `IAGA_SENTINEL_*` (clean break, no
  fallback); signer key dir `~/.armor/` → `~/.iaga-sentinel/`; default
  DB `agent_armor.db` → `iaga_sentinel.db`; API-key prefix `aa_` →
  `iaga_` (newly generated keys only — existing keys still validate);
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
  identifiers were renamed (see Renamed above) — behaviour did not
  change.**
- The covenant in `ENTERPRISE.md`: *Enterprise will never
  retroactively remove features from OSS. If something works in
  OSS today, it works in OSS forever.*

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in. Each
release converts automatically and irrevocably to Apache-2.0 four
years after publication.

---

## [1.0.0] — Unreleased ("Fortezza")

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
- **M2 — Signed Action Receipts.** Ed25519-signed records of every
  governance verdict, hash-chained per `run_id` (Merkle append-log).
  SQLite and Postgres backends. New CLI: `iaga replay --list`,
  `iaga replay <run_id>`, `iaga replay <run_id> --verify-only`.
  Signer key auto-generated at `~/.iaga-sentinel/keys/receipt_signer.ed25519`
  on first run, override via `IAGA_SENTINEL_SIGNER_KEY_PATH`.
- **M3 — Agent Policy Language (APL).** Typed DSL with deterministic
  tree-walk evaluator, instruction budget, short-circuit boolean
  evaluation, hash-linked replay safety. New crate `iaga-sentinel-apl`. CLI:
  `iaga policy test <file.apl>` and `iaga policy lint <file.apl>`.
  WASM codegen for APL is tracked for 1.0.3.
- **M3.5 — Probabilistic Reasoning Plane.** New crate `iaga-sentinel-reasoning`
  with always-available `NoopEngine` plus `TractEngine` (pure-Rust
  ONNX via `tract-onnx`) behind opt-in `ml` feature. Model SHA-256
  digests embedded in every receipt. CLI: `iaga reasoning info`.
  Pre-trained models ship in 1.0.2. *(See [1.1.0] entry for
  re-scoping: curated ONNX library lives in IAGA Sentinel Enterprise.)*
- **M4 — Enforcement Kernel scaffold.** New crate `iaga-sentinel-kernel` with
  cross-platform `UserspaceKernel` (soft enforcement, every OS) and
  Linux `BpfKernel` scaffold under `linux-bpf` feature. New CLI:
  `iaga run [--agent-id ...] [--cwd ...] -- <cmd>` and
  `iaga kernel status`. The real eBPF/LSM loader lands in 1.0.1.
  *(See [1.1.0] entry: real Aya-rs loader re-scoped to IAGA Sentinel
  Enterprise; the OSS scaffold + honest posture continue in 1.x.)*
- **M5 — `iaga run` traverses the full governance pipeline.** Every
  governed launch produces a signed receipt. Postgres receipt backend
  is wired automatically based on the `DATABASE_URL` scheme.
  Cargo feature composition: `iaga-sentinel-core/sqlite|postgres` transitively
  enables the matching `iaga-sentinel-receipts` feature.
- **M6 — APL as live policy engine.** `iaga serve --policy <file.apl>`
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
  hardened in M2–M5; M3.5 + M4 add supply chain attestation /
  blast radius enforcement / behavioral baseline / counterparty trust
  scaffolding.
- **All paths** `community/` → `crates/iaga-sentinel-core/`. Detailed renames
  in [MIGRATION.md](MIGRATION.md).
- **Cargo `default` features** for `iaga-sentinel-core`:
  `["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]`.

### Re-scoped after 1.0 GA (boundary clarification, see 1.1.0 entry above)

> The lists below preserved verbatim from the 1.0 GA changelog for
> historical fidelity. The **2026-05-08 OSS↔Enterprise boundary
> clarification** re-scopes these capabilities — see the [1.1.0]
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
  Hindley–Milner type checker. **Reinstated → OSS 1.2 roadmap.**

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

## [0.4.0] — 2026-XX-XX ("Azzurra")

The community runtime that proved the thesis. 8-layer defense in depth
behind a single `/v1/inspect` HTTP gate. Policy as YAML + templates.
SDKs in Python and TypeScript. SQLite + Postgres durable state.

See git history for the full 0.4.0 changelog.
