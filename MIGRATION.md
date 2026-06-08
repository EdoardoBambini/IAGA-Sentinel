# Migration Guide

This document tracks breaking changes and path renames across IAGA Sentinel
releases. The high-level 1.0 design lives in [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md);
this file tracks the **concrete moves** you need to make when bumping versions.

---

## 0.4.0 → 1.0.0-alpha.1 (M1: "Fortezza Foundation")

**Scope:** repository layout only. No runtime API change. No policy format
change. All 0.4.0 behavior is preserved; tests pass unchanged.

### What moved

| Before (0.4.0) | After (1.0.0-alpha.1) | Notes |
|---|---|---|
| `community/` | `crates/iaga-sentinel-core/` | Cargo crate, now a workspace member |
| `community/Cargo.toml` package name `iaga-sentinel` | `iaga-sentinel-core` | the **crate** renamed; the **binary** is still `iaga-sentinel` |
| `visual/` | `ui/` | official frontend, will be embedded via `ui-embed` feature |
| `assets/hero.gif` | `media/hero.gif` | media consolidated under one folder |
| `assets/hero.mp4` | `media/hero.mp4` | still gitignored (large) |
| `assets/brain.gif` | `media/brain.gif` | |
| `community/target/` | `target/` (repo root) | workspace-level target |
| `community/Cargo.lock` | `Cargo.lock` (repo root) | workspace-level lock |

### What stayed

- Binary name `iaga-sentinel` unchanged (backward compat).
- Library name `iaga_sentinel` (so `use iaga_sentinel::*` keeps working in tests and SDK consumers).
- Policy YAML format unchanged (APL migration comes in M3).
- SDK layout in `sdks/python` and `sdks/typescript` unchanged.
- `docs/`, `charts/`, `skills-lock.json`, `iaga-sentinel.config.json` unchanged.
- `iaga-sentinel-video/` Remotion project unchanged, still standalone.

### What's new

- `iaga` is now an official alias binary (same entry point as `iaga-sentinel`).
  Both are built from `crates/iaga-sentinel-core` and can be invoked
  interchangeably.
- `ui-embed` Cargo feature on `iaga-sentinel-core`. When enabled, embeds
  `ui/dist/` into the binary via `rust-embed`. Requires a prior
  `cd ui && npm run build`. Route wiring (`/ui`) lands in a later milestone.
- Workspace-level `Cargo.toml` at the repo root with shared dependency
  versions, future crates (`iaga-sentinel-receipts`, `iaga-sentinel-apl`,
  `iaga-sentinel-reasoning`, `iaga-sentinel-kernel`, `iaga-mesh`) will land here without
  further repo reshuffles.

### Breaking commands

If your scripts used any of these, update accordingly:

```diff
- cd community && cargo build
+ cargo build --workspace
+ # or scoped:
+ cargo build -p iaga-sentinel-core

- cd community && cargo test --all-features
+ cargo test --workspace --all-features

- community/target/release/iaga-sentinel
+ target/release/iaga-sentinel

- cd visual && npm install
+ cd ui && npm install
```

### CI

The workflow at `.github/workflows/ci.yml` was rewritten to run from the
workspace root. Branch trigger `feat/1.0-**` was added so M1+ branches
get CI without a PR.

### Why

See [`docs/adr/0001-workspace-split.md`](docs/adr/0001-workspace-split.md).
Short version: we need a multi-crate workspace so that `iaga-sentinel-receipts`
(M2), `iaga-sentinel-apl` (M3), `iaga-sentinel-reasoning` (M3.5), `iaga-sentinel-kernel` (M4),
and `iaga-mesh` (M5) can grow as separate, feature-gated crates without
touching `iaga-sentinel-core`. The M1 split is deliberately conservative: we
create the workspace and move the single crate in, but **do not** slice
`iaga-sentinel-core` itself. That comes later, milestone by milestone.

---

## 1.0.0-alpha.1 M2, "Signed Action Receipts" (staged, not committed)

**Scope:** additive. No runtime API change for 0.4.0 consumers. No policy
format change. `audit_events` is untouched; a new `receipts` table is
written *in addition* whenever the `receipts` cargo feature is active
(default on). All 0.4.0 behavior preserved; 166/166 pre-existing tests
still pass.

### What's new

- New crate `crates/iaga-sentinel-receipts/` providing:
  - `Receipt` / `ReceiptBody`, canonical, Ed25519-signed record of a
    governance verdict.
  - `ReceiptStore` trait with SQLite and Postgres backends.
  - `ReceiptSigner`, single-key Ed25519 signer loaded from
    `<HOME>/.iaga-sentinel/keys/receipt_signer.ed25519` (generated on first run,
    `chmod 0600` on Unix). Override path via env `IAGA_SENTINEL_SIGNER_KEY_PATH`.
  - Hash-linked append-only chain (one chain per `run_id`) with
    end-to-end `verify_chain` that rejects any tampering.
  - `replay(store, run_id, evaluator)`, drift-detection primitive; the
    full "re-run pipeline in sandbox" replay lands in M5.

- New optional field on `AppState`:
  `pub receipts: Option<Arc<dyn ReceiptLogger>>`. `None` when the
  `receipts` feature is disabled or the host hasn't wired a logger.

- New `iaga-sentinel-core` cargo feature `receipts` (default **on**):
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts"]
  receipts = ["dep:iaga-sentinel-receipts"]
  ```

- New CLI subcommand (feature-gated):
  ```
  iaga replay --list
  iaga replay <run_id>
  iaga replay <run_id> --verify-only
  ```

- `execute_pipeline` now performs a best-effort dual-write: after each
  successful `audit_store.append`, if `state.receipts` is `Some`, a
  signed receipt is appended to the corresponding Merkle chain. Errors
  on the receipt path are logged at `warn!` and never propagate.

### Environment / ops notes

- **Signer key path**: `$HOME/.iaga-sentinel/keys/receipt_signer.ed25519`. Back
  this up, losing the private key means new runs start a new chain and
  old chains can still be *verified* (public key derived from
  `signer_key_id`) but not *extended* with matching signatures.
- **DB backend**: the automatic wiring currently enables receipts only
  on `sqlite:` URLs. Postgres support in `iaga-sentinel-receipts` is compiled
  and tested; the `iaga-sentinel-core` helper that auto-enables it on Postgres
  DSNs is a follow-up (tracked for M5).
- **Disabling receipts**: build with `--no-default-features --features
  "demo,sqlite"` (omitting `receipts`). The binary will run exactly as
  0.4.0 with no signing overhead.

### What stayed

- `audit_events` table and all its APIs unchanged.
- `iaga-sentinel` and `iaga` binary names unchanged.
- Policy format unchanged.
- Trait `AuditStore` unchanged.
- SDK surface unchanged.

---

## 1.0.0-alpha.1 M3, "Agent Policy Language" (staged, not committed)

**Scope:** additive. No change to 0.4.0 YAML policy pipeline. New crate
`iaga-sentinel-apl` provides an independent parser + deterministic evaluator for
`.apl` source files. Integration with the live policy store is deferred
to M5; M3 ships the language, the types and a dry-run CLI.

### What's new

- New crate `crates/iaga-sentinel-apl/` providing:
  - `logos`-based lexer (keywords, operators, string escapes, `//` comments),
  - recursive-descent parser producing a `Program` AST,
  - structural validator (unique policy names, builtin arity, non-empty paths),
  - tree-walk evaluator with instruction budget (`EvalBudget`, default 10_000 steps),
  - public `compile(src)` and `evaluate_program(program, ctx, budget)` entry points.

- Supported APL surface (MVP, see [`docs/adr/0004-apl-mvp.md`](docs/adr/0004-apl-mvp.md)):
  ```apl
  policy "name" {
    when <expr>
    then allow|review|block [, reason="..."] [, evidence=<expr>]
  }
  ```
  Expressions support literals (string/int/bool), dotted path access
  (`action.url.host`), comparisons (`== != < <= > >=`), boolean
  logic with short-circuit (`and or not`), membership (`in`, `not in`)
  and builtin calls (`contains starts_with ends_with len lower upper
  secret_ref`).

- New `iaga-sentinel-core` cargo feature `apl` (default **on**):
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts", "apl"]
  apl = ["dep:iaga-sentinel-apl"]
  ```

- New CLI subcommand (feature-gated):
  ```
  iaga policy test <file.apl>
  iaga policy test <file.apl> --context ctx.json
  ```
  Without `--context` only parse + validate. With a JSON context, the
  evaluator runs and prints `FIRE policy=... verdict=...` for the
  first policy that triggers.

- Example policy + sample context shipped at
  `crates/iaga-sentinel-apl/examples/no_pii_egress.apl` (+ `sample_context.json`).

### Contracts

- **Execution order**: policies run in declaration order; the first
  truthy `when` produces the verdict. Authors order by severity.
- **Missing paths** evaluate to `null` and are falsy. Policies must
  not assume the presence of optional fields.
- **Determinism**: no I/O, no wall-clock, no RNG. Same AST + same
  context ⇒ same result, forever. This is what makes APL compatible
  with the receipt-replay model from M2.
- **Budget**: every AST-node visit decrements a counter; exhaustion
  produces `AplError::BudgetExhausted`, never a silent pass.

### What's *not* in M3 (intentionally)

- WASM codegen (→ M3.1). The tree-walk evaluator is already deterministic.
- Full Hindley-Milner type checker (→ M3.1). The M3 validator is structural.
- APL policies wired into `execute_pipeline` as the live policy engine
  (→ M5). For now the YAML loader remains the authoritative policy
  source; APL runs via the CLI dry-run only.
- Loops, closures, let-bindings, user-defined functions, file imports,
  LSP/IDE integration. Added as the language stabilizes.

### What stayed

- YAML policy loader unchanged. No `iaga policy migrate` yet, it lands
  in M5 when the live swap happens.
- `audit_events`, `receipts`, `AuditStore`, `ReceiptStore` unchanged.
- SDK surface unchanged.

---

## 1.0.0-alpha.1 M3.5, "Probabilistic Reasoning Plane" (staged, not committed)

**Scope:** additive. Pipeline behavior unchanged when no reasoning
engine is wired or the `ml` feature is off. New crate `iaga-sentinel-reasoning`
provides the ML evidence surface; `iaga-sentinel-core` wires it through to
`SignedReceiptLogger` so receipts now carry `model_digests` + `ml_scores`
**when and only when** an engine is active and produces evidence.

### What's new

- New crate `crates/iaga-sentinel-reasoning/` providing:
  - `ReasoningEngine` trait with two impls: `NoopEngine` (always
    present) and `TractEngine` (feature `ml`, pure-Rust ONNX via
    `tract-onnx`).
  - `EvalInput` / `MlEvidence` / `ModelDigest` types, matched in
    shape to `iaga_sentinel_receipts::{ModelDigest, MlScoreBundle}` so the
    glue layer is a one-liner.
  - SHA-256 digest computation for every loaded model file.
  - MVP hash-bag-of-byte-ngrams tokenizer (`[1, 64]` float32), see
    [ADR 0005](docs/adr/0005-reasoning-plane-mvp.md) for the
    deliberate scope decision.
  - Env-driven model spec: `IAGA_SENTINEL_REASONING_MODELS=name1:path1,name2:path2`.

- New `iaga-sentinel-core` features:
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts", "apl", "reasoning"]
  reasoning = ["dep:iaga-sentinel-reasoning"]
  ml = ["reasoning", "iaga-sentinel-reasoning/ml"]
  ```
  - `reasoning` is **default on** but only enables the `NoopEngine`.
    No native deps, no binary bloat, no behavior change at runtime.
  - `ml` is **default off**. Adds `tract-onnx` to the build (~5 MB
    binary growth, ~2 min cold compile) and activates the
    `TractEngine` so `IAGA_SENTINEL_REASONING_MODELS` actually loads.

- New optional field on `AppState`:
  `pub reasoning: Option<Arc<dyn ReasoningHandle>>`, same
  feature-agnostic pattern as `receipts`.

- New CLI subcommand (feature-gated on `reasoning`, not `ml`):
  ```
  iaga reasoning info
  ```
  Prints engine name, loaded model count, and per-model SHA-256
  digest. Suggests next step (`--features ml` rebuild or
  `IAGA_SENTINEL_REASONING_MODELS` setting) when no models are loaded.

- `execute_pipeline` now invokes `reasoning.evaluate_json(...)` once
  before the risk score. Output is passed to `SignedReceiptLogger.record`
  as `Option<&ReasoningOutcome>`. Errors are logged at `warn!` and
  swallowed: a broken ML engine never fails the governance decision.

### Receipt schema impact

The `Receipt` JSON shape is **unchanged**. The fields `model_digests`
and `ml_scores` already existed in M2; they were always serialized
empty/None. Now they get populated when reasoning is active and an
engine produces evidence.

For runs where reasoning is off or produces no evidence, receipts are
**bit-identical** to M2. Replay of legacy chains is unaffected.

### Trait change (internal, not public API)

`pipeline::receipts::ReceiptLogger::record` signature changed:

```diff
-async fn record(&self, event: &StoredAuditEvent);
+async fn record(&self, event: &StoredAuditEvent, evidence: Option<&ReasoningOutcome>);
```

This is internal to `iaga-sentinel-core` (`pipeline::receipts` is `pub` for the
binary's own use, not part of a stable public surface). The two call
sites in `execute_pipeline.rs` were updated; the fast-path block sends
`None`, the main verdict path sends the eval outcome.

### Environment / ops notes

- **Default behavior unchanged**: without `--features ml` and without
  setting `IAGA_SENTINEL_REASONING_MODELS`, the engine is `NoopEngine` and
  receipts look exactly like M2.
- **Disabling reasoning entirely**: `--no-default-features --features
  "demo,sqlite,receipts,apl"`. `AppState.reasoning` will be `None`
  and the pipeline skips the eval call.
- **Real ONNX models**: build with `--features ml`, set
  `IAGA_SENTINEL_REASONING_MODELS=name:/abs/path/model.onnx,...`. The model
  must accept `[1, 64]` float32 input. M3.5.1 will lift the latter
  constraint with pluggable tokenizers.

### What stayed

- `audit_events` / `receipts` schemas unchanged.
- `AuditStore` / `ReceiptStore` traits unchanged.
- APL surface unchanged (M5 will add `ml.*` paths to the eval context).
- SDK API unchanged.
- 166/166 pre-existing core tests still pass.

---

## 1.0.0-alpha.1 M4, "Enforcement Kernel" (staged, not committed)

**Scope:** additive. New crate `iaga-sentinel-kernel` provides a cross-platform
`EnforcementKernel` trait, a working `UserspaceKernel` for every OS,
and a `BpfKernel` scaffold (Linux, feature `linux-bpf`). Pipeline
behavior is unchanged; the kernel is reachable today only through the
new `iaga run` subcommand.

The actual eBPF/LSM loader (the part that makes enforcement
authoritative) is tracked for M4.1. M4 ships the trait shape so M4.1
is purely additive.

### What's new

- New crate `crates/iaga-sentinel-kernel/` providing:
  - `EnforcementKernel` trait, `launch(spec) -> LaunchOutcome`,
    `backend_name()`, `is_authoritative()`.
  - `UserspaceKernel`, cross-platform launcher with policy pre-check,
    scoped environment (allowlist of inherited vars + explicit
    overrides), optional cwd, sync wait + exit code capture.
    Declares `is_authoritative() == false` (soft enforcement).
  - `BpfKernel`, Linux + `linux-bpf` feature. Today returns `Block`
    with reason "linux-bpf scaffold; loader pending M4.1". Same trait
    surface as `UserspaceKernel` so M4.1 swap is config, not refactor.
  - `ProcessSpec`, `KernelDecision`, `LaunchOutcome`, narrow types
    that travel cleanly across the userspace/eBPF datapath boundary.

- New `iaga-sentinel-core` features:
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]
  kernel = ["dep:iaga-sentinel-kernel"]
  linux-bpf = ["kernel", "iaga-sentinel-kernel/linux-bpf"]
  ```

- New CLI subcommands (feature-gated on `kernel`):
  ```
  iaga kernel status
  iaga run [--agent-id AGENT] [--cwd DIR] -- <program> [args...]
  ```
  `iaga run` spawns a child under the userspace kernel. The policy
  callback is `allow_all` for M4, wiring `execute_pipeline` as the
  policy source is M5 (when APL becomes the authoritative engine).

### Honest posture

`iaga kernel status` reports `authoritative: no (soft enforcement)`
until the eBPF loader ships in M4.1. We do not market kernel
enforcement we don't yet provide. The binary tells the operator the
truth.

### What stayed

- `audit_events` / `receipts` schemas unchanged.
- `AppState`, `AuditStore`, `ReceiptStore`, `ReasoningHandle` unchanged.
- APL surface unchanged.
- SDK API unchanged.
- 219/219 default-feature tests still pass.

---

## 1.0.0-alpha.1 M5, "Hardening + 1.0 RC" (staged, not committed)

**Scope:** wiring pass. The scaffolds from M2-M4 are now connected
end-to-end. `iaga run` traverses the governance pipeline; every
launch produces a signed receipt; Postgres is a first-class receipt
backend; `--features postgres` works without extra config.

### What's new

- **`iaga run` is governed end to end.** `cmd_kernel_run` now builds a
  full `AppState` and uses `execute_pipeline` as the kernel's policy
  callback. Verdict comes from the same pipeline that serves
  `iaga inspect`. Fail-closed on pipeline error.

- **Receipt for every governed launch.** Side effect of the wiring
  above: each `iaga run` produces an audit event + a signed,
  Merkle-chained receipt. `iaga replay --list` shows your launches
  alongside HTTP-served runs. Tamper detection works identically.

- **Postgres receipts wired from the binary.** `try_build_receipt_logger`
  selects backend by URL scheme:
  - `sqlite:` → `SqliteReceiptStore`
  - `postgres://` / `postgresql://` → `PgReceiptStore`
  Build with `--features postgres` and set
  `DATABASE_URL=postgres://...`, receipts go to Postgres
  automatically, no extra flags.

- **Cargo feature composition for storage backends.** `iaga-sentinel-core`'s
  `sqlite` and `postgres` features now transitively enable
  `iaga-sentinel-receipts`'s matching feature via `iaga-sentinel-receipts?/sqlite` and
  `iaga-sentinel-receipts?/postgres`. No more divergence between the host
  binary and the receipts crate on which DB driver is compiled in.

- **Auto-seed on first `iaga run`.** If the policy store has zero
  profiles, `cmd_kernel_run` seeds the demo set so the first launch
  produces a meaningful verdict instead of "Agent not found". Idempotent.

### Trait change (`iaga-sentinel-kernel`, internal)

`PolicyCheck` is now async:

```diff
-pub type PolicyCheck = Arc<dyn Fn(&ProcessSpec) -> KernelDecision + Send + Sync>;
+pub type PolicyCheck = Arc<
+    dyn for<'a> Fn(&'a ProcessSpec)
+        -> Pin<Box<dyn Future<Output = KernelDecision> + Send + 'a>>
+        + Send + Sync,
+>;
```

All in-tree callers (`UserspaceKernel::allow_all`, the test suite)
were updated. Not a public-API breaking change because `iaga-sentinel-kernel`
has no external consumers in 1.0-alpha.

### What's *not* in M5 (intentionally deferred)

- ❌ APL as the authoritative policy source in `iaga serve`
  (`--policy file.apl` overlay) → **M6**. Requires designing the merge
  between APL evaluation and the current risk scoring; deserves its
  own ADR (0008) and a focused milestone.
- ❌ Drift replay with full pipeline re-execution against historical
  receipts → reinstated to **OSS 1.2** roadmap as additive on the
  receipt body (`pipeline_inputs_capture`, `apl_eval_trace`,
  `ml_inference_inputs` all optional, no schema-breaking). The
  forensic *time-travel* variant (event sourcing + temporal queries
  DB-state-per-verdict) lives in IAGA Sentinel Enterprise (#13). See
  [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).
- ❌ Real Aya-rs eBPF/LSM loader Linux → **IAGA Sentinel Enterprise** (#16).
- ❌ Cross-platform kernel (macOS Endpoint Security, Windows ETW/WFP)
  → **IAGA Sentinel Enterprise** (#17). The OSS `UserspaceKernel`
  cross-platform soft enforcement remains and is documented honestly
  by `iaga kernel status`.
- ❌ Mesh (gRPC gossip, federated rate budgets, single-cluster + tier-2
  multi-region active-active) → **IAGA Sentinel Enterprise** (#3 + #18).
- ❌ Native KMS SDK signer backends (AWS KMS / Azure Key Vault /
  HashiCorp Vault / PKCS#11 HSM) → **IAGA Sentinel Enterprise** (#20).
  The `Signer` trait + `LocalDiskSigner` refactor is reinstated to
  **OSS 1.2** as additive primitive; the BYOK filesystem-mount pattern
  via `IAGA_SENTINEL_SIGNER_KEY_PATH` stays OSS forever.
- ❌ License switch → already implicit. BUSL-1.1 with Change License
  Apache-2.0 baked into the licence auto-converts 4 years after each
  release; no manual action required.

### What stayed

- `audit_events` / `receipts` schemas unchanged.
- `ReceiptLogger`, `ReasoningHandle`, `EnforcementKernel` trait shapes
  unchanged (only `PolicyCheck` callback type became async).
- APL surface unchanged.
- SDK API unchanged.
- 225/225 default-feature tests still pass.

---

## 1.0.0-alpha.1 GA pre-flight, E2E hardening (staged, not committed)

End-to-end smoke testing of the 1.0 GA candidate (server, CLI, HTTP API,
APL overlay, Docker compose) surfaced four issues that have been fixed
in the working tree:

### Fixes

- **`Dockerfile` rewritten for the workspace layout.** The previous
  Dockerfile pointed at `community/Cargo.toml` and `community/src/`,
  paths that no longer exist after the M1 workspace split. The
  container built but ran a 430 KB stub binary that exited
  immediately without output. The new Dockerfile is a single-shot
  `cargo build --release --bin iaga --locked` against the real
  workspace; the resulting binary is ~18 MB and starts cleanly under
  `docker compose up`. The dependency-cache trick used previously
  was fragile across multi-crate workspaces and has been removed.
- **CLI banner** showed "8 Layers ARMED". Updated to "12 Layers ARMED"
  to match the 1.0 marketing surface (M3.5 + M4 added 4 layers on top
  of the original 8).
- **`iaga-sentinel-core` Cargo description** said "(Community Edition)".
  Updated to "(open-source edition)" for consistency with the
  Community vs Enterprise documentation in README + ENTERPRISE.md.

### Documented behaviour clarifications (no code change)

These are not bugs; they are operator-facing facts that the README
quickstart now spells out:

- HTTP API auth header is `Authorization: Bearer <key>`. There is no
  `X-API-Key` header.
- `InspectRequest` JSON uses camelCase keys at every level
  (`agentId`, `toolName`, `actionType`). The serde `#[serde(rename_all
  = "camelCase")]` attribute is the source of truth.
- The receipt signer key path defaults to
  `~/.iaga-sentinel/keys/receipt_signer.ed25519` natively and to
  `/home/iaga/.iaga-sentinel/keys/receipt_signer.ed25519` inside the
  Docker container. Receipts signed by one cannot be verified by the
  other unless you mount the key in or set `IAGA_SENTINEL_SIGNER_KEY_PATH`.

### Test posture

- 234/234 default-feature tests still pass.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `docker compose build && docker compose up -d` healthy on the
  first attempt with the new Dockerfile; `/health` returns 200,
  `iaga inspect` over HTTP returns the expected verdicts.

---

## 1.0.0-alpha.1 M6, "APL as Live Policy Engine" (staged, not committed)

**Scope:** additive. The YAML profile + workspace policy system from
0.4.0 stays authoritative. APL is loaded as an *overlay* via
`iaga serve --policy file.apl` and merged stricter-wins with the
YAML risk decision: APL can tighten the verdict, never relax it.

### What's new

- **`iaga serve --policy <file.apl>`** loads an APL bundle at boot.
  Fail-fast on any compile error: if the operator asked for APL, they
  want APL.

- **Stricter-wins merge** in `execute_pipeline`: after the YAML risk
  score, the pipeline evaluates the APL overlay against a JSON context
  built from the request (`agent`, `action`, `workspace`, `risk`, and
  `ml` when reasoning is on) and merges via
  `merge_decisions(yaml, apl)` where `Block > Review > Allow`.

- **`policy_hash` in receipts is real now.** When an overlay is loaded,
  the SHA-256 of the compiled APL bundle replaces the M2 placeholder
  constant in every receipt body. Replay distinguishes runs with /
  without APL active by inspecting `policy_hash`.

- **`iaga policy lint <file.apl>`** semantic alias for
  `iaga policy test <file.apl>` without `--context`. Parse + validate
  only.

- **Example bundle** `crates/iaga-sentinel-core/examples/policies/strict.apl`
  shipped: three policies that tighten the YAML baseline (block
  high-risk shell, review all email, block off-allowlist HTTP).

- **`AppState.apl_overlay: Option<Arc<AplOverlay>>`** (cfg-gated on
  `feature = "apl"`, default on).

- **`try_build_receipt_logger(db_url, policy_hash)`** signature
  changed: now accepts an optional `policy_hash` override so the
  caller can pass the APL bundle digest. `None` preserves M2/M5
  behavior with the placeholder constant.

### Receipt shape

JSON shape unchanged. Only the *content* of `policy_hash` changes
when APL is loaded. Receipts produced before M6 (or in runs without
`--policy`) remain bit-identical to M5, replay legacy intact.

### What's *not* in M6 (deferred)

- ❌ `iaga policy migrate` (YAML → APL converter) → **OSS-eligible**
  per [ADR 0010](docs/adr/0010-oss-enterprise-boundary.md), no fixed
  schedule. Small utility, ships when ready as additive 1.x.y.
- ❌ Hot reload without restart → 1.0.x if requested.
- ❌ Multiple `--policy` files concatenated → 1.0.x if requested.
- ❌ APL replacing YAML entirely → not scheduled; the YAML profile
  system co-exists with the APL stricter-wins overlay indefinitely.
- ❌ Drift replay with full pipeline re-execution → reinstated to
  **OSS 1.2** roadmap as additive (`pipeline_inputs_capture`,
  `apl_eval_trace`, `ml_inference_inputs` optional fields on the
  receipt body, no breaking change). The forensic time-travel variant
  (event sourcing + temporal queries DB-state-per-verdict) lives in
  IAGA Sentinel Enterprise (#13).

### What stayed

- YAML profile + workspace policy system unchanged. Backward compat
  with 0.4.0 is full: not passing `--policy` produces identical
  behavior to M5.
- `audit_events` / `receipts` schemas unchanged.
- All trait shapes (`AuditStore`, `ReceiptStore`, `ReasoningHandle`,
  `EnforcementKernel`) unchanged.
- SDK API unchanged.

---

## 1.0 → 1.1.0

**Scope:** consolidation + complete project rebrand **Agent Armor →
IAGA Sentinel**. Governance behaviour is unchanged, the 12-layer
pipeline, verdict logic, receipt format (Ed25519 + Merkle), and the
HTTP API contract (endpoints, camelCase JSON, `Authorization:
Bearer`) are identical to 1.0.0. **Only names changed.** Those
renames are breaking for CLI users, operators, and crate consumers,
so upgrade deliberately using the table below.

> Why a minor (1.1.0) and not a major: runtime/API behaviour and the
> on-disk formats are compatible with 1.0.0; the break is limited to
> identifiers (binary, env vars, paths, crate/type names). This is a
> documented one-time exception, the 1.x line otherwise keeps the
> no-breaking-change guarantee.

### Rename map (breaking)

| Area | 1.0 (Agent Armor) | 1.1 (IAGA Sentinel) |
|---|---|---|
| Primary binary | `agent-armor` | `iaga-sentinel` |
| Short binary | `armor` | `iaga` |
| Workspace crates | `armor-core`, `armor-receipts`, `armor-apl`, `armor-kernel`, `armor-reasoning` | `iaga-sentinel-core`, `-receipts`, `-apl`, `-kernel`, `-reasoning` |
| Library imports | `agent_armor`, `armor_receipts`, … | `iaga_sentinel`, `iaga_sentinel_receipts`, … |
| Env vars | `AGENT_ARMOR_*`, `ARMOR_*` (`ARMOR_SIGNER_KEY_PATH`, `ARMOR_OPEN_MODE`, `ARMOR_REASONING_MODELS`, `ARMOR_LOG_LEVEL`, …) | `IAGA_SENTINEL_*` (`IAGA_SENTINEL_SIGNER_KEY_PATH`, `IAGA_SENTINEL_OPEN_MODE`, …) |
| Signer key dir | `~/.armor/keys/receipt_signer.ed25519` | `~/.iaga-sentinel/keys/receipt_signer.ed25519` |
| Default SQLite | `agent_armor.db` | `iaga_sentinel.db` |
| API-key prefix | `aa_…` | `iaga_…` (newly generated keys only) |
| Webhook headers | `X-Armor-Signature`, `X-Armor-Event` | `X-Iaga-Sentinel-Signature`, `X-Iaga-Sentinel-Event` |
| MCP tool names | `agentarmor.inspect`, `agentarmor.response_scan` | `iaga.inspect`, `iaga.response_scan` |
| Python SDK | `from agent_armor import ArmorClient` | `from iaga_sentinel import SentinelClient` |
| Public types | `ArmorClient`, `ArmorError`, `ArmorEvent`, … | `SentinelClient`, `SentinelError`, `SentinelEvent`, … |

### Migration steps

1. **Binary:** invoke `iaga` (or `iaga-sentinel`) instead of `armor` /
   `agent-armor`.
2. **Env vars:** rename `AGENT_ARMOR_*` / `ARMOR_*` to
   `IAGA_SENTINEL_*`. The old names are **not** read as a fallback
   (clean break).
3. **Signer key:** move `~/.armor/keys/` to `~/.iaga-sentinel/keys/`
   (or set `IAGA_SENTINEL_SIGNER_KEY_PATH`) to keep signing the same
   receipt chain. Otherwise 1.1 generates a fresh key and starts a new
   chain; old chains still *verify* but can't be *extended*.
4. **Database:** point at the existing DB explicitly -
   `--db sqlite:agent_armor.db` (or `DATABASE_URL=…`), or rename the
   file to `iaga_sentinel.db`. The schema is identical.
5. **Webhook consumers:** update header checks to `X-Iaga-Sentinel-*`.
6. **MCP clients:** call `iaga.inspect` / `iaga.response_scan`.
7. **SDK / crate consumers:** update package and type imports per the
   table.

### What did NOT change

- HTTP API: endpoint paths, request/response JSON (camelCase),
  `Authorization: Bearer <key>`. Existing API keys still validate -
  only the prefix of *newly generated* keys changed.
- Receipt format (Ed25519 + Merkle hash-chain) and `replay` verify.
- APL syntax, `.apl` files, policy YAML format.
- Database schema (SQLite + Postgres), feature flags, sub-command set.
- License: BUSL-1.1 with Change License Apache-2.0 baked in.

---

## 1.1 → 1.2.0

**Scope:** the **primitive evolution release**. Ships the four
primitives that ADR 0010 §3 reinstated to OSS 1.2. **No breaking
changes.** No runtime semantics change for existing 1.1 callers;
every callsite (CLI, HTTP, library API) compiles unchanged.

### Signer trait + LocalDiskSigner (ADR 0011)

`iaga_sentinel_receipts::ReceiptSigner` is now a `type alias` for
`LocalDiskSigner`, every existing import keeps working. The new
trait `Signer: Send + Sync` (async, object-safe) is what the
pipeline holds as `Arc<dyn Signer>`. SDK consumers wanting to
implement custom signers (e.g. for offline KMS testing) should
target the trait. Native KMS SDK backends (AWS KMS / Azure Key Vault
/ HashiCorp Vault / PKCS#11 HSM) remain Enterprise (ADR 0010 §2.20).
BYOK via `IAGA_SENTINEL_SIGNER_KEY_PATH` filesystem-mount remains
the OSS path forever.

### Drift replay additive (ADR 0012)

Three new optional fields on `ReceiptBody`:
`pipeline_inputs_capture`, `apl_eval_trace`, `ml_inference_inputs`.
Populated **only** when the host opts in via env
`IAGA_SENTINEL_RECEIPT_CAPTURE=1` (default off). When off, the
serialization is byte-identical to 1.1, chain hashes and signatures
stay stable, mixed 1.1/1.2 stores verify cleanly.

**PII warning**: when capture is enabled, `pipeline_inputs_capture.request_json`
contains the request payload that drove the verdict, which may
include sensitive content. Backups, exports, and offsite copies of
receipts pick that up too. **Keep capture disabled in production
unless the receipt store is in scope of the same data-protection
controls as the request bus.**

New CLI: `iaga replay --re-execute <run_id>` (mutex with
`--verify-only`) reports per-receipt capture availability. Full
pipeline re-execution wiring is a 1.3 follow-up; the 1.2 MVP shows
which receipts have capture material and which don't.

### Plugin Sigstore + SBOM offline attestation (ADR 0013)

New Cargo feature `plugin-attestation` (default off). When enabled,
the plugin registry searches for sibling `<plugin>.sigstore.json`
and `<plugin>.cdx.json` files at load time and populates
`PluginManifest.attestation` / `.sbom` / `.attestation_offline_verified`.

**Scope honesty**: this is **offline structural verification only**
- bundle well-formedness + payload digest match. Rekor inclusion
proof and Fulcio root CA chain validation are **not** performed
in OSS 1.2. For full chain-of-trust, run `cosign verify` out of
band, or upgrade to IAGA Sentinel Enterprise (hosted marketplace
+ supply-chain SLA).

CLI: `iaga plugin verify <plugin.wasm>` outputs a table/JSON
report and exits non-zero if a bundle is present but verification
fails.

### APL Hindley-Milner + WASM codegen MVP (ADR 0014)

`compile_with_types(src)` is the new entrypoint pairing `compile`
with Algorithm W type inference over the existing APL AST. CLI:
`iaga policy check <file.apl>` prints per-policy `when` types and
reports type errors.

New feature `apl-wasm` (default off) adds the WASM codegen primitive.
The tree-walk evaluator remains the canonical executor for the full
APL surface, `evaluate_program()` is unchanged. The WASM MVP only
handles literal + boolean / numeric / comparison operations; Path
/ Call / Membership are rejected with clear errors pointing the
caller back to the tree-walk path. Full WASM coverage + parity
proptest is a 1.3 follow-up.

CLI: `iaga policy compile <file.apl> [--output bundle.wasm]` (gated
on `apl-wasm`).

### Feature flag summary

All four primitives are opt-in. Default behaviour matches 1.1 exactly:

| Feature | Crate | Default | Pulls in |
|---|---|---|---|
| `plugin-attestation` | `iaga-sentinel-core` | off | `base64` |
| `apl-wasm` | `iaga-sentinel-apl` (forwarded from core) | off | `wasm-encoder` |
| Env `IAGA_SENTINEL_RECEIPT_CAPTURE=1` |, (host env) | unset |, |

### What did **not** change

- License: BUSL-1.1 + Change License Apache-2.0 baked in. Change
  Date `2030-05-03` preserved (1.2 is additive, no new release
  Change-Date reset).
- HTTP API surface (`/v1/inspect`, `/v1/receipts`, `/health`).
- Receipt JSON keys, signing-bytes canonical form, signature alg
  (Ed25519), Merkle linking.
- CLI sub-cmd surface that existed in 1.1.
- Database schema for `iaga-sentinel-receipts` SQLite / Postgres
  backends.
- Naming (everything is still `iaga-sentinel` / `iaga` / IAGA
  Sentinel, see [`feedback_rebrand_iaga_sentinel`] in 1.1).

---

## 1.2.0 → 1.3.0

**Scope:** the **conformity-evidence release**. Three additive, opt-in primitives,
no breaking changes; default behaviour and receipt bytes are unchanged with the
new features off. See [`IAGA_SENTINEL_1.3.md`](IAGA_SENTINEL_1.3.md) and ADRs 0015–0017.

- New slim crate `iaga-sentinel-verify` (binary `iaga-verify`): offline receipt
  verification, no DB, no async. Export a run with
  `iaga replay <run_id> --export run.json`, then `iaga-verify run.json --key <hex>`.
- New `iaga-sentinel-core` feature `otel-receipts` (default off): emit each signed
  receipt as an OpenTelemetry span on `/v1/telemetry/spans` and `/v1/telemetry/export`.
- New `iaga-sentinel-core` feature `plugin-manifest-signing` (default off): Ed25519
  signed plugin manifests, `iaga plugins sign-manifest` / `verify-manifest`.

Upgrade is risk-free: default behaviour matches 1.2 exactly.

---

## 1.3.0 → 1.3.1

**Scope:** the **1.3 conformity-closure patch** (ADR 0018). Additive, no breaking
changes. Receipts produced before 1.3.1 verify unchanged, the new optional field is
elided when absent.

- **Receipt `is_authoritative` flag.** `ReceiptBody` gains an optional
  `is_authoritative` field, set to `false` on every open-build receipt (soft
  enforcement). New receipts carry it; pre-1.3.1 receipts (field absent) stay
  byte-identical and verify unchanged.
- **OpenTelemetry roadmap keys.** The receipt span now carries `iaga.receipt.id`,
  `iaga.chain.head`, `iaga.policy.verdict`, and `iaga.is_authoritative`, alongside
  the existing `receipt.*` aliases (feature `otel-receipts`).
- **Sensitive-environment scrub.** `iaga run` strips a denylist of 23 known
  secret-bearing variables from governed child processes, even when passed
  explicitly. Extend it with a TOML file at `IAGA_SENTINEL_ENV_DENYLIST`.
- **`verify-only` feature.** `iaga-sentinel-verify` gains a default-on `verify-only`
  feature so the reproducible build
  `cargo build --release -p iaga-sentinel-verify --no-default-features --features verify-only`
  is valid.

### What stayed

- Receipt JSON keys, canonical signing bytes, Ed25519 + SHA-256 chain link.
  Receipts with the new field absent are byte-identical to 1.3.0.
- HTTP API surface, Bearer auth, camelCase JSON keys.
- Database schema, APL AST, SDK surface.
- License: BUSL-1.1 with Change License Apache-2.0 baked in.
- All Enterprise categories in ADR 0010 §2.

Upgrade is risk-free.

---

## Future (not yet released)

The OSS line has no fixed milestone calendar. Bug fixes, dependency
hardening, documentation, ergonomic improvements, and security
advisories ship as they make sense, as 1.x.y patch or 1.x minor
releases. Concrete entries appear in this file when they ship.

Larger capabilities (real eBPF/LSM loader, cross-platform kernel
backends, governance mesh, KMS-backed signers, curated ML library,
EU AI Act / GDPR / DORA compliance pack, confidential-computing
receipts, forensic time-travel replay) are part of the IAGA
Sentinel Enterprise edition, see
[`ENTERPRISE.md`](ENTERPRISE.md).
