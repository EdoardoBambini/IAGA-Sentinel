# ADR 0001 — Cargo Workspace Split (M1, "Fortezza Foundation")

- **Status:** Accepted
- **Date:** 2026-04-22
- **Context milestone:** IAGA Sentinel 1.0 — M1

> **Status update 2026-05-08**: il crate `iaga-mesh` citato come futuro M5 in
> questo ADR non è mai stato realizzato come crate OSS. La governance mesh è
> stata riallocata in IAGA Sentinel Enterprise — vedi
> [ADR 0010](0010-oss-enterprise-boundary.md) per il boundary corrente.
> I 5 crate OSS effettivamente shippati restano: `iaga-sentinel-core`,
> `iaga-sentinel-receipts`, `iaga-sentinel-apl`, `iaga-sentinel-reasoning`, `iaga-sentinel-kernel`.

## Context

IAGA Sentinel 0.4.0 ships as a single Cargo crate at `community/` with a
1900+ line `src/lib.rs` + `src/main.rs` and 15 submodules orchestrated
by a 983-line `pipeline/execute_pipeline.rs`. The 1.0 design
([`IAGA_SENTINEL_1.0.md`](../../IAGA_SENTINEL_1.0.md)) introduces five new
subsystems that must evolve independently: signed receipts (`iaga-sentinel-receipts`,
M2), the Agent Policy Language (`iaga-sentinel-apl`, M3), a probabilistic reasoning
plane (`iaga-sentinel-reasoning`, M3.5), a kernel-level enforcement layer
(`iaga-sentinel-kernel`, M4), and a governance mesh (`iaga-mesh`, M5).

## Decision

Convert the repo to a **Cargo workspace** in M1. Move the existing
single crate from `community/` to `crates/iaga-sentinel-core/` **without
internal refactoring**. Future milestones add new crates as additional
`[workspace] members`, each feature-gated, each depending on
`iaga-sentinel-core` or its successors — never the other way around until
explicit deprecation.

The short binary alias `iaga` is introduced alongside `iaga-sentinel`,
both compiled from the same `main.rs`, so the 1.0 branding can land
without breaking anyone's scripts.

## Alternatives considered

1. **Aggressive slice up front** — extract `pipeline/`, `storage/`,
   `plugins/` into separate crates immediately. **Rejected**: the
   15-module pipeline and the trait-based `AppState` coupling would
   cause weeks of refactor before any 1.0 feature lands. Risk of
   breaking tests is high and the refactor is unmotivated until APL
   (M3) reshapes the policy engine anyway.

2. **Stay mono-crate, add feature flags** — keep everything in
   `iaga-sentinel` and gate new subsystems via features. **Rejected**:
   compile times balloon, feature-flag combinatorics become the CI
   bottleneck, and downstream consumers can't pull in `iaga-sentinel-apl`
   without also pulling `iaga-sentinel-kernel` deps.

3. **Separate repos per subsystem** — `iaga-sentinel-core`,
   `iaga-sentinel-receipts`, etc., in independent repos. **Rejected**:
   coordinated versioning across 6 repos during heavy alpha
   development would dominate our process cost. Revisit post-1.0.

## Consequences

**Positive:**

- New crates can be added one at a time with their own feature flags
  and dependency graphs (ONNX Runtime for `iaga-sentinel-reasoning`, libbpf
  for `iaga-sentinel-kernel` on Linux, gRPC/tonic for `iaga-mesh`) without
  bloating `iaga-sentinel-core` compile time for users who don't need them.
- Workspace-level `Cargo.lock` gives deterministic builds across
  members.
- `cargo clippy --workspace` and `cargo test --workspace` enforce
  uniform quality across all crates.

**Negative / accepted trade-offs:**

- All users of the `community/` path must update scripts, CI, and
  docs (see [`MIGRATION.md`](../../MIGRATION.md)).
- The existing CI cache keys are invalidated; first post-merge
  CI run will be slow.
- `iaga-sentinel-core` is a monolith internally. This is a known
  debt, not a feature, and will be attacked milestone by milestone
  starting with M2 (extracting the receipt log).

## Scope of M1 changes

- New root `Cargo.toml` declaring `[workspace]` with a single member.
- `git mv community crates/iaga-sentinel-core`.
- Package name `iaga-sentinel-core`; binary names `iaga-sentinel` **and**
  `iaga`; library name `iaga_sentinel` unchanged.
- New `ui-embed` feature with a scaffolding `ui_embed.rs` module
  (the HTTP route for `/ui` is explicitly **not** wired in M1).
- `visual/` → `ui/`, `assets/` → `media/`, `.gitignore` hygiene.
- CI workflow rewritten to run from the workspace root.

No `.rs` source file in `iaga-sentinel-core` is refactored in M1. Any
behavioral regression found post-merge is therefore almost certainly
a path/cargo-config issue, not a code bug.
