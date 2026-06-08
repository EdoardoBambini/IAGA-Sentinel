# ADR 0001: Workspace Split

- **Status:** Accepted
- **Date:** 2026-04-22

## Context

IAGA Sentinel started as a single runtime. The 1.0 line needed clearer ownership boundaries for the core pipeline, receipt verification, policy language, reasoning layer, and kernel-facing execution surface.

## Decision

Split the repository into a Cargo workspace with focused crates:

- `iaga-sentinel-core` for the server, CLI, pipeline, storage, dashboard, and integration surface.
- `iaga-sentinel-receipts` for signed receipts, Merkle linking, replay helpers, and storage abstractions.
- `iaga-sentinel-apl` for the Agent Policy Language parser, validator, and evaluator.
- `iaga-sentinel-reasoning` for optional ML evidence engines.
- `iaga-sentinel-kernel` for governed process execution and kernel-facing abstractions.

The default developer flow remains workspace-level: `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`.

## Consequences

The split makes public APIs easier to review and lets verification tools reuse receipt logic without pulling in the full server. It also makes feature flags clearer: ML, Postgres, plugin attestation, APL WASM, and receipt export can be enabled where they matter.

The trade-off is additional workspace coordination. Cross-crate changes now require more deliberate dependency direction and test coverage, but the resulting boundaries are healthier for a public project.
