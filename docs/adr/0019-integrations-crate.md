# ADR 0019: Integrations Crate

- **Status:** Accepted
- **Date:** 2026-06-09

## Context

The 1.4 release adds first-class agent and framework integrations across
Python, TypeScript, and Rust. Python and TypeScript SDK adapters already mirror
the public `POST /v1/inspect` wire contract instead of importing pipeline
internals. Rust users needed the same lightweight option.

## Decision

Add `crates/iaga-sentinel-integrations` as a standalone leaf crate. It mirrors
the public HTTP contract with serde `camelCase` types and ships an async
`SentinelClient` over `reqwest`.

The crate supports:

- `inspect`, which calls `POST /v1/inspect`.
- `inspect_with_policy`, with fail-open default behavior and fail-closed opt-in.
- `enforce`, which turns `block` and `review` decisions into errors for callers
  that want direct control-flow enforcement.

The crate does not depend on `iaga-sentinel-core`, and it does not redefine the
receipt schema or cryptographic verification logic. Signed receipts remain owned
by `iaga-sentinel-receipts`.

## Consequences

Rust integrations can depend on a small client crate instead of compiling the
server and pipeline. The public wire contract is now mirrored in the Python SDK,
TypeScript SDK, and Rust integrations crate, so contract changes must update all
three surfaces together.

Tests keep live-sidecar cases opt-in while unit tests cover serialization and
fail-open/fail-closed behavior offline.
