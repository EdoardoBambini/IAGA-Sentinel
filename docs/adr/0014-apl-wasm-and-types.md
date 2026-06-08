# ADR 0014: APL Type Checker and WASM Codegen MVP

- **Status:** Accepted
- **Date:** 2026-05-28

## Context

APL started with a deterministic tree-walk evaluator. The language also needed stronger static checking and a public path toward WASM execution.

## Decision

Ship a Hindley-Milner style type checker for APL and an MVP WASM codegen path behind the `apl-wasm` feature.

The tree-walk evaluator remains canonical for the full language. WASM codegen supports a limited subset first: literals and simple boolean/numeric/comparison expressions that do not require context imports.

Do not add `wasmtime` to the APL crate. The compiler emits WASM bytes; hosts decide how to execute them.

## Consequences

APL authors get better feedback through `iaga policy check`, and the project has a public codegen primitive without expanding the default runtime footprint.

The WASM MVP is not a full replacement for tree-walk execution. Full context-aware WASM execution and parity testing can be added after the minimal public API is stable.
