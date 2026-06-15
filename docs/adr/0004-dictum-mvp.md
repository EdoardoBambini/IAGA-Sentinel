# ADR 0004: Dictum MVP

- **Status:** Accepted
- **Date:** 2026-04-23

## Context

The project needed a policy language that could express governance rules deterministically and be replayed from evidence. YAML profiles were useful for configuration, but not expressive enough as the long-term policy surface.

## Decision

Introduce `iaga-sentinel-dictum`, a standalone Rust crate for **Dictum** (formerly APL / Agent Policy Language). The MVP includes:

- A lexer and recursive-descent parser.
- A structural validator.
- A pure tree-walk evaluator with an instruction budget.
- A CLI surface for linting and dry-run evaluation against JSON context.

Dictum expressions are deterministic: no wall clock, no filesystem, no network, no randomness. Missing paths evaluate to `null`, and policies must handle absent values explicitly.

WASM execution is not part of the MVP. The tree-walk evaluator is the canonical execution path until a later ADR expands the WASM surface.

## Consequences

Dictum gives the project a replayable policy layer without tying policy authoring to server internals. Keeping the crate standalone makes it usable from future linting, IDE, and verification tools.

The MVP is deliberately conservative. It proves syntax, validation, and deterministic evaluation before becoming the only source of runtime policy decisions.
