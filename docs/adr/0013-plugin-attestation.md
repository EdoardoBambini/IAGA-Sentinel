# ADR 0013: Offline Plugin Attestation

- **Status:** Accepted
- **Date:** 2026-05-28

## Context

The plugin system can load WASM files from `IAGA_SENTINEL_PLUGIN_DIR`. The open build needed a lightweight way to record and verify plugin provenance metadata without introducing heavy online dependencies.

## Decision

Add an optional `plugin-attestation` feature for offline Sigstore bundle and CycloneDX SBOM checks.

The verifier checks local sibling attestation files and records whether a plugin was structurally verified. It does not perform online Rekor lookup, Fulcio root validation, or live threat-intelligence matching.

Receipts can include optional plugin attestation metadata. When no attestation is present, existing receipt signing behavior is unchanged.

## Consequences

The open build gains a practical supply-chain primitive that works offline and in CI. The feature is default-off and avoids large cryptographic dependency chains.

The guarantee is intentionally scoped: offline structural verification is not a complete public-key infrastructure or live reputation system. Operators that need stronger chain-of-trust checks can layer those checks externally or use a managed deployment.
