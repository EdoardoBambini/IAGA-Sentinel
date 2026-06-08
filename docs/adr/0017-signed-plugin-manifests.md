# ADR 0017: Signed Plugin Manifests

- **Status:** Accepted
- **Date:** 2026-06-06

## Context

ADR 0013 added offline attestation checks. The plugin loader also needed a simple way for operators to pin trusted signer keys and verify a plugin-specific manifest.

## Decision

Add `plugin-manifest-signing`, disabled by default. A plugin can ship with:

- `<plugin>.manifest.json`
- `<plugin>.manifest.json.sig`

The manifest records plugin name, version, SHA-256 digest, creation time, and signer key ID. The signature is Ed25519 over the manifest bytes.

Add CLI commands to sign and verify manifests:

- `iaga plugins sign-manifest <wasm>`
- `iaga plugins verify-manifest <wasm> --trusted-keys <file>`

## Consequences

Operators can verify plugin integrity and signer identity against a local trust list without introducing new heavy cryptographic dependencies.

This does not create a global trust hierarchy. Key provenance and policy for trusted keys remain operator responsibilities.
