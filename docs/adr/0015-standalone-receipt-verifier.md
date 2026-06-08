# ADR 0015: Standalone Receipt Verifier and Run Export

- **Status:** Accepted
- **Date:** 2026-06-06

## Context

The central promise of signed receipts is independent verification. Before this ADR, verification was tied to the full `iaga` binary and its broader runtime dependencies.

## Decision

Add a slim `iaga-sentinel-verify` crate and `iaga-verify` binary. The verifier reads an exported run file and calls the same `verify_chain` implementation used by the runtime.

Add `iaga replay <run_id> --export <file.json>` to export:

- `run_id`
- `signer_verifying_key`
- `receipts`

The verifier accepts `--key <hex>` for an expected public key. If no key is provided, it can fall back to the embedded key while warning that this verifies internal consistency, not signer authenticity.

## Consequences

Auditors and downstream tools can verify receipt chains without a database, server, network connection, or full IAGA runtime.

The export format is stable enough for the verifier, but it is not yet a separately versioned public standard.
