# ADR 0011: Signer Trait and Local Disk Signer

- **Status:** Accepted
- **Date:** 2026-05-28

## Context

Signed receipts originally used a concrete local Ed25519 signer. That was enough for the first receipt implementation, but the public API needed a stable trait so alternative signers could be integrated without rewriting receipt logging.

## Decision

Introduce a `Signer` trait and keep `LocalDiskSigner` as the open-build implementation. `ReceiptSigner` remains as a compatibility alias where needed.

The trait covers the minimum public surface:

- key identifier
- verifying key
- async signing of receipt bodies

`LocalDiskSigner` continues to load or create a 32-byte Ed25519 key from the configured filesystem path, including `IAGA_SENTINEL_SIGNER_KEY_PATH`.

Native KMS/HSM SDK integrations are not included in the open build. They can be implemented behind the same trait without changing the receipt schema.

## Consequences

The open build keeps a simple, auditable signer path while giving downstream users a stable abstraction. Existing local signer workflows continue to work.

The trait intentionally avoids discovery protocols, URI factories, and managed lifecycle behavior. Those concerns can be added by deployments that need them without increasing the default binary surface.
