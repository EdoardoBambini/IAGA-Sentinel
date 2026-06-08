# ADR 0003: Signed Receipts

- **Status:** Accepted
- **Date:** 2026-04-23

## Context

IAGA Sentinel's main artifact is evidence: every governance decision should produce a record that can be checked later without trusting a running server. The 1.0 line needed a compact receipt format, signing strategy, replay surface, and storage abstraction.

## Decision

Create `iaga-sentinel-receipts` as a reusable crate. Each receipt has a stable body, an Ed25519 signature, a signer key identifier, and a parent hash that links the run into a tamper-evident chain.

The receipt body includes the decision inputs needed for audit and replay: run and sequence identifiers, input and policy hashes, verdict, risk score, timestamp, optional plugin and model digests, and parent hash.

Use deterministic struct serialization for signing bytes. Avoid unordered maps in the signed body unless a future schema version introduces canonical JSON handling.

Store receipts behind a `ReceiptStore` trait with SQLite and Postgres implementations. The runtime treats receipt logging as best-effort: receipt failures are warned about, but they do not change the governance verdict.

## Consequences

Signed receipts become reusable outside the main server. The CLI can verify chains and later export them for standalone verification.

The receipt format intentionally starts narrow. KMS/HSM integrations and richer replay capture are separate design decisions layered on top of the same signed body model.
