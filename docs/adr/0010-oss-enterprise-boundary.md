# ADR 0010: Open Build and Enterprise Boundary

- **Status:** Accepted
- **Date:** 2026-05-08

## Context

IAGA Sentinel has an open build and a commercial Enterprise edition. The public repository needs a clear, stable boundary so users understand what they can verify from source and what belongs to the commercial product.

The open build already ships the evidence core: signed receipts, deterministic replay, Dictum, the reasoning abstraction with BYO ONNX, `UserspaceKernel`, the Linux `BpfKernel` scaffold, API and CLI surfaces, SQLite/Postgres storage, and the dashboard.

Some implementation tracks require platform-specific engineering, managed operations, or external compliance workflows. Those tracks are better described as Enterprise commitments instead of open-build features.

## Decision

The open build owns the conceptual governance kernel:

- Receipt schema, Ed25519 signatures, chain verification, and replay.
- Dictum parser, validator, evaluator, and live overlay.
- Reasoning framework with user-provided models.
- Cross-platform userspace governance and honest kernel status reporting.
- Public HTTP API, CLI, storage backends, and local dashboard.
- BYOK via filesystem-mounted signing keys.
- Public extension primitives such as plugin attestation and signed plugin manifests.

Enterprise owns managed, platform-specific, or compliance-delivery implementations:

- Authoritative kernel enforcement implementations.
- Native KMS/HSM signer integrations and managed key lifecycle.
- Multi-tenant, SSO, SIEM, and managed deployment features.
- Compliance dossier generation and qualified-signature workflows.
- Curated model libraries, managed threat intelligence, and operational support.
- Advanced forensic replay and confidential-computing deployments.

The rule is simple: open-build primitives remain public and verifiable; managed or highly specialized implementations may live in Enterprise.

## Public Promise

Features that ship in the open build are not silently moved behind an Enterprise-only gate later. Enterprise may add stronger implementations on top of public abstractions, but the public primitives remain available in the open build.

The CLI and evidence must report enforcement posture honestly. If the open build is using soft enforcement, receipts and status output should say so.

## Consequences

Users get a direct source-verifiable core and a clear understanding of which claims can be reproduced from a checkout. Enterprise positioning stays explicit without exposing internal plans, private paths, customer targeting, pricing logic, or milestone commitments.

Future docs should link to this ADR for the boundary, and should avoid relying on private design notes or unpublished roadmap files.
