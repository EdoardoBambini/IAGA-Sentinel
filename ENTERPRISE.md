# IAGA Sentinel Enterprise

> **Status — in development, not yet available.** IAGA Sentinel Enterprise is a planned commercial edition, currently in active development. The capabilities described on this page are planned directions, not shipping features. Nothing here is an offer to sell, a price quote, or a commitment to deliver any specific feature or date. Want to follow it, help shape it, or be first to try it? Leave your email at `info@iaga.tech` to join the early-access list and we will reach out as it takes shape.

IAGA Sentinel Enterprise is the planned commercial edition built around the same evidence core as the open build. The open repository is, and will remain, the source-verifiable runtime that is available today: signed receipts, deterministic replay, Dictum policies, local verification, the CLI, the HTTP API, and the default dashboard.

Enterprise is being designed for teams that will need managed deployment, compliance workflows, identity integration, platform-specific enforcement, or support arrangements that go beyond the public runtime.

## Open Build Boundary

The open build includes the public governance primitives, available today:

- Signed receipt schema, Ed25519 signatures, and chain verification.
- Deterministic replay and the standalone `iaga-verify` verifier.
- Dictum parsing, validation, evaluation, and live overlay.
- Reasoning framework with bring-your-own ONNX models.
- Cross-platform userspace governance and honest enforcement posture reporting.
- BYOK through filesystem-mounted signing keys.
- Offline plugin attestation and signed plugin manifest primitives.

Features that ship in the open build are not silently moved behind an Enterprise-only gate. The public boundary is documented in [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).

## Planned Enterprise Scope

The Enterprise edition is planned to add managed and platform-specific capabilities around the evidence core:

- Compliance evidence packaging for regulated reviews.
- Qualified-signature and managed-key integrations.
- SSO, RBAC, multi-tenancy, and operational audit workflows.
- Native SIEM and managed deployment options.
- Platform-specific authoritative enforcement implementations.
- Curated model and threat-intelligence packages.
- Support and deployment options.

These are planned directions rather than commitments, and the list will evolve as we build. The open build remains fully useful on its own.

## Early access

The open build is the best place to start today. It is the best way to inspect the evidence model, verify receipt chains, and decide whether the runtime fits your architecture.

If you would like to be among the first to try Enterprise, help shape its priorities, or simply be kept informed, leave your email at `info@iaga.tech` and we will add you to the early-access list. No commitment and no purchase, just early information.
