# IAGA Sentinel Enterprise

IAGA Sentinel Enterprise is the commercial edition built around the same evidence core as the open build. The open repository remains the source-verifiable runtime: signed receipts, deterministic replay, Dictum policies, local verification, the CLI, the HTTP API, and the default dashboard.

Enterprise is for teams that need managed deployment, compliance workflows, identity integration, platform-specific enforcement, or support obligations that go beyond the public runtime.

## Open Build Boundary

The open build includes the public governance primitives:

- Signed receipt schema, Ed25519 signatures, and chain verification.
- Deterministic replay and the standalone `iaga-verify` verifier.
- Dictum parsing, validation, evaluation, and live overlay.
- Reasoning framework with bring-your-own ONNX models.
- Cross-platform userspace governance and honest enforcement posture reporting.
- BYOK through filesystem-mounted signing keys.
- Offline plugin attestation and signed plugin manifest primitives.

Features that ship in the open build are not silently moved behind an Enterprise-only gate. The public boundary is documented in [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).

## Enterprise Scope

Enterprise adds managed and platform-specific capabilities around the evidence core:

- Compliance evidence packaging for regulated reviews.
- Qualified-signature and managed-key integrations.
- SSO, RBAC, multi-tenancy, and operational audit workflows.
- Native SIEM and managed deployment options.
- Platform-specific authoritative enforcement implementations.
- Curated model and threat-intelligence packages.
- Commercial support and deployment assistance.

The open build remains useful on its own. Enterprise exists when a team needs the surrounding operational, compliance, and support layer.

## Evaluation

Start with the open build. It is the best way to inspect the evidence model, verify receipt chains, and decide whether the runtime fits your architecture.

For Enterprise discussions, contact `info@iaga.tech`.
