# IAGA Sentinel 1.1 — Notes

> 1.1 is a **consolidation + rebrand release** of the OSS line. The
> 1.0 design shipped the full governance kernel; 1.1 holds that line,
> renames the project to IAGA Sentinel, and clarifies how the OSS
> edition relates to the IAGA Sentinel Enterprise commercial product.
>
> If you are looking for the 1.0 design rationale (the seven pillars,
> the twelve-layer defense in depth, the receipt model, APL),
> see [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md). That document is
> still current.

---

## What 1.1 changes

Two things:

1. **Complete rebrand** — the project is renamed *Agent Armor → IAGA
   Sentinel* across the board: binary (`agent-armor` → `iaga`, with
   `iaga-sentinel` as the long-form name), crates (`armor-*` →
   `iaga-sentinel-*`), library import paths, environment variables
   (`AGENT_ARMOR_*` / `ARMOR_*` → `IAGA_SENTINEL_*`), the signer key
   directory (`~/.armor/` → `~/.iaga-sentinel/`), the default SQLite
   path (`agent_armor.db` → `iaga_sentinel.db`), the API-key prefix
   (`aa_` → `iaga_`), webhook headers (`X-Armor-*` →
   `X-Iaga-Sentinel-*`), and the MCP tool names (`agentarmor.*` →
   `iaga.*`).
2. **OSS↔Enterprise boundary** turned into an explicit public
   commitment (`CHANGELOG.md`, `MIGRATION.md`, `ENTERPRISE.md`,
   `README.md`, `docs/adr/0010-oss-enterprise-boundary.md`).

**Governance behaviour is unchanged.** The 12-layer pipeline, the
verdict logic, the receipt format (Ed25519 + Merkle), and the HTTP
API contract (endpoints, camelCase JSON, Bearer auth) are identical
to 1.0.0 — only names changed. The renames *are* breaking for CLI
users, operators, and crate consumers; see
[`MIGRATION.md`](MIGRATION.md) for the one-to-one mapping. Existing
API keys keep working — only newly generated keys use the `iaga_`
prefix.

## Why a release at all

To formalise the OSS line's posture going forward. The 1.0 GA was
the right scope for the open kernel. Subsequent capabilities
(real eBPF/LSM loader, cross-platform kernel backends, governance
mesh, KMS-backed signing, curated ML libraries, EU AI Act / GDPR /
DORA compliance tooling, confidential-computing receipts, forensic
time-travel replay) live in the Enterprise edition. 1.1 is the
release where that boundary becomes a public commitment instead of
an internal note.

## What stays in OSS, forever

The OSS edition keeps the full governance kernel:

- Enforcement kernel trait + `UserspaceKernel` cross-platform.
- `BpfKernel` scaffold (Linux, feature `linux-bpf`) with the same
  honest "soft enforcement" posture as 1.0 — `iaga kernel status`
  continues to report the truth.
- Receipt schema (Ed25519-signed, Merkle log, hash-chained per
  `run_id`) and the SQLite + Postgres backends.
- APL parser + validator + tree-walk evaluator + APL live overlay.
- Reasoning plane: `NoopEngine` always available, `TractEngine`
  (pure-Rust ONNX via `tract-onnx`) behind feature `ml`.
- 12-layer defence-in-depth pipeline.
- All CLI sub-commands.
- UI embedded via `ui-embed` feature.
- License: BUSL-1.1 with Change License Apache-2.0 baked in. Each
  release converts automatically to Apache-2.0 four years after
  publication.

These are the primitives. They will not be feature-gated, paywalled,
or rebranded. The promise from ADR 0002 stands.

## What lives in Enterprise

Capabilities where the value is **scale, UX, evidence, ops, or
contractual support** — not the security primitive itself —
ship in the Enterprise edition. See [`ENTERPRISE.md`](ENTERPRISE.md)
for the full list and EU AI Act / GDPR / DORA mapping. Headlines:

- Real eBPF/LSM loader (Linux authoritative kernel enforcement).
- macOS Endpoint Security + Windows ETW/WFP backends, distributed
  signed/notarized turnkey.
- Governance mesh (single-cluster + multi-region active-active).
- BYOK Signer KMS backends (AWS KMS, Azure Key Vault, HashiCorp
  Vault, PKCS#11 HSM) + managed key lifecycle + eIDAS qualified
  pipeline.
- Curated ML model library with threat-intel feed + GPU
  acceleration.
- Curated eBPF/LSM program library AI-specific.
- Confidential-computing receipts (SGX / SEV-SNP / Nitro Enclave).
- Forensic replay with time-travel.
- Compliance pack (Annex IV dossier, DPO dashboard, RoPA + DPIA,
  post-market monitoring, ISO/IEC 42001 console).
- Multi-tenant isolation, Enterprise SSO, native SIEM connectors,
  air-gapped distribution, founder-led 24/7 SLA, conformity
  assessment workflow with notified body.

## OSS roadmap going forward

No fixed milestone calendar for the OSS line. Improvements ship as
they make sense — bug fixes, dependency hardening, documentation,
ergonomics, security advisories. Larger capabilities are evaluated
case by case against the OSS↔Enterprise boundary documented above.

When something does ship, it lands as a minor (1.x) or patch
(1.x.y) release. Apart from the one-time 1.1 rebrand renames
(catalogued in [`MIGRATION.md`](MIGRATION.md)), the 1.x line keeps
the usual semver guarantee: no breaking API or behaviour changes.

## References

- 1.0 design: [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md)
- ADR series: [`docs/adr/`](docs/adr/)
- Enterprise pitch + boundary: [`ENTERPRISE.md`](ENTERPRISE.md)
- Migration: [`MIGRATION.md`](MIGRATION.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)
