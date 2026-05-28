<h1 align="center">IAGA Sentinel 1.0</h1>

<p align="center">
  <strong>Zero-trust governance kernel for autonomous AI agents.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.1.0-blue" alt="version" />
  <img src="https://img.shields.io/badge/license-BUSL--1.1-blue" alt="license" />
  <img src="https://img.shields.io/badge/12%20layers-defense%20in%20depth-green" alt="12 layers" />
  <img src="https://img.shields.io/badge/Rust-stable-orange" alt="Rust" />
</p>

<p align="center">
  <a href="#what-1-0-is">What 1.0 is</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#status">Status</a>
</p>

<p align="center">
  <img src="media/hero.gif" alt="IAGA Sentinel — kernel-enforced governance for autonomous agents" width="720" />
</p>

---

## What 1.0 is

Three things in one binary, glued by a typed deterministic policy language:

1. **A kernel.** IAGA Sentinel sits below the agent SDK. Process launches go
   through `iaga run`, which consults the governance pipeline before
   spawning. The 0.4.0 HTTP sidecar still works for SDK-aware agents;
   the kernel is the chokepoint for everything else.
2. **A signed log.** Every governance verdict produces an Ed25519-signed
   receipt linked to the previous one in a Merkle append-log per run.
   Replay verifies the chain bit-exact and detects policy drift.
3. **A reasoning brain.** Optional ML models (ONNX, opt-in) emit
   evidence — never verdicts. The deterministic policy decides; ML
   produces scores the policy can read. Receipts embed the SHA-256 of
   every model that touched the decision.

All driven by APL: a typed DSL with deterministic tree-walk evaluation,
loadable as a `--policy` overlay on top of the YAML profile system.

---

## Quickstart

### Install + start

```bash
cargo install --path crates/iaga-sentinel-core

# Default sqlite, demo data seeded on first boot
iaga serve
```

### CLI flow (no auth)

```bash
# Path to a JSON file (camelCase keys, see note below)
iaga inspect ./payload.json

# Launch a child process under the governance pipeline
iaga run --agent-id openclaw-builder-01 -- python my_agent.py

# Replay the signed receipt chain
iaga replay --list
iaga replay <run_id>
iaga replay <run_id> --verify-only      # signatures + Merkle links only
iaga replay <run_id> --re-execute       # 1.2: surface drift-replay capture
                                        # (set IAGA_SENTINEL_RECEIPT_CAPTURE=1 on serve)

# Test an APL policy file
iaga policy lint crates/iaga-sentinel-apl/examples/no_pii_egress.apl
iaga policy test crates/iaga-sentinel-apl/examples/no_pii_egress.apl \
    --context crates/iaga-sentinel-apl/examples/sample_context.json

# 1.2 — Hindley-Milner type-check (always available)
iaga policy check crates/iaga-sentinel-apl/examples/no_pii_egress.apl

# 1.2 — compile APL to a WASM module (requires --features apl-wasm)
iaga policy compile policy.apl --output policy.wasm

# 1.2 — verify a plugin's Sigstore bundle + SBOM (requires --features plugin-attestation)
iaga plugins verify ./plugins/my-plugin.wasm

# Inspect kernel + reasoning posture
iaga kernel status
iaga reasoning info

# Load an APL bundle as a live overlay on top of YAML
iaga serve --policy crates/iaga-sentinel-core/examples/policies/strict.apl
```

### HTTP API flow

```bash
# Generate an API key once
iaga gen-key --label my-app
# → Key: iaga_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Inspect via HTTP. Auth header is `Authorization: Bearer <key>`.
# Payload uses camelCase: agentId, toolName, actionType.
curl -X POST http://localhost:7777/v1/inspect \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer iaga_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' \
  -d '{
    "agentId":  "openclaw-builder-01",
    "framework":"langchain",
    "action": {
      "type":     "shell",
      "toolName": "bash",
      "payload":  {"cmd": "ls"}
    }
  }'
```

### Docker

```bash
docker compose up -d
curl http://localhost:4010/health     # → 200
docker compose down
```

The container persists its DB and signer key in a named volume
(`iaga-sentinel-data`). Receipts signed inside the container can only be
verified by the same container; to share a signer key across deployments
mount your own key file or set `IAGA_SENTINEL_SIGNER_KEY_PATH`.

### Postgres

```bash
DATABASE_URL=postgres://user:pwd@host/iaga_sentinel \
  cargo install --path crates/iaga-sentinel-core --features postgres

iaga serve   # receipts now go to Postgres automatically
```

---

## Features

Cargo features on `iaga-sentinel-core`:

| Feature      | Default | Adds                                                                  |
|--------------|---------|------------------------------------------------------------------------|
| `sqlite`     | ✅      | SQLite backend for audit + receipts.                                   |
| `postgres`   | ❌      | Postgres backend.                                                      |
| `receipts`   | ✅      | Ed25519-signed Merkle-chained receipts (M2).                           |
| `apl`        | ✅      | Agent Policy Language parser + evaluator + `iaga policy ...` (M3).    |
| `reasoning`  | ✅      | Reasoning plane scaffold + `iaga reasoning info` (M3.5).              |
| `ml`         | ❌      | `tract-onnx` ML backend; opt-in, +~5 MB binary, +~2 min cold compile.  |
| `kernel`     | ✅      | Enforcement kernel + `iaga run` + `iaga kernel status` (M4).         |
| `linux-bpf`  | ❌      | Linux eBPF/LSM scaffold + ringbuf API. Real Aya-rs loader lives in IAGA Sentinel Enterprise. |
| `ui-embed`   | ❌      | Embeds `ui/dist/` into the binary via `rust-embed`.                    |
| `plugin-attestation` | ❌ | Offline Sigstore bundle + CycloneDX SBOM verify + `iaga plugins verify` (1.2). |
| `apl-wasm`   | ❌      | APL → WASM codegen MVP + `iaga policy compile` (1.2). The Hindley-Milner type checker (`iaga policy check`) is always on, no feature needed. |

`default = ["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]`.

---

## Architecture

12 layers of defense in depth, organized into 7 architectural pillars
described in [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md):

1. **Enforcement Kernel** — `crates/iaga-sentinel-kernel/` (M4 scaffold + `UserspaceKernel` cross-platform soft enforcement; real eBPF/LSM loader + macOS ES + Windows ETW/WFP backends in IAGA Sentinel Enterprise).
2. **Signed Receipts** — `crates/iaga-sentinel-receipts/` (M2).
3. **Agent Policy Language** — `crates/iaga-sentinel-apl/` (M3 tree-walk + M6 live overlay + 1.2 Hindley-Milner type checker; 1.2 WASM codegen MVP behind `apl-wasm` feature, full coverage in 1.3).
4. **Attested Plugins** — supply-chain integrity. 1.2 offline Sigstore + SBOM CycloneDX primitive behind `plugin-attestation` feature; private hosted marketplace + supply-chain SLA + signed threat-intel feed in Enterprise.
5. **Governance Mesh** — single-cluster baseline + tier-2 multi-region active-active live in Enterprise.
6. **Visual Plane** — `ui/` embedded via `ui-embed` feature.
7. **Probabilistic Reasoning** — `crates/iaga-sentinel-reasoning/` (M3.5 scaffold + `tract` backend + BYO ONNX; curated ML library in Enterprise).

Workspace layout:

```
iaga-sentinel/
├── crates/
│   ├── iaga-sentinel-core/          # pipeline, server, CLI, AppState
│   ├── iaga-sentinel-receipts/      # Ed25519 + Merkle log + replay
│   ├── iaga-sentinel-apl/           # APL parser + evaluator
│   ├── iaga-sentinel-reasoning/     # ML evidence (tract-onnx behind `ml`)
│   └── iaga-sentinel-kernel/        # cross-platform launcher + eBPF scaffold
├── docs/adr/                # 13 ADRs (0001–0014, no 0009)
├── ui/                      # frontend (embedded via ui-embed feature)
├── media/                   # hero assets
├── IAGA_SENTINEL_1.0.md       # design document (+ 1.1, 1.2 release notes)
├── MIGRATION.md             # 0.4.0 → 1.0 → 1.1 → 1.2 per-milestone notes
└── CHANGELOG.md             # release notes
```

---

## Documentation

- **Design**:
  [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md),
  [`IAGA_SENTINEL_1.1.md`](IAGA_SENTINEL_1.1.md),
  [`IAGA_SENTINEL_1.2.md`](IAGA_SENTINEL_1.2.md)
- **Migration from 0.4.0**: [`MIGRATION.md`](MIGRATION.md)
- **Release notes**: [`CHANGELOG.md`](CHANGELOG.md)
- **Architectural decisions**:
  - [ADR 0001 — Workspace split](docs/adr/0001-workspace-split.md)
  - [ADR 0002 — Open-source license + scope decisions](docs/adr/0002-open-source-license-and-scope.md)
  - [ADR 0003 — Signed receipts design](docs/adr/0003-signed-receipts-design.md)
  - [ADR 0004 — APL MVP](docs/adr/0004-apl-mvp.md)
  - [ADR 0005 — Reasoning plane MVP](docs/adr/0005-reasoning-plane-mvp.md)
  - [ADR 0006 — Kernel MVP](docs/adr/0006-kernel-mvp.md)
  - [ADR 0007 — M5 hardening + RC posture](docs/adr/0007-m5-hardening-rc.md)
  - [ADR 0008 — APL as live policy engine](docs/adr/0008-apl-as-live-policy-engine.md)
  - [ADR 0010 — OSS↔Enterprise boundary clarification](docs/adr/0010-oss-enterprise-boundary.md)
  - [ADR 0011 — `Signer` trait + `LocalDiskSigner` (OSS 1.2)](docs/adr/0011-signer-trait-and-local-disk.md)
  - [ADR 0012 — Drift replay additive (OSS 1.2)](docs/adr/0012-drift-replay-additive.md)
  - [ADR 0013 — Plugin Sigstore + SBOM attestation (OSS 1.2)](docs/adr/0013-plugin-attestation.md)
  - [ADR 0014 — APL HM type checker + WASM codegen scaffolding (OSS 1.2)](docs/adr/0014-apl-wasm-and-types.md)
- **Contributing**: [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## Status

**1.0 GA shipped.** All six 1.0 milestones complete, 234/234 default
tests passing, clippy `--all-targets -D warnings` clean. **1.1.0
released as a consolidation minor** (binary swap, zero runtime change,
boundary clarification only). **1.2.0 ships the four reinstated
primitives** — see [`IAGA_SENTINEL_1.2.md`](IAGA_SENTINEL_1.2.md).

What's intentionally honest about the posture:

- `iaga kernel status` reports `authoritative: no (soft enforcement)`
  on `UserspaceKernel`. The real Aya-rs eBPF/LSM loader (Linux,
  authoritative kernel enforcement) lives in IAGA Sentinel Enterprise.
  We don't market enforcement we don't yet provide in the OSS build.
- `iaga reasoning info` reports `engine: noop` unless models are
  configured. The reasoning framework + `TractEngine` + BYO ONNX are
  in OSS; the curated ML model library (intent-drift /
  prompt-injection / anomaly-seq pre-trained, signed, threat-intel
  fed) lives in Enterprise.
- APL today is tree-walking, fully deterministic, and replay-safe.
  **1.2 adds the Hindley-Milner type checker** (always available via
  `iaga policy check`) and a **WASM codegen scaffolding MVP** (gated
  on the `apl-wasm` Cargo feature) for literal + boolean / numeric /
  comparison expressions. The tree-walk evaluator remains canonical
  for the full APL surface; full WASM coverage with host imports for
  Path / Call / Membership is 1.3 work.
- macOS Endpoint Security + Windows ETW/WFP kernel backends,
  governance mesh, native KMS SDK signers (AWS KMS / Azure Key Vault
  / HashiCorp Vault / PKCS#11), GPU ML — all in IAGA Sentinel
  Enterprise. The boundary is documented in
  [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).

**1.2.0 (shipped)** lands the four primitives ADR 0010 §3
reinstated to the OSS roadmap:

1. `Signer` trait + `LocalDiskSigner` refactor (ADR 0011).
2. Drift replay additive + `iaga replay --re-execute` (ADR 0012).
3. Plugin Sigstore + SBOM CycloneDX offline attestation (ADR 0013,
   feature `plugin-attestation`).
4. APL Hindley-Milner type checker + WASM codegen MVP (ADR 0014,
   feature `apl-wasm`).

All four are additive — no breaking changes against 1.1. Features
are opt-in; default behaviour matches 1.1 byte-for-byte. The 1.x
line continues to ship additively.

**1.3 candidates** (no schedule): `iaga policy migrate` (YAML → APL),
full WASM coverage + parity proptest, postgres CI matrix, dependency
hardening pass. Larger Enterprise-side capabilities remain in
[IAGA Sentinel Enterprise](ENTERPRISE.md).

---

---

## Community vs Enterprise

> **IAGA Sentinel Enterprise: from governance kernel to audit dossier in 14 days.**

The governance kernel is the same in both editions. Enterprise adds
modules that live in a separate commercial repository. The table below
lists only what is **verifiable today** — what you can clone, build,
inspect, or call against a running instance. The OSS↔Enterprise
boundary (20 Enterprise categories + 4 primitives reinstated to OSS
1.2 roadmap) is documented in
[`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).

### What ships in the open-source build today (this repository)

Verifiable by `git clone && cargo test --workspace && docker compose up -d`:

- **12-layer governance pipeline** — single binary, single endpoint
  (`POST /v1/inspect`), 259/259 default tests passing.
- **Signed action receipts** — Ed25519 + Merkle append-log per run,
  verifiable offline with `iaga replay <run_id> --verify-only`.
- **Agent Policy Language (APL)** — typed DSL with deterministic
  tree-walk evaluator, instruction budget, short-circuit evaluation.
  Try with `iaga policy lint <file.apl>`.
- **APL live overlay** — load a bundle as `iaga serve --policy
  <file.apl>`. Stricter-wins merge with the YAML profile system.
- **Reasoning plane scaffold** — `iaga reasoning info`. Bring your
  own ONNX models via `--features ml` (`tract` backend, no native
  deps).
- **Cross-platform UserspaceKernel** — `iaga run -- <cmd>` spawns
  governed child processes on Linux, macOS, Windows.
- **HTTP API with Bearer auth** — `iaga gen-key` then call
  `POST /v1/inspect` with `Authorization: Bearer <key>`.
- **SQLite and Postgres backends** — switch by setting
  `DATABASE_URL=postgres://...` and building with `--features
  postgres`. Receipts go to the matching backend automatically.
- **BYOK-ready signer** — `IAGA_SENTINEL_SIGNER_KEY_PATH` lets you point at
  any 32-byte Ed25519 key file, including one served by your KMS
  (AWS KMS, Azure Key Vault, HashiCorp Vault, on-prem HSM via the
  filesystem-mount pattern).
- **Docker deployment** — `docker compose up -d`, `/health` returns
  200 within ~10 seconds on the first attempt.
- **WASM plugin loading** — `iaga plugins list` and `iaga plugins
  validate <file.wasm>`.

Run the smoke yourself, every claim above is reproducible from a
clean checkout.

### What IAGA Sentinel Enterprise adds (separate commercial repository)

Verifiable on request with a sandbox instance — these are concrete
modules, not promises. Each lives in a separate commercial repo and
is not feasible to reimplement quickly from the OSS surface alone:

- **EU AI Act + GDPR + DORA compliance evidence engine.** Generates
  Annex IV dossiers, RoPA, DPIA, post-market monitoring reports,
  EU AI Office incident notifications. PDF + JSON-LD output, signed
  with qualified e-signatures (eIDAS). Tied to the OSS receipt
  schema so dossiers cite the chain that produced them.
- **DPO Dashboard.** Web app for human-in-the-loop review queues,
  escalation, SLA timers, audit-trailed approvals signed Ed25519 for
  non-repudiation.
- **Multi-tenant isolation paths.** Schema-per-tenant DB layer,
  per-tenant resource quotas, cross-tenant audit isolation,
  tenant lifecycle management.
- **Enterprise SSO.** SAML 2.0 + OIDC + SCIM provisioning,
  fine-grained RBAC with role inheritance, MFA enforcement,
  IP allowlist per tenant.
- **eIDAS qualified signature pipeline.** ETSI EN 319 132
  (XAdES / PAdES / CAdES), Long-Term Validation profile, connectors
  to specific EU Trust Service Providers. Receipts gain legal
  weight in EU jurisdictions.
- **Native SIEM connectors.** Splunk, Datadog, Elastic, Sentinel,
  Chronicle. Field mappings done; not "send us a webhook".
- **Air-gapped distribution.** Offline update channel with signed
  bundle delivery, custom installer, air-gap registry, bundle
  verification chain.
- **Founder-led support.** SLA 99.95%, 24/7 oncall handled by the
  same team that wrote the kernel. No tier-1 ticket triage.
- **Iaga Cloud managed deployment** — when you do not want to run
  the box yourself.

The compliance pieces require a compliance officer + EU regulatory
lawyer kept current as the regulator publishes new guidelines. That
work is what you are paying for, on top of the code itself.

### Open-core promise

The conceptual governance kernel — receipt schema, replay algorithm,
APL evaluator (with WASM codegen + Hindley-Milner type checker in OSS
1.2), reasoning framework with BYO ONNX, `UserspaceKernel`
cross-platform soft enforcement, `BpfKernel` Linux scaffold with
honest "soft enforcement" posture, BYOK signer pattern + `Signer`
trait + `LocalDiskSigner` (OSS 1.2), Sigstore + SBOM plugin
attestation primitive (OSS 1.2), drift replay additivo (OSS 1.2)
— is the open-source build. It is licensed under **BUSL-1.1** with
**Change License: Apache-2.0** baked into the licence itself: four
years after publication every release converts automatically and
irrevocably to Apache-2.0. No manual switch, no walk-back possible.

The implementations that require specialist engineering at scale —
real Aya-rs eBPF/LSM loader on Linux, macOS Endpoint Security +
Windows ETW/WFP backends, governance mesh (single-cluster + tier-2),
four native KMS SDK backends, curated ML model library — live in
IAGA Sentinel Enterprise. None of them shipped in OSS 1.0 GA, so
moving them to Enterprise does not violate the **never retroactively
remove from OSS** covenant.

The full boundary is documented in
[`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md)
and reinforced in [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md) §9 so
future founders cannot rewrite it.

### Why Enterprise exists

For teams in regulated environments (banks, insurers, healthcare,
public sector, critical infrastructure), the question is not *"can
we be compliant"* — OSS answers that. The question is *"can we
**prove** it to the auditor / notified body / DPO / regulator
within two weeks instead of six months"*. Enterprise turns the OSS
mechanisms into the dossiers, dashboards, and signed evidence packs
that the EU AI Act, GDPR, and DORA ask for in their acceptance
language, and gives you a phone number to the people who wrote the
governance kernel when something goes wrong.

See [`ENTERPRISE.md`](ENTERPRISE.md) for the full Enterprise pitch
and the EU AI Act / GDPR / DORA article-by-article mapping. Contact:
`enterprise@iaga.start@gmail.com`.

---

## License

The open-source build of IAGA Sentinel is licensed under
[**Business Source License 1.1**](LICENSE) with **Change License:
Apache-2.0** and a **Change Date** of four years from publication.
What that means in plain English:

- You can run, copy, modify, and redistribute IAGA Sentinel freely for
  internal use, research, evaluation, and any non-production use.
- You can run IAGA Sentinel in production *as long as your use does not
  consist of offering IAGA Sentinel itself to third parties as a hosted
  or managed service that exposes a substantial set of its features*
  (see the Additional Use Grant in [`LICENSE`](LICENSE)). Building
  your own product *on top of* IAGA Sentinel for your customers is
  fine.
- Four years after each release is published, that specific release
  converts automatically and irrevocably to **Apache-2.0**. The
  conversion is written into the licence itself, so it is not
  something we can walk back later.

IAGA Sentinel Enterprise is sold under a separate commercial agreement.
The two share the same kernel; Enterprise adds modules that live in a
separate repository and are not covered by this licence.

Repository: <https://github.com/EdoardoBambini/IAGA-Sentinel>
Contact: `iaga.start@gmail.com`
