# IAGA Sentinel 1.3 Notes

> 1.3 is the conformity-evidence release of the OSS line. The 1.0
> design shipped the governance kernel; 1.1 held the line and
> clarified the OSS and Enterprise boundary; 1.2 shipped the four
> reinstated primitives; 1.3 strengthens the trusted-evidence
> substrate with three additive primitives and reframes the public
> narrative around the EU AI Act conformity evidence layer.
>
> For the 1.0 design rationale (the seven pillars, the twelve-layer
> defense in depth, the receipt model, APL) see
> [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md). Prior release notes:
> [`IAGA_SENTINEL_1.1.md`](IAGA_SENTINEL_1.1.md),
> [`IAGA_SENTINEL_1.2.md`](IAGA_SENTINEL_1.2.md).

---

## What 1.3 changes

Three primitives, all additive, all opt-in. No breaking changes
against 1.2. Default behaviour and receipt bytes are unchanged with
the new features off. The OSS and Enterprise boundary from ADR 0010
§2 is reaffirmed: none of the Enterprise categories slip into OSS.

### 1. Standalone receipt verifier and run export (ADR 0015)

A new slim crate `iaga-sentinel-verify` produces the binary
`iaga-verify`: no database, no async runtime, about 3 MB against the
27 MB full binary. It reuses `verify_chain` to check the Ed25519
signatures and the Merkle links of a receipt chain offline.

Export a run, then verify it:

```bash
iaga replay <run_id> --export run.json
iaga-verify run.json --key <hex>     # CHAIN OK or BROKEN, exit 0 or 1
```

The expected public key is pinned with `--key`, which the auditor
pins out of band. Without `--key`, the verifier falls back to the key
embedded in the export and prints a loud warning that it is
self-asserted. This is the artifact you hand an auditor: the proof
verifies without trusting IAGA.

### 2. OpenTelemetry receipt export (ADR 0016)

New Cargo feature `otel-receipts` (default off, no new dependency).
Each signed receipt also surfaces as an OTel span
`iaga_sentinel.receipt` in the existing telemetry feed, carrying the
run id, seq, verdict, input and policy hashes, risk score, and signer
key id. It is visible via `GET /v1/telemetry/spans` and
`/v1/telemetry/export`, so any OpenTelemetry backend ingests the
evidence next to the rest of your observability.

Scope is honest: this is the in-process OTel feed and export
endpoint, not an OTLP push to a remote collector. That is a later
step.

### 3. Ed25519-signed plugin manifests (ADR 0017)

New Cargo feature `plugin-manifest-signing` (default off), orthogonal
to `plugin-attestation`. A plugin ships `<plugin>.manifest.json`
(name, version, plugin sha256, signer key id) plus a detached
`<plugin>.manifest.json.sig`. Verification checks that the manifest
sha256 matches the actual plugin bytes and that the signature
verifies against a trusted-key list.

```bash
iaga plugins sign-manifest my-plugin.wasm --name my-plugin --version 1.0.0
iaga plugins verify-manifest my-plugin.wasm --trusted-keys keys.txt
```

It reuses the receipts Ed25519 path and `LocalDiskSigner`. Scope is
honest: it verifies payload integrity and signer identity against
keys you trust, not key provenance or a PKI. Qualified eIDAS
signatures via a Trust Service Provider stay Enterprise.

---

## Positioning

1.3 also reframes the public narrative. The headline is the EU AI Act
conformity evidence layer for AI agents, not a generic governance
kernel. The README and ENTERPRISE.md lead with the evidence and the
honest posture: soft enforcement today, authoritative eBPF/LSM on the
Enterprise roadmap, sell the proof not the block. The operator
dashboard at `/` is restyled to a minimal theme. The unwired `ui/`
React visualization and the `ui-embed` feature are removed, keeping
the repository Rust-first.

---

## What did not change

- License: BUSL-1.1 with Change License Apache-2.0 baked in.
- Naming: everything is still `iaga-sentinel`, `iaga`, IAGA Sentinel.
- HTTP API surface, Bearer auth, camelCase JSON keys.
- Receipt JSON keys, canonical signing bytes, Ed25519 plus SHA-256
  chain link. Receipts produced with the new features off are
  byte-identical to 1.2.
- Database schema for `iaga-sentinel-receipts`.
- APL AST and tree-walk evaluator.
- All Enterprise categories in ADR 0010 §2.

---

## Feature flag cheat-sheet

```toml
[dependencies]
iaga-sentinel-core = { version = "1.3", features = [
    "otel-receipts",            # receipts as OpenTelemetry spans
    "plugin-manifest-signing",  # Ed25519 signed plugin manifests
] }
```

The standalone verifier is a separate binary:
`cargo install --path crates/iaga-sentinel-verify` gives you
`iaga-verify`.

Default behaviour matches 1.2 exactly. Upgrade to 1.3 is risk-free.

---

## 1.3.1, conformity closure (patch)

1.3.1 reconciles the shipped open build with the 1.3 roadmap's "verifier
sovereignty" OSS track (ADR 0018). All additive, no breaking changes against
1.3.0. Receipts produced before 1.3.1 verify unchanged; the new optional field is
elided when absent.

- **Receipt honesty flag.** `ReceiptBody` gains an optional `is_authoritative`
  field, set to `false` on every open-build receipt because OSS enforcement is
  soft (no authoritative kernel ships in the open build;
  `UserspaceKernel::is_authoritative()` is `false`). Elided from the signing bytes
  when absent, so 1.3.0 receipts stay byte-identical and verify unchanged.
- **OpenTelemetry roadmap keys.** The receipt span now also carries
  `iaga.receipt.id` (`run_id:seq`), `iaga.chain.head` (the receipt body hash),
  `iaga.policy.verdict`, and `iaga.is_authoritative`, alongside the existing
  `receipt.*` aliases. Full `gen_ai.*` GenAI semantic-convention alignment is a 1.4
  deliverable.
- **Sensitive-environment scrub.** `iaga run` strips a denylist of 23 known
  secret-bearing variables (cloud and model-provider credentials, registry tokens,
  the signing-key path) from every governed child process, even when passed
  explicitly via the launch spec. Extend the denylist at runtime with a TOML file
  at `IAGA_SENTINEL_ENV_DENYLIST`.
- **`verify-only` feature + CI coverage.** `iaga-sentinel-verify` gains a default-on
  `verify-only` feature so the reproducible build
  `cargo build --release -p iaga-sentinel-verify --no-default-features --features verify-only`
  is valid. CI now also exercises the `otel-receipts` and `plugin-manifest-signing`
  features, which previously had no coverage.

270/270 default tests pass. Upgrade from 1.3.0 is risk-free.

---

## Forward

The OSS line continues to ship additively. The larger capabilities
stay on the Enterprise side, or need an environment this milestone
could not build and test: the real eBPF/LSM loader on Linux, macOS
Endpoint Security and Windows ETW backends, curated ML models, the
governance mesh, and the EU AI Act, GDPR, and DORA compliance pack.
See [`ENTERPRISE.md`](ENTERPRISE.md).
