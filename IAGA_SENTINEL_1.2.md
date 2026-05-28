# IAGA Sentinel 1.2 — Notes

> 1.2 is the **primitive evolution release** of the OSS line. The
> 1.0 design shipped the full governance kernel; 1.1 held that line
> and clarified the OSS↔Enterprise boundary; 1.2 ships the four
> primitives that ADR 0010 §3 reinstated to the OSS roadmap.
>
> If you are looking for the 1.0 design rationale (the seven pillars,
> the twelve-layer defense in depth, the receipt model, APL),
> see [`IAGA_SENTINEL_1.0.md`](IAGA_SENTINEL_1.0.md). The 1.1 release
> note lives at [`IAGA_SENTINEL_1.1.md`](IAGA_SENTINEL_1.1.md).

---

## What 1.2 changes

Four primitives, all additive, all opt-in. **No breaking changes**
against 1.1. The OSS↔Enterprise boundary from ADR 0010 §2 is
reaffirmed verbatim — none of the 20 Enterprise categories slip
into OSS.

### 1. `Signer` trait + `LocalDiskSigner` (ADR 0011)

The receipt signer is now exposed as a public trait:

```rust
#[async_trait]
pub trait Signer: Send + Sync {
    fn key_id(&self) -> &str;
    fn verifying_key(&self) -> VerifyingKey;
    async fn sign_body(&self, body: ReceiptBody) -> Result<Receipt>;
}
```

The default impl, `LocalDiskSigner`, is the renamed `ReceiptSigner`
struct from 1.0 / 1.1. A type alias `pub type ReceiptSigner =
LocalDiskSigner;` keeps every existing callsite compiling unchanged.

`SignedReceiptLogger` now holds `Arc<dyn Signer>`, giving Enterprise
builds a clean injection point for KMS-backed signers without
recompiling the OSS core. The four native KMS SDK backends
(AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 HSM) remain
Enterprise — they plug behind the same trait. BYOK via filesystem
mount (`IAGA_SENTINEL_SIGNER_KEY_PATH`) stays OSS forever.

### 2. Drift replay additive (ADR 0012)

`ReceiptBody` gains three optional capture fields:
`pipeline_inputs_capture`, `apl_eval_trace`, `ml_inference_inputs`.
Populated only when the host opts in via env
`IAGA_SENTINEL_RECEIPT_CAPTURE=1`. When off, the serialization is
byte-identical to 1.1: chain hashes and signatures stay stable, mixed
1.1/1.2 stores verify cleanly.

New CLI flag `iaga replay --re-execute <run_id>` surfaces the
capture data per receipt and reports availability summary. **PII
warning**: when capture is on, the request payload travels into
the receipt store; treat backups accordingly.

Forensic time-travel (event sourcing + DB-state-per-verdict temporal
queries) stays Enterprise (ADR 0010 §2.13).

### 3. Plugin Sigstore + SBOM offline attestation (ADR 0013)

New Cargo feature `plugin-attestation` (default off, depends on
`base64`). When enabled, the WASM plugin loader looks for sibling
`<plugin>.sigstore.json` and `<plugin>.cdx.json` files at load time
and populates `PluginManifest.attestation` / `.sbom` /
`.attestation_offline_verified`. The receipt body's `PluginDigest`
gains optional `attested` and `attestation_issuer`.

**Scope is honest**: this is **offline structural verification only**
— bundle well-formedness + payload digest match. Rekor inclusion
proof and Fulcio root CA chain validation are not performed in
OSS 1.2. The CLI says so loudly:

```
note: offline verification only checks bundle structure + payload
digest. Full Rekor inclusion proof + Fulcio root attestation lives
in IAGA Sentinel Enterprise (see ENTERPRISE.md / ADR 0013).
```

For full chain-of-trust, run `cosign verify` out of band, or
upgrade to Enterprise (hosted marketplace + supply-chain SLA +
signed threat-intel feed).

CLI: `iaga plugin verify <path>` outputs a table or JSON report
and exits non-zero on bundle-present-but-verify-failed.

### 4. APL Hindley-Milner type checker + WASM codegen scaffolding (ADR 0014)

`crates/iaga-sentinel-apl/src/types.rs` implements Algorithm W over
the existing `Expr` enum. `compile_with_types(src)` is the new
entrypoint that pairs `compile()` with type inference. CLI:
`iaga policy check <file.apl>` prints per-policy `when` types and
reports type errors (`Mismatch`, `OccursCheck`, `BuiltinArity`,
`NonBoolWhen`).

`Ty::Unknown` is the sentinel for path lookups (`action.url.host`)
since the JSON context is dynamically typed. Builtin signatures are
hardcoded for the seven APL builtins (`contains`, `starts_with`,
`ends_with`, `len`, `lower`, `upper`, `secret_ref`).

New Cargo feature `apl-wasm` (default off, depends on `wasm-encoder`)
adds a WASM codegen scaffolding. The tree-walk evaluator
(`evaluate_program()`) remains the canonical executor — the WASM
MVP only handles literal + boolean / numeric / comparison
operations. Path / Call / Membership are rejected with clear errors.

```
policy compile: codegen failed: APL → WASM 1.2 MVP does not support
path lookups (`action.url`); use tree-walk evaluator
note: APL WASM MVP 1.2 supports literal + boolean / numeric /
comparison ops only. Path / Call / Membership remain on the
tree-walk evaluator. See ADR 0014.
```

CLI: `iaga policy compile <file.apl> [--output bundle.wasm]` (gated
on `apl-wasm`). Full WASM coverage + parity proptest is 1.3 work.

AOT-optimized codegen (cranelift opt-levels, WASI side-effects),
curated rule library + LSP / language server stay Enterprise.

---

## What did **not** change

- **License**: BUSL-1.1 with Change License Apache-2.0 baked in.
  Change Date `2030-05-03` preserved.
- **Naming**: everything is still `iaga-sentinel` / `iaga` / IAGA
  Sentinel. No `armor` anywhere.
- **HTTP API surface**: `/v1/inspect`, `/v1/receipts`, `/health`,
  Bearer auth, camelCase JSON keys.
- **Receipt JSON keys, signing-bytes canonical form, signature alg**:
  Ed25519, SHA-256 chain link. 1.1 receipts deserialize via serde
  defaults, signatures verify.
- **Database schema**: SQLite / Postgres backends for
  `iaga-sentinel-receipts` are unchanged; the `body_json TEXT`
  column transparently roundtrips the new optional fields.
- **APL AST + tree-walk evaluator**: `evaluate_program` is byte-for-byte
  unchanged.
- **All 20 Enterprise categories** in ADR 0010 §2.

---

## Feature flag cheat-sheet

```toml
# Cargo.toml of your host application
[dependencies]
iaga-sentinel-core = { version = "1.2", features = [
    "plugin-attestation",  # offline Sigstore + SBOM verify
    "apl-wasm",            # APL HM + WASM codegen
] }
```

```bash
# Drift-replay capture (off by default — PII implications)
export IAGA_SENTINEL_RECEIPT_CAPTURE=1
```

Default behaviour matches 1.1 exactly: no capture, no attestation,
no WASM codegen. Upgrade to 1.2 is risk-free.

---

## Forward (1.3 candidates)

The OSS line continues to ship additively. 1.3 candidates
(no fixed schedule):

- `iaga policy migrate` (YAML → APL converter) — debt closure for
  ADR 0008.
- Full APL WASM coverage (Path / Call / Membership with host imports)
  + parity proptest tree-walk vs WASM.
- Postgres + full cross-platform CI matrix (promote 1.2 compile-sanity
  to required CI status).
- Dependency hardening pass (the 3 RUSTSEC ignores).

Larger capabilities — real eBPF/LSM loader on Linux, macOS Endpoint
Security + Windows ETW kernel backends, governance mesh, native
KMS SDK backends, curated ML library, EU AI Act + GDPR + DORA
compliance pack, confidential-computing receipts, forensic
time-travel replay — remain part of IAGA Sentinel Enterprise
(see [`ENTERPRISE.md`](ENTERPRISE.md)).
