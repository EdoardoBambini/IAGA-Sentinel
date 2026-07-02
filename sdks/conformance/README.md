# Cross-language verifier conformance vectors

`golden_chain.json` is a signed `ChainExport` produced by the **canonical Rust
code**, used to prove that non-Rust offline verifiers reach the same verdict
from the same signed bytes (roadmap 1.3, "verifier sovereignty").

Regenerate it deterministically (fixed key seed, fixed fields):

```sh
cargo run -p iaga-sentinel-verify --example emit_golden_export > sdks/conformance/golden_chain.json
```

Verifiers checked against it:

- **Rust (canonical):** `cargo run -p iaga-sentinel-verify --bin iaga-verify -- sdks/conformance/golden_chain.json --key ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c`
- **Python (no dependencies):** `python sdks/python/iaga_verify.py sdks/conformance/golden_chain.json --key <hex>` — tested in `sdks/python/tests/test_iaga_verify.py`.
- **Node/TypeScript (no dependencies):** `node sdks/typescript/verify.mjs sdks/conformance/golden_chain.json --key <hex>` — tested in `sdks/typescript/verify.smoke.mjs`. Uses `node:crypto`; a browser WASM/WebCrypto build is a follow-up.

All produce the same `CHAIN OK … seq=0..N …` line and the same exit codes
(0 valid, 1 broken/empty, 2 usage, 3 IO/parse/unsupported). A receipt carrying
floating-point values (e.g. `ml_scores`) is the one shape the dependency-free
re-serializers refuse rather than risk a divergent verdict; use the Rust
verifier for those.

## Conformance suite (1.9)

`manifest.json` turns this directory into a runnable badge: a verifier "passes
the IAGA receipt suite" when it agrees with every vector's expected outcome.

| vector | expect | what it proves |
| --- | --- | --- |
| `golden_chain.json` | `ok` | a genuine 4-receipt chain verifies against the pinned key |
| `tampered_chain.json` | `broken` | flipping a single signature byte is caught (negative test) |
| `empty_chain.json` | `empty` | an empty export is reported as empty, not silently "valid" |

`expect` is `ok` (valid), `broken` (a signature or Merkle link fails), or
`empty` (no receipts); `key` is the hex Ed25519 public key each vector is pinned
to. Run the whole corpus with the canonical verifier:

```sh
cargo run -p iaga-sentinel-verify --bin iaga-verify -- --conformance sdks/conformance/
# -> PASS golden_chain.json ok / PASS tampered_chain.json broken / ...
#    CONFORMANCE OK  3/3 vectors passed   (exit 0)
```

It prints `PASS`/`FAIL` per vector and exits non-zero if any vector disagrees,
so it drops straight into CI. To add a vector, drop a new `<name>.json` export
here and add a line to `manifest.json`; negative (`broken`) vectors are as
valuable as positive ones.
