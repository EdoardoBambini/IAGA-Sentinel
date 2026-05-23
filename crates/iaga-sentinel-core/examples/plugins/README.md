# Example Plugins

This folder contains a real IAGA Sentinel WASM plugin source that is compiled and
validated during tests.

## Files

- `review_hint.wat`: minimal plugin source in WAT format

## Why WAT here

The runtime loads `.wasm` files, but keeping the example in WAT lets the repo
ship a human-readable plugin without requiring a separate Rust-to-WASM toolchain
just to inspect the example. The CI/test path compiles this file to `.wasm` and
validates the exported IAGA Sentinel plugin contract.

## Local validation

From the workspace root:

```bash
cargo test -p iaga-sentinel-core --features plugins --test plugin_example_tests
```
