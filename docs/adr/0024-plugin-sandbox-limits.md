# ADR 0024: Plugin sandbox resource limits

- **Status:** Accepted
- **Date:** 2026-07-01

## Context

The WASM plugin host (`crates/iaga-sentinel-core/src/plugins/host.rs`, feature
`plugins`) loaded and ran guest modules on a default `wasmtime::Engine` with no
resource bounds. Plugins are memory-isolated (no host functions, no WASI), but
"isolated" is not "bounded": an untrusted or buggy plugin could infinite-loop or
allocate unbounded linear memory and starve the host process. Plugin evidence is
**advisory** — the pipeline already tolerates a plugin that errors — so the gap
was availability, not verdict integrity. This was a stated known limitation and
a pure OSS win (it does not overlap the Enterprise boundary in ADR 0010).

## Decision

Run every plugin guest under two bounds, applied per store:

- **Fuel metering** (`Config::consume_fuel(true)` + `Store::set_fuel`) bounds
  total guest instructions per call. Chosen over epoch interruption because it
  is deterministic and single-threaded — no background timer thread — which
  keeps replay reproducible and matches the "no clock/RNG in the decision path"
  invariant. Default budget `100_000_000`, tunable via
  `IAGA_SENTINEL_PLUGIN_FUEL`.
- **Linear-memory cap** via a `StoreLimits` resource limiter. Default 64 MiB,
  tunable via `IAGA_SENTINEL_PLUGIN_MEMORY_MB`. Instance/table budgets are left
  at wasmtime defaults (ponytail: the memory cap is what protects the host;
  capping tables risks rejecting a legitimate indirect-call plugin).

A guest that exhausts fuel or exceeds the memory cap **traps**. The trap surfaces
as `Err` from the call, which the registry already handles: the plugin is dropped
from the evidence outputs and recorded in `errors` (see `registry::evaluate`).
So resource exhaustion degrades exactly like any pre-existing plugin failure —
the host survives and the verdict is computed from the plugins that succeeded.

## Consequences

Operators can run untrusted community plugins without a runaway starving the
host, which is a prerequisite for a shared plugin ecosystem. Because fuel is
consumed deterministically per input, a given plugin either always completes or
always traps for a given request, so verdicts stay replay-reproducible and the
receipt's `plugin_digests` (module load hash) are untouched — signed-receipt
bytes are unchanged.

This is cooperative, resource-level sandboxing, stated honestly: it bounds a
*buggy or greedy* plugin, not a *maliciously crafted* one probing for a wasmtime
escape. Fuel/epoch/table hardening beyond the memory + instruction bounds, and
any authoritative isolation, remain future / Enterprise scope (consistent with
the kernel's `is_authoritative: false` posture and ADR 0010).
