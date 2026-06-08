# ADR 0006: Kernel MVP

- **Status:** Accepted
- **Date:** 2026-04-25

## Context

The project needed a governed execution surface for launching tools and agents. A real kernel-enforcement backend has platform and build constraints, so the 1.0 line needed a portable MVP that reports its authority honestly.

## Decision

Introduce `iaga-sentinel-kernel` with:

- `UserspaceKernel`, a cross-platform launcher that gates child process execution through the policy pipeline.
- `BpfKernel`, a Linux-only scaffold behind `linux-bpf` that exposes the intended kernel-facing shape without claiming hard enforcement.
- `iaga run` and `iaga kernel status` as user-facing CLI surfaces.

`UserspaceKernel` uses a conservative environment model: a small allowlist plus explicitly supplied variables, with later hardening for known secret-bearing variables.

## Consequences

The open build can govern command execution on Linux, macOS, and Windows without requiring privileged kernel setup. The status command makes the posture explicit: the default open build is soft enforcement.

The MVP does not market hard blocking it does not provide. Authoritative kernel enforcement remains a separate implementation concern layered behind the same public abstractions.
