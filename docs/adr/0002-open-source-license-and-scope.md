# ADR 0002: License and 1.0 Scope

- **Status:** Accepted
- **Date:** 2026-04-23

## Context

The project needed a license and scope that supported public adoption while protecting the project from direct hosted-service resale during its early life. The 1.0 line also needed clear defaults for ML, kernel execution, and distributed governance.

## Decision

IAGA Sentinel uses Business Source License 1.1 with an automatic Change License to Apache-2.0 four years after each release is published. The conversion is written into `LICENSE`, so each release has a predictable open-source future without requiring a later relicensing action.

The default build remains lightweight:

- ML support is feature-flagged and off by default.
- The open build includes `UserspaceKernel` and a Linux `BpfKernel` scaffold with honest status reporting.
- The first public 1.0 release is single-node. Distributed mesh behavior is outside the 1.0 open-build runtime.

## Consequences

The license gives users a durable path to Apache-2.0 while limiting direct hosted-service reuse during the BUSL term. Contributors can review the exact terms in `LICENSE` before contributing.

The scope choices keep the default binary portable and easy to build. Advanced deployment features can be added without weakening the core public promise: shipped open-build features are not silently moved behind an Enterprise-only gate.
