# ADR 0005: Reasoning Plane MVP

- **Status:** Accepted
- **Date:** 2026-04-25

## Context

The reasoning plane adds probabilistic evidence to a deterministic governance pipeline. ML should never make the final decision by itself; it should provide signed evidence that policy can inspect.

## Decision

Create `iaga-sentinel-reasoning` as an optional crate. The default engine is `NoopEngine`; the optional `ml` feature enables a `TractEngine` that can load user-provided ONNX models from local paths.

Model output is normalized into `MlEvidence` and attached to the policy context. The pipeline continues if a model is missing or fails: failed ML contributes empty evidence, not a runtime crash or implicit allow/block decision.

The MVP tokenizer is intentionally simple and dependency-light. Real deployment-specific tokenization is left to configured models or later extension points.

## Consequences

The open build stays small by default while still providing a clean path for teams that want ML evidence. Because ML evidence is signed into receipts, later audits can see which models contributed to a decision.

The main limitation is that quality depends on user-provided models. Curated models, calibration pipelines, and managed model distribution are outside the MVP.
