# ADR 0016: OpenTelemetry Receipt Export

- **Status:** Accepted
- **Date:** 2026-06-06

## Context

Receipts should fit into the observability stacks teams already use. The server already has an in-process telemetry module, so receipt spans can reuse that path without adding a full OpenTelemetry SDK dependency.

## Decision

Add an `otel-receipts` feature to `iaga-sentinel-core`, disabled by default. When enabled, each signed receipt emits an OpenTelemetry-shaped span through the existing telemetry buffer and export endpoint.

The span includes receipt identifiers, verdict, risk score, hashes, signer key ID, timestamp, and chain metadata. Later releases can add broader GenAI semantic-convention mapping.

This is an in-process export path. It does not push directly to an OTLP collector.

## Consequences

Operators can correlate receipt evidence with existing traces and logs while keeping the default binary unchanged.

The feature is intentionally narrow. A full OTLP push exporter can be added later if the project needs one.
