# ADR 0012: Additive Drift Replay Capture

- **Status:** Accepted
- **Date:** 2026-05-28

## Context

Basic replay verifies that a receipt chain is intact. Drift analysis needs optional inputs that allow a later run to compare behavior against the original decision context.

The feature must not change existing receipt bytes when capture is disabled.

## Decision

Add optional capture fields to the receipt body:

- `pipeline_inputs_capture`
- `apl_eval_trace`
- `ml_inference_inputs`

The fields are omitted from signing bytes when absent. Capture is disabled by default and enabled only through `IAGA_SENTINEL_RECEIPT_CAPTURE=1` or equivalent true values.

`iaga replay --re-execute` can inspect captured inputs and provide a replay path. Full reconstruction of historical database state or external threat-feed state is outside this feature.

## Consequences

Default behavior stays byte-compatible with earlier receipts. Teams that need drift analysis can opt into richer receipts with a clear data-handling trade-off.

Captured request payloads may contain sensitive data. Public docs must state that enabling capture changes the sensitivity of receipt backups and exports.
