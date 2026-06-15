# ADR 0008: Dictum as a Live Policy Overlay

- **Status:** Accepted
- **Date:** 2026-04-25

## Context

ADR 0004 introduced Dictum as a standalone language. The next step was to let operators load Dictum policies into the running server without breaking existing YAML/profile behavior.

## Decision

Dictum becomes an optional live overlay loaded with `iaga serve --policy <file.dictum>`. Existing YAML profiles and risk thresholds remain active. Dictum can only make the final decision stricter:

- `allow + allow = allow`
- any `review` result raises the decision to `review`
- any `block` result raises the decision to `block`

Receipts include the active policy hash when a Dictum bundle is loaded. If no Dictum policy is active, the hash remains the existing baseline value.

Automatic YAML-to-Dictum migration and hot reload are deferred. The first live integration favors deterministic behavior and clear evidence over migration convenience.

## Consequences

Operators can adopt Dictum gradually. Existing deployments keep their current profile behavior while gaining a stronger policy overlay when needed.

The stricter-wins merge model is easy to explain and replay. It also avoids a risky rewrite of the existing policy store during the 1.0 line.
