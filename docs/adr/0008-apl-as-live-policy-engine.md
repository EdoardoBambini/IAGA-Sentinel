# ADR 0008: APL as a Live Policy Overlay

- **Status:** Accepted
- **Date:** 2026-04-25

## Context

ADR 0004 introduced APL as a standalone language. The next step was to let operators load APL policies into the running server without breaking existing YAML/profile behavior.

## Decision

APL becomes an optional live overlay loaded with `iaga serve --policy <file.apl>`. Existing YAML profiles and risk thresholds remain active. APL can only make the final decision stricter:

- `allow + allow = allow`
- any `review` result raises the decision to `review`
- any `block` result raises the decision to `block`

Receipts include the active policy hash when an APL bundle is loaded. If no APL policy is active, the hash remains the existing baseline value.

Automatic YAML-to-APL migration and hot reload are deferred. The first live integration favors deterministic behavior and clear evidence over migration convenience.

## Consequences

Operators can adopt APL gradually. Existing deployments keep their current profile behavior while gaining a stronger policy overlay when needed.

The stricter-wins merge model is easy to explain and replay. It also avoids a risky rewrite of the existing policy store during the 1.0 line.
