# ADR 0007: M5 Hardening and Release-Candidate Posture

- **Status:** Accepted
- **Date:** 2026-04-25

## Context

Before the 1.0 release candidate, the project needed to reduce ambiguity around storage, async policy evaluation, demo behavior, and honest feature reporting.

## Decision

M5 includes:

- Async policy-check plumbing where runtime behavior already requires async work.
- Postgres receipt integration alongside SQLite.
- Clearer CLI status for features that are scaffolds or optional.
- Explicit demo seeding behavior instead of implicit production defaults.

Dictum as the primary runtime policy source is deferred to a dedicated ADR. Full drift replay, managed mesh behavior, and authoritative kernel loading are not part of M5.

## Consequences

The release-candidate line becomes easier to operate and easier to describe. Users can see what is active, what is optional, and what is only a scaffold.

The trade-off is that some ambitious features stay out of the release candidate. That is intentional: public docs should describe what the binary does today, not what a future implementation might do.
