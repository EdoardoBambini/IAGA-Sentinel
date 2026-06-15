# ADR 0023: Dictum Secret Detection, Host-Aware Egress, and Session Receipt Chains

- **Status:** Accepted
- **Date:** 2026-06-13

## Context

Three gaps surfaced when the policy and egress path was exercised with real
calls against a running sidecar.

1. **`secret_ref()` was a placeholder.** The Armor Policy Language exposed a
   `secret_ref(x)` builtin and shipped an example policy
   (`crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum`) that depended on it,
   but the evaluator returned a hardcoded `false`. The advertised "block secret
   egress" policy could never fire. A second, latent bug compounded it: the
   evaluator flattened a builtin's arguments to a runtime `Value` before
   dispatch, and object subtrees flatten to `Null`, so `secret_ref(action.payload)`
   never saw the payload at all.

2. **Dictum could not parse URLs.** The only string operations were substring
   matches (`contains`, `starts_with`). A per-host egress allowlist was
   impossible: a substring check for `hooks.slack.com` also matches the
   look-alike `hooks.slack.com.attacker.tld`, and the core workspace allowlist
   (`evaluate_policy`) compared the *raw* `destination` string against bare-host
   `allowed_domains`, so a full URL such as `https://api.github.com/x` failed
   the match and was force-blocked. Because the Dictum overlay only tightens a
   verdict, that core over-block could not be relaxed by a policy.

3. **Signed receipts never chained.** The receipt `run_id` was the per-action
   `event_id`, so every receipt was a length-1 run. The `parent_hash` Merkle
   linking existed but was never exercised; a multi-step session produced N
   independent receipts rather than one tamper-evident chain. Separately, a
   verdict forced by the policy layer (off-domain destination, unregistered
   tool, schema-invalid payload) was floored to the block threshold with only a
   generic "escalated by security layers" note, dropping the human-readable
   cause from the audit event and the receipt.

## Decision

- **Detect secrets in the Dictum crate.** Add a private `secrets` module to
  `iaga-sentinel-dictum` holding a fixed, lookaround-free credential/PII regex set
  (mirroring the core response-scanner) compiled once. `secret_ref` is
  special-cased before argument flattening: it resolves the argument's raw JSON
  subtree, serializes it, and runs the detector. Matching is pure (no I/O,
  clock, or RNG), so the evaluator stays deterministic for receipt replay. The
  detector lives in the Dictum crate, not the core, because core depends on the
  Dictum crate and never the reverse, and because `iaga policy test` must detect
  secrets standalone.

- **Add a hand-rolled `url_host()` builtin.** It extracts the lowercased host
  from a URL (scheme, userinfo, port, and path stripped; IPv6 brackets
  preserved). No URL-parsing dependency is added, keeping the crate lean and
  deterministic. Unparsable input yields `""`, which matches no allowlist entry
  and therefore blocks under a `not in` rule (fail-safe). The core
  `evaluate_policy` egress check is made host-aware the same way, with a small
  duplicated `host_of` helper (the Dictum crate is an optional dependency and that
  module compiles in every feature configuration, so it cannot import the Dictum
  function).

- **Group receipts by session and surface causes.** `StoredAuditEvent` gains an
  optional `session_id`, populated only from an explicit caller
  `metadata.sessionId` (never the agent-id fallback, which would chain unrelated
  session-less calls). The receipt `run_id` becomes `session_id` when present,
  else `event_id`. The field is elided from serialization when absent, so a
  session-less receipt stays byte identical to earlier releases and existing
  chains still verify. The risk scorer now appends the substantive policy
  findings to the verdict reasons whenever it escalates, and the schema-invalid
  block records its reason, so no `block` or `review` is reasonless.

## Consequences

- Secret-egress and per-host-allowlist policies now enforce as documented;
  `no_pii_egress.dictum` fires on a real credential.
- A full URL to an allowed host is no longer over-blocked, and look-alike-domain
  bypasses are caught by `url_host()`.
- A multi-action session produces one hash-chained run that `iaga-verify`
  validates end to end and that breaks at the exact tampered `seq`.
- Backward compatibility is preserved: the default build is unaffected by the
  optional `session_id` field, receipts without a session id are byte identical
  to 1.5.3, and the Dictum crate gains only `regex` and `once_cell` (already in the
  workspace lock). The duplicated `host_of` in core is a deliberate, documented
  copy to keep `evaluate_policy` free of a feature-gated dependency.
