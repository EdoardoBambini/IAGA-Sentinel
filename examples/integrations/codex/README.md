# IAGA Sentinel — OpenAI Codex CLI gate

Govern every Codex CLI tool call **inside Codex's own loop**. Before Codex runs
a shell command, applies a patch, or calls an MCP tool, the `iaga-codex hook`
binary asks the IAGA Sentinel sidecar for a verdict (`POST /v1/inspect`) and
**blocks** denied actions with exit code 2 — the model sees the policy
justification and can change course. Every governed call leaves one signed,
offline-verifiable receipt.

Unlike the observation-style adapters, this gate **fails closed by default**:
no verdict (sidecar down, timeout, unregistered agent) means the action does
not run. Set `IAGA_CODEX_FAIL=open` to trade enforcement for availability —
the coverage gap is then declared on stderr instead of being attested.

This is the **agent-loop** enforcement tier: stronger than advisory (a `block`
verdict actually stops the action), weaker than a kernel (whoever controls the
host can disable the hook, unless it is org-managed). The limit is recorded in
the evidence itself: every open-build receipt carries
`is_authoritative: false`. We do not market enforcement we do not provide.

## Status & version pin

> **What works & what's missing:** see [STATUS.md](STATUS.md) — the verified
> what-works list (gate, compiler, ingest, Phase 2 OS-sandbox egress) plus a
> small roadmap of what's left.
>
> **Codex version pin:** **`codex-cli 0.138.0-alpha.7`**. This README is the
> only place in the repository that pins the Codex version.
>
> **execpolicy compiler — validated.** The `.rules` syntax emitted by
> `iaga-codex export-rules` is confirmed against `codex execpolicy check` on
> the pinned version (pattern is an argv prefix of `str | list[str]`; an
> empty inner list like `["curl", []]` is invalid, not a wildcard;
> decisions are `allow` / `prompt` / `forbidden`; `match` / `not_match` are
> parse-time assertions). It lives in one file,
> `crates/iaga-sentinel-codex/src/execpolicy_format.rs`.
>
> ⚠ **Gate hook & ingest stream — pre-spike.** The Codex hook **payload
> field names**, the **hook registration syntax** (`config.toml.example`),
> and the **`codex exec --json` stream field names** (used by `ingest`, §9)
> are still provisional until the spikes capture real events. Each contract
> lives in exactly one file — the hook payload in
> `crates/iaga-sentinel-codex/src/codex_event.rs`, the exec stream in
> `crates/iaga-sentinel-codex/src/exec_stream.rs` — plus the
> `*.provisional.json{,l}` fixtures; nothing else changes when corrected.
> (Reference: hooks engine stable from ~v0.124.0, PreToolUse from ~v0.117.0.)

## Files

| File | Use |
|---|---|
| `codex.policy.yaml` | Registers the `codex` agent. **Required** (fail-closed gate: unregistered = everything blocked). |
| `config.toml.example` | Hook registration in Codex's `config.toml` (dev + org-managed paths). |
| `../../../crates/iaga-sentinel-codex/` | The plug-in crate: `iaga-codex` binary (`hook` + `export-rules`), all Codex-specific code. |

## 1. Build the gate binary

```bash
cargo build --release -p iaga-sentinel-codex
# -> ./target/release/iaga-codex
```

## 2. Start the sidecar

```bash
cargo build --release --workspace
IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

The sidecar listens on `http://localhost:4010`. If the sidecar enforces auth,
create an `agent`-scoped API key (`iaga gen-key --scope agent`) and export it
as `IAGA_API_KEY` in the environment Codex runs in.

## 3. Register the agent (required, not optional)

`/v1/inspect` returns `404` for unknown agents, and this gate fails closed —
an unregistered agent means **every tool call is blocked** with a message
pointing here. Import the bundled policy once:

```bash
./target/release/iaga import examples/integrations/codex/codex.policy.yaml
```

It maps Codex's tool names to action types and defaults every decision to
**allow**, so each call still produces a receipt while the injection firewall
independently blocks dangerous payloads (e.g. exfiltration of `.env` via
`curl`). Tighten any tool to `maxDecision: review` to require human approval.

## 4. Register the hook in Codex

Copy the hook entry from [`config.toml.example`](config.toml.example) into
your Codex `config.toml` and point it at the built binary.

- **Developer path:** user/project config. Codex requires explicit **trust**
  for non-managed hooks, pinned by content hash — review and approve with
  `/hooks` inside the Codex TUI. Verify the binary's checksum against the
  release artifact before trusting it.
- **Org-managed path:** ship the same entry via managed configuration
  (`requirements.toml` / MDM). Managed hooks are trusted by policy and cannot
  be disabled by the user's own config — this is what makes the gate
  non-optional on a fleet.

## 5. Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `IAGA_BASE_URL` | `http://localhost:4010` | Sidecar base URL. |
| `IAGA_API_KEY` | _(none)_ | Bearer token, if the sidecar requires auth (`agent` scope suffices). |
| `IAGA_CODEX_AGENT_ID` | `codex` | Registered `agentId` recorded on the receipt. The Codex `session_id` rides in `metadata`, never in the agent id. |
| `IAGA_CODEX_FAIL` | `closed` | `closed`: block when no verdict can be obtained. `open`: allow and declare the gap on stderr. |
| `IAGA_CODEX_TIMEOUT_MS` | `1000` | Hard timeout for the inspect round-trip (the hook runs synchronously inside Codex's loop). |

## 6. What the gate does

| IAGA decision | Gate result | Effect in Codex |
|---|---|---|
| `allow` | exit `0` | The tool call proceeds. A signed receipt exists anyway. |
| `block` | exit `2` + justification on stdout | The pending tool call is blocked; user and model see the policy reason. |
| `review` | exit `2` + review message | Conservative block: approve from the IAGA dashboard, then retry. (If the spike confirms Codex supports an "ask" hook response, `review` will map to it.) |
| _no verdict_ | fail policy | `closed` (default): exit `2`. `open`: exit `0`, gap declared on stderr, **no receipt**. |

Non-`PreToolUse` events are a declared no-op (exit `0`, no inspect call) in
this minimal gate; PostToolUse/SessionStart/Stop receipts are next.

The hook never interprets, interpolates, or logs the tool payload — it is
attacker-influenced (the model composes commands from repository content) and
crosses the gate as opaque JSON.

## 7. Verify a receipt offline

`auditEvent.eventId` from the verdict is the receipt's `run_id`:

```bash
./target/release/iaga replay --list
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json        # -> CHAIN OK
```

The exported receipt includes `is_authoritative: false` — the enforcement
posture is part of the signed evidence.

## 8. Compile a static execpolicy layer (defense in depth)

The gate is cooperative: whoever controls the host can disable the hook.
Codex's **native** execpolicy engine, by contrast, is evaluated by Codex
itself and holds even then. `export-rules` compiles your Dictum bundle into a
native `.rules` file so the two layers reinforce each other (both merge
strictest-wins: `forbidden` > `prompt` > `allow`).

```bash
cargo build --release -p iaga-sentinel-codex
./target/release/iaga-codex export-rules \
  --dictum path/to/bundle.dictum \
  --out codex-sentinel.rules
```

It emits one `prefix_rule` per Dictum policy that maps **faithfully** onto a
command prefix (e.g. `when starts_with(action.payload.command, "curl")` →
`pattern = ["curl"]`, `block` → `forbidden`). Policies with runtime
conditions (risk score, `contains`, membership, `secret_ref`, ML/usage) have
no static command-prefix equivalent: they are reported as **runtime-only**
and stay enforced by the gate. The file header carries the SHA-256 of the
source bundle so drift between the static and runtime layers is detectable.

Validate the generated file with Codex (parse-time `match`/`not_match`
assertions mean a clean parse is itself a round-trip test):

```bash
codex execpolicy check --pretty --rules codex-sentinel.rules -- curl http://evil.com
# -> {"decision":"forbidden", ...}
```

Register `.rules` files via your Codex `config.toml`; ship them through
managed config to make the static layer non-optional on a fleet.

## 9. Ingest session telemetry (advisory evidence)

The gate and the execpolicy layer act *before* a tool call. The **ingest**
acts *after* — it turns a `codex exec --json` run into the same signed,
offline-verifiable receipt chain, so even sessions that ran without the gate
leave evidence. This is the **advisory** tier: each observed action is
recorded as a receipt (`metadata.enforcement = "advisory"`), never blocked —
the action has already happened. The honesty line is the same:
`is_authoritative: false`.

It mints one receipt per **completed action** in the stream
(`command_execution`, `file_change`, `mcp_tool_call`, `web_search`);
reasoning, messages, and in-flight item updates mint nothing. Three input
modes:

```bash
cargo build --release -p iaga-sentinel-codex

# 1. Live pipe (attestation = live-ingest):
codex exec --json "tidy up the repo" | ./target/release/iaga-codex ingest

# 2. Spawn Codex and attest its stdout (attestation = live-ingest).
#    An absolute path works, so Codex need not be on PATH:
./target/release/iaga-codex ingest -- codex exec --json "tidy up the repo"

# 3. Re-process a captured stream (attestation = post-hoc):
./target/release/iaga-codex ingest --from session.jsonl
```

Each attested action prints a line you can paste straight into a replay, and
a final tally:

```
ATTESTED command_execution block receipt=<eventId>
ATTESTED file_change allow receipt=<eventId>
INGESTED events=14 actionable=5 attested=5 allow=4 review=0 block=1 failed=0
```

Then verify any receipt offline exactly as in §7
(`iaga replay <eventId> --export chain.json` → `iaga-verify chain.json` →
`CHAIN OK`). Exit codes: `0` fully attested, `1` a spawned command exited
non-zero, `2` an attestation gap (an action the sidecar could not verdict,
including an unregistered agent), `3` an I/O or usage error.

Ingest observes; it does not enforce. A `block` verdict here is *recorded*,
not applied — to actually stop an action, use the gate (§4) or the
execpolicy layer (§8). Tailing the rollout files under `~/.codex/sessions`
is intentionally unsupported: their format drifts across Codex minors, so
the live `--json` stream is the reliable source.

## 10. Run the tests

```bash
cargo test -p iaga-sentinel-codex
# round-trip against a real Codex binary on PATH:
cargo test -p iaga-sentinel-codex -- --ignored
```

No live sidecar and no Codex binary required for the default suite: gate
mapping tests are fixture-driven (`tests/fixtures/*.provisional.json`), gate
tests run against an in-process mock `/v1/inspect` (allow, block
justification, conservative review, 404 hint, fail-closed, fail-open, hard
timeout, malformed stdin), the ingest tests drive the same mock from
`*.provisional.jsonl` streams (advisory metadata, post-hoc attestation,
malformed-line resilience, recorded-block, 404 abort, plus end-to-end binary
runs covering the file/spawn input modes and every exit code), and the
compiler has unit + golden-file tests (`tests/fixtures/sample_bundle.dictum` →
`.golden.rules`). The `--ignored` round-trip shells out to `codex execpolicy
check` to validate the generated syntax against the pinned Codex version.

## Security model & bypass surface

- **Trust:** Codex pins non-managed hooks by content hash; verify the binary
  checksum against the release artifact. Org-managed hooks are not
  user-disableable.
- **Bypass:** whoever controls the host can disable the hook, use bypass
  flags, or run a shell outside Codex. Mitigation is layered — org-managed
  config, the compiled execpolicy `.rules` static layer (§8), and post-hoc
  ingest of session telemetry (§9) for sessions that ran ungoverned — and the
  limit is declared cryptographically: `is_authoritative: false` in every
  receipt.
- **Privacy:** tool payloads can contain secrets; the gate never persists or
  logs them. Redaction happens sidecar-side under the sidecar's policy.
