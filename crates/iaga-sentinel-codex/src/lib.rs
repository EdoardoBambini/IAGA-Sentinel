//! IAGA Sentinel — OpenAI Codex CLI plug-in.
//!
//! Everything Codex-specific lives in this crate, behind the single
//! `iaga-codex` binary; the core `iaga` binary has no knowledge of Codex.
//! The plug-in speaks only the public wire contract of `POST /v1/inspect`
//! (via `iaga-sentinel-integrations`), never the core pipeline.
//!
//! Two capabilities ship so far:
//!
//! **The gate** (`iaga-codex hook`, PreToolUse only): Codex calls the hook
//! with a JSON event on stdin, the gate maps it onto an
//! [`iaga_sentinel_integrations::InspectRequest`], asks the sidecar for a
//! verdict and blocks denied actions with exit code 2, fail-closed by
//! default. Every governed call mints one signed receipt server-side.
//!
//! **The compiler** (`iaga-codex export-rules`): compiles an APL bundle to
//! a native execpolicy `.rules` file — a static command-prefix layer that
//! holds even when hooks are disabled. Only policies that map *faithfully*
//! onto a command prefix are emitted; the rest stay runtime-only (the gate
//! enforces them).
//!
//! **The ingest** (`iaga-codex ingest`): consumes a `codex exec --json`
//! telemetry stream (live from stdin or a spawned child, or post-hoc from a
//! captured file) and mints one signed receipt per observed action. This is
//! the *advisory* tier — the verdict is recorded, never applied (the action
//! already ran) — so it closes the evidence loop without claiming
//! enforcement it does not provide.
//!
//! Module map (deliberately specific names — no `main.rs`/`config.rs`
//! clones of files that already exist elsewhere in the workspace):
//! - [`hook_config`] — environment-driven configuration (base URL, API
//!   key, agent id, fail policy, hard timeout).
//! - [`codex_event`] — THE single place that knows the Codex hook payload
//!   field names. Provisional until the payload spike lands real fixtures
//!   (see `docs/adr/0022-codex-integration.md`).
//! - [`inspect_client`] — thin HTTP client for `/v1/inspect` with a hard
//!   timeout.
//! - [`hook_gate`] — gate orchestration: parse → map → inspect → exit code.
//! - [`execpolicy_format`] — THE single place that knows execpolicy
//!   `.rules` syntax. Provisional until validated against `codex
//!   execpolicy check`.
//! - [`rules_compiler`] — APL AST → execpolicy rules (pure, faithful subset).
//! - [`rules_export`] — `export-rules` I/O orchestration.
//! - [`exec_stream`] — THE single place that knows the `codex exec --json`
//!   stream field names. Provisional until the stream spike lands real
//!   fixtures (see `docs/adr/0022-codex-integration.md`).
//! - [`session_ingest`] — ingest orchestration: stream → inspect → receipts.

pub mod codex_event;
pub mod exec_stream;
pub mod execpolicy_format;
pub mod hook_config;
pub mod hook_gate;
pub mod inspect_client;
pub mod rules_compiler;
pub mod rules_export;
pub mod session_ingest;
