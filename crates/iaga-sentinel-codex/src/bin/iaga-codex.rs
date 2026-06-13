//! `iaga-codex` — IAGA Sentinel plug-in binary for OpenAI Codex CLI.
//!
//! Kept deliberately thin: all behaviour lives in the library modules so
//! exit codes and messages are testable in-process. This file only parses
//! the CLI, reads input, runs the chosen subcommand and exits.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{exit, Command, Stdio};

use clap::{Parser, Subcommand};

use iaga_sentinel_codex::exec_stream::Attestation;
use iaga_sentinel_codex::hook_config::Config;
use iaga_sentinel_codex::session_ingest::{self, IngestSummary};
use iaga_sentinel_codex::{hook_gate, rules_export};

#[derive(Parser)]
#[command(name = "iaga-codex", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Codex command hook: read one hook event (JSON) on stdin, govern it
    /// through IAGA Sentinel's POST /v1/inspect, and exit 0 (allow) or 2
    /// (block). Register it in Codex's config.toml, see
    /// examples/integrations/codex/README.md.
    Hook,

    /// Compile an APL bundle to a native Codex execpolicy `.rules` file:
    /// a static command-prefix layer that holds even when hooks are
    /// disabled. Only policies that map faithfully onto a command prefix
    /// are emitted; the rest are reported as runtime-only.
    ExportRules {
        /// Path to the APL bundle (`.apl` source file).
        #[arg(long)]
        apl: PathBuf,

        /// Path to write the generated `.rules` file.
        #[arg(long)]
        out: PathBuf,
    },

    /// Ingest a `codex exec --json` telemetry stream into signed receipts
    /// (advisory tier: each observed action is recorded, never blocked).
    ///
    /// Three input modes:
    /// - default — stream from stdin, live:
    ///   `codex exec --json "task" | iaga-codex ingest`
    /// - `--from <file>` — re-process a captured stream, post-hoc:
    ///   `iaga-codex ingest --from session.jsonl`
    /// - `-- <command...>` — spawn the command, attest its stdout, live:
    ///   `iaga-codex ingest -- codex exec --json "task"`
    Ingest {
        /// Re-process a captured stream from a file (post-hoc attestation).
        /// Mutually exclusive with a spawned `-- <command>`.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,

        /// Spawn this command and attest its stdout stream (live-ingest).
        /// Everything after `--` is the program and its arguments; an
        /// absolute path works, so Codex need not be on PATH.
        #[arg(last = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hook => exit(run_hook()),
        Commands::ExportRules { apl, out } => exit(rules_export::run_export(&apl, &out)),
        Commands::Ingest { from, command } => exit(run_ingest(from, command)),
    }
}

/// Read one hook event from stdin and gate it. Returns the process exit
/// code (the async inspect call runs on a single-threaded runtime built
/// only for this subcommand).
fn run_hook() -> i32 {
    let mut raw = String::new();
    // An unreadable stdin is treated like an empty event and goes through
    // the same fail policy as any malformed payload.
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        eprintln!("[iaga-codex] could not read stdin: {e}");
    }

    let config = Config::from_env();
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            // No runtime means no inspect call is possible: apply the same
            // fail policy as an unreachable sidecar.
            eprintln!("[iaga-codex] could not start async runtime: {e}");
            return hook_gate::transport_failure_exit_code(&config);
        }
    };

    let outcome = runtime.block_on(hook_gate::run(&raw, &config));
    // The justification goes to stdout so Codex can surface it to the user
    // and the model; diagnostics stay on stderr.
    if let Some(message) = outcome.message {
        println!("{message}");
    }
    outcome.exit_code
}

/// Dispatch the ingest subcommand across its three input modes and fold the
/// attestation tally (and any spawned child's status) into one exit code.
fn run_ingest(from: Option<PathBuf>, command: Vec<String>) -> i32 {
    // `--from` names a recording; `-- <command>` spawns a live producer.
    // Asking for both is a contradiction, not a merge.
    if from.is_some() && !command.is_empty() {
        eprintln!("[iaga-codex] choose either --from <file> or a spawned `-- <command>`, not both");
        return session_ingest::EXIT_IO;
    }

    let config = Config::from_env();
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[iaga-codex] could not start async runtime: {e}");
            return session_ingest::EXIT_IO;
        }
    };

    if !command.is_empty() {
        return run_ingest_spawn(&runtime, &config, command);
    }

    if let Some(path) = from {
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("[iaga-codex] cannot read capture `{}`: {e}", path.display());
                return session_ingest::EXIT_IO;
            }
        };
        let lines = BufReader::new(file).lines().map_while(Result::ok);
        let summary = runtime.block_on(session_ingest::ingest_lines(
            lines,
            &config,
            Attestation::PostHoc,
        ));
        finish(&summary, None)
    } else {
        // Default: the stream arrives on stdin (a live pipe from Codex).
        let stdin = std::io::stdin();
        let lines = stdin.lock().lines().map_while(Result::ok);
        let summary = runtime.block_on(session_ingest::ingest_lines(
            lines,
            &config,
            Attestation::LiveIngest,
        ));
        finish(&summary, None)
    }
}

/// Spawn `command`, attest its stdout in real time, and pass its stderr
/// through so the operator still sees Codex working.
fn run_ingest_spawn(
    runtime: &tokio::runtime::Runtime,
    config: &Config,
    command: Vec<String>,
) -> i32 {
    // `command` is non-empty here (checked by the caller).
    let (program, args) = command.split_first().expect("non-empty command");

    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("[iaga-codex] could not spawn `{program}`: {e}");
            return session_ingest::EXIT_IO;
        }
    };

    let stdout = child.stdout.take().expect("child stdout is piped");
    let lines = BufReader::new(stdout).lines().map_while(Result::ok);
    let summary = runtime.block_on(session_ingest::ingest_lines(
        lines,
        config,
        Attestation::LiveIngest,
    ));

    // The child has closed stdout (EOF ended the loop); reap it.
    let child_status = match child.wait() {
        Ok(status) => Some(status),
        Err(e) => {
            eprintln!("[iaga-codex] could not wait for `{program}`: {e}");
            None
        }
    };

    finish(&summary, child_status)
}

/// Print the final summary line and resolve the exit code.
///
/// Precedence (3 > 2 > 1 > 0): an I/O/setup failure or attestation gap
/// (from the tally) outranks a non-zero child status — a clean ingest of a
/// stream from a command that itself failed still reports the command's
/// failure as exit 1.
fn finish(summary: &IngestSummary, child_status: Option<std::process::ExitStatus>) -> i32 {
    println!("{}", session_ingest::render_summary(summary));

    let tally_code = session_ingest::exit_code(summary);
    if tally_code != session_ingest::EXIT_OK {
        return tally_code;
    }
    if let Some(status) = child_status {
        if !status.success() {
            eprintln!("[iaga-codex] the spawned command exited unsuccessfully ({status})");
            return session_ingest::EXIT_CHILD;
        }
    }
    session_ingest::EXIT_OK
}

/// A single-threaded Tokio runtime built per subcommand for the inspect
/// round-trips (the plug-in does no other async work).
fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
