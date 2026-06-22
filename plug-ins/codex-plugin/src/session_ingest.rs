//! Ingest orchestration: a `codex exec --json` stream → one signed receipt
//! per observed action.
//!
//! This is the **advisory** enforcement tier (the opposite end from the
//! gate): the verdict is *recorded*, never *applied* — the action the
//! stream narrates has already run. So there is no fail policy to honour
//! and nothing to block; per-item failures are counted and the stream
//! keeps flowing, because an evidence plane should record as much as it can
//! rather than abort on the first hiccup. The one hard stop is an
//! unregistered agent (HTTP 404): every later call would fail identically,
//! so we bail with the exact fix.
//!
//! Stdout carries one structured `ATTESTED …` line per minted receipt (so
//! the demo can pipe an `eventId` straight into `iaga replay`); the caller
//! renders the final `INGESTED …` summary from the returned
//! [`IngestSummary`]. Diagnostics and the raw stream stay on stderr — item
//! payloads are attacker-influenced and are never logged (see
//! [`crate::exec_stream`]).

use iaga_sentinel_integrations::GovernanceDecision;

use crate::exec_stream::{self, Attestation, LineAction};
use crate::hook_config::Config;
use crate::inspect_client::{InspectClient, InspectError};

/// Exit codes (workspace convention 0/1/2/3; precedence 3 > 2 > 1).
///
/// `EXIT_CHILD` (1) is decided by the binary, which alone knows the
/// spawned command's status; the ingest loop itself never returns it.
pub const EXIT_OK: i32 = 0;
pub const EXIT_CHILD: i32 = 1;
pub const EXIT_GAP: i32 = 2;
pub const EXIT_IO: i32 = 3;

/// One minted receipt, surfaced for the summary and for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    pub item_type: String,
    pub decision: GovernanceDecision,
    pub receipt_id: String,
}

/// Tally of one ingest run.
#[derive(Debug, Default, Clone)]
pub struct IngestSummary {
    /// Stream lines that parsed as JSON (excludes blank and malformed).
    pub events: u64,
    /// Completed, payload-bearing items that warranted an inspect call.
    pub actionable: u64,
    /// Actionable items that received a verdict (one receipt each).
    pub attested: u64,
    pub allow: u64,
    pub review: u64,
    pub block: u64,
    /// Actionable items whose inspect call failed (the attestation gap).
    pub failed: u64,
    /// Lines that did not parse as JSON.
    pub malformed: u64,
    /// Parsed lines with no recognizable discriminator (likely a Codex
    /// stream addition); skipped loudly, not silently.
    pub unrecognized: u64,
    /// The run stopped early on an unregistered-agent 404.
    pub aborted: bool,
    /// The inspect client could not even be built.
    pub setup_failed: bool,
    /// Per-receipt records, in stream order.
    pub records: Vec<Attested>,
}

/// Map a decision to its lowercase wire token for the `ATTESTED` line.
fn decision_token(decision: GovernanceDecision) -> &'static str {
    match decision {
        GovernanceDecision::Allow => "allow",
        GovernanceDecision::Review => "review",
        GovernanceDecision::Block => "block",
    }
}

/// Format one real-time `ATTESTED` line.
fn format_attested(record: &Attested) -> String {
    format!(
        "ATTESTED {} {} receipt={}",
        record.item_type,
        decision_token(record.decision),
        record.receipt_id
    )
}

/// Consume a stream of lines, minting one receipt per observed action.
///
/// Async only for the inspect round-trips: it is driven on a
/// current-thread runtime and pulls `lines` lazily, so a live pipe or a
/// spawned child is attested in real time (one blocking read between
/// inspect calls, with nothing else to starve — same shape as the gate's
/// `block_on`).
pub async fn ingest_lines<I>(lines: I, config: &Config, attestation: Attestation) -> IngestSummary
where
    I: IntoIterator<Item = String>,
{
    let mut summary = IngestSummary::default();

    let client = match InspectClient::new(config) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("[iaga-codex] could not build the HTTP client: {e}");
            summary.setup_failed = true;
            return summary;
        }
    };

    // The most recent thread id seen rides on every later receipt's
    // metadata, tying a session's actions together for `iaga replay`.
    let mut thread_id: Option<String> = None;

    for raw in lines {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        let event = match exec_stream::parse_line(line) {
            Ok(event) => event,
            Err(e) => {
                eprintln!("[iaga-codex] skipping a stream line that is not valid JSON: {e}");
                summary.malformed += 1;
                continue;
            }
        };
        summary.events += 1;

        if let Some(tid) = &event.thread_id {
            thread_id = Some(tid.clone());
        }

        let item = match exec_stream::classify(event) {
            LineAction::Skip => continue,
            LineAction::Unrecognized => {
                eprintln!(
                    "[iaga-codex] stream line has no recognizable item to attest; skipping \
                     (the line shape may be newer than this build)"
                );
                summary.unrecognized += 1;
                continue;
            }
            LineAction::Attest(item) => item,
        };

        summary.actionable += 1;
        let item_type = item.kind.clone().unwrap_or_else(|| "unknown".to_string());
        let request =
            exec_stream::to_inspect_request(&item, thread_id.as_deref(), attestation, config);

        match client.inspect(&request).await {
            Ok(result) => {
                // CRYPTO-CODEX-1: a verdict with no `eventId` produces no
                // replayable receipt. Count it as a gap (failed) instead of
                // printing a green ATTESTED line with an empty receipt id that
                // can never be verified.
                let receipt_id = result
                    .audit_event
                    .get("eventId")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());
                let Some(receipt_id) = receipt_id else {
                    eprintln!(
                        "[iaga-codex] verdict for a `{item_type}` item carried no eventId; \
                         not attested (no replayable receipt)"
                    );
                    summary.failed += 1;
                    continue;
                };
                summary.attested += 1;
                match result.decision {
                    GovernanceDecision::Allow => summary.allow += 1,
                    GovernanceDecision::Review => summary.review += 1,
                    GovernanceDecision::Block => summary.block += 1,
                }
                let record = Attested {
                    item_type,
                    decision: result.decision,
                    receipt_id,
                };
                // Real-time: one line per receipt as the action is observed.
                println!("{}", format_attested(&record));
                summary.records.push(record);
            }
            Err(InspectError::AgentNotRegistered { agent_id, base_url }) => {
                eprintln!(
                    "[iaga-codex] agent '{agent_id}' is not registered at {base_url} — \
                     run: iaga import plug-ins/codex-plugin/codex.policy.yaml"
                );
                summary.failed += 1;
                summary.aborted = true;
                break;
            }
            Err(e) => {
                // Advisory plane: record the gap, keep ingesting.
                eprintln!("[iaga-codex] could not attest a `{item_type}` item: {e}");
                summary.failed += 1;
            }
        }
    }

    summary
}

/// Render the final one-line `INGESTED …` summary for stdout.
pub fn render_summary(summary: &IngestSummary) -> String {
    let mut line = format!(
        "INGESTED events={} actionable={} attested={} allow={} review={} block={} failed={}",
        summary.events,
        summary.actionable,
        summary.attested,
        summary.allow,
        summary.review,
        summary.block,
        summary.failed,
    );
    if summary.malformed > 0 {
        line.push_str(&format!(" malformed={}", summary.malformed));
    }
    if summary.unrecognized > 0 {
        line.push_str(&format!(" unrecognized={}", summary.unrecognized));
    }
    if summary.aborted {
        line.push_str(" aborted=true");
    }
    line
}

/// Exit code from the tally alone (the binary folds in a spawned child's
/// status afterwards). Setup failure (3) outranks an attestation gap (2);
/// a fully attested stream is success (0).
pub fn exit_code(summary: &IngestSummary) -> i32 {
    if summary.setup_failed {
        EXIT_IO
    } else if summary.aborted || summary.failed > 0 {
        EXIT_GAP
    } else {
        EXIT_OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_line_stays_clean_when_nothing_went_wrong() {
        let summary = IngestSummary {
            events: 5,
            actionable: 2,
            attested: 2,
            allow: 1,
            block: 1,
            ..Default::default()
        };
        assert_eq!(
            render_summary(&summary),
            "INGESTED events=5 actionable=2 attested=2 allow=1 review=0 block=1 failed=0"
        );
        assert_eq!(exit_code(&summary), EXIT_OK);
    }

    #[test]
    fn summary_line_surfaces_problems_and_maps_to_gap_exit() {
        let summary = IngestSummary {
            events: 4,
            actionable: 2,
            attested: 1,
            allow: 1,
            failed: 1,
            malformed: 1,
            unrecognized: 1,
            aborted: true,
            ..Default::default()
        };
        let line = render_summary(&summary);
        assert!(line.contains("failed=1"));
        assert!(line.contains("malformed=1"));
        assert!(line.contains("unrecognized=1"));
        assert!(line.contains("aborted=true"));
        assert_eq!(exit_code(&summary), EXIT_GAP);
    }

    #[test]
    fn setup_failure_outranks_a_gap() {
        let summary = IngestSummary {
            setup_failed: true,
            failed: 3,
            ..Default::default()
        };
        assert_eq!(exit_code(&summary), EXIT_IO);
    }

    #[test]
    fn attested_line_is_demo_pasteable() {
        let record = Attested {
            item_type: "command_execution".to_string(),
            decision: GovernanceDecision::Block,
            receipt_id: "evt_123".to_string(),
        };
        assert_eq!(
            format_attested(&record),
            "ATTESTED command_execution block receipt=evt_123"
        );
    }
}
