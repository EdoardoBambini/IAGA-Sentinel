//! Live Dictum policy overlay (M6).
//!
//! Loaded at server startup via `iaga serve --policy file.dictum`. The
//! pipeline consults it after the YAML risk score and merges decisions
//! using a "stricter wins" rule: Dictum can tighten the verdict, never
//! relax it. See ADR 0008 for the design rationale.
//!
//! Receipts produced while an overlay is active embed the SHA-256
//! digest of the compiled Dictum bundle in the `policy_hash` field, so
//! replay distinguishes between Dictum-active and YAML-only runs.

use std::path::{Path, PathBuf};

use iaga_sentinel_dictum::{
    evaluate_program_traced, Context as DictumContext, EvalTrace, Program, Value as DictumValue,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::core::types::GovernanceDecision;

#[derive(Debug, Error)]
pub enum DictumOverlayError {
    #[error("cannot read Dictum file `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Dictum compile error in `{path}`: {source}")]
    Compile {
        path: String,
        #[source]
        source: iaga_sentinel_dictum::DictumError,
    },
    /// The compiled bundle could not be serialized to compute its policy hash.
    /// Fatal at startup: a receipt must never carry a fake "valid" hash
    /// (CRYPTO-POLICYHASH-7b).
    #[error("cannot hash Dictum bundle `{path}`: {source}")]
    PolicyHash {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

pub struct DictumOverlay {
    program: Program,
    source_path: PathBuf,
    policy_hash: String,
}

impl DictumOverlay {
    /// Load + compile a Dictum file. Returns the overlay or a typed error
    /// (host fail-fast on startup if loading fails).
    pub fn load(path: &Path) -> Result<Self, DictumOverlayError> {
        let src = std::fs::read_to_string(path).map_err(|e| DictumOverlayError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let program =
            iaga_sentinel_dictum::compile(&src).map_err(|e| DictumOverlayError::Compile {
                path: path.display().to_string(),
                source: e,
            })?;
        let policy_hash =
            compute_policy_hash(&program).map_err(|e| DictumOverlayError::PolicyHash {
                path: path.display().to_string(),
                source: e,
            })?;
        Ok(Self {
            program,
            source_path: path.to_path_buf(),
            policy_hash,
        })
    }

    /// Run the overlay against the given context and return a full
    /// [`EvalTrace`]: the first fired policy (if any), how many policies were
    /// evaluated, the names that fired, and whether an eval error forced a
    /// fail-closed decision.
    ///
    /// Unlike the old behaviour, an eval error is **not** treated as no-fire:
    /// a Block/Review policy whose `when` errors fails closed with its own
    /// verdict (PIP-DICTUM-FAILOPEN). Each policy's `when` gets its own budget
    /// (DET-DICTUM-2). We still `warn!` so operators see the error.
    pub fn evaluate(&self, ctx: &DictumContext) -> EvalTrace {
        let trace = evaluate_program_traced(&self.program, ctx);
        if trace.eval_errored {
            tracing::warn!(
                source = %self.source_path.display(),
                "dictum overlay eval error; failing closed on Block/Review policies"
            );
        }
        trace
    }

    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn policy_count(&self) -> usize {
        self.program.policies.len()
    }
}

/// SHA-256 of the canonical JSON encoding of the program. The encoding
/// is deterministic given the AST (no maps, struct field order fixed
/// in `iaga-sentinel-dictum`), so two byte-identical sources produce the same hash.
///
/// A serialization error is **fatal** (returned to the caller, which fails the
/// startup load): a receipt must never carry a constant fake-but-valid hash
/// (CRYPTO-POLICYHASH-7b).
fn compute_policy_hash(program: &Program) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(program)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Hex-encoded SHA-256 of a fired policy's evidence value. Binds *which*
/// evidence drove the verdict into the signed receipt without leaking the raw
/// content (PIP-DICTUM-UNBOUND). `ponytail:` `Value` has no maps, so its
/// `Display` is a deterministic canonical form — hash that, no extra
/// serialization machinery.
pub fn evidence_sha256(v: &DictumValue) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{v}").as_bytes());
    hex::encode(hasher.finalize())
}

/// Stricter-wins merge between the YAML risk decision and a Dictum
/// fired verdict. Dictum can tighten the verdict; it cannot relax it.
pub fn merge_decisions(
    yaml: GovernanceDecision,
    dictum: iaga_sentinel_dictum::Verdict,
) -> GovernanceDecision {
    let dictum_as_yaml = match dictum {
        iaga_sentinel_dictum::Verdict::Allow => GovernanceDecision::Allow,
        iaga_sentinel_dictum::Verdict::Review => GovernanceDecision::Review,
        iaga_sentinel_dictum::Verdict::Block => GovernanceDecision::Block,
    };
    stricter(yaml, dictum_as_yaml)
}

fn stricter(a: GovernanceDecision, b: GovernanceDecision) -> GovernanceDecision {
    fn rank(d: GovernanceDecision) -> u8 {
        match d {
            GovernanceDecision::Allow => 0,
            GovernanceDecision::Review => 1,
            GovernanceDecision::Block => 2,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// Build the JSON context that the overlay sees, given the inbound
/// request and the risk-engine output.
///
/// Shape:
/// ```json
/// {
///   "agent": { "id": "...", "framework": "..." },
///   "action": { "kind": "...", "tool_name": "...", "payload": {...} },
///   "workspace": { "id": "...", "allowlist": [...] },
///   "risk": { "score": 74, "decision": "block" },
///   "ml": { ... }
/// }
/// ```
#[allow(clippy::too_many_arguments)]
pub fn build_overlay_context(
    request: &crate::core::types::InspectRequest,
    risk_score: u32,
    yaml_decision: GovernanceDecision,
    workspace_id: Option<&str>,
    workspace_allowlist: &[String],
    ml_scores: Option<&serde_json::Value>,
    session_cost_usd: Option<f64>,
    budget_limit_usd: Option<f64>,
) -> DictumContext {
    let action_kind = match request.action.action_type {
        crate::core::types::ActionType::Shell => "shell",
        crate::core::types::ActionType::FileRead => "file_read",
        crate::core::types::ActionType::FileWrite => "file_write",
        crate::core::types::ActionType::Http => "http",
        crate::core::types::ActionType::DbQuery => "db_query",
        crate::core::types::ActionType::Email => "email",
        crate::core::types::ActionType::Custom => "custom",
    };
    let decision_str = match yaml_decision {
        GovernanceDecision::Allow => "allow",
        GovernanceDecision::Review => "review",
        GovernanceDecision::Block => "block",
    };
    let payload_json =
        serde_json::to_value(&request.action.payload).unwrap_or(serde_json::Value::Null);
    let workspace_json = serde_json::json!({
        "id": workspace_id.unwrap_or(""),
        "allowlist": workspace_allowlist,
    });
    let mut root = serde_json::json!({
        "agent": {
            "id": request.agent_id,
            "framework": request.framework,
        },
        "action": {
            "kind": action_kind,
            "tool_name": request.action.tool_name,
            "payload": payload_json,
        },
        "workspace": workspace_json,
        "risk": {
            "score": risk_score,
            "decision": decision_str,
        },
    });
    if let (Some(ml), Some(obj)) = (ml_scores, root.as_object_mut()) {
        obj.insert("ml".to_string(), ml.clone());
    }
    // 1.5 cost-control: expose cumulative session spend + the configured budget
    // so a policy can write `when usage.session_cost_usd > budget.limit ...`.
    if let Some(obj) = root.as_object_mut() {
        if let Some(spent) = session_cost_usd {
            obj.insert(
                "usage".to_string(),
                serde_json::json!({ "session_cost_usd": spent }),
            );
        }
        if let Some(limit) = budget_limit_usd {
            obj.insert("budget".to_string(), serde_json::json!({ "limit": limit }));
        }
    }
    DictumContext::from_value(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_context_includes_cost_when_provided() {
        use crate::core::types::{ActionDetail, ActionType, InspectRequest};
        use std::collections::HashMap;
        let req = InspectRequest {
            agent_id: "a".into(),
            tenant_id: None,
            workspace_id: None,
            framework: "test".into(),
            protocol: None,
            action: ActionDetail {
                action_type: ActionType::Http,
                tool_name: "t".into(),
                payload: HashMap::new(),
            },
            requested_secrets: None,
            metadata: None,
            usage: None,
        };
        // With cost provided, `usage` + `budget` land in the policy context so
        // `when usage.session_cost_usd > budget.limit ...` can evaluate.
        let ctx = build_overlay_context(
            &req,
            10,
            GovernanceDecision::Allow,
            Some("ws"),
            &[],
            None,
            Some(6.5),
            Some(5.0),
        );
        assert_eq!(ctx.root["usage"]["session_cost_usd"], 6.5);
        assert_eq!(ctx.root["budget"]["limit"], 5.0);

        // Without cost, neither key is present (keeps the context unchanged for
        // non-cost builds / sessions with no spend tracking).
        let ctx2 = build_overlay_context(
            &req,
            10,
            GovernanceDecision::Allow,
            Some("ws"),
            &[],
            None,
            None,
            None,
        );
        assert!(ctx2.root.get("usage").is_none());
        assert!(ctx2.root.get("budget").is_none());
    }

    #[test]
    fn stricter_block_beats_allow() {
        assert_eq!(
            stricter(GovernanceDecision::Allow, GovernanceDecision::Block),
            GovernanceDecision::Block
        );
        assert_eq!(
            stricter(GovernanceDecision::Block, GovernanceDecision::Allow),
            GovernanceDecision::Block
        );
    }

    #[test]
    fn stricter_review_between_allow_and_block() {
        assert_eq!(
            stricter(GovernanceDecision::Allow, GovernanceDecision::Review),
            GovernanceDecision::Review
        );
        assert_eq!(
            stricter(GovernanceDecision::Review, GovernanceDecision::Block),
            GovernanceDecision::Block
        );
    }

    #[test]
    fn merge_dictum_block_overrides_yaml_allow() {
        let merged = merge_decisions(
            GovernanceDecision::Allow,
            iaga_sentinel_dictum::Verdict::Block,
        );
        assert_eq!(merged, GovernanceDecision::Block);
    }

    #[test]
    fn merge_dictum_allow_does_not_relax_yaml_block() {
        let merged = merge_decisions(
            GovernanceDecision::Block,
            iaga_sentinel_dictum::Verdict::Allow,
        );
        assert_eq!(merged, GovernanceDecision::Block);
    }

    fn write_tmp(name: &str, src: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        std::fs::write(&path, src).expect("write tmp dictum");
        path
    }

    #[test]
    fn load_valid_dictum_yields_policy_count_and_hash() {
        let path = write_tmp(
            "iaga_sentinel_dictum_overlay_valid.dictum",
            r#"policy "p1" { when true then block }
               policy "p2" { when false then allow }"#,
        );
        let overlay = DictumOverlay::load(&path).expect("must load");
        assert_eq!(overlay.policy_count(), 2);
        assert_eq!(overlay.policy_hash().len(), 64);
        assert!(overlay.policy_hash().chars().all(|c| c.is_ascii_hexdigit()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_returns_io_error() {
        let path = std::path::PathBuf::from("does/not/exist/here.dictum");
        match DictumOverlay::load(&path) {
            Err(DictumOverlayError::Io { .. }) => {}
            other => panic!("expected Io error, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn load_invalid_dictum_returns_compile_error() {
        let path = write_tmp(
            "iaga_sentinel_dictum_overlay_bad.dictum",
            r#"policy "broken" { when @ then allow }"#,
        );
        match DictumOverlay::load(&path) {
            Err(DictumOverlayError::Compile { .. }) => {}
            other => panic!("expected Compile error, got {:?}", other.is_ok()),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_hash_is_deterministic_for_same_source() {
        let src = r#"policy "p" { when true then review }"#;
        let p1 = write_tmp("iaga_sentinel_dictum_overlay_det1.dictum", src);
        let p2 = write_tmp("iaga_sentinel_dictum_overlay_det2.dictum", src);
        let h1 = DictumOverlay::load(&p1).unwrap().policy_hash().to_string();
        let h2 = DictumOverlay::load(&p2).unwrap().policy_hash().to_string();
        assert_eq!(h1, h2);
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn evaluate_returns_first_fired_policy() {
        let path = write_tmp(
            "iaga_sentinel_dictum_overlay_eval.dictum",
            r#"policy "high_risk" {
                 when risk.score > 80
                 then block, reason="too risky"
               }"#,
        );
        let overlay = DictumOverlay::load(&path).expect("must load");
        let ctx = iaga_sentinel_dictum::Context::from_value(serde_json::json!({
            "risk": { "score": 95 }
        }));
        let fired = overlay.evaluate(&ctx).fired.expect("must fire");
        assert_eq!(fired.policy_name, "high_risk");
        assert_eq!(fired.verdict, iaga_sentinel_dictum::Verdict::Block);
        let _ = std::fs::remove_file(&path);
    }
}
