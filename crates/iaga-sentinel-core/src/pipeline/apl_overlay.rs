//! Live APL policy overlay (M6).
//!
//! Loaded at server startup via `iaga serve --policy file.apl`. The
//! pipeline consults it after the YAML risk score and merges decisions
//! using a "stricter wins" rule: APL can tighten the verdict, never
//! relax it. See ADR 0008 for the design rationale.
//!
//! Receipts produced while an overlay is active embed the SHA-256
//! digest of the compiled APL bundle in the `policy_hash` field, so
//! replay distinguishes between APL-active and YAML-only runs.

#![cfg(feature = "apl")]

use std::path::{Path, PathBuf};

use iaga_sentinel_apl::{
    evaluate_program, Context as AplContext, EvalBudget, PolicyFired, Program,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::core::types::GovernanceDecision;

#[derive(Debug, Error)]
pub enum AplOverlayError {
    #[error("cannot read APL file `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("APL compile error in `{path}`: {source}")]
    Compile {
        path: String,
        #[source]
        source: iaga_sentinel_apl::AplError,
    },
}

pub struct AplOverlay {
    program: Program,
    source_path: PathBuf,
    policy_hash: String,
}

impl AplOverlay {
    /// Load + compile an APL file. Returns the overlay or a typed error
    /// (host fail-fast on startup if loading fails).
    pub fn load(path: &Path) -> Result<Self, AplOverlayError> {
        let src = std::fs::read_to_string(path).map_err(|e| AplOverlayError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let program = iaga_sentinel_apl::compile(&src).map_err(|e| AplOverlayError::Compile {
            path: path.display().to_string(),
            source: e,
        })?;
        let policy_hash = compute_policy_hash(&program);
        Ok(Self {
            program,
            source_path: path.to_path_buf(),
            policy_hash,
        })
    }

    /// Run the overlay against the given context. Returns the first
    /// fired policy, or `None` if no policy in the bundle matched.
    /// Errors during eval are logged at warn and treated as no-fire.
    pub fn evaluate(&self, ctx: &AplContext) -> Option<PolicyFired> {
        let mut budget = EvalBudget::default();
        match evaluate_program(&self.program, ctx, &mut budget) {
            Ok(Some(fired)) => Some(fired),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, source = %self.source_path.display(), "apl overlay eval error");
                None
            }
        }
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
/// in `iaga-sentinel-apl`), so two byte-identical sources produce the same hash.
fn compute_policy_hash(program: &Program) -> String {
    let bytes =
        serde_json::to_vec(program).unwrap_or_else(|_| b"iaga-sentinel-apl-bundle-error".to_vec());
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

/// Stricter-wins merge between the YAML risk decision and an APL
/// fired verdict. APL can tighten the verdict; it cannot relax it.
pub fn merge_decisions(
    yaml: GovernanceDecision,
    apl: iaga_sentinel_apl::Verdict,
) -> GovernanceDecision {
    let apl_as_yaml = match apl {
        iaga_sentinel_apl::Verdict::Allow => GovernanceDecision::Allow,
        iaga_sentinel_apl::Verdict::Review => GovernanceDecision::Review,
        iaga_sentinel_apl::Verdict::Block => GovernanceDecision::Block,
    };
    stricter(yaml, apl_as_yaml)
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
pub fn build_overlay_context(
    request: &crate::core::types::InspectRequest,
    risk_score: u32,
    yaml_decision: GovernanceDecision,
    workspace_id: Option<&str>,
    workspace_allowlist: &[String],
    ml_scores: Option<&serde_json::Value>,
) -> AplContext {
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
    AplContext::from_value(root)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn merge_apl_block_overrides_yaml_allow() {
        let merged = merge_decisions(GovernanceDecision::Allow, iaga_sentinel_apl::Verdict::Block);
        assert_eq!(merged, GovernanceDecision::Block);
    }

    #[test]
    fn merge_apl_allow_does_not_relax_yaml_block() {
        let merged = merge_decisions(GovernanceDecision::Block, iaga_sentinel_apl::Verdict::Allow);
        assert_eq!(merged, GovernanceDecision::Block);
    }

    fn write_tmp(name: &str, src: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        std::fs::write(&path, src).expect("write tmp apl");
        path
    }

    #[test]
    fn load_valid_apl_yields_policy_count_and_hash() {
        let path = write_tmp(
            "iaga_sentinel_apl_overlay_valid.apl",
            r#"policy "p1" { when true then block }
               policy "p2" { when false then allow }"#,
        );
        let overlay = AplOverlay::load(&path).expect("must load");
        assert_eq!(overlay.policy_count(), 2);
        assert_eq!(overlay.policy_hash().len(), 64);
        assert!(overlay.policy_hash().chars().all(|c| c.is_ascii_hexdigit()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_returns_io_error() {
        let path = std::path::PathBuf::from("does/not/exist/here.apl");
        match AplOverlay::load(&path) {
            Err(AplOverlayError::Io { .. }) => {}
            other => panic!("expected Io error, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn load_invalid_apl_returns_compile_error() {
        let path = write_tmp(
            "iaga_sentinel_apl_overlay_bad.apl",
            r#"policy "broken" { when @ then allow }"#,
        );
        match AplOverlay::load(&path) {
            Err(AplOverlayError::Compile { .. }) => {}
            other => panic!("expected Compile error, got {:?}", other.is_ok()),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_hash_is_deterministic_for_same_source() {
        let src = r#"policy "p" { when true then review }"#;
        let p1 = write_tmp("iaga_sentinel_apl_overlay_det1.apl", src);
        let p2 = write_tmp("iaga_sentinel_apl_overlay_det2.apl", src);
        let h1 = AplOverlay::load(&p1).unwrap().policy_hash().to_string();
        let h2 = AplOverlay::load(&p2).unwrap().policy_hash().to_string();
        assert_eq!(h1, h2);
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn evaluate_returns_first_fired_policy() {
        let path = write_tmp(
            "iaga_sentinel_apl_overlay_eval.apl",
            r#"policy "high_risk" {
                 when risk.score > 80
                 then block, reason="too risky"
               }"#,
        );
        let overlay = AplOverlay::load(&path).expect("must load");
        let ctx = iaga_sentinel_apl::Context::from_value(serde_json::json!({
            "risk": { "score": 95 }
        }));
        let fired = overlay.evaluate(&ctx).expect("must fire");
        assert_eq!(fired.policy_name, "high_risk");
        assert_eq!(fired.verdict, iaga_sentinel_apl::Verdict::Block);
        let _ = std::fs::remove_file(&path);
    }
}
