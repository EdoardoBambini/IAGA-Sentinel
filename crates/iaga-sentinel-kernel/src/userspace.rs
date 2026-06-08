//! Cross-platform userspace launcher. Always available, "soft" enforcement.
//!
//! What it does:
//! - Runs the policy callback before spawning anything. If the policy
//!   says `Block`, the child never starts.
//! - Spawns the child via `tokio::process::Command` with a scoped
//!   environment (only entries explicitly listed in `ProcessSpec.env`
//!   plus a small allowlist of inherited vars: `PATH`, `HOME`,
//!   `SystemRoot` on Windows). No accidental leakage of secrets the
//!   host happens to have in its env.
//! - Scrubs a denylist of known-sensitive variables (cloud and model
//!   provider credentials, registry tokens, the receipt signing key
//!   path) from the final child environment, even when passed explicitly
//!   via `ProcessSpec.env`. The denylist is extendable via a TOML file
//!   at `IAGA_SENTINEL_ENV_DENYLIST` (1.3.1).
//! - Sets the working directory if specified.
//!
//! What it does NOT do (deliberate, deferred to `BpfKernel`):
//! - Restrict syscalls.
//! - Prevent `execve` of arbitrary binaries the child decides to run.
//! - Cap network egress at the kernel layer.
//! - Mediate filesystem access beyond what cwd + env can express.
//!
//! For all of that you want the eBPF LSM backend (M4.1).

use std::collections::HashMap;
use std::process::Stdio;

use async_trait::async_trait;

use crate::decision::{KernelDecision, LaunchOutcome, ProcessSpec};
use crate::engine::{EnforcementKernel, PolicyCheck};
use crate::errors::{KernelError, Result};

/// Environment variables that are inherited from the parent unless the
/// `ProcessSpec.env` explicitly overrides them. Conservatively small
/// so secrets in the parent's env can't leak into the agent's child.
const INHERITED_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "USERNAME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SystemRoot",  // Windows
    "USERPROFILE", // Windows
    "TEMP",        // Windows
    "TMPDIR",      // Unix
];

/// Known-sensitive environment variables that must never reach a governed
/// child, even when explicitly placed in `ProcessSpec.env`. This is a
/// deny-by-name layer on top of `INHERITED_ENV_ALLOWLIST`: the allowlist
/// already blocks accidental inheritance, this list additionally scrubs
/// secrets the caller passes through and guards against the allowlist being
/// widened later. Extend it at runtime via a TOML file pointed to by
/// `IAGA_SENTINEL_ENV_DENYLIST` (see `load_denylist_extension`).
const SENSITIVE_ENV_DENYLIST: &[&str] = &[
    // Cloud provider credentials
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_API_KEY",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_ID",
    // Model / inference provider keys
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    // Source control + package registries
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DOCKER_PASSWORD",
    // Misc secrets
    "SLACK_TOKEN",
    "STRIPE_API_KEY",
    "VAULT_TOKEN",
    "DATABASE_URL",
    // The receipt signing key path must never leak to a governed child.
    "IAGA_SENTINEL_SIGNER_KEY_PATH",
];

/// TOML schema for the optional denylist extension file.
#[derive(serde::Deserialize)]
struct DenylistFile {
    #[serde(default)]
    deny: Vec<String>,
}

/// Load extra sensitive-var names from an optional TOML file. `path` is the
/// value of `IAGA_SENTINEL_ENV_DENYLIST`. Format:
/// ```toml
/// deny = ["MY_CUSTOM_SECRET", "INTERNAL_TOKEN"]
/// ```
/// Unreadable or malformed files degrade to the built-in list (warn only):
/// a bad config must never harden into a crash on the launch path.
fn load_denylist_extension(path: Option<&str>) -> Vec<String> {
    let path = match path {
        Some(p) if !p.is_empty() => p,
        _ => return Vec::new(),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "sensitive-env denylist TOML unreadable; using built-in list only");
            return Vec::new();
        }
    };
    match toml::from_str::<DenylistFile>(&text) {
        Ok(f) => f.deny,
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "sensitive-env denylist TOML malformed; using built-in list only");
            Vec::new()
        }
    }
}

/// Effective denylist (uppercased for case-insensitive matching) given an
/// optional TOML extension path. Split from `sensitive_denylist` so it is
/// testable without mutating the process environment.
fn build_denylist(extra_path: Option<&str>) -> std::collections::HashSet<String> {
    let mut set: std::collections::HashSet<String> = SENSITIVE_ENV_DENYLIST
        .iter()
        .map(|s| s.to_ascii_uppercase())
        .collect();
    for extra in load_denylist_extension(extra_path) {
        set.insert(extra.to_ascii_uppercase());
    }
    set
}

/// The effective sensitive-env denylist: the built-ins plus any names from
/// the TOML file at `IAGA_SENTINEL_ENV_DENYLIST`.
fn sensitive_denylist() -> std::collections::HashSet<String> {
    let extra = std::env::var("IAGA_SENTINEL_ENV_DENYLIST").ok();
    build_denylist(extra.as_deref())
}

pub struct UserspaceKernel {
    policy: PolicyCheck,
}

impl UserspaceKernel {
    pub fn new(policy: PolicyCheck) -> Self {
        Self { policy }
    }

    /// Construct with a permissive default policy that always allows.
    /// Useful for tests and for hosts that intentionally want a
    /// no-op kernel (e.g. development).
    pub fn allow_all() -> Self {
        let policy: PolicyCheck = std::sync::Arc::new(|_spec: &ProcessSpec| {
            Box::pin(async { KernelDecision::Allow })
                as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
        });
        Self { policy }
    }

    fn build_env(spec: &ProcessSpec) -> HashMap<String, String> {
        let denylist = sensitive_denylist();
        let mut env: HashMap<String, String> = HashMap::new();
        for key in INHERITED_ENV_ALLOWLIST {
            // Defense in depth: never inherit a known-sensitive var even if
            // the allowlist is widened to include one in a later change.
            if denylist.contains(&key.to_ascii_uppercase()) {
                continue;
            }
            if let Ok(v) = std::env::var(key) {
                env.insert((*key).to_string(), v);
            }
        }
        for (k, v) in &spec.env {
            env.insert(k.clone(), v.clone());
        }
        // Authoritative scrub: known-sensitive vars never reach a governed
        // child, even when passed explicitly via `ProcessSpec.env`. Secrets
        // must be delivered through a vetted channel, not the process env.
        env.retain(|k, _| !denylist.contains(&k.to_ascii_uppercase()));
        env
    }
}

#[async_trait]
impl EnforcementKernel for UserspaceKernel {
    async fn launch(&self, spec: &ProcessSpec) -> Result<LaunchOutcome> {
        let decision = (self.policy)(spec).await;
        if matches!(decision, KernelDecision::Block) {
            return Ok(LaunchOutcome {
                decision,
                reason: Some("policy blocked launch".into()),
                pid: None,
                exit_code: None,
                backend: self.backend_name(),
            });
        }
        if matches!(decision, KernelDecision::Review) {
            // The host is responsible for surfacing the review request
            // and either approving or rejecting. The userspace kernel
            // does not hold the launch on its own.
            return Ok(LaunchOutcome {
                decision,
                reason: Some("policy held launch for human review".into()),
                pid: None,
                exit_code: None,
                backend: self.backend_name(),
            });
        }

        let mut cmd = tokio::process::Command::new(&spec.program);
        cmd.args(&spec.args);
        cmd.env_clear();
        for (k, v) in Self::build_env(spec) {
            cmd.env(k, v);
        }
        if let Some(cwd) = &spec.working_dir {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        let mut child = cmd.spawn().map_err(|e| KernelError::Spawn {
            program: spec.program.clone(),
            msg: e.to_string(),
        })?;
        let pid = child.id();

        // For M4 we wait synchronously on the child so the receipt
        // for the launch can record the final exit code. Long-lived
        // detached agents are an M4.1 use case (host owns the handle).
        let status = child.wait().await.map_err(|e| KernelError::Spawn {
            program: spec.program.clone(),
            msg: format!("wait failed: {}", e),
        })?;

        Ok(LaunchOutcome {
            decision,
            reason: None,
            pid,
            exit_code: status.code(),
            backend: self.backend_name(),
        })
    }

    fn backend_name(&self) -> &'static str {
        "userspace"
    }

    fn is_authoritative(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with_env(pairs: &[(&str, &str)]) -> ProcessSpec {
        ProcessSpec {
            agent_id: "test".into(),
            program: "true".into(),
            args: vec![],
            working_dir: None,
            env: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn build_env_scrubs_sensitive_vars_from_spec_env() {
        let spec = spec_with_env(&[
            ("OPENAI_API_KEY", "sk-secret"),
            ("aws_secret_access_key", "lowercase-also-scrubbed"),
            ("MY_TOOL_FLAG", "1"),
        ]);
        let env = UserspaceKernel::build_env(&spec);
        assert!(
            !env.contains_key("OPENAI_API_KEY"),
            "known secret must be scrubbed from the child env"
        );
        assert!(
            !env.contains_key("aws_secret_access_key"),
            "scrub is case-insensitive"
        );
        assert_eq!(
            env.get("MY_TOOL_FLAG").map(String::as_str),
            Some("1"),
            "non-sensitive explicit vars are preserved"
        );
    }

    #[test]
    fn builtin_denylist_has_23_entries() {
        assert_eq!(SENSITIVE_ENV_DENYLIST.len(), 23);
    }

    #[test]
    fn toml_extension_adds_custom_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deny.toml");
        std::fs::write(&path, "deny = [\"CUSTOM_SECRET\", \"internal_token\"]")
            .expect("write toml");
        let set = build_denylist(Some(path.to_str().unwrap()));
        assert!(set.contains("CUSTOM_SECRET"));
        assert!(set.contains("INTERNAL_TOKEN"), "extension is uppercased");
        // Built-ins remain present alongside the extension.
        assert!(set.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn missing_toml_path_degrades_to_builtins() {
        let set = build_denylist(Some("/nonexistent/deny.toml"));
        assert!(set.contains("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(set.len(), SENSITIVE_ENV_DENYLIST.len());
    }
}
