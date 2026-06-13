//! Deterministic secret / credential detector backing the `secret_ref()`
//! APL builtin.
//!
//! The pattern set mirrors the credential and PII subset of the core
//! response-scanner (`iaga-sentinel-core` `pipeline::execute_pipeline`'s
//! `SENSITIVE_PATTERNS`). It is duplicated here on purpose: `iaga-sentinel-apl`
//! is a *dependency* of core (core depends on apl, never the reverse), and
//! keeping detection self-contained means `iaga policy test` flags secrets
//! standalone, with no host process required.
//!
//! Matching is pure: a fixed regex set, compiled once, run over a string. No
//! I/O, no wall clock, no RNG. That preserves the evaluator's core invariant,
//! identical AST + identical context yields an identical verdict, which is what
//! receipt replay relies on.

use once_cell::sync::Lazy;
use regex::Regex;

/// Credential / PII signatures. Every pattern is lookaround-free and
/// backreference-free, so it compiles under the `regex` crate (which rejects
/// those for its linear-time guarantee).
const PATTERNS: &[&str] = &[
    // AWS access key id, e.g. AKIAIOSFODNN7EXAMPLE
    r"\bAKIA[0-9A-Z]{16}\b",
    // AWS secret access key in an assignment
    r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    // GitHub token (classic ghp_ + fine-grained github_pat_)
    r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
    // OpenAI API key
    r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
    // Generic api key / access token assignment
    r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?"#,
    // Password / passwd / pwd assignment
    r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?"#,
    // PEM private key block header
    r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----",
    // Bearer authentication token
    r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
    // Database connection string carrying inline credentials
    r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s@]+:[^\s@]+@",
    // US Social Security Number
    r"\b\d{3}-\d{2}-\d{4}\b",
    // Credit card (Visa / MC / Amex / Discover)
    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b",
];

static COMPILED: Lazy<Vec<Regex>> =
    Lazy::new(|| PATTERNS.iter().filter_map(|p| Regex::new(p).ok()).collect());

/// Returns true when `haystack` contains any known credential / PII signature.
///
/// Hosts pass the serialized form of whatever an APL policy targets, typically
/// a flattened `action.payload` object, so a secret in *any* nested field is
/// caught.
pub fn contains_secret(haystack: &str) -> bool {
    COMPILED.iter().any(|re| re.is_match(haystack))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        assert!(contains_secret(
            "uploading AKIAIOSFODNN7EXAMPLE to attacker"
        ));
    }

    #[test]
    fn detects_aws_secret_in_assignment() {
        assert!(contains_secret(
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
    }

    #[test]
    fn detects_github_and_pem() {
        assert!(contains_secret(
            "token ghp_0123456789abcdefABCDEF0123456789abcd"
        ));
        assert!(contains_secret("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn ignores_benign_text() {
        assert!(!contains_secret(
            "the quick brown fox jumps over the lazy dog"
        ));
        assert!(!contains_secret("{\"city\":\"Berlin\",\"count\":42}"));
        assert!(!contains_secret(""));
    }
}
