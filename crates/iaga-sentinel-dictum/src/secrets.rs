//! Deterministic secret / credential detector backing the `secret_ref()`
//! Dictum builtin.
//!
//! The pattern set mirrors the credential and PII subset of the core
//! response-scanner (`iaga-sentinel-core` `pipeline::execute_pipeline`'s
//! `SENSITIVE_PATTERNS`). It is duplicated here on purpose: `iaga-sentinel-dictum`
//! is a *dependency* of core (core depends on dictum, never the reverse), and
//! keeping detection self-contained means `iaga policy test` flags secrets
//! standalone, with no host process required.
//!
//! Matching is pure: a fixed regex set, compiled once, run over a string. No
//! I/O, no wall clock, no RNG. That preserves the evaluator's core invariant,
//! identical AST + identical context yields an identical verdict, which is what
//! receipt replay relies on.

use once_cell::sync::Lazy;
use regex::Regex;

/// Credential / PII signatures whose mere presence is a hit. Every pattern is
/// lookaround-free and backreference-free, so it compiles under the `regex`
/// crate (which rejects those for its linear-time guarantee).
///
/// Credit-card and SSN patterns are handled separately (see `contains_secret`):
/// the bare regexes over-fire (CRYPTO-DICTUM-9) — any 16-digit run or any
/// `ddd-dd-dddd` would Block a benign payload, a deterministic self-DoS — so a
/// card match must pass the Luhn checksum and an SSN match must be accompanied
/// by an explicit SSN keyword.
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
];

static COMPILED: Lazy<Vec<Regex>> =
    Lazy::new(|| PATTERNS.iter().filter_map(|p| Regex::new(p).ok()).collect());

/// Credit-card candidate: a BIN-prefixed 13-16 digit run (Visa / MC / Amex /
/// Discover). Only a hit when the digits also pass [`luhn_valid`].
static CC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b",
    )
    .expect("static cc regex")
});

/// US Social Security Number shape. Only a hit when an explicit SSN keyword is
/// also present, since `ddd-dd-dddd` matches many benign formatted numbers.
static SSN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("static ssn regex"));

/// Returns true when `haystack` contains any known credential / PII signature.
///
/// Hosts pass the serialized form of whatever a Dictum policy targets, typically
/// a flattened `action.payload` object, so a secret in *any* nested field is
/// caught.
pub fn contains_secret(haystack: &str) -> bool {
    if COMPILED.iter().any(|re| re.is_match(haystack)) {
        return true;
    }
    // Credit card: a match only counts if it passes the Luhn checksum.
    if CC_RE.find_iter(haystack).any(|m| luhn_valid(m.as_str())) {
        return true;
    }
    // SSN: gate on an explicit keyword to avoid blocking benign formatted numbers.
    let lower = haystack.to_ascii_lowercase();
    if (lower.contains("ssn") || lower.contains("social security")) && SSN_RE.is_match(haystack) {
        return true;
    }
    false
}

/// Luhn (mod-10) checksum over the digits of a candidate card number. Rejects
/// anything outside the 13-19 digit range and any string failing the checksum,
/// so a random 16-digit value no longer self-DoSes a benign payload.
fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u8> = candidate
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = u32::from(d);
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
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

    #[test]
    fn credit_card_requires_luhn() {
        // Both match the Visa BIN regex; only the Luhn-valid one is a hit, so a
        // benign 16-digit number can no longer self-DoS a payload.
        assert!(contains_secret("card 4111 1111 1111 1111 on file"));
        assert!(!contains_secret("order ref 4111 1111 1111 1112"));
    }

    #[test]
    fn ssn_requires_keyword() {
        // A bare ddd-dd-dddd is not enough to Block.
        assert!(!contains_secret("ticket 123-45-6789 was resolved"));
        // An explicit SSN keyword qualifies it.
        assert!(contains_secret("SSN: 123-45-6789"));
        assert!(contains_secret("social security number 123-45-6789"));
    }
}
