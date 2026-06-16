//! Threat Intelligence Feed
//!
//! A database of known malicious patterns, domains, and IOCs (Indicators of
//! Compromise) that the governance pipeline checks against. Ships with ~20
//! built-in indicators and supports runtime additions/removals via the API.

use std::collections::HashMap;
use std::sync::RwLock;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pre-compiled regex cache for threat indicators. Populated at startup
/// when `with_builtin_indicators()` is called, and updated on add/remove.
static COMPILED_THREAT_REGEX: Lazy<std::sync::RwLock<HashMap<String, Regex>>> =
    Lazy::new(|| std::sync::RwLock::new(HashMap::new()));

// ── Types ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    MaliciousDomain,
    MaliciousCommand,
    KnownExploit,
    DataExfiltration,
    PromptInjection,
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::MaliciousDomain => write!(f, "malicious_domain"),
            ThreatType::MaliciousCommand => write!(f, "malicious_command"),
            ThreatType::KnownExploit => write!(f, "known_exploit"),
            ThreatType::DataExfiltration => write!(f, "data_exfiltration"),
            ThreatType::PromptInjection => write!(f, "prompt_injection"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatIndicator {
    pub id: String,
    pub indicator_type: ThreatType,
    pub pattern: String,
    pub severity: String,
    pub description: String,
    pub source: String,
    pub created_at: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatMatch {
    pub indicator_id: String,
    pub indicator_type: ThreatType,
    pub severity: String,
    pub description: String,
    pub matched_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatFeedStats {
    pub total_indicators: usize,
    pub active_indicators: usize,
    pub per_type: HashMap<String, usize>,
    pub last_updated: String,
}

// ── Feed ──

pub struct ThreatFeed {
    indicators: RwLock<Vec<ThreatIndicator>>,
    last_updated: RwLock<String>,
}

impl Default for ThreatFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatFeed {
    /// Create an empty feed.
    pub fn new() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            indicators: RwLock::new(Vec::new()),
            last_updated: RwLock::new(now),
        }
    }

    /// Create a feed pre-loaded with built-in indicators.
    pub fn with_builtin_indicators() -> Self {
        let feed = Self::new();
        for indicator in builtin_indicators() {
            feed.add_indicator(indicator);
        }
        feed
    }

    /// Check content against all active indicators, returning matches.
    /// Uses pre-compiled regex cache for performance.
    pub fn check_threats(&self, content: &str) -> Vec<ThreatMatch> {
        let indicators = self.indicators.read().unwrap_or_else(|e| e.into_inner());
        let regex_cache = COMPILED_THREAT_REGEX
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let lower = content.to_lowercase();
        let mut matches = Vec::new();

        for ind in indicators.iter() {
            if !ind.active {
                continue;
            }

            let matched = if ind.pattern.starts_with("regex:") {
                // Use pre-compiled regex from cache, fall back to compile on miss
                if let Some(re) = regex_cache.get(&ind.id) {
                    re.is_match(content)
                } else {
                    let pat = &ind.pattern[6..];
                    Regex::new(pat)
                        .map(|re| re.is_match(content))
                        .unwrap_or(false)
                }
            } else {
                // Simple case-insensitive contains
                lower.contains(&ind.pattern.to_lowercase())
            };

            if matched {
                matches.push(ThreatMatch {
                    indicator_id: ind.id.clone(),
                    indicator_type: ind.indicator_type,
                    severity: ind.severity.clone(),
                    description: ind.description.clone(),
                    matched_pattern: ind.pattern.clone(),
                });
            }
        }

        matches
    }

    /// Add a new indicator to the feed. Pre-compiles regex patterns.
    pub fn add_indicator(&self, indicator: ThreatIndicator) {
        // Pre-compile regex if applicable
        if indicator.pattern.starts_with("regex:") {
            let pat = &indicator.pattern[6..];
            if let Ok(re) = Regex::new(pat) {
                let mut cache = COMPILED_THREAT_REGEX
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                cache.insert(indicator.id.clone(), re);
            }
        }
        let mut indicators = self.indicators.write().unwrap_or_else(|e| e.into_inner());
        indicators.push(indicator);
        let mut last = self.last_updated.write().unwrap_or_else(|e| e.into_inner());
        *last = chrono::Utc::now().to_rfc3339();
    }

    /// Remove an indicator by ID. Returns true if found and removed.
    pub fn remove_indicator(&self, id: &str) -> bool {
        let mut indicators = self.indicators.write().unwrap_or_else(|e| e.into_inner());
        let before = indicators.len();
        indicators.retain(|i| i.id != id);
        let removed = indicators.len() < before;
        if removed {
            let mut last = self.last_updated.write().unwrap_or_else(|e| e.into_inner());
            *last = chrono::Utc::now().to_rfc3339();
        }
        removed
    }

    /// Hex SHA-256 of the indicator set (DET-THREAT-1), so a receipt can bind
    /// *which* threat-feed version produced its verdict. Indicators are sorted
    /// by id and only the decision-relevant fields (id, type, pattern, active)
    /// are hashed, so cosmetic edits (description/source/timestamp) don't churn
    /// it. Deterministic — no clock, no RNG.
    pub fn feed_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut inds = self
            .indicators
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        inds.sort_by(|a, b| a.id.cmp(&b.id));
        let mut h = Sha256::new();
        for i in &inds {
            h.update(i.id.as_bytes());
            h.update([0x1f]);
            h.update(i.indicator_type.to_string().as_bytes());
            h.update([0x1f]);
            h.update(i.pattern.as_bytes());
            h.update([0x1f]);
            h.update([u8::from(i.active)]);
            h.update([0x1e]);
        }
        hex::encode(h.finalize())
    }

    /// List all indicators.
    pub fn list_indicators(&self) -> Vec<ThreatIndicator> {
        self.indicators
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Get feed statistics.
    pub fn get_stats(&self) -> ThreatFeedStats {
        let indicators = self.indicators.read().unwrap_or_else(|e| e.into_inner());
        let mut per_type: HashMap<String, usize> = HashMap::new();
        let mut active_count = 0;

        for ind in indicators.iter() {
            *per_type.entry(ind.indicator_type.to_string()).or_insert(0) += 1;
            if ind.active {
                active_count += 1;
            }
        }

        ThreatFeedStats {
            total_indicators: indicators.len(),
            active_indicators: active_count,
            per_type,
            last_updated: self
                .last_updated
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }
}

// ── Built-in Indicators ──

fn builtin_indicators() -> Vec<ThreatIndicator> {
    let now = chrono::Utc::now().to_rfc3339();
    let source = "iaga-sentinel-builtin".to_string();

    let mut indicators = Vec::new();
    let mut id_counter = 0u32;

    let mut add = |itype: ThreatType, pattern: &str, severity: &str, desc: &str| {
        id_counter += 1;
        indicators.push(ThreatIndicator {
            id: format!("builtin-{:03}", id_counter),
            indicator_type: itype,
            pattern: pattern.to_string(),
            severity: severity.to_string(),
            description: desc.to_string(),
            source: source.clone(),
            created_at: now.clone(),
            active: true,
        });
    };

    // ── Malicious Domains ──
    add(
        ThreatType::MaliciousDomain,
        "webhook.site",
        "high",
        "Known data exfiltration endpoint, webhook.site",
    );
    add(
        ThreatType::MaliciousDomain,
        "requestbin.com",
        "high",
        "Known data exfiltration endpoint, requestbin.com",
    );
    add(
        ThreatType::MaliciousDomain,
        "burpcollaborator.net",
        "critical",
        "Burp Suite collaborator, used in security testing/attacks",
    );
    add(
        ThreatType::MaliciousDomain,
        "ngrok.io",
        "high",
        "Tunnel service often used for exfiltration, ngrok.io",
    );
    add(
        ThreatType::MaliciousDomain,
        "pipedream.net",
        "high",
        "Known data exfiltration endpoint, pipedream.net",
    );

    // ── Malicious Commands ──
    add(
        ThreatType::MaliciousCommand,
        "rm -rf /",
        "critical",
        "Destructive command, recursive force-delete root filesystem",
    );
    add(
        ThreatType::MaliciousCommand,
        "mkfs",
        "critical",
        "Destructive command, formats a filesystem",
    );
    add(
        ThreatType::MaliciousCommand,
        "dd if=/dev/zero",
        "critical",
        "Destructive command, overwrites device with zeros",
    );
    add(
        ThreatType::MaliciousCommand,
        "regex::\\(\\)\\s*\\{\\s*:\\|:\\s*&\\s*\\}\\s*;\\s*:",
        "critical",
        "Fork bomb, exhausts system resources",
    );
    add(
        ThreatType::MaliciousCommand,
        "chmod 777",
        "high",
        "Dangerous permissions, world-readable/writable/executable",
    );
    add(
        ThreatType::MaliciousCommand,
        "regex:curl\\s+.*\\|\\s*sh",
        "critical",
        "Remote code execution, piping curl output to shell",
    );
    add(
        ThreatType::MaliciousCommand,
        "regex:wget\\s+.*\\|\\s*bash",
        "critical",
        "Remote code execution, piping wget output to bash",
    );

    // ── Data Exfiltration ──
    add(
        ThreatType::DataExfiltration,
        "regex:base64.*curl|curl.*base64",
        "high",
        "Data exfiltration, base64 encoding combined with curl",
    );
    add(
        ThreatType::DataExfiltration,
        "regex:tar\\s+.*\\|\\s*nc\\s+",
        "high",
        "Data exfiltration, tar piped to netcat",
    );
    add(
        ThreatType::DataExfiltration,
        "/etc/passwd",
        "high",
        "Sensitive file access, system password file",
    );
    add(
        ThreatType::DataExfiltration,
        "/etc/shadow",
        "critical",
        "Sensitive file access, system shadow password file",
    );
    add(
        ThreatType::DataExfiltration,
        ".ssh/id_rsa",
        "critical",
        "Sensitive file access, SSH private key",
    );

    // ── Known Exploits ──
    add(
        ThreatType::KnownExploit,
        "regex:\\$\\{jndi:(ldap|rmi|dns)://",
        "critical",
        "Log4Shell (CVE-2021-44228), JNDI injection pattern",
    );
    add(
        ThreatType::KnownExploit,
        "169.254.169.254",
        "critical",
        "SSRF, AWS/cloud metadata endpoint",
    );
    add(
        ThreatType::KnownExploit,
        "metadata.google",
        "critical",
        "SSRF, GCP metadata endpoint",
    );

    // ── Prompt Injection ──
    add(
        ThreatType::PromptInjection,
        "ignore previous",
        "high",
        "Prompt injection, attempts to override prior instructions",
    );
    add(
        ThreatType::PromptInjection,
        "system prompt",
        "high",
        "Prompt injection, references system prompt",
    );
    add(
        ThreatType::PromptInjection,
        "you are now",
        "medium",
        "Prompt injection, attempts role reassignment",
    );
    add(
        ThreatType::PromptInjection,
        "regex:(?i)DAN\\s+mode",
        "high",
        "Prompt injection, DAN (Do Anything Now) jailbreak attempt",
    );

    indicators
}
