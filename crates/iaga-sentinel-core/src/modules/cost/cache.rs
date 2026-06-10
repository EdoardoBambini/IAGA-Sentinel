//! Deterministic response cache (ADR 0021, open build "cost reduction").
//!
//! Returns a previously-seen downstream MCP tool result instead of forwarding
//! an identical, safe, read-only call again. Exact/normalized key only —
//! SEMANTIC (embedding-similarity) caching is an Enterprise feature, because it
//! needs a real embedding model + vector index that the open build's reasoning
//! backend cannot provide (ADR 0021).
//!
//! Process-global + in-memory (like the spend store and session graph), TTL'd
//! and size-capped. Savings are surfaced through the cost summary, not as audit
//! rows, so they never double-count the governance event for the same call.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

use crate::core::types::ActionType;

/// Entries older than this are treated as misses and dropped.
const TTL_MS: u64 = 5 * 60 * 1000;
/// Hard cap; the oldest entry is evicted when full.
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub agent_id: String,
    pub tool_name: String,
    pub args_hash: String,
}

#[derive(Clone)]
pub struct CachedResponse {
    pub result_json: serde_json::Value,
    /// What the original call cost (micro-USD), so a hit can report the avoided
    /// spend. Zero when the downstream result carried no usage to price.
    pub original_cost_micros: u64,
    pub stored_at_ms: u64,
}

/// Cumulative cache outcomes for the process, surfaced via the cost summary.
#[derive(Default, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub savings_micros: u64,
}

static CACHE: Lazy<RwLock<HashMap<CacheKey, CachedResponse>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static STATS: Lazy<RwLock<CacheStats>> = Lazy::new(|| RwLock::new(CacheStats::default()));

/// Wall-clock millis since the epoch (used only for TTL; coarse is fine).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Safe to serve from cache? Open build: read-only file reads only — never a
/// side-effecting call. Broadening to safe HTTP GETs is a follow-up.
pub fn is_cacheable(action_type: ActionType) -> bool {
    matches!(action_type, ActionType::FileRead)
}

/// SHA-256 of a canonical (key-sorted) encoding of the tool arguments, so
/// argument order never changes the key. Independent of serde_json's map impl.
pub fn args_hash(arguments: &serde_json::Value) -> String {
    let mut h = Sha256::new();
    h.update(canonical(arguments).as_bytes());
    hex::encode(h.finalize())
}

fn canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let key = serde_json::to_string(k).unwrap_or_default();
                    format!("{key}:{}", canonical(&map[k]))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Look up a live (non-expired) entry, updating hit/miss + savings stats.
pub fn get(key: &CacheKey) -> Option<CachedResponse> {
    let now = now_ms();
    let found = { CACHE.read().ok()?.get(key).cloned() };
    match found {
        Some(v) if now.saturating_sub(v.stored_at_ms) <= TTL_MS => {
            if let Ok(mut s) = STATS.write() {
                s.hits += 1;
                s.savings_micros = s.savings_micros.saturating_add(v.original_cost_micros);
            }
            Some(v)
        }
        Some(_) => {
            if let Ok(mut map) = CACHE.write() {
                map.remove(key);
            }
            if let Ok(mut s) = STATS.write() {
                s.misses += 1;
            }
            None
        }
        None => {
            if let Ok(mut s) = STATS.write() {
                s.misses += 1;
            }
            None
        }
    }
}

/// Store a response. Evicts the oldest entry when at capacity.
pub fn put(key: CacheKey, result_json: serde_json::Value, original_cost_micros: u64) {
    let value = CachedResponse {
        result_json,
        original_cost_micros,
        stored_at_ms: now_ms(),
    };
    if let Ok(mut map) = CACHE.write() {
        if map.len() >= MAX_ENTRIES && !map.contains_key(&key) {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, v)| v.stored_at_ms)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
        map.insert(key, value);
    }
}

/// Cumulative cache stats for the process.
pub fn stats() -> CacheStats {
    STATS.read().map(|s| *s).unwrap_or_default()
}

/// Best-effort: extract a `usage` block from a downstream tool result and price
/// it (caller `costUsd` wins, else the local pricing table), so a future cache
/// hit can report the avoided spend. Zero when no usage is present.
pub fn estimate_cost_micros(result: &serde_json::Value) -> u64 {
    let usage = result
        .get("usage")
        .or_else(|| result.get("_meta").and_then(|m| m.get("usage")));
    let Some(usage) = usage else {
        return 0;
    };
    if let Some(cost) = usage
        .get("costUsd")
        .or_else(|| usage.get("cost_usd"))
        .and_then(|v| v.as_f64())
    {
        return iaga_sentinel_cost::usd_to_micros(cost);
    }
    let provider = usage.get("provider").and_then(|v| v.as_str()).unwrap_or("");
    let model = usage.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let prompt = usage
        .get("promptTokens")
        .or_else(|| usage.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let completion = usage
        .get("completionTokens")
        .or_else(|| usage.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    crate::pipeline::cost::pricing()
        .cost_micros(provider, model, prompt, completion)
        .unwrap_or(0)
}

#[cfg(test)]
pub fn reset() {
    if let Ok(mut m) = CACHE.write() {
        m.clear();
    }
    if let Ok(mut s) = STATS.write() {
        *s = CacheStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(args_hash: &str) -> CacheKey {
        CacheKey {
            agent_id: "agent-x".into(),
            tool_name: "filesystem.read".into(),
            args_hash: args_hash.into(),
        }
    }

    #[test]
    fn gate_allows_only_read_only() {
        assert!(is_cacheable(ActionType::FileRead));
        assert!(!is_cacheable(ActionType::Shell));
        assert!(!is_cacheable(ActionType::FileWrite));
        assert!(!is_cacheable(ActionType::Http));
        assert!(!is_cacheable(ActionType::DbQuery));
    }

    #[test]
    fn args_hash_is_order_independent() {
        let a = serde_json::json!({ "path": "/a", "depth": 2 });
        let b = serde_json::json!({ "depth": 2, "path": "/a" });
        assert_eq!(args_hash(&a), args_hash(&b));
        let c = serde_json::json!({ "path": "/other", "depth": 2 });
        assert_ne!(args_hash(&a), args_hash(&c));
    }

    #[test]
    fn put_then_get_returns_cached_value_with_cost() {
        reset();
        let k = key("hash-roundtrip");
        assert!(get(&k).is_none());
        put(
            k.clone(),
            serde_json::json!({ "content": "hello" }),
            1_500_000,
        );
        let hit = get(&k).expect("cache hit");
        assert_eq!(hit.result_json, serde_json::json!({ "content": "hello" }));
        assert_eq!(hit.original_cost_micros, 1_500_000);
    }

    #[test]
    fn expired_entry_is_a_miss() {
        reset();
        let k = key("hash-expired");
        // Insert an entry stamped far in the past so it is past the TTL.
        if let Ok(mut map) = CACHE.write() {
            map.insert(
                k.clone(),
                CachedResponse {
                    result_json: serde_json::json!({ "stale": true }),
                    original_cost_micros: 10,
                    stored_at_ms: now_ms().saturating_sub(TTL_MS + 1_000),
                },
            );
        }
        assert!(get(&k).is_none(), "stale entry must be treated as a miss");
    }
}
