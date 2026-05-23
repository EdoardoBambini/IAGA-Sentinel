use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::core::types::RateLimitConfig;

/// Result of a rate limit check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub reset_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u32>,
}

/// Per-key status snapshot for the status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitStatus {
    pub agent_id: String,
    pub requests_last_minute: u32,
    pub requests_last_hour: u32,
    pub requests_last_5_seconds: u32,
    pub config: RateLimitConfig,
}

/// Sliding-window rate limiter backed by in-memory timestamp vectors.
pub struct RateLimiter {
    /// Map from key (agent_id or agent_id:tool_name) to sorted timestamps.
    windows: RwLock<HashMap<String, Vec<Instant>>>,
    config: RwLock<RateLimitConfig>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            config: RwLock::new(config),
        }
    }

    /// Build the key used for rate-limit tracking.
    fn make_key(agent_id: &str, tool_name: Option<&str>) -> String {
        match tool_name {
            Some(t) => format!("{}:{}", agent_id, t),
            None => agent_id.to_string(),
        }
    }

    /// Check whether a request is allowed and, if so, record it.
    pub async fn check_rate(&self, agent_id: &str, tool_name: Option<&str>) -> RateLimitResult {
        let config = self.config.read().await.clone();
        let key = Self::make_key(agent_id, tool_name);
        let now = Instant::now();

        let mut windows = self.windows.write().await;
        let timestamps = windows.entry(key).or_insert_with(Vec::new);

        // Prune entries older than 1 hour (the largest window we care about).
        let one_hour_ago = now.checked_sub(Duration::from_secs(3600)).unwrap_or(now);
        timestamps.retain(|t| *t >= one_hour_ago);

        let one_minute_ago = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        let five_seconds_ago = now.checked_sub(Duration::from_secs(5)).unwrap_or(now);

        let count_minute = timestamps.iter().filter(|t| **t >= one_minute_ago).count() as u32;
        let count_hour = timestamps.len() as u32;
        let count_burst = timestamps
            .iter()
            .filter(|t| **t >= five_seconds_ago)
            .count() as u32;

        // Determine which limit is hit (if any) and calculate retry_after.
        let (allowed, retry_after_secs) = if count_burst >= config.burst_limit {
            // Burst limit: retry after the oldest burst-window entry expires.
            let oldest_burst = timestamps
                .iter()
                .filter(|t| **t >= five_seconds_ago)
                .min()
                .copied()
                .unwrap_or(now);
            let wait = Duration::from_secs(5)
                .checked_sub(now.duration_since(oldest_burst))
                .unwrap_or(Duration::from_secs(1));
            (false, Some(wait.as_secs() as u32 + 1))
        } else if count_minute >= config.max_per_minute {
            let oldest_minute = timestamps
                .iter()
                .filter(|t| **t >= one_minute_ago)
                .min()
                .copied()
                .unwrap_or(now);
            let wait = Duration::from_secs(60)
                .checked_sub(now.duration_since(oldest_minute))
                .unwrap_or(Duration::from_secs(1));
            (false, Some(wait.as_secs() as u32 + 1))
        } else if count_hour >= config.max_per_hour {
            let oldest_hour = timestamps.iter().min().copied().unwrap_or(now);
            let wait = Duration::from_secs(3600)
                .checked_sub(now.duration_since(oldest_hour))
                .unwrap_or(Duration::from_secs(1));
            (false, Some(wait.as_secs() as u32 + 1))
        } else {
            (true, None)
        };

        if allowed {
            timestamps.push(now);
        }

        let remaining = config.max_per_minute.saturating_sub(if allowed {
            count_minute + 1
        } else {
            count_minute
        });

        let reset_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 60; // next minute-window reset

        RateLimitResult {
            allowed,
            remaining,
            reset_at,
            retry_after_secs,
        }
    }

    /// Return current rate-limit status for an agent (read-only, does not record).
    pub async fn status(&self, agent_id: &str) -> RateLimitStatus {
        let config = self.config.read().await.clone();
        let now = Instant::now();

        let windows = self.windows.read().await;

        let (req_minute, req_hour, req_burst) = if let Some(timestamps) = windows.get(agent_id) {
            let one_minute_ago = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
            let one_hour_ago = now.checked_sub(Duration::from_secs(3600)).unwrap_or(now);
            let five_seconds_ago = now.checked_sub(Duration::from_secs(5)).unwrap_or(now);

            let m = timestamps.iter().filter(|t| **t >= one_minute_ago).count() as u32;
            let h = timestamps.iter().filter(|t| **t >= one_hour_ago).count() as u32;
            let b = timestamps
                .iter()
                .filter(|t| **t >= five_seconds_ago)
                .count() as u32;
            (m, h, b)
        } else {
            (0, 0, 0)
        };

        RateLimitStatus {
            agent_id: agent_id.to_string(),
            requests_last_minute: req_minute,
            requests_last_hour: req_hour,
            requests_last_5_seconds: req_burst,
            config,
        }
    }

    /// Get the current config.
    pub async fn get_config(&self) -> RateLimitConfig {
        self.config.read().await.clone()
    }

    /// Update the config at runtime.
    pub async fn update_config(&self, new_config: RateLimitConfig) {
        let mut cfg = self.config.write().await;
        *cfg = new_config;
    }

    /// Prune all entries older than 1 hour to free memory.
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let one_hour_ago = now.checked_sub(Duration::from_secs(3600)).unwrap_or(now);
        let mut windows = self.windows.write().await;

        windows.retain(|_key, timestamps| {
            timestamps.retain(|t| *t >= one_hour_ago);
            !timestamps.is_empty()
        });
    }
}
