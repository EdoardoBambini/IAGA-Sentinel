//! Cost/usage value types.
//!
//! See the crate root for the [`UsageReport`] (wire) vs [`UsageData`]
//! (canonical, micro-USD) distinction.

use serde::{Deserialize, Serialize};

/// Where a resolved cost figure came from. Recorded for auditability so an
/// operator can tell a caller-asserted cost from a locally-priced one, and a
/// real charge from a cache hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostSource {
    /// Cost supplied verbatim by the caller (ground truth; wins over the table).
    Caller,
    /// Cost computed locally from the pricing table.
    PricingTable,
    /// Synthesized for a cache hit: the call never reached the provider.
    Cache,
    /// No rate was available; cost recorded as zero.
    Unpriced,
}

/// Raw usage as reported by a caller (an agent SDK, the `/v1/inspect` body, or
/// the MCP proxy). Costs are in human USD; token counts are exact when the
/// provider returned them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReport {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    /// Caller-asserted cost in USD. When present it overrides the pricing table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

/// Canonical usage record embedded in a signed receipt and the audit store.
///
/// Money is held as integer **micro-USD** (`cost_micros`, 1e-6 USD) for two
/// reasons: an exact integer ledger avoids floating-point drift when costs are
/// summed, and it keeps the type `Eq` — which `ReceiptBody` derives and relies
/// on. Float dollars are derived on demand via [`UsageData::cost_usd`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageData {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    /// Cost in micro-USD (1e-6 USD). Zero when `cost_source` is `Unpriced` or
    /// `Cache`.
    pub cost_micros: u64,
    /// True when this row was served from cache without hitting the provider.
    #[serde(default, skip_serializing_if = "is_false")]
    pub cache_hit: bool,
    /// Micro-USD saved by a cache hit (the cost the call would otherwise have
    /// incurred). `None` unless this is a cache hit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub savings_micros: Option<u64>,
    pub cost_source: CostSource,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl UsageData {
    /// Cost in USD, derived from `cost_micros`. For display and aggregation
    /// only; the signed receipt stores the exact micros.
    pub fn cost_usd(&self) -> f64 {
        micros_to_usd(self.cost_micros)
    }

    /// Savings in USD, derived. Zero when this is not a cache hit.
    pub fn savings_usd(&self) -> f64 {
        self.savings_micros.map(micros_to_usd).unwrap_or(0.0)
    }
}

/// USD to micro-USD, rounding to the nearest micro-dollar. Negative or
/// non-finite inputs clamp to zero (a cost can never be negative).
pub fn usd_to_micros(usd: f64) -> u64 {
    if !usd.is_finite() || usd <= 0.0 {
        return 0;
    }
    (usd * 1_000_000.0).round() as u64
}

/// micro-USD to USD, for display and aggregation only.
pub fn micros_to_usd(micros: u64) -> f64 {
    micros as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micros_round_trip() {
        assert_eq!(usd_to_micros(1.234567), 1_234_567);
        assert_eq!(usd_to_micros(0.0000005), 1); // rounds to nearest micro
        assert_eq!(micros_to_usd(1_500_000), 1.5);
    }

    #[test]
    fn negative_and_nonfinite_clamp_to_zero() {
        assert_eq!(usd_to_micros(-5.0), 0);
        assert_eq!(usd_to_micros(f64::NAN), 0);
        assert_eq!(usd_to_micros(f64::INFINITY), 0);
    }

    #[test]
    fn usage_data_json_is_camel_case_and_elides_defaults() {
        let u = UsageData {
            provider: "anthropic".into(),
            model: "claude-opus-4-8".into(),
            prompt_tokens: Some(10),
            completion_tokens: Some(20),
            total_tokens: Some(30),
            cost_micros: 525_000,
            cache_hit: false,
            savings_micros: None,
            cost_source: CostSource::PricingTable,
        };
        let v: serde_json::Value = serde_json::to_value(&u).unwrap();
        assert_eq!(v["costMicros"], 525_000);
        assert_eq!(v["promptTokens"], 10);
        assert_eq!(v["costSource"], "pricing_table");
        // false bool and None option are elided to keep the receipt minimal.
        assert!(v.get("cacheHit").is_none());
        assert!(v.get("savingsMicros").is_none());
        // round-trips
        let back: UsageData = serde_json::from_value(v).unwrap();
        assert_eq!(back, u);
    }

    #[test]
    fn cache_hit_serializes_savings() {
        let u = UsageData {
            provider: "anthropic".into(),
            model: "claude-haiku-4-5".into(),
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            cost_micros: 0,
            cache_hit: true,
            savings_micros: Some(1_200),
            cost_source: CostSource::Cache,
        };
        let v: serde_json::Value = serde_json::to_value(&u).unwrap();
        assert_eq!(v["cacheHit"], true);
        assert_eq!(v["savingsMicros"], 1_200);
        assert_eq!(u.savings_usd(), 0.0012);
    }
}
