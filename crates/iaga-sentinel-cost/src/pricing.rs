//! Self-hosted pricing table: converts provider/model token counts to
//! micro-USD with no external billing API.
//!
//! The [`PricingTable::builtin`] list lets the feature work with zero config;
//! operators override it with a file (loaded by `iaga-sentinel-core`). A
//! caller-supplied cost always takes precedence over the table — the table is
//! only consulted when the caller did not report a dollar figure (see
//! [`crate::resolve_usage`]). List prices drift, so treat table-derived costs
//! as indicative, not an invoice.

use crate::usage::usd_to_micros;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-model rate in USD per million tokens (the unit vendors publish).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRate {
    pub input_per_mtok_usd: f64,
    pub output_per_mtok_usd: f64,
}

impl ModelRate {
    /// Cost in micro-USD for the given token counts.
    ///
    /// DET-COST-1: each component is rounded to integer micro-USD and the
    /// integers are summed (`saturating_add`). Per-component rounding is the
    /// specified, order-independent semantics — a single `round` over the f64
    /// sum left "round-to-the-sum vs per-component" unspecified — and the
    /// integer sum can never wrap the signed ledger even with an absurd token
    /// count (the f64→u64 cast in `usd_to_micros` saturates).
    pub fn cost_micros(&self, prompt_tokens: u64, completion_tokens: u64) -> u64 {
        let input = usd_to_micros(prompt_tokens as f64 / 1_000_000.0 * self.input_per_mtok_usd);
        let output =
            usd_to_micros(completion_tokens as f64 / 1_000_000.0 * self.output_per_mtok_usd);
        input.saturating_add(output)
    }
}

/// A self-hosted price list, keyed `provider -> model -> rate`. Provider and
/// model lookups are case-insensitive; keys are normalized to lowercase by
/// [`PricingTable::builtin`] and should be normalized after loading from a file
/// via [`PricingTable::normalize`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PricingTable {
    #[serde(default)]
    pub providers: HashMap<String, HashMap<String, ModelRate>>,
    /// Fallback rate when no `(provider, model)` entry matches. When absent, an
    /// unmatched model is recorded as `unpriced` (zero cost).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_rate: Option<ModelRate>,
}

/// Date the [`PricingTable::builtin`] rates were last checked against
/// published list prices (ISO 8601). A const rather than a `PricingTable`
/// field on purpose: adding a field would change the serialized table (and
/// the `/v1/cost/pricing` JSON) for existing consumers. Hosts use this to
/// warn when the built-in list has gone stale — list prices drift, and a
/// receipt silently priced off an old table corrupts the cost ledger's
/// usefulness without anyone noticing. Bump it whenever the rates below are
/// re-verified.
pub const BUILTIN_PRICING_EFFECTIVE_DATE: &str = "2026-05-01";

impl PricingTable {
    /// Built-in published list prices (USD per million tokens), as of
    /// [`BUILTIN_PRICING_EFFECTIVE_DATE`]. Overridable via
    /// `IAGA_SENTINEL_PRICING_FILE`; a caller-supplied cost always wins.
    /// See ADR 0020.
    pub fn builtin() -> Self {
        fn rate(input: f64, output: f64) -> ModelRate {
            ModelRate {
                input_per_mtok_usd: input,
                output_per_mtok_usd: output,
            }
        }
        let anthropic = HashMap::from([
            ("claude-opus-4-8".to_string(), rate(15.0, 75.0)),
            ("claude-opus-4-1".to_string(), rate(15.0, 75.0)),
            ("claude-sonnet-4-6".to_string(), rate(3.0, 15.0)),
            ("claude-sonnet-4-5".to_string(), rate(3.0, 15.0)),
            ("claude-haiku-4-5".to_string(), rate(1.0, 5.0)),
            ("claude-3-5-haiku".to_string(), rate(0.8, 4.0)),
        ]);
        let openai = HashMap::from([
            ("gpt-4o".to_string(), rate(2.5, 10.0)),
            ("gpt-4o-mini".to_string(), rate(0.15, 0.6)),
            ("gpt-4-turbo".to_string(), rate(10.0, 30.0)),
            ("gpt-4.1".to_string(), rate(2.0, 8.0)),
            ("gpt-4.1-mini".to_string(), rate(0.4, 1.6)),
        ]);
        let providers = HashMap::from([
            ("anthropic".to_string(), anthropic),
            ("openai".to_string(), openai),
        ]);
        Self {
            providers,
            default_rate: None,
        }
    }

    /// Lowercase every provider and model key in place. Call after loading a
    /// table from a file so case-insensitive lookup works.
    pub fn normalize(&mut self) {
        let normalized = self
            .providers
            .drain()
            .map(|(provider, models)| {
                let models = models
                    .into_iter()
                    .map(|(model, r)| (model.to_lowercase(), r))
                    .collect();
                (provider.to_lowercase(), models)
            })
            .collect();
        self.providers = normalized;
    }

    /// Parse a table from a JSON string, then normalize keys.
    pub fn from_json_str(s: &str) -> serde_json::Result<Self> {
        let mut table: Self = serde_json::from_str(s)?;
        table.normalize();
        Ok(table)
    }

    /// The rate for `(provider, model)`, falling back to `default_rate`.
    pub fn rate(&self, provider: &str, model: &str) -> Option<&ModelRate> {
        self.providers
            .get(&provider.to_lowercase())
            .and_then(|models| models.get(&model.to_lowercase()))
            .or(self.default_rate.as_ref())
    }

    /// Cost in micro-USD for the given usage, or `None` if unpriced (no
    /// matching rate and no `default_rate`).
    pub fn cost_micros(
        &self,
        provider: &str,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
    ) -> Option<u64> {
        self.rate(provider, model)
            .map(|r| r.cost_micros(prompt_tokens, completion_tokens))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_rate_math_is_micro_exact() {
        let r = ModelRate {
            input_per_mtok_usd: 3.0,
            output_per_mtok_usd: 15.0,
        };
        // 500k in @ $3/Mtok = $1.50 ; 250k out @ $15/Mtok = $3.75 ; total $5.25
        assert_eq!(r.cost_micros(500_000, 250_000), 5_250_000);
    }

    #[test]
    fn cost_rounds_per_component_and_saturates() {
        // Per-component rounding: 1 token each rounds up to 1 micro
        // independently (2 total), where rounding the f64 sum first would give 1
        // — this pins the specified semantics (DET-COST-1).
        let r = ModelRate {
            input_per_mtok_usd: 0.6,
            output_per_mtok_usd: 0.6,
        };
        assert_eq!(r.cost_micros(1, 1), 2);

        // An absurd token count must saturate, never wrap or panic.
        let big = ModelRate {
            input_per_mtok_usd: 1e9,
            output_per_mtok_usd: 1e9,
        };
        assert_eq!(big.cost_micros(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn builtin_lookup_is_case_insensitive() {
        let t = PricingTable::builtin();
        let a = t.cost_micros("anthropic", "claude-opus-4-8", 1_000_000, 0);
        let b = t.cost_micros("Anthropic", "Claude-Opus-4-8", 1_000_000, 0);
        assert_eq!(a, Some(15_000_000));
        assert_eq!(a, b);
    }

    #[test]
    fn unknown_without_default_is_none() {
        let t = PricingTable::builtin();
        assert_eq!(t.cost_micros("acme", "mystery-1", 100, 100), None);
    }

    #[test]
    fn default_rate_is_fallback() {
        let t = PricingTable {
            default_rate: Some(ModelRate {
                input_per_mtok_usd: 1.0,
                output_per_mtok_usd: 1.0,
            }),
            ..Default::default()
        };
        assert_eq!(
            t.cost_micros("x", "y", 1_000_000, 1_000_000),
            Some(2_000_000)
        );
    }

    #[test]
    fn from_json_normalizes_keys() {
        let json = r#"{
            "providers": { "OpenAI": { "GPT-4o": { "inputPerMtokUsd": 2.5, "outputPerMtokUsd": 10.0 } } }
        }"#;
        let t = PricingTable::from_json_str(json).unwrap();
        assert_eq!(
            t.cost_micros("openai", "gpt-4o", 1_000_000, 0),
            Some(2_500_000)
        );
    }
}
