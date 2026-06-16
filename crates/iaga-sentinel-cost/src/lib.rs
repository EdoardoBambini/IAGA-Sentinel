//! # iaga-sentinel-cost
//!
//! Canonical cost/usage types and the self-hosted pricing engine shared by
//! `iaga-sentinel-receipts` (the signed ledger) and `iaga-sentinel-core`
//! (capture, aggregation, budget enforcement).
//!
//! Design notes:
//! - **Leaf crate**: depends only on `serde` (+ `serde_json`), no other
//!   workspace crate. This lets `iaga-sentinel-receipts` embed [`UsageData`]
//!   in `ReceiptBody` without a dependency cycle (receipts must not depend on
//!   core).
//! - **Two shapes, on purpose**: [`UsageReport`] is the *wire* form a caller
//!   reports (costs as human USD, because that is what callers compute);
//!   [`UsageData`] is the *canonical* form embedded in a signed receipt
//!   (money as integer micro-USD so the ledger is exact and the type stays
//!   `Eq`, which `ReceiptBody` requires).
//! - **Self-hosted pricing**: token to USD conversion happens locally via
//!   [`PricingTable`]; no external billing API is ever called. A
//!   caller-supplied cost always wins over the table (see [`resolve_usage`]).

pub mod pricing;
pub mod usage;

pub use pricing::{ModelRate, PricingTable, BUILTIN_PRICING_EFFECTIVE_DATE};
pub use usage::{micros_to_usd, usd_to_micros, CostSource, UsageData, UsageReport};

/// Resolve a caller's [`UsageReport`] into the canonical [`UsageData`] embedded
/// in receipts and the audit store.
///
/// Precedence for the recorded cost:
/// 1. a caller-supplied `cost_usd` (ground truth, wins over the table),
/// 2. else the local [`PricingTable`] priced from token counts,
/// 3. else `unpriced` (zero cost, recorded as such so it is auditable).
pub fn resolve_usage(report: &UsageReport, pricing: &PricingTable) -> UsageData {
    let prompt = report.prompt_tokens.unwrap_or(0);
    let completion = report.completion_tokens.unwrap_or(0);
    // Derive total when the caller did not send it but sent both halves.
    let total_tokens =
        report
            .total_tokens
            .or(match (report.prompt_tokens, report.completion_tokens) {
                // saturating: caller-supplied counts must not panic (debug) or
                // wrap (release) into an absurd signed ledger value (SOUND-COST-1).
                (Some(p), Some(c)) => Some(p.saturating_add(c)),
                _ => None,
            });
    let (cost_micros, cost_source) = match report.cost_usd {
        Some(usd) => (usd_to_micros(usd), CostSource::Caller),
        None => match pricing.cost_micros(&report.provider, &report.model, prompt, completion) {
            Some(m) => (m, CostSource::PricingTable),
            None => (0, CostSource::Unpriced),
        },
    };
    UsageData {
        provider: report.provider.clone(),
        model: report.model.clone(),
        prompt_tokens: report.prompt_tokens,
        completion_tokens: report.completion_tokens,
        total_tokens,
        cost_micros,
        cache_hit: false,
        savings_micros: None,
        cost_source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(cost_usd: Option<f64>) -> UsageReport {
        UsageReport {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-6".into(),
            prompt_tokens: Some(1_000_000),
            completion_tokens: Some(1_000_000),
            total_tokens: None,
            cost_usd,
        }
    }

    #[test]
    fn caller_cost_wins_over_table() {
        let out = resolve_usage(&report(Some(0.42)), &PricingTable::builtin());
        assert_eq!(out.cost_source, CostSource::Caller);
        assert_eq!(out.cost_micros, 420_000);
    }

    #[test]
    fn pricing_table_prices_when_no_caller_cost() {
        // Sonnet 4.6 builtin: $3/Mtok in, $15/Mtok out → 1M+1M tokens = $18.
        let out = resolve_usage(&report(None), &PricingTable::builtin());
        assert_eq!(out.cost_source, CostSource::PricingTable);
        assert_eq!(out.cost_micros, 18_000_000);
    }

    #[test]
    fn unknown_model_is_unpriced() {
        let mut r = report(None);
        r.model = "no-such-model".into();
        let out = resolve_usage(&r, &PricingTable::builtin());
        assert_eq!(out.cost_source, CostSource::Unpriced);
        assert_eq!(out.cost_micros, 0);
    }

    #[test]
    fn total_tokens_derived_when_missing() {
        let out = resolve_usage(&report(Some(0.0)), &PricingTable::builtin());
        assert_eq!(out.total_tokens, Some(2_000_000));
    }
}
