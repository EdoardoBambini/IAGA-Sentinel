//! 1.5 cost-control capture (ADR 0020).
//!
//! Resolves caller-reported usage into the canonical [`UsageData`] embedded in
//! receipts and the audit ledger, pricing tokens locally via a process-global
//! [`PricingTable`]. The table is loaded once from `IAGA_SENTINEL_PRICING_FILE`
//! (YAML or JSON) or falls back to the dated built-in list. A caller-supplied
//! cost always wins over the table (see [`iaga_sentinel_cost::resolve_usage`]).
//!
//! This module is compiled only under the `cost-control` feature; the default
//! build never references it, so its behavior cannot affect a 1.4.0-identical
//! build.

use std::sync::Arc;

use once_cell::sync::Lazy;

use iaga_sentinel_cost::{PricingTable, UsageData};

use crate::core::types::InspectRequest;

static PRICING: Lazy<Arc<PricingTable>> = Lazy::new(|| Arc::new(load_pricing_table()));

/// The process-global pricing table (loaded once on first use).
pub fn pricing() -> &'static PricingTable {
    &PRICING
}

/// The configured per-session budget in USD, from the
/// `IAGA_SENTINEL_SESSION_BUDGET_USD` env var. Returns `None` (no enforcement)
/// when unset, unparseable, or non-positive. Read once on first use.
pub fn session_budget_usd() -> Option<f64> {
    static BUDGET: Lazy<Option<f64>> = Lazy::new(|| {
        std::env::var("IAGA_SENTINEL_SESSION_BUDGET_USD")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|v| *v > 0.0)
    });
    *BUDGET
}

/// Resolve the usage reported on an inspect request into the canonical ledger
/// form. Returns `None` when the caller reported no usage.
pub fn resolve_for_request(input: &InspectRequest) -> Option<UsageData> {
    input
        .usage
        .as_ref()
        .map(|report| iaga_sentinel_cost::resolve_usage(report, pricing()))
}

/// Load the pricing table from `IAGA_SENTINEL_PRICING_FILE` (YAML or JSON), or
/// the built-in list when the env var is unset, the file is unreadable, or it
/// fails to parse. Keys are normalized to lowercase for case-insensitive lookup.
fn load_pricing_table() -> PricingTable {
    let Ok(path) = std::env::var("IAGA_SENTINEL_PRICING_FILE") else {
        return PricingTable::builtin();
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "cost: pricing file unreadable; using built-in table");
            return PricingTable::builtin();
        }
    };
    let parsed = if path.ends_with(".json") {
        serde_json::from_str::<PricingTable>(&contents).map_err(|e| e.to_string())
    } else {
        serde_yaml::from_str::<PricingTable>(&contents).map_err(|e| e.to_string())
    };
    match parsed {
        Ok(mut table) => {
            table.normalize();
            tracing::info!(path = %path, "cost: loaded pricing table");
            table
        }
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "cost: pricing file parse failed; using built-in table");
            PricingTable::builtin()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{ActionDetail, ActionType, InspectRequest, UsageReport};
    use std::collections::HashMap;

    fn req_with_usage(usage: Option<UsageReport>) -> InspectRequest {
        InspectRequest {
            agent_id: "a".into(),
            tenant_id: None,
            workspace_id: None,
            framework: "test".into(),
            protocol: None,
            action: ActionDetail {
                action_type: ActionType::Http,
                tool_name: "t".into(),
                payload: HashMap::new(),
            },
            requested_secrets: None,
            metadata: None,
            usage,
        }
    }

    #[test]
    fn no_reported_usage_resolves_to_none() {
        assert!(resolve_for_request(&req_with_usage(None)).is_none());
    }

    #[test]
    fn caller_cost_is_captured_verbatim() {
        let report = UsageReport {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-6".into(),
            prompt_tokens: Some(10),
            completion_tokens: Some(20),
            total_tokens: None,
            cost_usd: Some(0.05),
        };
        let u = resolve_for_request(&req_with_usage(Some(report))).expect("usage");
        assert_eq!(u.cost_source, iaga_sentinel_cost::CostSource::Caller);
        assert_eq!(u.cost_micros, 50_000);
        assert_eq!(u.total_tokens, Some(30)); // derived from prompt + completion
    }
}
