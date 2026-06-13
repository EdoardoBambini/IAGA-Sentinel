//! 1.5 cost-control storage tests: append audit events carrying usage, then
//! assert the aggregation queries roll them up correctly and that usage
//! round-trips through `list()`.

use iaga_sentinel::core::types::*;
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::AuditStore;

fn event(id: &str, agent: &str, tool: &str, usage: Option<UsageData>) -> StoredAuditEvent {
    StoredAuditEvent {
        event_id: id.into(),
        agent_id: agent.into(),
        tenant_id: None,
        framework: "test".into(),
        action_type: ActionType::Http,
        tool_name: tool.into(),
        decision: GovernanceDecision::Allow,
        timestamp: "2026-06-09T12:00:00Z".into(),
        reasons: vec![],
        review_status: ReviewStatus::NotRequired,
        risk_score: 10,
        usage,
        session_id: None,
    }
}

fn priced(model: &str, cost_micros: u64, total_tokens: u64) -> UsageData {
    UsageData {
        provider: "anthropic".into(),
        model: model.into(),
        prompt_tokens: Some(total_tokens / 2),
        completion_tokens: Some(total_tokens / 2),
        total_tokens: Some(total_tokens),
        cost_micros,
        cache_hit: false,
        savings_micros: None,
        cost_source: CostSource::PricingTable,
    }
}

#[tokio::test]
async fn cost_aggregation_rolls_up_usage() {
    let store = SqliteStorage::new("sqlite::memory:")
        .await
        .expect("in-memory sqlite");

    // Two priced actions on different models...
    store
        .append(&event(
            "e1",
            "agent-a",
            "search",
            Some(priced("claude-sonnet-4-6", 18_000_000, 2_000_000)),
        ))
        .await
        .unwrap();
    store
        .append(&event(
            "e2",
            "agent-a",
            "fetch",
            Some(priced("claude-opus-4-8", 90_000_000, 1_000_000)),
        ))
        .await
        .unwrap();
    // ...one cache hit (zero cost, records the avoided spend as savings)...
    let mut hit = priced("claude-sonnet-4-6", 0, 0);
    hit.cache_hit = true;
    hit.savings_micros = Some(18_000_000);
    hit.cost_source = CostSource::Cache;
    store
        .append(&event("e3", "agent-a", "search", Some(hit)))
        .await
        .unwrap();
    // ...and one action with no usage at all (must be ignored by cost rollups).
    store
        .append(&event("e4", "agent-b", "noop", None))
        .await
        .unwrap();

    let summary = store.cost_summary(None, None).await.unwrap();
    // net = 18 + 90 + 0 = 108 ; savings = 18 ; gross = net + savings = 126
    assert!(
        (summary.net_cost_usd - 108.0).abs() < 1e-6,
        "net={}",
        summary.net_cost_usd
    );
    assert!(
        (summary.savings_usd - 18.0).abs() < 1e-6,
        "savings={}",
        summary.savings_usd
    );
    assert!(
        (summary.gross_cost_usd - 126.0).abs() < 1e-6,
        "gross={}",
        summary.gross_cost_usd
    );
    assert_eq!(summary.total_tokens, 3_000_000);
    assert_eq!(summary.cache_hits, 1);
    assert_eq!(summary.total_actions, 3, "e4 carries no usage");

    let by_model = store.cost_by_model(None, None, 10).await.unwrap();
    let opus = by_model
        .iter()
        .find(|r| r.key == "claude-opus-4-8")
        .expect("opus row");
    assert!((opus.net_cost_usd - 90.0).abs() < 1e-6);
    let sonnet = by_model
        .iter()
        .find(|r| r.key == "claude-sonnet-4-6")
        .expect("sonnet row");
    assert!((sonnet.net_cost_usd - 18.0).abs() < 1e-6);
    assert_eq!(sonnet.cache_hits, 1);

    // list() round-trips usage from the stored JSON column.
    let listed = store.list(10).await.unwrap();
    let e2 = listed
        .iter()
        .find(|e| e.event_id == "e2")
        .expect("e2 listed");
    let u = e2.usage.as_ref().expect("usage round-trips");
    assert_eq!(u.model, "claude-opus-4-8");
    assert_eq!(u.cost_micros, 90_000_000);
}
