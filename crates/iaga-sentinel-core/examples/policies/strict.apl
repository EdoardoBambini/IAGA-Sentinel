// IAGA Sentinel 1.0 — example "strict" APL overlay.
// Load with:
//   iaga serve --policy crates/iaga-sentinel-core/examples/policies/strict.apl
//
// All three policies tighten the YAML baseline. None of them relaxes:
// the merge in execute_pipeline is "stricter wins" by design.

policy "halt_on_high_risk_shell" {
  when action.kind == "shell"
   and risk.score > 50
  then block, reason="shell with elevated risk"
}

policy "review_all_email_egress" {
  when action.kind == "email"
  then review, reason="all email goes through human review under strict overlay"
}

policy "block_off_allowlist_http" {
  when action.kind == "http"
   and action.tool_name not in workspace.allowlist
  then block, reason="off-allowlist http egress"
}
