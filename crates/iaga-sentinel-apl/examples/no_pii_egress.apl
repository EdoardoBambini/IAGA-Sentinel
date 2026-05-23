// Example APL policy set. Run with:
//   iaga policy test crates/iaga-sentinel-apl/examples/no_pii_egress.apl \
//       --context crates/iaga-sentinel-apl/examples/sample_context.json

policy "no_secrets_to_public_http" {
  when action.kind == "http.request"
   and action.url.host not in workspace.allowlist
   and secret_ref(action.payload)
  then block, reason="PII egress", evidence=action.url.host
}

policy "halt_on_hijack_suspicion" {
  when action.kind == "shell"
   and action.risk_score > 80
  then block, reason="injection suspected"
}

policy "default_allow" {
  when true
  then allow
}
