use once_cell::sync::Lazy;
use std::collections::HashSet;

static DEMO_VAULT: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s = HashSet::new();
    s.insert("secretref://prod/github/token");
    s.insert("secretref://prod/slack/webhook");
    s
});

pub fn secret_exists(secret_ref: &str) -> bool {
    DEMO_VAULT.contains(secret_ref)
}
