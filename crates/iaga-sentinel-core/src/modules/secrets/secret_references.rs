use super::vault::secret_exists;
use crate::core::types::{AgentProfile, InspectRequest, SecretInjectionPlan};

const SECRET_REF_PREFIX: &str = "secretref://";

pub fn plan_secret_injection(
    input: &InspectRequest,
    profile: &AgentProfile,
) -> SecretInjectionPlan {
    let mut approved = Vec::new();
    let mut denied = Vec::new();

    let secrets = match &input.requested_secrets {
        Some(s) => s,
        None => return SecretInjectionPlan { approved, denied },
    };

    for secret_ref in secrets {
        if !secret_ref.starts_with(SECRET_REF_PREFIX) {
            denied.push(secret_ref.clone());
            continue;
        }

        if !secret_exists(secret_ref) {
            denied.push(secret_ref.clone());
            continue;
        }

        if !profile.approved_secrets.contains(secret_ref) {
            denied.push(secret_ref.clone());
            continue;
        }

        approved.push(secret_ref.clone());
    }

    SecretInjectionPlan { approved, denied }
}
