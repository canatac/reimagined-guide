//! Detection rules — regroupées par catégorie pour clean code / maintenabilité.
//!
//! Chaque sous-module contient un ensemble cohérent de règles:
//! - `traffic`  : volume, bounce, codes SMTP, anomalies horaires, queue
//! - `geo`      : destinations pays/ASN nouveaux ou à haut risque
//! - `auth`     : brute force, clés API dormantes
//! - `identity` : SPF/DKIM drift, rotation identité, corrélations cross-tenant, rate-limit
//! - `helpers`  : utilitaires partagés (crate-private)
//!
//! Rules are evaluated by the background engine every SECURITY_EVAL_INTERVAL_S
//! seconds (default 60). Each rule queries MongoDB over a configurable window.

pub(crate) mod helpers;
mod traffic;
mod geo;
mod auth;
mod identity;

pub use helpers::RuleContext;

pub use traffic::{
    rule_abuse_volume_spike, rule_bounce_rate_surge,
    rule_smtp_code_spike_temp, rule_smtp_code_spike_perm,
    rule_hourly_anomaly, rule_queue_buildup,
};
pub use geo::{
    rule_new_destination_country, rule_new_destination_asn,
    rule_high_risk_asn_country,
};
pub use auth::{rule_auth_brute_force, rule_stale_api_key};
pub use identity::{
    rule_spf_dkim_drift, rule_sender_identity_rotation,
    rule_cross_tenant_payload_correlation, rule_rate_limit_circumvention,
};

use super::SecurityAlert;
use helpers::RuleContext;

pub async fn evaluate_all(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    // Run rules concurrently where possible
    let (r1, r2, r3, r4, r5) = tokio::join!(
        rule_abuse_volume_spike(ctx),
        rule_bounce_rate_surge(ctx),
        rule_smtp_code_spike_temp(ctx),
        rule_smtp_code_spike_perm(ctx),
        rule_new_destination_country(ctx),
    );
    let (r6, r7, r8, r9, r10) = tokio::join!(
        rule_new_destination_asn(ctx),
        rule_auth_brute_force(ctx),
        rule_high_risk_asn_country(ctx),
        rule_spf_dkim_drift(ctx),
        rule_sender_identity_rotation(ctx),
    );
    let (r11, r12, r13, r14, r15) = tokio::join!(
        rule_hourly_anomaly(ctx),
        rule_queue_buildup(ctx),
        rule_cross_tenant_payload_correlation(ctx),
        rule_rate_limit_circumvention(ctx),
        rule_stale_api_key(ctx),
    );

    [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15]
        .into_iter()
        .flatten()
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::helpers::{env_u64, since};

    #[test]
    fn test_env_u64_default() {
        std::env::remove_var("SEC_VOLUME_SPIKE_THRESHOLD");
        assert_eq!(env_u64("SEC_VOLUME_SPIKE_THRESHOLD", 999), 999);
    }

    #[test]
    fn test_env_u64_from_env() {
        std::env::set_var("SEC_TEST_VAL", "42");
        assert_eq!(env_u64("SEC_TEST_VAL", 0), 42);
        std::env::remove_var("SEC_TEST_VAL");
    }

    #[test]
    fn test_since_is_in_past() {
        let s = since(60);
        let dt = chrono::DateTime::parse_from_rfc3339(&s).unwrap();
        assert!(dt < chrono::Utc::now());
    }
}

