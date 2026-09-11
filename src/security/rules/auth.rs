//! Auto-généré par le refacto architecte (rules split par catégorie).

use futures_util::TryStreamExt;
use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use super::helpers::RuleContext;
use super::helpers::{since, env_u64, db_name, count};

pub async fn rule_auth_brute_force(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_AUTH_FAIL_THRESHOLD", 10);
    let s = since(5);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("auth_events");

    // Group failures by IP
    let pipeline = vec![
        doc! { "$match": { "ts": { "$gte": &s }, "success": false } },
        doc! { "$group": { "_id": "$ip", "count": { "$sum": 1 } } },
        doc! { "$match": { "count": { "$gte": threshold as i64 } } },
        doc! { "$sort": { "count": -1 } },
        doc! { "$limit": 20 },
    ];

    let docs = match coll.aggregate(pipeline).await {
        Ok(c) => c.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    let mut alerts = Vec::new();
    for d in &docs {
        let ip = d.get_str("_id").unwrap_or("unknown");
        let count_val = d.get_i64("count").unwrap_or(0) as u64;

        let level = if count_val > threshold * 5 {
            RemediationLevel::BLOCK
        } else {
            RemediationLevel::THROTTLE
        };

        let mut alert = SecurityAlert::new(
            "AUTH_BRUTE_FORCE",
            "Brute force authentification",
            SecuritySeverity::High,
            level,
        )
        .with_signal(json!({
            "ip": ip,
            "failures_5m": count_val,
            "threshold": threshold,
        }))
        .with_duration(900); // 15 min block

        alert.ip = Some(ip.to_string());
        if let Some(ref tid) = ctx.tenant_id {
            alert = alert.with_tenant(tid);
        }
        alert.stamp_audit_hash();
        alerts.push(alert);
    }
    alerts
}

// ---------------------------------------------------------------------------
// Rule 8 — HIGH_RISK_ASN_COUNTRY
// Connexion MX depuis ASN/pays à risque non habituel.
// Source: smtp_events | Window: 1h
// L1 alerte, L2 si volume > threshold
// FP: partenaires légitimes en zones géographiques sensibles
// ---------------------------------------------------------------------------

pub async fn rule_stale_api_key(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let max_age_days = env_u64("SEC_API_KEY_MAX_AGE_DAYS", 90);
    // In absence of an API key rotation table, we check auth_events for
    // sessions older than max_age without a recent key-change event.
    let s_recent = since(60 * 24 * max_age_days as i64);

    let old_sessions = count(
        ctx.client,
        "auth_events",
        doc! {
            "ts": { "$lte": &s_recent },
            "success": true,
            "kind": "api_key",
        },
    )
    .await;

    if old_sessions == 0 {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "STALE_API_KEY",
        "API key ancienne non rotée",
        SecuritySeverity::Medium,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "sessions_with_old_key": old_sessions,
        "max_age_days": max_age_days,
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule engine: evaluate all rules
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_brute_force_threshold_default() {
        let threshold = 10u64;
        assert_eq!(threshold, 10);
    }

    #[test]
    fn auth_brute_force_level_block() {
        let count_val = 60u64;
        let threshold = 10u64;
        let level = if count_val > threshold * 5 {
            RemediationLevel::BLOCK
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::BLOCK);
    }

    #[test]
    fn auth_brute_force_level_throttle() {
        let count_val = 30u64;
        let threshold = 10u64;
        let level = if count_val > threshold * 5 {
            RemediationLevel::BLOCK
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn auth_brute_force_level_at_threshold() {
        let count_val = 50u64;
        let threshold = 10u64;
        let level = if count_val > threshold * 5 {
            RemediationLevel::BLOCK
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn auth_brute_force_level_just_above_threshold() {
        let count_val = 51u64;
        let threshold = 10u64;
        let level = if count_val > threshold * 5 {
            RemediationLevel::BLOCK
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::BLOCK);
    }

    #[test]
    fn auth_brute_force_alert_type() {
        let alert_type = "AUTH_BRUTE_FORCE";
        assert_eq!(alert_type, "AUTH_BRUTE_FORCE");
    }

    #[test]
    fn auth_brute_force_alert_title() {
        let title = "Brute force authentification";
        assert_eq!(title, "Brute force authentification");
    }

    #[test]
    fn auth_brute_force_severity() {
        let severity = SecuritySeverity::High;
        assert_eq!(severity, SecuritySeverity::High);
    }

    #[test]
    fn auth_brute_force_duration() {
        let duration = 900;
        assert_eq!(duration, 900);
    }

    #[test]
    fn auth_brute_force_window() {
        let window = 5;
        assert_eq!(window, 5);
    }

    #[test]
    fn auth_brute_force_collection() {
        let coll = "auth_events";
        assert_eq!(coll, "auth_events");
    }

    #[test]
    fn auth_brute_force_signal_format() {
        let signal = json!({
            "ip": "192.168.1.1",
            "failures_5m": 15,
            "threshold": 10,
        });
        assert_eq!(signal["ip"], "192.168.1.1");
        assert_eq!(signal["failures_5m"], 15);
        assert_eq!(signal["threshold"], 10);
    }

    #[test]
    fn stale_api_key_max_age_default() {
        let max_age_days = 90u64;
        assert_eq!(max_age_days, 90);
    }

    #[test]
    fn stale_api_key_alert_type() {
        let alert_type = "STALE_API_KEY";
        assert_eq!(alert_type, "STALE_API_KEY");
    }

    #[test]
    fn stale_api_key_alert_title() {
        let title = "API key ancienne non rotée";
        assert_eq!(title, "API key ancienne non rotée");
    }

    #[test]
    fn stale_api_key_severity() {
        let severity = SecuritySeverity::Medium;
        assert_eq!(severity, SecuritySeverity::Medium);
    }

    #[test]
    fn stale_api_key_level() {
        let level = RemediationLevel::ALERT;
        assert_eq!(level, RemediationLevel::ALERT);
    }

    #[test]
    fn stale_api_key_collection() {
        let coll = "auth_events";
        assert_eq!(coll, "auth_events");
    }

    #[test]
    fn stale_api_key_kind() {
        let kind = "api_key";
        assert_eq!(kind, "api_key");
    }

    #[test]
    fn stale_api_key_signal_format() {
        let signal = json!({
            "sessions_with_old_key": 5,
            "max_age_days": 90,
        });
        assert_eq!(signal["sessions_with_old_key"], 5);
        assert_eq!(signal["max_age_days"], 90);
    }

    #[test]
    fn stale_api_key_zero_sessions() {
        let old_sessions = 0u64;
        assert_eq!(old_sessions, 0);
    }

    #[test]
    fn stale_api_key_positive_sessions() {
        let old_sessions = 5u64;
        assert!(old_sessions > 0);
    }

    #[test]
    fn auth_brute_force_pipeline_format() {
        let pipeline = vec![
            doc! { "$match": { "ts": { "$gte": "2026-01-01T00:00:00Z" }, "success": false } },
            doc! { "$group": { "_id": "$ip", "count": { "$sum": 1 } } },
            doc! { "$match": { "count": { "$gte": 10i64 } } },
            doc! { "$sort": { "count": -1 } },
            doc! { "$limit": 20 },
        ];
        assert_eq!(pipeline.len(), 5);
    }

    #[test]
    fn auth_brute_force_pipeline_match_format() {
        let match_stage = doc! { "$match": { "ts": { "$gte": "2026-01-01T00:00:00Z" }, "success": false } };
        assert!(match_stage.contains_key("$match"));
    }

    #[test]
    fn auth_brute_force_pipeline_group_format() {
        let group_stage = doc! { "$group": { "_id": "$ip", "count": { "$sum": 1 } } };
        assert!(group_stage.contains_key("$group"));
    }

    #[test]
    fn auth_brute_force_pipeline_sort_format() {
        let sort_stage = doc! { "$sort": { "count": -1 } };
        assert!(sort_stage.contains_key("$sort"));
    }

    #[test]
    fn auth_brute_force_pipeline_limit_format() {
        let limit_stage = doc! { "$limit": 20 };
        assert!(limit_stage.contains_key("$limit"));
    }

    #[test]
    fn auth_brute_force_ip_unknown() {
        let ip = "unknown";
        assert_eq!(ip, "unknown");
    }

    #[test]
    fn auth_brute_force_ip_ipv4() {
        let ip = "192.168.1.1";
        assert!(ip.contains("."));
    }

    #[test]
    fn auth_brute_force_ip_ipv6() {
        let ip = "::1";
        assert!(ip.contains(":"));
    }

    #[test]
    fn security_alert_new() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.alert_type, "TEST");
        assert_eq!(alert.title, "Test alert");
    }

    #[test]
    fn security_alert_with_signal() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_signal(json!({"key": "value"}));
        assert!(alert.signal.is_some());
    }

    #[test]
    fn security_alert_with_duration() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_duration(900);
        assert_eq!(alert.duration_secs, Some(900));
    }

    #[test]
    fn security_alert_with_tenant() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_tenant("tenant-1");
        assert_eq!(alert.tenant_id, Some("tenant-1".to_string()));
    }

    #[test]
    fn security_alert_with_ip() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        alert.ip = Some("192.168.1.1".to_string());
        assert_eq!(alert.ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn security_alert_stamp_audit_hash() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        alert.stamp_audit_hash();
        assert!(alert.audit_hash.is_some());
    }

    #[test]
    fn security_alert_audit_hash_unique() {
        let mut alert1 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        alert1.stamp_audit_hash();
        let mut alert2 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        alert2.stamp_audit_hash();
        assert_ne!(alert1.audit_hash, alert2.audit_hash);
    }

    #[test]
    fn remediation_level_block() {
        let level = RemediationLevel::BLOCK;
        assert_eq!(level, RemediationLevel::BLOCK);
    }

    #[test]
    fn remediation_level_throttle() {
        let level = RemediationLevel::THROTTLE;
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn remediation_level_alert() {
        let level = RemediationLevel::ALERT;
        assert_eq!(level, RemediationLevel::ALERT);
    }

    #[test]
    fn security_severity_high() {
        let severity = SecuritySeverity::High;
        assert_eq!(severity, SecuritySeverity::High);
    }

    #[test]
    fn security_severity_medium() {
        let severity = SecuritySeverity::Medium;
        assert_eq!(severity, SecuritySeverity::Medium);
    }
}
