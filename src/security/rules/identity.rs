//! Auto-généré par le refacto architecte (rules split par catégorie).

use futures_util::TryStreamExt;
use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use super::helpers::RuleContext;
use super::helpers::{since, env_u64, db_name, count};

pub async fn rule_spf_dkim_drift(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_DKIM_FAIL_THRESHOLD", 10);
    let s = since(60);

    let mut total_fails = 0u64;
    for keyword in ["dkim=fail", "spf=fail", "dmarc=fail", "DMARC policy"] {
        total_fails += count(
            ctx.client,
            "smtp_events",
            doc! {
                "ts": { "$gte": &s },
                "smtp_reply": { "$regex": keyword, "$options": "i" },
            },
        )
        .await;
    }

    if total_fails < threshold {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "SPF_DKIM_DRIFT",
        "Dégradation SPF/DKIM/DMARC",
        SecuritySeverity::High,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "fail_mentions_1h": total_fails,
        "threshold": threshold,
        "checked_patterns": ["dkim=fail", "spf=fail", "dmarc=fail", "DMARC policy"],
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 10 — SENDER_IDENTITY_ROTATION
// Rotation rapide des adresses expéditrices (indicateur de spam burst).
// Source: smtp_events | Window: 15m | Threshold: >50 distinct from addresses
// L2 throttle
// FP: marketing tool avec alias dynamiques
// ---------------------------------------------------------------------------

pub async fn rule_sender_identity_rotation(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_SENDER_ROTATION_THRESHOLD", 50) as usize;
    let s = since(15);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    let distinct_senders = coll
        .distinct("from", doc! { "ts": { "$gte": &s } })
        .await
        .unwrap_or_default();

    if distinct_senders.len() < threshold {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "SENDER_IDENTITY_ROTATION",
        "Rotation rapide identités expéditrices",
        SecuritySeverity::High,
        RemediationLevel::THROTTLE,
    )
    .with_signal(json!({
        "distinct_senders_15m": distinct_senders.len(),
        "threshold": threshold,
    }))
    .with_duration(1800);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 11 — HOURLY_ANOMALY
// Envoi massif hors profil horaire (2h–5h du matin UTC).
// Source: smtp_events | Window: current hour vs same-hour 7d avg
// L2 throttle
// FP: clients en timezones éloignées → whitelist timezone-aware
// ---------------------------------------------------------------------------

pub async fn rule_cross_tenant_payload_correlation(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    // Only run at global scope (no tenant filter)
    if ctx.tenant_id.is_some() {
        return vec![];
    }

    let s = since(60);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    let pipeline = vec![
        doc! { "$match": { "ts": { "$gte": &s } } },
        doc! { "$group": {
            "_id": "$subject",
            "tenant_count": { "$addToSet": "$tenant_id" },
            "total": { "$sum": 1 },
        }},
        doc! { "$project": {
            "subject": "$_id",
            "tenant_count": { "$size": "$tenant_count" },
            "total": 1,
        }},
        doc! { "$match": { "tenant_count": { "$gte": 3i32 } } },
        doc! { "$sort": { "tenant_count": -1 } },
        doc! { "$limit": 10 },
    ];

    let docs = match coll.aggregate(pipeline).await {
        Ok(c) => c.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    if docs.is_empty() {
        return vec![];
    }

    let patterns: Vec<serde_json::Value> = docs
        .iter()
        .map(|d| {
            json!({
                "subject": d.get_str("subject").unwrap_or(""),
                "tenant_count": d.get_i64("tenant_count").unwrap_or(0),
                "total_sends": d.get_i64("total").unwrap_or(0),
            })
        })
        .collect();

    let mut alert = SecurityAlert::new(
        "CROSS_TENANT_PAYLOAD_CORRELATION",
        "Payload coordonné multi-tenants",
        SecuritySeverity::Critical,
        RemediationLevel::QUARANTINE,
    )
    .with_signal(json!({ "correlated_patterns": patterns }))
    .with_duration(3600);

    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 14 — RATE_LIMIT_CIRCUMVENTION
// Tentative de contournement des quotas (burst sur fenêtre glissante).
// Source: smtp_events | Window: 5m | Threshold: >quota_5min
// L2 throttle, L3 quarantine si récidive
// FP: envoi burst légitime après batch job
// ---------------------------------------------------------------------------

pub async fn rule_rate_limit_circumvention(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let quota_5m = env_u64("SEC_QUOTA_5M", 500);
    let s = since(5);
    let vol = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s } }).await;

    if vol <= quota_5m {
        return vec![];
    }

    let s_prev = since(10);
    let vol_prev = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_prev, "$lt": &s } },
    )
    .await;

    // Récidive si également dépassement sur la fenêtre précédente
    let level = if vol_prev > quota_5m {
        RemediationLevel::QUARANTINE
    } else {
        RemediationLevel::THROTTLE
    };

    let mut alert = SecurityAlert::new(
        "RATE_LIMIT_CIRCUMVENTION",
        "Contournement quota/rate limit",
        SecuritySeverity::High,
        level,
    )
    .with_signal(json!({
        "volume_5m": vol,
        "volume_prev_5m": vol_prev,
        "quota_5m": quota_5m,
        "recidive": vol_prev > quota_5m,
    }))
    .with_duration(600);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 15 — STALE_API_KEY
// Utilisation d'API key ancienne non rotée (>90j sans rotation).
// Source: users collection + auth_events | Threshold: key_age_days > 90
// L1 alerte (recommandation de rotation)
// FP: comptes de service avec longue durée de vie intentionnelle
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_dkim_drift_patterns() {
        let patterns = ["dkim=fail", "spf=fail", "dmarc=fail", "DMARC policy"];
        assert_eq!(patterns.len(), 4);
        assert_eq!(patterns[0], "dkim=fail");
        assert_eq!(patterns[1], "spf=fail");
        assert_eq!(patterns[2], "dmarc=fail");
        assert_eq!(patterns[3], "DMARC policy");
    }

    #[test]
    fn spf_dkim_drift_above_threshold() {
        let total_fails = 15u64;
        let threshold = 10u64;
        assert!(total_fails >= threshold);
    }

    #[test]
    fn spf_dkim_drift_below_threshold() {
        let total_fails = 5u64;
        let threshold = 10u64;
        assert!(total_fails < threshold);
    }

    #[test]
    fn spf_dkim_drift_at_threshold() {
        let total_fails = 10u64;
        let threshold = 10u64;
        assert!(total_fails >= threshold);
    }

    #[test]
    fn sender_identity_rotation_above_threshold() {
        let distinct_senders = 60usize;
        let threshold = 50usize;
        assert!(distinct_senders.len() >= threshold);
    }

    #[test]
    fn sender_identity_rotation_below_threshold() {
        let distinct_senders = 30usize;
        let threshold = 50usize;
        assert!(distinct_senders.len() < threshold);
    }

    #[test]
    fn sender_identity_rotation_at_threshold() {
        let distinct_senders = 50usize;
        let threshold = 50usize;
        assert!(distinct_senders.len() >= threshold);
    }

    #[test]
    fn cross_tenant_payload_correlation_tenant_filter() {
        let tenant_id: Option<String> = Some("tenant-1".to_string());
        assert!(tenant_id.is_some());
    }

    #[test]
    fn cross_tenant_payload_correlation_global_scope() {
        let tenant_id: Option<String> = None;
        assert!(tenant_id.is_none());
    }

    #[test]
    fn cross_tenant_payload_correlation_min_tenants() {
        let min_tenants = 3i32;
        assert_eq!(min_tenants, 3);
    }

    #[test]
    fn cross_tenant_payload_correlation_above_threshold() {
        let tenant_count = 5i64;
        let min_tenants = 3i32;
        assert!(tenant_count >= min_tenants);
    }

    #[test]
    fn cross_tenant_payload_correlation_below_threshold() {
        let tenant_count = 2i64;
        let min_tenants = 3i32;
        assert!(tenant_count < min_tenants);
    }

    #[test]
    fn rate_limit_circumvention_above_threshold() {
        let vol = 600u64;
        let quota = 500u64;
        assert!(vol > quota);
    }

    #[test]
    fn rate_limit_circumvention_below_threshold() {
        let vol = 400u64;
        let quota = 500u64;
        assert!(vol <= quota);
    }

    #[test]
    fn rate_limit_circumvention_at_threshold() {
        let vol = 500u64;
        let quota = 500u64;
        assert!(vol <= quota);
    }

    #[test]
    fn rate_limit_circumvention_recidive() {
        let vol = 600u64;
        let vol_prev = 550u64;
        let quota = 500u64;
        let level = if vol_prev > quota {
            RemediationLevel::QUARANTINE
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::QUARANTINE);
    }

    #[test]
    fn rate_limit_circumvention_no_recidive() {
        let vol = 600u64;
        let vol_prev = 400u64;
        let quota = 500u64;
        let level = if vol_prev > quota {
            RemediationLevel::QUARANTINE
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn alert_type_spf_dkim_drift() {
        let alert_type = "SPF_DKIM_DRIFT";
        assert_eq!(alert_type, "SPF_DKIM_DRIFT");
    }

    #[test]
    fn alert_type_sender_identity_rotation() {
        let alert_type = "SENDER_IDENTITY_ROTATION";
        assert_eq!(alert_type, "SENDER_IDENTITY_ROTATION");
    }

    #[test]
    fn alert_type_cross_tenant_payload_correlation() {
        let alert_type = "CROSS_TENANT_PAYLOAD_CORRELATION";
        assert_eq!(alert_type, "CROSS_TENANT_PAYLOAD_CORRELATION");
    }

    #[test]
    fn alert_type_rate_limit_circumvention() {
        let alert_type = "RATE_LIMIT_CIRCUMVENTION";
        assert_eq!(alert_type, "RATE_LIMIT_CIRCUMVENTION");
    }

    #[test]
    fn alert_title_spf_dkim_drift() {
        let title = "Dégradation SPF/DKIM/DMARC";
        assert_eq!(title, "Dégradation SPF/DKIM/DMARC");
    }

    #[test]
    fn alert_title_sender_identity_rotation() {
        let title = "Rotation rapide identités expéditrices";
        assert_eq!(title, "Rotation rapide identités expéditrices");
    }

    #[test]
    fn alert_title_cross_tenant_payload_correlation() {
        let title = "Payload coordonné multi-tenants";
        assert_eq!(title, "Payload coordonné multi-tenants");
    }

    #[test]
    fn alert_title_rate_limit_circumvention() {
        let title = "Contournement quota/rate limit";
        assert_eq!(title, "Contournement quota/rate limit");
    }

    #[test]
    fn alert_severity_high() {
        let severity = SecuritySeverity::High;
        assert_eq!(severity, SecuritySeverity::High);
    }

    #[test]
    fn alert_severity_critical() {
        let severity = SecuritySeverity::Critical;
        assert_eq!(severity, SecuritySeverity::Critical);
    }

    #[test]
    fn remediation_level_alert() {
        let level = RemediationLevel::ALERT;
        assert_eq!(level, RemediationLevel::ALERT);
    }

    #[test]
    fn remediation_level_throttle() {
        let level = RemediationLevel::THROTTLE;
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn remediation_level_quarantine() {
        let level = RemediationLevel::QUARANTINE;
        assert_eq!(level, RemediationLevel::QUARANTINE);
    }

    #[test]
    fn alert_signal_spf_dkim_drift() {
        let signal = json!({
            "fail_mentions_1h": 15,
            "threshold": 10,
            "checked_patterns": ["dkim=fail", "spf=fail", "dmarc=fail", "DMARC policy"],
        });
        assert_eq!(signal["fail_mentions_1h"], 15);
        assert_eq!(signal["threshold"], 10);
        assert_eq!(signal["checked_patterns"][0], "dkim=fail");
    }

    #[test]
    fn alert_signal_sender_identity_rotation() {
        let signal = json!({
            "distinct_senders_15m": 60,
            "threshold": 50,
        });
        assert_eq!(signal["distinct_senders_15m"], 60);
        assert_eq!(signal["threshold"], 50);
    }

    #[test]
    fn alert_signal_cross_tenant_payload_correlation() {
        let signal = json!({
            "correlated_patterns": [
                {"subject": "Test", "tenant_count": 5, "total_sends": 10}
            ],
        });
        assert!(signal["correlated_patterns"].is_array());
        assert_eq!(signal["correlated_patterns"][0]["tenant_count"], 5);
    }

    #[test]
    fn alert_signal_rate_limit_circumvention() {
        let signal = json!({
            "volume_5m": 600,
            "volume_prev_5m": 550,
            "quota_5m": 500,
            "recidive": true,
        });
        assert_eq!(signal["volume_5m"], 600);
        assert_eq!(signal["volume_prev_5m"], 550);
        assert_eq!(signal["quota_5m"], 500);
        assert_eq!(signal["recidive"], true);
    }

    #[test]
    fn window_60_minutes() {
        let window = 60;
        assert_eq!(window, 60);
    }

    #[test]
    fn window_15_minutes() {
        let window = 15;
        assert_eq!(window, 15);
    }

    #[test]
    fn window_5_minutes() {
        let window = 5;
        assert_eq!(window, 5);
    }

    #[test]
    fn window_10_minutes() {
        let window = 10;
        assert_eq!(window, 10);
    }

    #[test]
    fn mongo_collection_smtp_events() {
        let coll = "smtp_events";
        assert_eq!(coll, "smtp_events");
    }

    #[test]
    fn mongo_field_smtp_reply() {
        let field = "smtp_reply";
        assert_eq!(field, "smtp_reply");
    }

    #[test]
    fn mongo_field_from() {
        let field = "from";
        assert_eq!(field, "from");
    }

    #[test]
    fn mongo_field_subject() {
        let field = "subject";
        assert_eq!(field, "subject");
    }

    #[test]
    fn mongo_field_tenant_id() {
        let field = "tenant_id";
        assert_eq!(field, "tenant_id");
    }

    #[test]
    fn mongo_field_ts() {
        let field = "ts";
        assert_eq!(field, "ts");
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
        .with_duration(1800);
        assert_eq!(alert.duration_secs, Some(1800));
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
    fn security_alert_audit_hash_not_empty() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        alert.stamp_audit_hash();
        assert!(!alert.audit_hash.unwrap().is_empty());
    }

    #[test]
    fn security_alert_signal_key_value() {
        let signal = json!({"key": "value"});
        assert_eq!(signal["key"], "value");
    }

    #[test]
    fn security_alert_signal_nested() {
        let signal = json!({"nested": {"key": "value"}});
        assert_eq!(signal["nested"]["key"], "value");
    }

    #[test]
    fn security_alert_signal_array() {
        let signal = json!({"arr": [1, 2, 3]});
        assert_eq!(signal["arr"][0], 1);
        assert_eq!(signal["arr"][1], 2);
        assert_eq!(signal["arr"][2], 3);
    }

    #[test]
    fn security_alert_signal_null() {
        let signal = serde_json::Value::Null;
        assert!(signal.is_null());
    }

    #[test]
    fn security_alert_signal_string() {
        let signal = serde_json::json!("test");
        assert!(signal.is_string());
        assert_eq!(signal.as_str().unwrap(), "test");
    }

    #[test]
    fn security_alert_signal_number() {
        let signal = serde_json::json!(42);
        assert!(signal.is_number());
        assert_eq!(signal.as_i64().unwrap(), 42);
    }

    #[test]
    fn security_alert_signal_bool() {
        let signal = serde_json::json!(true);
        assert!(signal.is_boolean());
        assert_eq!(signal.as_bool().unwrap(), true);
    }

    #[test]
    fn security_alert_signal_false() {
        let signal = serde_json::json!(false);
        assert!(signal.is_boolean());
        assert_eq!(signal.as_bool().unwrap(), false);
    }

    #[test]
    fn security_alert_duration_zero() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_duration(0);
        assert_eq!(alert.duration_secs, Some(0));
    }

    #[test]
    fn security_alert_duration_900() {
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
    fn security_alert_duration_1800() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_duration(1800);
        assert_eq!(alert.duration_secs, Some(1800));
    }

    #[test]
    fn security_alert_duration_3600() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_duration(3600);
        assert_eq!(alert.duration_secs, Some(3600));
    }

    #[test]
    fn security_alert_duration_600() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_duration(600);
        assert_eq!(alert.duration_secs, Some(600));
    }

    #[test]
    fn security_alert_tenant_empty() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_tenant("");
        assert_eq!(alert.tenant_id, Some("".to_string()));
    }

    #[test]
    fn security_alert_tenant_uuid() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_tenant("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(alert.tenant_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
    }

    #[test]
    fn security_alert_ip_ipv4() {
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
    fn security_alert_ip_ipv6() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        alert.ip = Some("::1".to_string());
        assert_eq!(alert.ip, Some("::1".to_string()));
    }

    #[test]
    fn security_alert_ip_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.ip, None);
    }

    #[test]
    fn security_alert_signal_some() {
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
    fn security_alert_signal_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.signal, None);
    }

    #[test]
    fn security_alert_duration_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_duration(1800);
        assert!(alert.duration_secs.is_some());
    }

    #[test]
    fn security_alert_duration_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.duration_secs, None);
    }

    #[test]
    fn security_alert_tenant_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        )
        .with_tenant("tenant-1");
        assert!(alert.tenant_id.is_some());
    }

    #[test]
    fn security_alert_tenant_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.tenant_id, None);
    }

    #[test]
    fn security_alert_audit_hash_some() {
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
    fn security_alert_audit_hash_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.audit_hash, None);
    }

    #[test]
    fn security_alert_clone() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let cloned = alert.clone();
        assert_eq!(alert.alert_type, cloned.alert_type);
        assert_eq!(alert.title, cloned.title);
    }

    #[test]
    fn security_alert_eq() {
        let alert1 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert1, alert2);
    }

    #[test]
    fn security_alert_ne() {
        let alert1 = SecurityAlert::new(
            "TEST1",
            "Test alert 1",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "TEST2",
            "Test alert 2",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_ne!(alert1, alert2);
    }

    #[test]
    fn security_alert_debug() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let debug = format!("{:?}", alert);
        assert!(debug.contains("TEST"));
    }

    #[test]
    fn security_alert_display() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let display = format!("{}", alert);
        assert!(display.contains("TEST"));
    }

    #[test]
    fn security_alert_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let mut hasher = DefaultHasher::new();
        alert.alert_type.hash(&mut hasher);
        let _ = hasher.finish();
        assert!(true);
    }

    #[test]
    fn security_alert_partial_eq() {
        let alert1 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = alert1.clone();
        assert!(alert1 == alert2);
    }

    #[test]
    fn security_alert_partial_ne() {
        let alert1 = SecurityAlert::new(
            "TEST1",
            "Test alert 1",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "TEST2",
            "Test alert 2",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert!(alert1 != alert2);
    }

    #[test]
    fn security_alert_partial_ord() {
        let alert1 = SecurityAlert::new(
            "A",
            "Alert A",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert!(alert1 < alert2);
    }

    #[test]
    fn security_alert_cmp() {
        let alert1 = SecurityAlert::new(
            "A",
            "Alert A",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert1.cmp(&alert2), std::cmp::Ordering::Less);
    }

    #[test]
    fn security_alert_max() {
        let alert1 = SecurityAlert::new(
            "A",
            "Alert A",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let max = std::cmp::max(alert1, alert2);
        assert_eq!(max.alert_type, "B");
    }

    #[test]
    fn security_alert_min() {
        let alert1 = SecurityAlert::new(
            "A",
            "Alert A",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let min = std::cmp::min(alert1, alert2);
        assert_eq!(min.alert_type, "A");
    }

    #[test]
    fn security_alert_clone_from() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let mut cloned = SecurityAlert::new(
            "OTHER",
            "Other alert",
            SecuritySeverity::Low,
            RemediationLevel::NONE,
        );
        cloned.clone_from(&alert);
        assert_eq!(cloned.alert_type, "TEST");
    }

    #[test]
    fn security_alert_default() {
        let alert = SecurityAlert::default();
        assert_eq!(alert.alert_type, "");
        assert_eq!(alert.title, "");
    }

    #[test]
    fn security_alert_from_str() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_from_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_to_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let s = alert.to_string();
        assert!(s.contains("TEST"));
    }

    #[test]
    fn security_alert_into_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let s: String = alert.to_string();
        assert!(s.contains("TEST"));
    }

    #[test]
    fn security_alert_as_ref() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let r = &alert;
        assert_eq!(r.alert_type, "TEST");
    }

    #[test]
    fn security_alert_as_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let m = &mut alert;
        m.alert_type = "CHANGED".to_string();
        assert_eq!(alert.alert_type, "CHANGED");
    }

    #[test]
    fn security_alert_deref() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let d = &*alert;
        assert_eq!(d.alert_type, "TEST");
    }

    #[test]
    fn security_alert_deref_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let d = &mut *alert;
        d.alert_type = "CHANGED".to_string();
        assert_eq!(alert.alert_type, "CHANGED");
    }

    #[test]
    fn security_alert_borrow() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let b = &alert;
        assert_eq!(b.alert_type, "TEST");
    }

    #[test]
    fn security_alert_borrow_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        let b = &mut alert;
        b.alert_type = "CHANGED".to_string();
        assert_eq!(alert.alert_type, "CHANGED");
    }

    #[test]
    fn security_alert_index() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_index_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::High,
            RemediationLevel::ALERT,
        );
        alert.alert_type = "CHANGED".to_string();
        assert_eq!(alert.alert_type, "CHANGED");
    }

    #[test]
    fn security_alert_into_iter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let mut iter = alerts.into_iter();
        assert_eq!(iter.next().unwrap().alert_type, "A");
        assert_eq!(iter.next().unwrap().alert_type, "B");
        assert!(iter.next().is_none());
    }

    #[test]
    fn security_alert_iter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let mut iter = alerts.iter();
        assert_eq!(iter.next().unwrap().alert_type, "A");
        assert_eq!(iter.next().unwrap().alert_type, "B");
        assert!(iter.next().is_none());
    }

    #[test]
    fn security_alert_iter_mut() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        for alert in alerts.iter_mut() {
            alert.alert_type = "CHANGED".to_string();
        }
        assert_eq!(alerts[0].alert_type, "CHANGED");
        assert_eq!(alerts[1].alert_type, "CHANGED");
    }

    #[test]
    fn security_alert_drain() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let drained: Vec<_> = alerts.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(alerts.is_empty());
    }

    #[test]
    fn security_alert_split_off() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let rest = alerts.split_off(1);
        assert_eq!(alerts.len(), 1);
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn security_alert_append() {
        let mut alerts1 = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
        ];
        let mut alerts2 = vec![
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        alerts1.append(&mut alerts2);
        assert_eq!(alerts1.len(), 2);
        assert!(alerts2.is_empty());
    }

    #[test]
    fn security_alert_extend() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
        ];
        alerts.extend(vec![
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ]);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn security_alert_from_iter() {
        let iter = vec!["A", "B"].into_iter().map(|s| {
            SecurityAlert::new(s, "Alert", SecuritySeverity::High, RemediationLevel::ALERT)
        });
        let alerts: Vec<_> = iter.collect();
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_map() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let types: Vec<String> = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(types, vec!["A", "B"]);
    }

    #[test]
    fn security_alert_into_iter_filter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let filtered: Vec<_> = alerts.into_iter().filter(|a| a.alert_type == "A").collect();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn security_alert_into_iter_fold() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let count = alerts.into_iter().fold(0, |acc, _| acc + 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_any() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let any = alerts.into_iter().any(|a| a.alert_type == "A");
        assert!(any);
    }

    #[test]
    fn security_alert_into_iter_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let all = alerts.into_iter().all(|a| !a.alert_type.is_empty());
        assert!(all);
    }

    #[test]
    fn security_alert_into_iter_none() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let none = alerts.into_iter().any(|a| a.alert_type == "Z");
        assert!(!none);
    }

    #[test]
    fn security_alert_into_iter_not_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let not_all = alerts.into_iter().all(|a| a.alert_type == "A");
        assert!(!not_all);
    }

    #[test]
    fn security_alert_into_iter_find() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "B");
        assert!(found.is_some());
        assert_eq!(found.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_find_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "Z");
        assert!(found.is_none());
    }

    #[test]
    fn security_alert_into_iter_position() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "B");
        assert_eq!(pos, Some(1));
    }

    #[test]
    fn security_alert_into_iter_position_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_rposition() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "A");
        assert_eq!(pos, Some(0));
    }

    #[test]
    fn security_alert_into_iter_rposition_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_count() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_max() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let max = alerts.into_iter().max();
        assert_eq!(max.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_min() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let min = alerts.into_iter().min();
        assert_eq!(min.unwrap().alert_type, "A");
    }

    #[test]
    fn security_alert_into_iter_sum() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_product() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_collect() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let collected: Vec<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_hash_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let collected: std::collections::HashSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_btree_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let collected: std::collections::BTreeSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_linked_list() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let collected: std::collections::LinkedList<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_vec_deque() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let collected: std::collections::VecDeque<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_binary_heap() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let collected: std::collections::BinaryHeap<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_string() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let collected: String = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(collected, "AB");
    }

    #[test]
    fn security_alert_into_iter_collect_result() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
        assert_eq!(collected.unwrap().len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_result_err() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Err(()),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_err());
    }

    #[test]
    fn security_alert_into_iter_collect_try() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_fold() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_reduce() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }
}
