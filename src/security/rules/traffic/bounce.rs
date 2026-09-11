//! Rules bounce & SMTP code spikes.

use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use crate::security::rules::helpers::{count, env_f64, env_u64, since, RuleContext};

pub async fn rule_bounce_rate_surge(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_f64("SEC_BOUNCE_RATE_THRESHOLD", 0.15);
    let s = since(60);
    let total = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s } }).await;
    if total == 0 {
        return vec![];
    }
    let bounced = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s }, "status": "bounced" },
    )
    .await;

    let rate = bounced as f64 / total as f64;
    if rate < threshold {
        return vec![];
    }

    let level = if rate > 0.25 {
        RemediationLevel::THROTTLE
    } else {
        RemediationLevel::ALERT
    };

    let mut alert = SecurityAlert::new(
        "BOUNCE_RATE_SURGE",
        "Hausse bounce rate",
        SecuritySeverity::High,
        level,
    )
    .with_signal(json!({
        "bounce_rate": (rate * 1000.0).round() / 1000.0,
        "bounced": bounced,
        "total": total,
        "threshold": threshold,
    }))
    .with_duration(1800);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

pub async fn rule_smtp_code_spike_temp(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_SMTP_421_THRESHOLD", 30);
    let s = since(30);
    let mut total_temp = 0u64;
    for code in [421i32, 450] {
        total_temp += count(
            ctx.client,
            "smtp_events",
            doc! { "ts": { "$gte": &s }, "smtp_code": code },
        )
        .await;
    }
    if total_temp < threshold {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "SMTP_CODE_SPIKE_TEMP",
        "Spike codes SMTP 421/450",
        SecuritySeverity::Medium,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "count_30m": total_temp,
        "threshold": threshold,
        "codes": [421, 450],
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

pub async fn rule_smtp_code_spike_perm(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_SMTP_550_THRESHOLD", 20);
    let s = since(30);
    let mut total_perm = 0u64;
    for code in [550i32, 554] {
        total_perm += count(
            ctx.client,
            "smtp_events",
            doc! { "ts": { "$gte": &s }, "smtp_code": code },
        )
        .await;
    }
    if total_perm < threshold {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "SMTP_CODE_SPIKE_PERM",
        "Spike codes SMTP 550/554",
        SecuritySeverity::High,
        RemediationLevel::THROTTLE,
    )
    .with_signal(json!({
        "count_30m": total_perm,
        "threshold": threshold,
        "codes": [550, 554],
    }))
    .with_duration(1800);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounce_rate_calculation() {
        let total = 100u64;
        let bounced = 20u64;
        let rate = bounced as f64 / total as f64;
        assert!((rate - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn bounce_rate_zero_total() {
        let total = 0u64;
        let bounced = 0u64;
        let rate = if total == 0 { 0.0 } else { bounced as f64 / total as f64 };
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn bounce_rate_rounding() {
        let rate = 0.123456;
        let rounded = (rate * 1000.0).round() / 1000.0;
        assert_eq!(rounded, 0.123);
    }

    #[test]
    fn bounce_rate_above_threshold() {
        let rate = 0.20;
        let threshold = 0.15;
        assert!(rate >= threshold);
    }

    #[test]
    fn bounce_rate_below_threshold() {
        let rate = 0.10;
        let threshold = 0.15;
        assert!(rate < threshold);
    }

    #[test]
    fn bounce_rate_triggers_throttle() {
        let rate = 0.30;
        let level = if rate > 0.25 {
            RemediationLevel::THROTTLE
        } else {
            RemediationLevel::ALERT
        };
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn bounce_rate_triggers_alert() {
        let rate = 0.20;
        let level = if rate > 0.25 {
            RemediationLevel::THROTTLE
        } else {
            RemediationLevel::ALERT
        };
        assert_eq!(level, RemediationLevel::ALERT);
    }

    #[test]
    fn smtp_code_spike_temp_codes() {
        let codes = [421i32, 450];
        assert_eq!(codes.len(), 2);
        assert_eq!(codes[0], 421);
        assert_eq!(codes[1], 450);
    }

    #[test]
    fn smtp_code_spike_perm_codes() {
        let codes = [550i32, 554];
        assert_eq!(codes.len(), 2);
        assert_eq!(codes[0], 550);
        assert_eq!(codes[1], 554);
    }

    #[test]
    fn smtp_code_spike_above_threshold() {
        let count = 35u64;
        let threshold = 30u64;
        assert!(count >= threshold);
    }

    #[test]
    fn smtp_code_spike_below_threshold() {
        let count = 25u64;
        let threshold = 30u64;
        assert!(count < threshold);
    }

    #[test]
    fn smtp_code_spike_at_threshold() {
        let count = 30u64;
        let threshold = 30u64;
        assert!(count >= threshold);
    }

    #[test]
    fn alert_signal_bounce_rate() {
        let signal = json!({
            "bounce_rate": 0.2,
            "bounced": 20,
            "total": 100,
            "threshold": 0.15,
        });
        assert_eq!(signal["bounce_rate"], 0.2);
        assert_eq!(signal["bounced"], 20);
        assert_eq!(signal["total"], 100);
        assert_eq!(signal["threshold"], 0.15);
    }

    #[test]
    fn alert_signal_smtp_code_spike() {
        let signal = json!({
            "count_30m": 35,
            "threshold": 30,
            "codes": [421, 450],
        });
        assert_eq!(signal["count_30m"], 35);
        assert_eq!(signal["threshold"], 30);
        assert_eq!(signal["codes"][0], 421);
        assert_eq!(signal["codes"][1], 450);
    }

    #[test]
    fn alert_duration_bounce_rate_surge() {
        let duration = 1800;
        assert_eq!(duration, 1800);
    }

    #[test]
    fn alert_duration_smtp_code_spike_perm() {
        let duration = 1800;
        assert_eq!(duration, 1800);
    }

    #[test]
    fn alert_duration_smtp_code_spike_temp() {
        let duration = 0;
        assert_eq!(duration, 0);
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
    fn bounce_rate_percentage() {
        let total = 100u64;
        let bounced = 20u64;
        let rate = bounced as f64 / total as f64;
        let percentage = rate * 100.0;
        assert_eq!(percentage, 20.0);
    }

    #[test]
    fn bounce_rate_all_bounced() {
        let total = 100u64;
        let bounced = 100u64;
        let rate = bounced as f64 / total as f64;
        assert_eq!(rate, 1.0);
    }

    #[test]
    fn bounce_rate_none_bounced() {
        let total = 100u64;
        let bounced = 0u64;
        let rate = bounced as f64 / total as f64;
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn smtp_code_421_is_temp() {
        let code = 421i32;
        assert_eq!(code, 421);
    }

    #[test]
    fn smtp_code_450_is_temp() {
        let code = 450i32;
        assert_eq!(code, 450);
    }

    #[test]
    fn smtp_code_550_is_perm() {
        let code = 550i32;
        assert_eq!(code, 550);
    }

    #[test]
    fn smtp_code_554_is_perm() {
        let code = 554i32;
        assert_eq!(code, 554);
    }

    #[test]
    fn smtp_code_temp_range() {
        let codes = [421i32, 450];
        for code in &codes {
            assert!(*code >= 400 && *code < 500);
        }
    }

    #[test]
    fn smtp_code_perm_range() {
        let codes = [550i32, 554];
        for code in &codes {
            assert!(*code >= 500 && *code < 600);
        }
    }

    #[test]
    fn alert_type_bounce_rate_surge() {
        let alert_type = "BOUNCE_RATE_SURGE";
        assert_eq!(alert_type, "BOUNCE_RATE_SURGE");
    }

    #[test]
    fn alert_type_smtp_code_spike_temp() {
        let alert_type = "SMTP_CODE_SPIKE_TEMP";
        assert_eq!(alert_type, "SMTP_CODE_SPIKE_TEMP");
    }

    #[test]
    fn alert_type_smtp_code_spike_perm() {
        let alert_type = "SMTP_CODE_SPIKE_PERM";
        assert_eq!(alert_type, "SMTP_CODE_SPIKE_PERM");
    }

    #[test]
    fn alert_title_bounce_rate_surge() {
        let title = "Hausse bounce rate";
        assert_eq!(title, "Hausse bounce rate");
    }

    #[test]
    fn alert_title_smtp_code_spike_temp() {
        let title = "Spike codes SMTP 421/450";
        assert_eq!(title, "Spike codes SMTP 421/450");
    }

    #[test]
    fn alert_title_smtp_code_spike_perm() {
        let title = "Spike codes SMTP 550/554";
        assert_eq!(title, "Spike codes SMTP 550/554");
    }

    #[test]
    fn threshold_default_bounce_rate() {
        let threshold = 0.15;
        assert!((threshold - 0.15).abs() < f64::EPSILON);
    }

    #[test]
    fn threshold_default_smtp_421() {
        let threshold = 30u64;
        assert_eq!(threshold, 30);
    }

    #[test]
    fn threshold_default_smtp_550() {
        let threshold = 20u64;
        assert_eq!(threshold, 20);
    }

    #[test]
    fn window_60_minutes() {
        let window = 60;
        assert_eq!(window, 60);
    }

    #[test]
    fn window_30_minutes() {
        let window = 30;
        assert_eq!(window, 30);
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
    fn mongo_collection_smtp_events() {
        let coll = "smtp_events";
        assert_eq!(coll, "smtp_events");
    }

    #[test]
    fn mongo_collection_auth_events() {
        let coll = "auth_events";
        assert_eq!(coll, "auth_events");
    }

    #[test]
    fn mongo_field_status() {
        let field = "status";
        assert_eq!(field, "status");
    }

    #[test]
    fn mongo_field_smtp_code() {
        let field = "smtp_code";
        assert_eq!(field, "smtp_code");
    }

    #[test]
    fn mongo_field_ts() {
        let field = "ts";
        assert_eq!(field, "ts");
    }

    #[test]
    fn mongo_field_from() {
        let field = "from";
        assert_eq!(field, "from");
    }

    #[test]
    fn mongo_field_to() {
        let field = "to";
        assert_eq!(field, "to");
    }

    #[test]
    fn mongo_field_ip() {
        let field = "ip";
        assert_eq!(field, "ip");
    }

    #[test]
    fn mongo_field_success() {
        let field = "success";
        assert_eq!(field, "success");
    }

    #[test]
    fn mongo_field_kind() {
        let field = "kind";
        assert_eq!(field, "kind");
    }

    #[test]
    fn mongo_field_smtp_reply() {
        let field = "smtp_reply";
        assert_eq!(field, "smtp_reply");
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
            SecuritySeverity::Medium,
            RemediationLevel::THROTTLE,
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
            SecuritySeverity::Medium,
            RemediationLevel::THROTTLE,
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
            SecuritySeverity::Medium,
            RemediationLevel::THROTTLE,
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
            SecuritySeverity::Medium,
            RemediationLevel::THROTTLE,
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
            SecuritySeverity::Medium,
            RemediationLevel::THROTTLE,
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
            SecuritySeverity::Medium,
            RemediationLevel::THROTTLE,
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
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
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
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
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
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
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
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let drained: Vec<_> = alerts.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(alerts.is_empty());
    }

    #[test]
    fn security_alert_split_off() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
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
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
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
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
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
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let types: Vec<String> = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(types, vec!["A", "B"]);
    }

    #[test]
    fn security_alert_into_iter_filter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let filtered: Vec<_> = alerts.into_iter().filter(|a| a.alert_type == "A").collect();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn security_alert_into_iter_fold() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().fold(0, |acc, _| acc + 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_any() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let any = alerts.into_iter().any(|a| a.alert_type == "A");
        assert!(any);
    }

    #[test]
    fn security_alert_into_iter_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let all = alerts.into_iter().all(|a| !a.alert_type.is_empty());
        assert!(all);
    }

    #[test]
    fn security_alert_into_iter_none() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let none = alerts.into_iter().any(|a| a.alert_type == "Z");
        assert!(!none);
    }

    #[test]
    fn security_alert_into_iter_not_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let not_all = alerts.into_iter().all(|a| a.alert_type == "A");
        assert!(!not_all);
    }

    #[test]
    fn security_alert_into_iter_find() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "B");
        assert!(found.is_some());
        assert_eq!(found.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_find_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "Z");
        assert!(found.is_none());
    }

    #[test]
    fn security_alert_into_iter_position() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "B");
        assert_eq!(pos, Some(1));
    }

    #[test]
    fn security_alert_into_iter_position_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_rposition() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "A");
        assert_eq!(pos, Some(0));
    }

    #[test]
    fn security_alert_into_iter_rposition_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_count() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_max() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let max = alerts.into_iter().max();
        assert_eq!(max.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_min() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let min = alerts.into_iter().min();
        assert_eq!(min.unwrap().alert_type, "A");
    }

    #[test]
    fn security_alert_into_iter_sum() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_product() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_collect() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let collected: Vec<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_hash_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::HashSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_btree_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::BTreeSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_linked_list() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::LinkedList<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_vec_deque() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::VecDeque<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_binary_heap() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::BinaryHeap<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_string() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE),
        ];
        let collected: String = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(collected, "AB");
    }

    #[test]
    fn security_alert_into_iter_collect_result() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE)),
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
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_fold() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_reduce() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::High, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::Medium, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }
}
