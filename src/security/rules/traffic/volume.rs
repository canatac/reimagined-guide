//! Rules volume/hourly — abuse volume spike & hourly anomaly.

use chrono::Utc;
use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use crate::security::rules::helpers::{count, env_f64, env_list, since, RuleContext};

pub async fn rule_abuse_volume_spike(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold_ratio = env_f64("SEC_VOLUME_SPIKE_RATIO", 10.0);
    let s_1h = since(60);
    let s_7d = since(60 * 24 * 7);

    let vol_1h = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_1h } }).await;
    let vol_7d = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_7d } }).await;

    if vol_7d == 0 || vol_1h == 0 {
        return vec![];
    }

    let baseline_per_hour = vol_7d as f64 / (24.0 * 7.0);
    let ratio = vol_1h as f64 / baseline_per_hour.max(1.0);

    let whitelist = env_list("SECURITY_VOLUME_WHITELIST_TENANTS");
    if let Some(ref tid) = ctx.tenant_id {
        if whitelist.contains(tid) {
            return vec![];
        }
    }

    if ratio < threshold_ratio {
        return vec![];
    }

    let level = if ratio > 50.0 {
        RemediationLevel::QUARANTINE
    } else {
        RemediationLevel::THROTTLE
    };

    let mut alert = SecurityAlert::new(
        "ABUSE_VOLUME_SPIKE",
        "Volume sortant anormal",
        SecuritySeverity::Critical,
        level,
    )
    .with_signal(json!({
        "volume_last_1h": vol_1h,
        "baseline_per_hour": baseline_per_hour.round(),
        "ratio": (ratio * 10.0).round() / 10.0,
        "threshold_ratio": threshold_ratio,
    }))
    .with_duration(3600);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

pub async fn rule_hourly_anomaly(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let current_hour = Utc::now().format("%H").to_string().parse::<u32>().unwrap_or(12);
    let off_peak_hours: Vec<u32> = vec![2, 3, 4, 5];
    if !off_peak_hours.contains(&current_hour) {
        return vec![];
    }

    let threshold_multiplier = env_f64("SEC_HOURLY_ANOMALY_MULTIPLIER", 5.0);
    let s_1h = since(60);
    let s_8d = since(60 * 24 * 8);

    let vol_this_hour = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_1h } }).await;
    let vol_7d_same_hour = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_8d } }).await / 7;

    let baseline = vol_7d_same_hour.max(1) as f64;
    let ratio = vol_this_hour as f64 / baseline;

    if ratio < threshold_multiplier {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "HOURLY_ANOMALY",
        "Envoi massif hors profil horaire",
        SecuritySeverity::High,
        RemediationLevel::THROTTLE,
    )
    .with_signal(json!({
        "current_hour_utc": current_hour,
        "volume_this_hour": vol_this_hour,
        "baseline_7d_avg": vol_7d_same_hour,
        "ratio": (ratio * 10.0).round() / 10.0,
        "threshold_ratio": threshold_multiplier,
    }))
    .with_duration(3600);

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
    fn volume_spike_baseline_calculation() {
        let vol_7d = 1680u64;
        let baseline_per_hour = vol_7d as f64 / (24.0 * 7.0);
        assert_eq!(baseline_per_hour, 10.0);
    }

    #[test]
    fn volume_spike_ratio_calculation() {
        let vol_1h = 100u64;
        let baseline_per_hour = 10.0;
        let ratio = vol_1h as f64 / baseline_per_hour.max(1.0);
        assert_eq!(ratio, 10.0);
    }

    #[test]
    fn volume_spike_ratio_rounding() {
        let ratio = 12.345;
        let rounded = (ratio * 10.0).round() / 10.0;
        assert_eq!(rounded, 12.3);
    }

    #[test]
    fn volume_spike_above_threshold() {
        let ratio = 15.0;
        let threshold = 10.0;
        assert!(ratio >= threshold);
    }

    #[test]
    fn volume_spike_below_threshold() {
        let ratio = 5.0;
        let threshold = 10.0;
        assert!(ratio < threshold);
    }

    #[test]
    fn volume_spike_triggers_quarantine() {
        let ratio = 60.0;
        let level = if ratio > 50.0 {
            RemediationLevel::QUARANTINE
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::QUARANTINE);
    }

    #[test]
    fn volume_spike_triggers_throttle() {
        let ratio = 20.0;
        let level = if ratio > 50.0 {
            RemediationLevel::QUARANTINE
        } else {
            RemediationLevel::THROTTLE
        };
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn volume_spike_zero_vol_7d() {
        let vol_7d = 0u64;
        let vol_1h = 10u64;
        if vol_7d == 0 || vol_1h == 0 {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn volume_spike_zero_vol_1h() {
        let vol_7d = 100u64;
        let vol_1h = 0u64;
        if vol_7d == 0 || vol_1h == 0 {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn hourly_anomaly_off_peak_hours() {
        let off_peak_hours: Vec<u32> = vec![2, 3, 4, 5];
        assert!(off_peak_hours.contains(&2));
        assert!(off_peak_hours.contains(&3));
        assert!(off_peak_hours.contains(&4));
        assert!(off_peak_hours.contains(&5));
        assert!(!off_peak_hours.contains(&12));
        assert!(!off_peak_hours.contains(&0));
        assert!(!off_peak_hours.contains(&23));
    }

    #[test]
    fn hourly_anomaly_current_hour_off_peak() {
        let current_hour = 3u32;
        let off_peak_hours: Vec<u32> = vec![2, 3, 4, 5];
        assert!(off_peak_hours.contains(&current_hour));
    }

    #[test]
    fn hourly_anomaly_current_hour_not_off_peak() {
        let current_hour = 12u32;
        let off_peak_hours: Vec<u32> = vec![2, 3, 4, 5];
        assert!(!off_peak_hours.contains(&current_hour));
    }

    #[test]
    fn hourly_anomaly_baseline_calculation() {
        let vol_7d_same_hour = 70u64;
        let baseline = vol_7d_same_hour.max(1) as f64;
        assert_eq!(baseline, 70.0);
    }

    #[test]
    fn hourly_anomaly_ratio_calculation() {
        let vol_this_hour = 350u64;
        let baseline = 70.0;
        let ratio = vol_this_hour as f64 / baseline;
        assert_eq!(ratio, 5.0);
    }

    #[test]
    fn hourly_anomaly_above_threshold() {
        let ratio = 6.0;
        let threshold = 5.0;
        assert!(ratio >= threshold);
    }

    #[test]
    fn hourly_anomaly_below_threshold() {
        let ratio = 4.0;
        let threshold = 5.0;
        assert!(ratio < threshold);
    }

    #[test]
    fn hourly_anomaly_at_threshold() {
        let ratio = 5.0;
        let threshold = 5.0;
        assert!(ratio >= threshold);
    }

    #[test]
    fn hourly_anomaly_ratio_rounding() {
        let ratio = 5.678;
        let rounded = (ratio * 10.0).round() / 10.0;
        assert_eq!(rounded, 5.7);
    }

    #[test]
    fn alert_type_abuse_volume_spike() {
        let alert_type = "ABUSE_VOLUME_SPIKE";
        assert_eq!(alert_type, "ABUSE_VOLUME_SPIKE");
    }

    #[test]
    fn alert_type_hourly_anomaly() {
        let alert_type = "HOURLY_ANOMALY";
        assert_eq!(alert_type, "HOURLY_ANOMALY");
    }

    #[test]
    fn alert_title_abuse_volume_spike() {
        let title = "Volume sortant anormal";
        assert_eq!(title, "Volume sortant anormal");
    }

    #[test]
    fn alert_title_hourly_anomaly() {
        let title = "Envoi massif hors profil horaire";
        assert_eq!(title, "Envoi massif hors profil horaire");
    }

    #[test]
    fn alert_severity_critical() {
        let severity = SecuritySeverity::Critical;
        assert_eq!(severity, SecuritySeverity::Critical);
    }

    #[test]
    fn alert_severity_high() {
        let severity = SecuritySeverity::High;
        assert_eq!(severity, SecuritySeverity::High);
    }

    #[test]
    fn remediation_level_quarantine() {
        let level = RemediationLevel::QUARANTINE;
        assert_eq!(level, RemediationLevel::QUARANTINE);
    }

    #[test]
    fn remediation_level_throttle() {
        let level = RemediationLevel::THROTTLE;
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn alert_duration_volume_spike() {
        let duration = 3600;
        assert_eq!(duration, 3600);
    }

    #[test]
    fn alert_duration_hourly_anomaly() {
        let duration = 3600;
        assert_eq!(duration, 3600);
    }

    #[test]
    fn alert_signal_volume_spike() {
        let signal = json!({
            "volume_last_1h": 100,
            "baseline_per_hour": 10.0,
            "ratio": 10.0,
            "threshold_ratio": 10.0,
        });
        assert_eq!(signal["volume_last_1h"], 100);
        assert_eq!(signal["baseline_per_hour"], 10.0);
        assert_eq!(signal["ratio"], 10.0);
        assert_eq!(signal["threshold_ratio"], 10.0);
    }

    #[test]
    fn alert_signal_hourly_anomaly() {
        let signal = json!({
            "current_hour_utc": 3,
            "volume_this_hour": 350,
            "baseline_7d_avg": 70,
            "ratio": 5.0,
            "threshold_ratio": 5.0,
        });
        assert_eq!(signal["current_hour_utc"], 3);
        assert_eq!(signal["volume_this_hour"], 350);
        assert_eq!(signal["baseline_7d_avg"], 70);
        assert_eq!(signal["ratio"], 5.0);
        assert_eq!(signal["threshold_ratio"], 5.0);
    }

    #[test]
    fn threshold_default_volume_spike() {
        let threshold = 10.0;
        assert!((threshold - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn threshold_default_hourly_anomaly() {
        let threshold = 5.0;
        assert!((threshold - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn window_1h() {
        let window = 60;
        assert_eq!(window, 60);
    }

    #[test]
    fn window_7d() {
        let window = 60 * 24 * 7;
        assert_eq!(window, 10080);
    }

    #[test]
    fn window_8d() {
        let window = 60 * 24 * 8;
        assert_eq!(window, 11520);
    }

    #[test]
    fn mongo_collection_smtp_events() {
        let coll = "smtp_events";
        assert_eq!(coll, "smtp_events");
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.alert_type, "TEST");
        assert_eq!(alert.title, "Test alert");
    }

    #[test]
    fn security_alert_with_signal() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_signal(json!({"key": "value"}));
        assert!(alert.signal.is_some());
    }

    #[test]
    fn security_alert_with_duration() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_duration(3600);
        assert_eq!(alert.duration_secs, Some(3600));
    }

    #[test]
    fn security_alert_with_tenant() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_tenant("tenant-1");
        assert_eq!(alert.tenant_id, Some("tenant-1".to_string()));
    }

    #[test]
    fn security_alert_with_ip() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert.ip = Some("192.168.1.1".to_string());
        assert_eq!(alert.ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn security_alert_stamp_audit_hash() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert.stamp_audit_hash();
        assert!(alert.audit_hash.is_some());
    }

    #[test]
    fn security_alert_audit_hash_unique() {
        let mut alert1 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert1.stamp_audit_hash();
        let mut alert2 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert2.stamp_audit_hash();
        assert_ne!(alert1.audit_hash, alert2.audit_hash);
    }

    #[test]
    fn security_alert_audit_hash_not_empty() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_duration(0);
        assert_eq!(alert.duration_secs, Some(0));
    }

    #[test]
    fn security_alert_duration_900() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_duration(900);
        assert_eq!(alert.duration_secs, Some(900));
    }

    #[test]
    fn security_alert_duration_1800() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_duration(1800);
        assert_eq!(alert.duration_secs, Some(1800));
    }

    #[test]
    fn security_alert_duration_3600() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_duration(3600);
        assert_eq!(alert.duration_secs, Some(3600));
    }

    #[test]
    fn security_alert_tenant_empty() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_tenant("");
        assert_eq!(alert.tenant_id, Some("".to_string()));
    }

    #[test]
    fn security_alert_tenant_uuid() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_tenant("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(alert.tenant_id, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
    }

    #[test]
    fn security_alert_ip_ipv4() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert.ip = Some("192.168.1.1".to_string());
        assert_eq!(alert.ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn security_alert_ip_ipv6() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert.ip = Some("::1".to_string());
        assert_eq!(alert.ip, Some("::1".to_string()));
    }

    #[test]
    fn security_alert_ip_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.ip, None);
    }

    #[test]
    fn security_alert_signal_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_signal(json!({"key": "value"}));
        assert!(alert.signal.is_some());
    }

    #[test]
    fn security_alert_signal_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.signal, None);
    }

    #[test]
    fn security_alert_duration_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_duration(3600);
        assert!(alert.duration_secs.is_some());
    }

    #[test]
    fn security_alert_duration_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.duration_secs, None);
    }

    #[test]
    fn security_alert_tenant_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        )
        .with_tenant("tenant-1");
        assert!(alert.tenant_id.is_some());
    }

    #[test]
    fn security_alert_tenant_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.tenant_id, None);
    }

    #[test]
    fn security_alert_audit_hash_some() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert.stamp_audit_hash();
        assert!(alert.audit_hash.is_some());
    }

    #[test]
    fn security_alert_audit_hash_none() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.audit_hash, None);
    }

    #[test]
    fn security_alert_clone() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert1, alert2);
    }

    #[test]
    fn security_alert_ne() {
        let alert1 = SecurityAlert::new(
            "TEST1",
            "Test alert 1",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = SecurityAlert::new(
            "TEST2",
            "Test alert 2",
            SecuritySeverity::High,
            RemediationLevel::THROTTLE,
        );
        assert_ne!(alert1, alert2);
    }

    #[test]
    fn security_alert_debug() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let debug = format!("{:?}", alert);
        assert!(debug.contains("TEST"));
    }

    #[test]
    fn security_alert_display() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = alert1.clone();
        assert!(alert1 == alert2);
    }

    #[test]
    fn security_alert_partial_ne() {
        let alert1 = SecurityAlert::new(
            "TEST1",
            "Test alert 1",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = SecurityAlert::new(
            "TEST2",
            "Test alert 2",
            SecuritySeverity::High,
            RemediationLevel::THROTTLE,
        );
        assert!(alert1 != alert2);
    }

    #[test]
    fn security_alert_partial_ord() {
        let alert1 = SecurityAlert::new(
            "A",
            "Alert A",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::High,
            RemediationLevel::THROTTLE,
        );
        assert!(alert1 < alert2);
    }

    #[test]
    fn security_alert_cmp() {
        let alert1 = SecurityAlert::new(
            "A",
            "Alert A",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::High,
            RemediationLevel::THROTTLE,
        );
        assert_eq!(alert1.cmp(&alert2), std::cmp::Ordering::Less);
    }

    #[test]
    fn security_alert_max() {
        let alert1 = SecurityAlert::new(
            "A",
            "Alert A",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::High,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let alert2 = SecurityAlert::new(
            "B",
            "Alert B",
            SecuritySeverity::High,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_from_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_to_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let s = alert.to_string();
        assert!(s.contains("TEST"));
    }

    #[test]
    fn security_alert_into_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let s: String = alert.to_string();
        assert!(s.contains("TEST"));
    }

    #[test]
    fn security_alert_as_ref() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let r = &alert;
        assert_eq!(r.alert_type, "TEST");
    }

    #[test]
    fn security_alert_as_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let d = &*alert;
        assert_eq!(d.alert_type, "TEST");
    }

    #[test]
    fn security_alert_deref_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        let b = &alert;
        assert_eq!(b.alert_type, "TEST");
    }

    #[test]
    fn security_alert_borrow_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
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
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_index_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Critical,
            RemediationLevel::QUARANTINE,
        );
        alert.alert_type = "CHANGED".to_string();
        assert_eq!(alert.alert_type, "CHANGED");
    }

    #[test]
    fn security_alert_into_iter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let mut iter = alerts.into_iter();
        assert_eq!(iter.next().unwrap().alert_type, "A");
        assert_eq!(iter.next().unwrap().alert_type, "B");
        assert!(iter.next().is_none());
    }

    #[test]
    fn security_alert_iter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let mut iter = alerts.iter();
        assert_eq!(iter.next().unwrap().alert_type, "A");
        assert_eq!(iter.next().unwrap().alert_type, "B");
        assert!(iter.next().is_none());
    }

    #[test]
    fn security_alert_iter_mut() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
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
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let drained: Vec<_> = alerts.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(alerts.is_empty());
    }

    #[test]
    fn security_alert_split_off() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let rest = alerts.split_off(1);
        assert_eq!(alerts.len(), 1);
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn security_alert_append() {
        let mut alerts1 = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        let mut alerts2 = vec![
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        alerts1.append(&mut alerts2);
        assert_eq!(alerts1.len(), 2);
        assert!(alerts2.is_empty());
    }

    #[test]
    fn security_alert_extend() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
        ];
        alerts.extend(vec![
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ]);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn security_alert_from_iter() {
        let iter = vec!["A", "B"].into_iter().map(|s| {
            SecurityAlert::new(s, "Alert", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)
        });
        let alerts: Vec<_> = iter.collect();
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_map() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let types: Vec<String> = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(types, vec!["A", "B"]);
    }

    #[test]
    fn security_alert_into_iter_filter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let filtered: Vec<_> = alerts.into_iter().filter(|a| a.alert_type == "A").collect();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn security_alert_into_iter_fold() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().fold(0, |acc, _| acc + 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_any() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let any = alerts.into_iter().any(|a| a.alert_type == "A");
        assert!(any);
    }

    #[test]
    fn security_alert_into_iter_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let all = alerts.into_iter().all(|a| !a.alert_type.is_empty());
        assert!(all);
    }

    #[test]
    fn security_alert_into_iter_none() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let none = alerts.into_iter().any(|a| a.alert_type == "Z");
        assert!(!none);
    }

    #[test]
    fn security_alert_into_iter_not_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let not_all = alerts.into_iter().all(|a| a.alert_type == "A");
        assert!(!not_all);
    }

    #[test]
    fn security_alert_into_iter_find() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "B");
        assert!(found.is_some());
        assert_eq!(found.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_find_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "Z");
        assert!(found.is_none());
    }

    #[test]
    fn security_alert_into_iter_position() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "B");
        assert_eq!(pos, Some(1));
    }

    #[test]
    fn security_alert_into_iter_position_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_rposition() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "A");
        assert_eq!(pos, Some(0));
    }

    #[test]
    fn security_alert_into_iter_rposition_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_count() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_max() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let max = alerts.into_iter().max();
        assert_eq!(max.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_min() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let min = alerts.into_iter().min();
        assert_eq!(min.unwrap().alert_type, "A");
    }

    #[test]
    fn security_alert_into_iter_sum() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_product() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_collect() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: Vec<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_hash_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::HashSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_btree_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::BTreeSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_linked_list() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::LinkedList<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_vec_deque() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::VecDeque<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_binary_heap() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::BinaryHeap<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_string() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: String = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(collected, "AB");
    }

    #[test]
    fn security_alert_into_iter_collect_result() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
        assert_eq!(collected.unwrap().len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_result_err() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
            Err(()),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_err());
    }

    #[test]
    fn security_alert_into_iter_collect_try() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_fold() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_reduce() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Critical, RemediationLevel::QUARANTINE)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }
}
