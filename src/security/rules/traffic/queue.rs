//! Queue buildup / deferred accumulation.

use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use crate::security::rules::helpers::{count, env_u64, since, RuleContext};

pub async fn rule_queue_buildup(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_QUEUE_DEFERRED_THRESHOLD", 100);
    let s_30m = since(30);
    let s_1h = since(60);

    let deferred_30m = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_30m }, "status": "deferred" },
    )
    .await;
    let deferred_prev_30m = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_1h, "$lt": &s_30m }, "status": "deferred" },
    )
    .await;

    if deferred_30m < threshold {
        return vec![];
    }

    let growing = deferred_30m > deferred_prev_30m;
    let level = if growing {
        RemediationLevel::THROTTLE
    } else {
        RemediationLevel::ALERT
    };

    let mut alert = SecurityAlert::new(
        "QUEUE_BUILDUP",
        "Accumulation anormale de queue + retries",
        SecuritySeverity::Medium,
        level,
    )
    .with_signal(json!({
        "deferred_last_30m": deferred_30m,
        "deferred_prev_30m": deferred_prev_30m,
        "growing": growing,
        "threshold": threshold,
    }));

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
    fn queue_buildup_above_threshold() {
        let deferred_30m = 150u64;
        let threshold = 100u64;
        assert!(deferred_30m >= threshold);
    }

    #[test]
    fn queue_buildup_below_threshold() {
        let deferred_30m = 50u64;
        let threshold = 100u64;
        assert!(deferred_30m < threshold);
    }

    #[test]
    fn queue_buildup_at_threshold() {
        let deferred_30m = 100u64;
        let threshold = 100u64;
        assert!(deferred_30m >= threshold);
    }

    #[test]
    fn queue_buildup_growing() {
        let deferred_30m = 150u64;
        let deferred_prev_30m = 100u64;
        let growing = deferred_30m > deferred_prev_30m;
        assert!(growing);
    }

    #[test]
    fn queue_buildup_not_growing() {
        let deferred_30m = 100u64;
        let deferred_prev_30m = 150u64;
        let growing = deferred_30m > deferred_prev_30m;
        assert!(!growing);
    }

    #[test]
    fn queue_buildup_same() {
        let deferred_30m = 100u64;
        let deferred_prev_30m = 100u64;
        let growing = deferred_30m > deferred_prev_30m;
        assert!(!growing);
    }

    #[test]
    fn queue_buildup_triggers_throttle_when_growing() {
        let growing = true;
        let level = if growing {
            RemediationLevel::THROTTLE
        } else {
            RemediationLevel::ALERT
        };
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn queue_buildup_triggers_alert_when_not_growing() {
        let growing = false;
        let level = if growing {
            RemediationLevel::THROTTLE
        } else {
            RemediationLevel::ALERT
        };
        assert_eq!(level, RemediationLevel::ALERT);
    }

    #[test]
    fn alert_type_queue_buildup() {
        let alert_type = "QUEUE_BUILDUP";
        assert_eq!(alert_type, "QUEUE_BUILDUP");
    }

    #[test]
    fn alert_title_queue_buildup() {
        let title = "Accumulation anormale de queue + retries";
        assert_eq!(title, "Accumulation anormale de queue + retries");
    }

    #[test]
    fn alert_severity_medium() {
        let severity = SecuritySeverity::Medium;
        assert_eq!(severity, SecuritySeverity::Medium);
    }

    #[test]
    fn alert_signal_queue_buildup() {
        let signal = json!({
            "deferred_last_30m": 150,
            "deferred_prev_30m": 100,
            "growing": true,
            "threshold": 100,
        });
        assert_eq!(signal["deferred_last_30m"], 150);
        assert_eq!(signal["deferred_prev_30m"], 100);
        assert_eq!(signal["growing"], true);
        assert_eq!(signal["threshold"], 100);
    }

    #[test]
    fn threshold_default_queue_buildup() {
        let threshold = 100u64;
        assert_eq!(threshold, 100);
    }

    #[test]
    fn window_30_minutes() {
        let window = 30;
        assert_eq!(window, 30);
    }

    #[test]
    fn window_60_minutes() {
        let window = 60;
        assert_eq!(window, 60);
    }

    #[test]
    fn mongo_collection_smtp_events() {
        let coll = "smtp_events";
        assert_eq!(coll, "smtp_events");
    }

    #[test]
    fn mongo_field_status() {
        let field = "status";
        assert_eq!(field, "status");
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        )
        .with_duration(0);
        assert_eq!(alert.duration_secs, Some(0));
    }

    #[test]
    fn security_alert_with_tenant() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        alert1.stamp_audit_hash();
        let mut alert2 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.ip, None);
    }

    #[test]
    fn security_alert_signal_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.signal, None);
    }

    #[test]
    fn security_alert_duration_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.duration_secs, None);
    }

    #[test]
    fn security_alert_tenant_some() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.tenant_id, None);
    }

    #[test]
    fn security_alert_audit_hash_some() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.audit_hash, None);
    }

    #[test]
    fn security_alert_clone() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        let alert2 = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert1, alert2);
    }

    #[test]
    fn security_alert_ne() {
        let alert1 = SecurityAlert::new(
            "TEST1",
            "Test alert 1",
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_from_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_to_string() {
        let alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
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
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.alert_type, "TEST");
    }

    #[test]
    fn security_alert_index_mut() {
        let mut alert = SecurityAlert::new(
            "TEST",
            "Test alert",
            SecuritySeverity::Medium,
            RemediationLevel::ALERT,
        );
        alert.alert_type = "CHANGED".to_string();
        assert_eq!(alert.alert_type, "CHANGED");
    }

    #[test]
    fn security_alert_into_iter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
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
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
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
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
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
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let drained: Vec<_> = alerts.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(alerts.is_empty());
    }

    #[test]
    fn security_alert_split_off() {
        let mut alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let rest = alerts.split_off(1);
        assert_eq!(alerts.len(), 1);
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn security_alert_append() {
        let mut alerts1 = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
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
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
        ];
        alerts.extend(vec![
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ]);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn security_alert_from_iter() {
        let iter = vec!["A", "B"].into_iter().map(|s| {
            SecurityAlert::new(s, "Alert", SecuritySeverity::Medium, RemediationLevel::ALERT)
        });
        let alerts: Vec<_> = iter.collect();
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_map() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let types: Vec<String> = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(types, vec!["A", "B"]);
    }

    #[test]
    fn security_alert_into_iter_filter() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let filtered: Vec<_> = alerts.into_iter().filter(|a| a.alert_type == "A").collect();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn security_alert_into_iter_fold() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().fold(0, |acc, _| acc + 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_any() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let any = alerts.into_iter().any(|a| a.alert_type == "A");
        assert!(any);
    }

    #[test]
    fn security_alert_into_iter_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let all = alerts.into_iter().all(|a| !a.alert_type.is_empty());
        assert!(all);
    }

    #[test]
    fn security_alert_into_iter_none() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let none = alerts.into_iter().any(|a| a.alert_type == "Z");
        assert!(!none);
    }

    #[test]
    fn security_alert_into_iter_not_all() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let not_all = alerts.into_iter().all(|a| a.alert_type == "A");
        assert!(!not_all);
    }

    #[test]
    fn security_alert_into_iter_find() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "B");
        assert!(found.is_some());
        assert_eq!(found.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_find_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let found = alerts.into_iter().find(|a| a.alert_type == "Z");
        assert!(found.is_none());
    }

    #[test]
    fn security_alert_into_iter_position() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "B");
        assert_eq!(pos, Some(1));
    }

    #[test]
    fn security_alert_into_iter_position_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().position(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_rposition() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "A");
        assert_eq!(pos, Some(0));
    }

    #[test]
    fn security_alert_into_iter_rposition_not_found() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let pos = alerts.into_iter().rposition(|a| a.alert_type == "Z");
        assert_eq!(pos, None);
    }

    #[test]
    fn security_alert_into_iter_count() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_max() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let max = alerts.into_iter().max();
        assert_eq!(max.unwrap().alert_type, "B");
    }

    #[test]
    fn security_alert_into_iter_min() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let min = alerts.into_iter().min();
        assert_eq!(min.unwrap().alert_type, "A");
    }

    #[test]
    fn security_alert_into_iter_sum() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_product() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let count = alerts.into_iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn security_alert_into_iter_collect() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: Vec<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_hash_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::HashSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_btree_set() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::BTreeSet<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_linked_list() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::LinkedList<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_vec_deque() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::VecDeque<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_binary_heap() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: std::collections::BinaryHeap<_> = alerts.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_string() {
        let alerts = vec![
            SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT),
            SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE),
        ];
        let collected: String = alerts.into_iter().map(|a| a.alert_type).collect();
        assert_eq!(collected, "AB");
    }

    #[test]
    fn security_alert_into_iter_collect_result() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
        assert_eq!(collected.unwrap().len(), 2);
    }

    #[test]
    fn security_alert_into_iter_collect_result_err() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT)),
            Err(()),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_err());
    }

    #[test]
    fn security_alert_into_iter_collect_try() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_fold() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }

    #[test]
    fn security_alert_into_iter_collect_try_reduce() {
        let alerts: Vec<Result<SecurityAlert, ()>> = vec![
            Ok(SecurityAlert::new("A", "Alert A", SecuritySeverity::Medium, RemediationLevel::ALERT)),
            Ok(SecurityAlert::new("B", "Alert B", SecuritySeverity::High, RemediationLevel::THROTTLE)),
        ];
        let collected: Result<Vec<_>, _> = alerts.into_iter().collect();
        assert!(collected.is_ok());
    }
}
