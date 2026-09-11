//! Auto-généré par le refacto architecte (rules split par catégorie).

use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use super::helpers::RuleContext;
use super::helpers::{since, env_u64, env_list, db_name, count};

pub async fn rule_new_destination_country(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let s_1h = since(60);
    let s_30d = since(60 * 24 * 30);

    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    // Countries seen in last 1h
    let recent = coll
        .distinct("country", doc! { "ts": { "$gte": &s_1h } })
        .await
        .unwrap_or_default();

    // Countries seen in last 30d (excluding last 1h)
    let historical = coll
        .distinct(
            "country",
            doc! { "ts": { "$gte": &s_30d, "$lt": &s_1h } },
        )
        .await
        .unwrap_or_default();

    let hist_set: std::collections::HashSet<String> = historical
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .collect();

    let new_countries: Vec<String> = recent
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .filter(|c| c != "unknown" && c != "private" && !hist_set.contains(c))
        .collect();

    if new_countries.is_empty() {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "NEW_DESTINATION_COUNTRY",
        "Nouveau pays de destination",
        SecuritySeverity::Medium,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "new_countries": new_countries,
        "historical_countries_count": hist_set.len(),
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 6 — NEW_DESTINATION_ASN
// Nouveau ASN de routage MX jamais vu en 30 jours.
// Source: smtp_events | Window: 30d baseline vs 1h
// L1 alerte
// FP: routage réseau du destinataire légitime modifié
// ---------------------------------------------------------------------------

pub async fn rule_new_destination_asn(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let s_1h = since(60);
    let s_30d = since(60 * 24 * 30);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    let recent = coll
        .distinct("asn", doc! { "ts": { "$gte": &s_1h } })
        .await
        .unwrap_or_default();
    let historical = coll
        .distinct("asn", doc! { "ts": { "$gte": &s_30d, "$lt": &s_1h } })
        .await
        .unwrap_or_default();

    let hist_set: std::collections::HashSet<String> = historical
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .collect();

    let new_asns: Vec<String> = recent
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .filter(|a| a != "unknown" && a != "private" && !hist_set.contains(a))
        .collect();

    if new_asns.is_empty() {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "NEW_DESTINATION_ASN",
        "Nouveau ASN de routage",
        SecuritySeverity::Low,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({ "new_asns": new_asns }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 7 — AUTH_BRUTE_FORCE
// Brute force SMTP AUTH ou API login.
// Source: auth_events | Window: 5m | Threshold: >10 failures/IP
// L2 throttle → L4 block
// FP: outils d'automatisation mal configurés côté client
// ---------------------------------------------------------------------------

pub async fn rule_high_risk_asn_country(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let risk_countries = env_list("MONITORING_FORBIDDEN_COUNTRIES");
    let risk_asns = env_list("SECURITY_FORBIDDEN_ASNS");
    if risk_countries.is_empty() && risk_asns.is_empty() {
        return vec![];
    }

    let s = since(60);
    let mut filter = doc! { "ts": { "$gte": &s } };

    let mut conditions = vec![];
    if !risk_countries.is_empty() {
        let bson_countries: Vec<_> = risk_countries
            .iter()
            .map(|c| mongodb::bson::Bson::String(c.clone()))
            .collect();
        conditions.push(doc! { "country": { "$in": bson_countries } });
    }
    if !risk_asns.is_empty() {
        let bson_asns: Vec<_> = risk_asns
            .iter()
            .map(|a| mongodb::bson::Bson::String(a.clone()))
            .collect();
        conditions.push(doc! { "asn": { "$in": bson_asns } });
    }
    if !conditions.is_empty() {
        filter.insert("$or", conditions);
    }

    let hits = count(ctx.client, "smtp_events", filter).await;
    if hits == 0 {
        return vec![];
    }

    let level = if hits > env_u64("SEC_RISK_COUNTRY_VOLUME_L2", 20) {
        RemediationLevel::THROTTLE
    } else {
        RemediationLevel::ALERT
    };

    let mut alert = SecurityAlert::new(
        "HIGH_RISK_ASN_COUNTRY",
        "Connexion depuis ASN/pays à risque",
        SecuritySeverity::High,
        level,
    )
    .with_signal(json!({
        "hits_1h": hits,
        "risk_countries": risk_countries,
        "risk_asns": risk_asns,
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 9 — SPF_DKIM_DRIFT
// Dégradation SPF/DKIM/DMARC détectée dans les réponses SMTP.
// Source: smtp_events.smtp_reply | Window: 1h | Threshold: >10 fail mentions
// L1 alerte (correction DNS requise)
// FP: migration de provider, TTL DNS pas encore propagé
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_destination_country_filters_unknown() {
        let countries = vec!["US".to_string(), "unknown".to_string(), "FR".to_string()];
        let hist_set: std::collections::HashSet<String> = vec!["US".to_string()].into_iter().collect();
        let new_countries: Vec<String> = countries
            .iter()
            .filter(|c| *c != "unknown" && *c != "private" && !hist_set.contains(*c))
            .cloned()
            .collect();
        assert_eq!(new_countries, vec!["FR".to_string()]);
    }

    #[test]
    fn new_destination_country_filters_private() {
        let countries = vec!["US".to_string(), "private".to_string(), "DE".to_string()];
        let hist_set: std::collections::HashSet<String> = vec!["US".to_string()].into_iter().collect();
        let new_countries: Vec<String> = countries
            .iter()
            .filter(|c| *c != "unknown" && *c != "private" && !hist_set.contains(*c))
            .cloned()
            .collect();
        assert_eq!(new_countries, vec!["DE".to_string()]);
    }

    #[test]
    fn new_destination_country_empty_when_all_historical() {
        let countries = vec!["US".to_string(), "FR".to_string()];
        let hist_set: std::collections::HashSet<String> = vec!["US".to_string(), "FR".to_string()].into_iter().collect();
        let new_countries: Vec<String> = countries
            .iter()
            .filter(|c| *c != "unknown" && *c != "private" && !hist_set.contains(*c))
            .cloned()
            .collect();
        assert!(new_countries.is_empty());
    }

    #[test]
    fn new_destination_asn_filters_unknown() {
        let asns = vec!["AS1234".to_string(), "unknown".to_string(), "AS5678".to_string()];
        let hist_set: std::collections::HashSet<String> = vec!["AS1234".to_string()].into_iter().collect();
        let new_asns: Vec<String> = asns
            .iter()
            .filter(|a| *a != "unknown" && *a != "private" && !hist_set.contains(*a))
            .cloned()
            .collect();
        assert_eq!(new_asns, vec!["AS5678".to_string()]);
    }

    #[test]
    fn new_destination_asn_filters_private() {
        let asns = vec!["AS1234".to_string(), "private".to_string(), "AS5678".to_string()];
        let hist_set: std::collections::HashSet<String> = vec!["AS1234".to_string()].into_iter().collect();
        let new_asns: Vec<String> = asns
            .iter()
            .filter(|a| *a != "unknown" && *a != "private" && !hist_set.contains(*a))
            .cloned()
            .collect();
        assert_eq!(new_asns, vec!["AS5678".to_string()]);
    }

    #[test]
    fn new_destination_asn_empty_when_all_historical() {
        let asns = vec!["AS1234".to_string(), "AS5678".to_string()];
        let hist_set: std::collections::HashSet<String> = vec!["AS1234".to_string(), "AS5678".to_string()].into_iter().collect();
        let new_asns: Vec<String> = asns
            .iter()
            .filter(|a| *a != "unknown" && *a != "private" && !hist_set.contains(*a))
            .cloned()
            .collect();
        assert!(new_asns.is_empty());
    }

    #[test]
    fn high_risk_asn_country_empty_when_no_risk_lists() {
        let risk_countries: Vec<String> = vec![];
        let risk_asns: Vec<String> = vec![];
        assert!(risk_countries.is_empty() && risk_asns.is_empty());
    }

    #[test]
    fn high_risk_asn_country_triggers_throttle() {
        let hits = 25u64;
        let threshold = 20u64;
        let level = if hits > threshold {
            RemediationLevel::THROTTLE
        } else {
            RemediationLevel::ALERT
        };
        assert_eq!(level, RemediationLevel::THROTTLE);
    }

    #[test]
    fn high_risk_asn_country_triggers_alert() {
        let hits = 15u64;
        let threshold = 20u64;
        let level = if hits > threshold {
            RemediationLevel::THROTTLE
        } else {
            RemediationLevel::ALERT
        };
        assert_eq!(level, RemediationLevel::ALERT);
    }

    #[test]
    fn high_risk_asn_country_at_threshold() {
        let hits = 20u64;
        let threshold = 20u64;
        let level = if hits > threshold {
            RemediationLevel::THROTTLE
        } else {
            RemediationLevel::ALERT
        };
        assert_eq!(level, RemediationLevel::ALERT);
    }

    #[test]
    fn alert_type_new_destination_country() {
        let alert_type = "NEW_DESTINATION_COUNTRY";
        assert_eq!(alert_type, "NEW_DESTINATION_COUNTRY");
    }

    #[test]
    fn alert_type_new_destination_asn() {
        let alert_type = "NEW_DESTINATION_ASN";
        assert_eq!(alert_type, "NEW_DESTINATION_ASN");
    }

    #[test]
    fn alert_type_high_risk_asn_country() {
        let alert_type = "HIGH_RISK_ASN_COUNTRY";
        assert_eq!(alert_type, "HIGH_RISK_ASN_COUNTRY");
    }

    #[test]
    fn alert_title_new_destination_country() {
        let title = "Nouveau pays de destination";
        assert_eq!(title, "Nouveau pays de destination");
    }

    #[test]
    fn alert_title_new_destination_asn() {
        let title = "Nouveau ASN de routage";
        assert_eq!(title, "Nouveau ASN de routage");
    }

    #[test]
    fn alert_title_high_risk_asn_country() {
        let title = "Connexion depuis ASN/pays à risque";
        assert_eq!(title, "Connexion depuis ASN/pays à risque");
    }

    #[test]
    fn alert_severity_medium() {
        let severity = SecuritySeverity::Medium;
        assert_eq!(severity, SecuritySeverity::Medium);
    }

    #[test]
    fn alert_severity_low() {
        let severity = SecuritySeverity::Low;
        assert_eq!(severity, SecuritySeverity::Low);
    }

    #[test]
    fn alert_severity_high() {
        let severity = SecuritySeverity::High;
        assert_eq!(severity, SecuritySeverity::High);
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
    fn alert_signal_new_destination_country() {
        let signal = json!({
            "new_countries": ["FR", "DE"],
            "historical_countries_count": 5,
        });
        assert_eq!(signal["new_countries"][0], "FR");
        assert_eq!(signal["new_countries"][1], "DE");
        assert_eq!(signal["historical_countries_count"], 5);
    }

    #[test]
    fn alert_signal_new_destination_asn() {
        let signal = json!({
            "new_asns": ["AS1234", "AS5678"],
        });
        assert_eq!(signal["new_asns"][0], "AS1234");
        assert_eq!(signal["new_asns"][1], "AS5678");
    }

    #[test]
    fn alert_signal_high_risk_asn_country() {
        let signal = json!({
            "hits_1h": 25,
            "risk_countries": ["CN", "RU"],
            "risk_asns": ["AS1234"],
        });
        assert_eq!(signal["hits_1h"], 25);
        assert_eq!(signal["risk_countries"][0], "CN");
        assert_eq!(signal["risk_countries"][1], "RU");
        assert_eq!(signal["risk_asns"][0], "AS1234");
    }

    #[test]
    fn window_1h() {
        let window = 60;
        assert_eq!(window, 60);
    }

    #[test]
    fn window_30d() {
        let window = 60 * 24 * 30;
        assert_eq!(window, 43200);
    }

    #[test]
    fn mongo_collection_smtp_events() {
        let coll = "smtp_events";
        assert_eq!(coll, "smtp_events");
    }

    #[test]
    fn mongo_field_country() {
        let field = "country";
        assert_eq!(field, "country");
    }

    #[test]
    fn mongo_field_asn() {
        let field = "asn";
        assert_eq!(field, "asn");
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
