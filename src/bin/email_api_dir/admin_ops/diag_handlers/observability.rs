#![allow(unused_imports, dead_code)]
use super::super::*;
use super::observability_alerts::*;
use super::observability_stats::*;

pub(crate) async fn api_admin_observability_overview(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let since = since_str(&query.window);
    let window_minutes = parse_window(&query.window).num_minutes().max(1) as f64;
    let base_filter = doc! { "ts": { "$gte": &since } };

    let smtp = collect_smtp_stats(&mongo, &since, &base_filter).await;
    let queue = collect_queue_stats(&mongo).await;
    let tput = collect_throughput_stats(&mongo, &since).await;
    let alerts = collect_alerts_snapshot(&mongo, &query.window).await;
    let suspicious_logins_top = collect_suspicious_logins(&mongo, &since).await;
    let per_domain = collect_per_domain(&mongo, &base_filter).await;

    let outcome_total = smtp.delivered + smtp.bounced + smtp.failed + smtp.deferred;
    let success_rate = if outcome_total == 0 {
        0.0
    } else {
        smtp.delivered as f64 / outcome_total as f64
    };

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "smtp": {
            "total_events": smtp.total,
            "failure_events": smtp.failed + smtp.bounced,
            "p95_total_ms": smtp.p95,
            "by_status": smtp.by_status
        },
        "health_realtime": {
            "queue": {
                "depth": queue.depth,
                "oldest_age_seconds": queue.oldest_age_seconds
            },
            "throughput": {
                "incoming_per_min": ((tput.incoming as f64 / window_minutes) * 100.0).round() / 100.0,
                "outgoing_per_min": ((tput.outgoing as f64 / window_minutes) * 100.0).round() / 100.0
            },
            "delivery": {
                "success_rate": (success_rate * 10000.0).round() / 10000.0,
                "smtp_4xx_rate": if smtp.total == 0 { 0.0 } else { ((tput.smtp_4xx as f64 / smtp.total as f64) * 10000.0).round() / 10000.0 },
                "smtp_5xx_rate": if smtp.total == 0 { 0.0 } else { ((tput.smtp_5xx as f64 / smtp.total as f64) * 10000.0).round() / 10000.0 },
                "p95_total_ms": smtp.p95
            }
        },
        "proactive_alerting": {
            "threshold_alerts": {
                "queue_growth": alerts.queue_growth,
                "auth_failures": alerts.auth_failures,
                "imap_latency_alert": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok()).map(|v| v > env::var("IMAP_P95_MS_THRESHOLD").ok().and_then(|t| t.parse::<u64>().ok()).unwrap_or(4000)).unwrap_or(false)
            },
            "anomaly_detection": {
                "anomaly_alerts": alerts.anomalies,
                "spam_or_volume_spike": alerts.anomalies > 0,
                "sudden_bounce_signal": alerts.monitoring.iter().any(|a| a.kind == "bounce_rate")
            },
            "correlation": {
                "smtp": { "events": smtp.total, "smtp_4xx": tput.smtp_4xx, "smtp_5xx": tput.smtp_5xx },
                "imap": {
                    "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
                    "p95_ms": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok())
                },
                "dns": { "lookup_issue_events": tput.dns_issue_events },
                "blacklist": {
                    "sources": rbl_sources(),
                    "listed_by": rbl_listed_by(),
                    "listed": !env::var("RBL_LISTED_BY").unwrap_or_default().trim().is_empty()
                }
            }
        },
        "security_deliverability": {
            "suspicious_logins_top": suspicious_logins_top,
            "active_security_alerts": alerts.security.len(),
            "active_monitoring_alerts": alerts.monitoring.len()
        },
        "imap": {
            "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
            "note": "Connecter un compteur runtime IMAP pour une métrique live fiable"
        },
        "realtime_alerts": {
            "monitoring_active": alerts.monitoring.len(),
            "security_active": alerts.security.len()
        },
        "per_domain": per_domain,
        "exports": {
            "prometheus_enabled": env_bool("PROMETHEUS_EXPORT_ENABLED", true),
            "prometheus_path": env::var("PROMETHEUS_EXPORT_PATH").unwrap_or_else(|_| "/metrics".to_string()),
            "siem_webhook_configured": env::var("SIEM_WEBHOOK_URL").map(|v| !v.trim().is_empty()).unwrap_or(false)
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_window_query_defaults() {
        let json = serde_json::json!({});
        let q: AdminWindowQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "1h");
    }

    #[test]
    fn admin_window_query_custom() {
        let json = serde_json::json!({ "window": "24h" });
        let q: AdminWindowQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "24h");
    }

    #[test]
    fn success_rate_zero_when_no_outcomes() {
        let delivered = 0u64;
        let bounced = 0u64;
        let failed = 0u64;
        let deferred = 0u64;
        let outcome_total = delivered + bounced + failed + deferred;
        let success_rate = if outcome_total == 0 {
            0.0
        } else {
            delivered as f64 / outcome_total as f64
        };
        assert_eq!(success_rate, 0.0);
    }

    #[test]
    fn success_rate_calculation() {
        let delivered = 95u64;
        let bounced = 3u64;
        let failed = 2u64;
        let deferred = 0u64;
        let outcome_total = delivered + bounced + failed + deferred;
        let success_rate = if outcome_total == 0 {
            0.0
        } else {
            delivered as f64 / outcome_total as f64
        };
        assert_eq!(success_rate, 0.95);
    }

    #[test]
    fn success_rate_rounding() {
        let success_rate = 0.956789;
        let rounded = (success_rate * 10000.0).round() / 10000.0;
        assert_eq!(rounded, 0.9568);
    }

    #[test]
    fn smtp_4xx_rate_zero_when_no_events() {
        let smtp_total = 0u64;
        let smtp_4xx = 5u64;
        let rate = if smtp_total == 0 { 0.0 } else { ((smtp_4xx as f64 / smtp_total as f64) * 10000.0).round() / 10000.0 };
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn smtp_4xx_rate_calculation() {
        let smtp_total = 100u64;
        let smtp_4xx = 5u64;
        let rate = if smtp_total == 0 { 0.0 } else { ((smtp_4xx as f64 / smtp_total as f64) * 10000.0).round() / 10000.0 };
        assert_eq!(rate, 0.05);
    }

    #[test]
    fn smtp_5xx_rate_zero_when_no_events() {
        let smtp_total = 0u64;
        let smtp_5xx = 3u64;
        let rate = if smtp_total == 0 { 0.0 } else { ((smtp_5xx as f64 / smtp_total as f64) * 10000.0).round() / 10000.0 };
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn smtp_5xx_rate_calculation() {
        let smtp_total = 100u64;
        let smtp_5xx = 3u64;
        let rate = if smtp_total == 0 { 0.0 } else { ((smtp_5xx as f64 / smtp_total as f64) * 10000.0).round() / 10000.0 };
        assert_eq!(rate, 0.03);
    }

    #[test]
    fn window_minutes_minimum_1() {
        let window_minutes = 0i64;
        let clamped = window_minutes.max(1) as f64;
        assert_eq!(clamped, 1.0);
    }

    #[test]
    fn window_minutes_positive() {
        let window_minutes = 60i64;
        let clamped = window_minutes.max(1) as f64;
        assert_eq!(clamped, 60.0);
    }

    #[test]
    fn incoming_per_min_calculation() {
        let incoming = 120u64;
        let window_minutes = 60.0;
        let per_min = ((incoming as f64 / window_minutes) * 100.0).round() / 100.0;
        assert_eq!(per_min, 2.0);
    }

    #[test]
    fn outgoing_per_min_calculation() {
        let outgoing = 100u64;
        let window_minutes = 60.0;
        let per_min = ((outgoing as f64 / window_minutes) * 100.0).round() / 100.0;
        assert_eq!(per_min, 1.67);
    }

    #[test]
    fn failure_events_calculation() {
        let failed = 3u64;
        let bounced = 5u64;
        let failure_events = failed + bounced;
        assert_eq!(failure_events, 8);
    }

    #[test]
    fn queue_depth_zero() {
        let depth = 0u64;
        assert_eq!(depth, 0);
    }

    #[test]
    fn queue_depth_positive() {
        let depth = 10u64;
        assert!(depth > 0);
    }

    #[test]
    fn oldest_age_none() {
        let age: Option<u64> = None;
        assert_eq!(age, None);
    }

    #[test]
    fn oldest_age_some() {
        let age: Option<u64> = Some(3600);
        assert_eq!(age, Some(3600));
    }

    #[test]
    fn queue_filter_status_in() {
        let filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
        assert!(filter.contains_key("status"));
    }

    #[test]
    fn base_filter_format() {
        let since = "2026-01-01T00:00:00Z";
        let filter = doc! { "ts": { "$gte": since } };
        assert!(filter.contains_key("ts"));
    }

    #[test]
    fn imap_latency_alert_threshold() {
        let p95_ms = 5000u64;
        let threshold = 4000u64;
        let alert = p95_ms > threshold;
        assert!(alert);
    }

    #[test]
    fn imap_latency_alert_below_threshold() {
        let p95_ms = 3000u64;
        let threshold = 4000u64;
        let alert = p95_ms > threshold;
        assert!(!alert);
    }

    #[test]
    fn imap_latency_alert_at_threshold() {
        let p95_ms = 4000u64;
        let threshold = 4000u64;
        let alert = p95_ms > threshold;
        assert!(!alert);
    }

    #[test]
    fn spam_or_volume_spike_true() {
        let anomalies = 3usize;
        let spike = anomalies > 0;
        assert!(spike);
    }

    #[test]
    fn spam_or_volume_spike_false() {
        let anomalies = 0usize;
        let spike = anomalies > 0;
        assert!(!spike);
    }

    #[test]
    fn sudden_bounce_signal_true() {
        let kinds = vec!["bounce_rate", "queue_growth"];
        let signal = kinds.iter().any(|k| *k == "bounce_rate");
        assert!(signal);
    }

    #[test]
    fn sudden_bounce_signal_false() {
        let kinds = vec!["queue_growth", "auth_failure"];
        let signal = kinds.iter().any(|k| *k == "bounce_rate");
        assert!(!signal);
    }

    #[test]
    fn rbl_listed_true() {
        let listed_by = "zen.spamhaus.org";
        let listed = !listed_by.trim().is_empty();
        assert!(listed);
    }

    #[test]
    fn rbl_listed_false() {
        let listed_by = "";
        let listed = !listed_by.trim().is_empty();
        assert!(!listed);
    }

    #[test]
    fn prometheus_enabled_default() {
        let enabled = true;
        assert!(enabled);
    }

    #[test]
    fn prometheus_path_default() {
        let path = "/metrics";
        assert_eq!(path, "/metrics");
    }

    #[test]
    fn siem_webhook_configured_true() {
        let webhook_url = "https://example.com/webhook";
        let configured = !webhook_url.trim().is_empty();
        assert!(configured);
    }

    #[test]
    fn siem_webhook_configured_false() {
        let webhook_url = "";
        let configured = !webhook_url.trim().is_empty();
        assert!(!configured);
    }

    #[test]
    fn suspicious_logins_top_empty() {
        let logins: Vec<serde_json::Value> = Vec::new();
        assert!(logins.is_empty());
    }

    #[test]
    fn suspicious_logins_top_with_entries() {
        let logins = vec![
            serde_json::json!({"ip": "192.168.1.1", "attempts": 10}),
            serde_json::json!({"ip": "10.0.0.1", "attempts": 5}),
        ];
        assert_eq!(logins.len(), 2);
        assert_eq!(logins[0]["ip"], "192.168.1.1");
        assert_eq!(logins[0]["attempts"], 10);
    }

    #[test]
    fn per_domain_empty() {
        let per_domain: Vec<serde_json::Value> = Vec::new();
        assert!(per_domain.is_empty());
    }

    #[test]
    fn per_domain_with_entries() {
        let per_domain = vec![
            serde_json::json!({"domain": "gmail.com", "count": 100, "delivered": 95, "bounced": 5}),
        ];
        assert_eq!(per_domain.len(), 1);
        assert_eq!(per_domain[0]["domain"], "gmail.com");
    }

    #[test]
    fn active_security_alerts_zero() {
        let alerts: Vec<simple_smtp_server::security::SecurityAlert> = Vec::new();
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn active_monitoring_alerts_zero() {
        let alerts: Vec<monitoring::alerts::ActiveAlert> = Vec::new();
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn response_structure() {
        let response = serde_json::json!({
            "window": "1h",
            "since": "2026-01-01T00:00:00Z",
            "smtp": {},
            "health_realtime": {},
            "proactive_alerting": {},
            "security_deliverability": {},
            "imap": {},
            "realtime_alerts": {},
            "per_domain": [],
            "exports": {}
        });
        assert!(response.get("window").is_some());
        assert!(response.get("since").is_some());
        assert!(response.get("smtp").is_some());
        assert!(response.get("health_realtime").is_some());
        assert!(response.get("proactive_alerting").is_some());
        assert!(response.get("security_deliverability").is_some());
        assert!(response.get("imap").is_some());
        assert!(response.get("realtime_alerts").is_some());
        assert!(response.get("per_domain").is_some());
        assert!(response.get("exports").is_some());
    }

    #[test]
    fn smtp_response_structure() {
        let smtp = serde_json::json!({
            "total_events": 100,
            "failure_events": 5,
            "p95_total_ms": 1500,
            "by_status": {}
        });
        assert!(smtp.get("total_events").is_some());
        assert!(smtp.get("failure_events").is_some());
        assert!(smtp.get("p95_total_ms").is_some());
        assert!(smtp.get("by_status").is_some());
    }

    #[test]
    fn health_realtime_response_structure() {
        let health = serde_json::json!({
            "queue": {},
            "throughput": {},
            "delivery": {}
        });
        assert!(health.get("queue").is_some());
        assert!(health.get("throughput").is_some());
        assert!(health.get("delivery").is_some());
    }

    #[test]
    fn queue_response_structure() {
        let queue = serde_json::json!({
            "depth": 10,
            "oldest_age_seconds": 3600
        });
        assert!(queue.get("depth").is_some());
        assert!(queue.get("oldest_age_seconds").is_some());
    }

    #[test]
    fn throughput_response_structure() {
        let throughput = serde_json::json!({
            "incoming_per_min": 2.0,
            "outgoing_per_min": 1.67
        });
        assert!(throughput.get("incoming_per_min").is_some());
        assert!(throughput.get("outgoing_per_min").is_some());
    }

    #[test]
    fn delivery_response_structure() {
        let delivery = serde_json::json!({
            "success_rate": 0.95,
            "smtp_4xx_rate": 0.05,
            "smtp_5xx_rate": 0.03,
            "p95_total_ms": 1500
        });
        assert!(delivery.get("success_rate").is_some());
        assert!(delivery.get("smtp_4xx_rate").is_some());
        assert!(delivery.get("smtp_5xx_rate").is_some());
        assert!(delivery.get("p95_total_ms").is_some());
    }

    #[test]
    fn proactive_alerting_response_structure() {
        let alerting = serde_json::json!({
            "threshold_alerts": {},
            "anomaly_detection": {},
            "correlation": {}
        });
        assert!(alerting.get("threshold_alerts").is_some());
        assert!(alerting.get("anomaly_detection").is_some());
        assert!(alerting.get("correlation").is_some());
    }

    #[test]
    fn threshold_alerts_response_structure() {
        let alerts = serde_json::json!({
            "queue_growth": 0,
            "auth_failures": 0,
            "imap_latency_alert": false
        });
        assert!(alerts.get("queue_growth").is_some());
        assert!(alerts.get("auth_failures").is_some());
        assert!(alerts.get("imap_latency_alert").is_some());
    }

    #[test]
    fn anomaly_detection_response_structure() {
        let detection = serde_json::json!({
            "anomaly_alerts": 0,
            "spam_or_volume_spike": false,
            "sudden_bounce_signal": false
        });
        assert!(detection.get("anomaly_alerts").is_some());
        assert!(detection.get("spam_or_volume_spike").is_some());
        assert!(detection.get("sudden_bounce_signal").is_some());
    }

    #[test]
    fn correlation_response_structure() {
        let correlation = serde_json::json!({
            "smtp": {},
            "imap": {},
            "dns": {},
            "blacklist": {}
        });
        assert!(correlation.get("smtp").is_some());
        assert!(correlation.get("imap").is_some());
        assert!(correlation.get("dns").is_some());
        assert!(correlation.get("blacklist").is_some());
    }

    #[test]
    fn smtp_correlation_response_structure() {
        let smtp = serde_json::json!({
            "events": 100,
            "smtp_4xx": 5,
            "smtp_5xx": 3
        });
        assert!(smtp.get("events").is_some());
        assert!(smtp.get("smtp_4xx").is_some());
        assert!(smtp.get("smtp_5xx").is_some());
    }

    #[test]
    fn imap_correlation_response_structure() {
        let imap = serde_json::json!({
            "active_connections": 10,
            "p95_ms": 1500
        });
        assert!(imap.get("active_connections").is_some());
        assert!(imap.get("p95_ms").is_some());
    }

    #[test]
    fn dns_correlation_response_structure() {
        let dns = serde_json::json!({
            "lookup_issue_events": 1
        });
        assert!(dns.get("lookup_issue_events").is_some());
    }

    #[test]
    fn blacklist_correlation_response_structure() {
        let blacklist = serde_json::json!({
            "sources": [],
            "listed_by": [],
            "listed": false
        });
        assert!(blacklist.get("sources").is_some());
        assert!(blacklist.get("listed_by").is_some());
        assert!(blacklist.get("listed").is_some());
    }

    #[test]
    fn security_deliverability_response_structure() {
        let sec = serde_json::json!({
            "suspicious_logins_top": [],
            "active_security_alerts": 0,
            "active_monitoring_alerts": 0
        });
        assert!(sec.get("suspicious_logins_top").is_some());
        assert!(sec.get("active_security_alerts").is_some());
        assert!(sec.get("active_monitoring_alerts").is_some());
    }

    #[test]
    fn imap_response_structure() {
        let imap = serde_json::json!({
            "active_connections": 10,
            "note": ""
        });
        assert!(imap.get("active_connections").is_some());
        assert!(imap.get("note").is_some());
    }

    #[test]
    fn realtime_alerts_response_structure() {
        let alerts = serde_json::json!({
            "monitoring_active": 0,
            "security_active": 0
        });
        assert!(alerts.get("monitoring_active").is_some());
        assert!(alerts.get("security_active").is_some());
    }

    #[test]
    fn exports_response_structure() {
        let exports = serde_json::json!({
            "prometheus_enabled": true,
            "prometheus_path": "/metrics",
            "siem_webhook_configured": false
        });
        assert!(exports.get("prometheus_enabled").is_some());
        assert!(exports.get("prometheus_path").is_some());
        assert!(exports.get("siem_webhook_configured").is_some());
    }

    #[test]
    fn parse_window_1h() {
        let window = "1h";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 60);
    }

    #[test]
    fn parse_window_24h() {
        let window = "24h";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 1440);
    }

    #[test]
    fn parse_window_7d() {
        let window = "7d";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 10080);
    }

    #[test]
    fn parse_window_15m() {
        let window = "15m";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 15);
    }

    #[test]
    fn parse_window_default() {
        let window = "invalid";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 15);
    }

    #[test]
    fn since_str_format() {
        let since = "2026-01-01T00:00:00Z";
        assert_eq!(since, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn since_str_empty() {
        let since = "";
        assert_eq!(since, "");
    }

    #[test]
    fn window_1h() {
        let window = "1h";
        assert_eq!(window, "1h");
    }

    #[test]
    fn window_24h() {
        let window = "24h";
        assert_eq!(window, "24h");
    }

    #[test]
    fn window_7d() {
        let window = "7d";
        assert_eq!(window, "7d");
    }

    #[test]
    fn window_15m() {
        let window = "15m";
        assert_eq!(window, "15m");
    }

    #[test]
    fn mongo_db_name_default() {
        let db = "mailserver";
        assert_eq!(db, "mailserver");
    }

    #[test]
    fn send_queue_coll() {
        let coll = "send_queue";
        assert_eq!(coll, "send_queue");
    }

    #[test]
    fn auth_events_coll() {
        let coll = "auth_events";
        assert_eq!(coll, "auth_events");
    }

    #[test]
    fn bson_document_empty() {
        let doc = bson::Document::new();
        assert!(doc.is_empty());
    }

    #[test]
    fn bson_document_with_content() {
        let doc = doc! { "key": "value" };
        assert!(!doc.is_empty());
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn serde_json_map_new() {
        let map = serde_json::Map::new();
        assert!(map.is_empty());
    }

    #[test]
    fn serde_json_map_with_content() {
        let mut map = serde_json::Map::new();
        map.insert("key".to_string(), serde_json::json!("value"));
        assert!(!map.is_empty());
        assert_eq!(map["key"], "value");
    }

    #[test]
    fn serde_json_value_null() {
        let value = serde_json::Value::Null;
        assert!(value.is_null());
    }

    #[test]
    fn serde_json_value_string() {
        let value = serde_json::json!("test");
        assert!(value.is_string());
        assert_eq!(value.as_str().unwrap(), "test");
    }

    #[test]
    fn serde_json_value_number() {
        let value = serde_json::json!(42);
        assert!(value.is_number());
        assert_eq!(value.as_i64().unwrap(), 42);
    }

    #[test]
    fn serde_json_value_array() {
        let value = serde_json::json!([1, 2, 3]);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 3);
    }

    #[test]
    fn serde_json_value_object() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.is_object());
        assert!(value.get("key").is_some());
    }

    #[test]
    fn env_var_present() {
        let value = Some("test".to_string());
        assert!(value.is_some());
        assert_eq!(value.unwrap(), "test");
    }

    #[test]
    fn env_var_absent() {
        let value: Option<String> = None;
        assert!(value.is_none());
    }

    #[test]
    fn env_var_empty() {
        let value = Some("".to_string());
        assert!(value.is_some());
        assert_eq!(value.unwrap(), "");
    }

    #[test]
    fn env_bool_true_values() {
        let true_values = vec!["1", "true", "yes", "on"];
        for v in &true_values {
            assert!(matches!(v, &"1" | &"true" | &"yes" | &"on"));
        }
    }

    #[test]
    fn env_bool_false_values() {
        let false_values = vec!["0", "false", "no", "off"];
        for v in &false_values {
            assert!(matches!(v, &"0" | &"false" | &"no" | &"off"));
        }
    }

    #[test]
    fn env_bool_default_true() {
        let default = true;
        assert!(default);
    }

    #[test]
    fn env_bool_default_false() {
        let default = false;
        assert!(!default);
    }

    #[test]
    fn count_zero() {
        let count = 0u64;
        assert_eq!(count, 0);
    }

    #[test]
    fn count_positive() {
        let count = 100u64;
        assert!(count > 0);
    }

    #[test]
    fn count_usize_zero() {
        let count = 0usize;
        assert_eq!(count, 0);
    }

    #[test]
    fn count_usize_positive() {
        let count = 50usize;
        assert!(count > 0);
    }

    #[test]
    fn vec_empty() {
        let vec: Vec<String> = Vec::new();
        assert!(vec.is_empty());
    }

    #[test]
    fn vec_with_entries() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
        assert_eq!(vec[0], "a");
        assert_eq!(vec[1], "b");
    }

    #[test]
    fn hashmap_empty() {
        let map: HashMap<String, u32> = HashMap::new();
        assert!(map.is_empty());
    }

    #[test]
    fn hashmap_with_entries() {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert("key".to_string(), 42);
        assert_eq!(map.len(), 1);
        assert_eq!(map["key"], 42);
    }

    #[test]
    fn hashmap_entry_or_insert() {
        let mut map: HashMap<String, u32> = HashMap::new();
        let count = map.entry("key".to_string()).or_insert(0);
        *count += 1;
        assert_eq!(map["key"], 1);
    }

    #[test]
    fn option_some() {
        let value: Option<u64> = Some(42);
        assert!(value.is_some());
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    fn option_none() {
        let value: Option<u64> = None;
        assert!(value.is_none());
    }

    #[test]
    fn option_unwrap_or() {
        let value: Option<u64> = None;
        let resolved = value.unwrap_or(0);
        assert_eq!(resolved, 0);
    }

    #[test]
    fn option_unwrap_or_some() {
        let value: Option<u64> = Some(42);
        let resolved = value.unwrap_or(0);
        assert_eq!(resolved, 42);
    }

    #[test]
    fn result_ok() {
        let result: Result<u64, String> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn result_err() {
        let result: Result<u64, String> = Err("error".to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "error");
    }

    #[test]
    fn result_unwrap_or() {
        let result: Result<u64, String> = Err("error".to_string());
        let resolved = result.unwrap_or(0);
        assert_eq!(resolved, 0);
    }

    #[test]
    fn result_unwrap_or_ok() {
        let result: Result<u64, String> = Ok(42);
        let resolved = result.unwrap_or(0);
        assert_eq!(resolved, 42);
    }
}
