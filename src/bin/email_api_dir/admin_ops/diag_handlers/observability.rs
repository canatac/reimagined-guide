#![allow(unused_imports, dead_code)]
use super::super::*;

use super::observability_stats::*;
use super::observability_alerts::*;

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
