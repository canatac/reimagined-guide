#![allow(unused_imports, dead_code)]
use super::super::*;

/// Résumé des compteurs SMTP par statut sur la fenêtre.
struct SmtpStatusStats {
    total: u64,
    delivered: u64,
    bounced: u64,
    failed: u64,
    deferred: u64,
    by_status: serde_json::Map<String, serde_json::Value>,
    p95: Option<u64>,
}

async fn collect_smtp_stats(
    mongo: &Arc<mongodb::Client>,
    since: &str,
    base_filter: &bson::Document,
) -> SmtpStatusStats {
    let total = storage::count_events(mongo, base_filter.clone()).await;
    let by_status_docs = storage::aggregate(
        mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
        ],
    )
    .await;
    let mut by_status = serde_json::Map::new();
    let (mut delivered, mut bounced, mut failed, mut deferred) = (0u64, 0u64, 0u64, 0u64);
    for doc in &by_status_docs {
        let status = doc.get_str("_id").unwrap_or("unknown").to_string();
        let count = doc.get_i64("count").unwrap_or(0) as u64;
        match status.as_str() {
            "delivered" => delivered = count,
            "bounced" => bounced = count,
            "failed" => failed = count,
            "deferred" => deferred = count,
            _ => {}
        }
        by_status.insert(status, serde_json::json!(count));
    }
    let p95 = storage::p95_total_ms(mongo, base_filter.clone(), 1000).await;
    let _ = since;
    SmtpStatusStats { total, delivered, bounced, failed, deferred, by_status, p95 }
}

struct QueueStats {
    depth: u64,
    oldest_age_seconds: Option<u64>,
}

async fn collect_queue_stats(mongo: &Arc<mongodb::Client>) -> QueueStats {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let queue_coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);
    let pending_queue_filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let depth = queue_coll
        .count_documents(pending_queue_filter.clone())
        .await
        .unwrap_or(0);
    let oldest_pending = queue_coll
        .find_one(pending_queue_filter)
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten();
    let oldest_age_seconds = oldest_pending
        .as_ref()
        .and_then(|d| d.get_datetime("created_at").ok())
        .map(|dt| (Utc::now().timestamp_millis() - dt.timestamp_millis()).max(0) as u64 / 1000);
    QueueStats { depth, oldest_age_seconds }
}

struct ThroughputStats {
    incoming: u64,
    outgoing: u64,
    smtp_4xx: u64,
    smtp_5xx: u64,
    dns_issue_events: u64,
}

async fn collect_throughput_stats(
    mongo: &Arc<mongodb::Client>,
    since: &str,
) -> ThroughputStats {
    let incoming = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "event_type": { "$in": ["accepted", "received"] } },
    )
    .await;
    let outgoing = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "status": { "$in": ["delivered", "bounced", "failed", "deferred"] } },
    )
    .await;
    let smtp_4xx = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "smtp_code": { "$gte": 400, "$lt": 500 } },
    )
    .await;
    let smtp_5xx = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "smtp_code": { "$gte": 500, "$lt": 600 } },
    )
    .await;
    let dns_issue_events = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "event_type": "dns_lookup", "status": { "$in": ["failed", "deferred"] } },
    )
    .await;
    ThroughputStats { incoming, outgoing, smtp_4xx, smtp_5xx, dns_issue_events }
}

struct AlertsSnapshot {
    monitoring: Vec<monitoring::alerts::ActiveAlert>,
    security: Vec<simple_smtp_server::security::SecurityAlert>,
    queue_growth: usize,
    auth_failures: usize,
    anomalies: usize,
}

async fn collect_alerts_snapshot(
    mongo: &Arc<mongodb::Client>,
    window: &str,
) -> AlertsSnapshot {
    use simple_smtp_server::security::audit;
    let monitoring = monitoring::alerts::evaluate_alerts(
        mongo,
        parse_window(window).num_minutes(),
        &AlertConfig::default(),
    )
    .await;
    let security = audit::query_active_alerts(mongo, 300).await;
    let queue_growth = monitoring
        .iter()
        .filter(|a| a.kind.contains("queue") || a.message.to_ascii_lowercase().contains("queue"))
        .count();
    let auth_failures = security
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("auth") || n.contains("brute") || n.contains("login")
        })
        .count();
    let anomalies = security
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("volume")
                || n.contains("spike")
                || n.contains("anormal")
                || n.contains("anomaly")
        })
        .count();
    AlertsSnapshot { monitoring, security, queue_growth, auth_failures, anomalies }
}

async fn collect_suspicious_logins(
    mongo: &Arc<mongodb::Client>,
    since: &str,
) -> Vec<serde_json::Value> {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let auth_events_coll = mongo
        .database(&db)
        .collection::<bson::Document>("auth_events");
    let docs = match auth_events_coll
        .aggregate(vec![
            doc! { "$match": { "ts": { "$gte": since }, "success": false } },
            doc! { "$group": { "_id": "$ip", "attempts": { "$sum": 1 } } },
            doc! { "$sort": { "attempts": -1 } },
            doc! { "$limit": 10 },
        ])
        .await
    {
        Ok(cursor) => cursor.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    docs.into_iter()
        .map(|d| {
            serde_json::json!({
                "ip": d.get_str("_id").unwrap_or("unknown"),
                "attempts": d.get_i64("attempts").unwrap_or(0)
            })
        })
        .collect()
}

async fn collect_per_domain(
    mongo: &Arc<mongodb::Client>,
    base_filter: &bson::Document,
) -> Vec<serde_json::Value> {
    let docs = storage::aggregate(
        mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$project": {
                "recipient_domain": { "$arrayElemAt": [ { "$split": ["$to", "@"] }, 1 ] },
                "status": "$status"
            }},
            doc! { "$group": {
                "_id": "$recipient_domain",
                "count": { "$sum": 1 },
                "delivered": { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
                "bounced": { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] }, "then": 1, "else": 0 } } }
            }},
            doc! { "$sort": { "count": -1 } },
            doc! { "$limit": 20 }
        ],
    )
    .await;
    docs.into_iter()
        .map(|d| {
            serde_json::json!({
                "domain": d.get_str("_id").unwrap_or("unknown"),
                "count": d.get_i64("count").unwrap_or(0),
                "delivered": d.get_i64("delivered").unwrap_or(0),
                "bounced": d.get_i64("bounced").unwrap_or(0)
            })
        })
        .collect()
}

fn rbl_sources() -> Vec<String> {
    env::var("RBL_CHECK_HOSTS")
        .unwrap_or_else(|_| "zen.spamhaus.org,bl.spamcop.net".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn rbl_listed_by() -> Vec<String> {
    env::var("RBL_LISTED_BY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

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
