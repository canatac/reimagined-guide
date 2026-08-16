#![allow(unused_imports, dead_code)]
use super::super::*;
pub(crate) async fn api_admin_observability_overview(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let since = since_str(&query.window);
    let window_minutes = parse_window(&query.window).num_minutes().max(1) as f64;
    let base_filter = doc! { "ts": { "$gte": &since } };

    let total = storage::count_events(&mongo, base_filter.clone()).await;
    let by_status_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
        ],
    )
    .await;

    let mut by_status = serde_json::Map::new();
    let mut delivered = 0u64;
    let mut bounced = 0u64;
    let mut failed = 0u64;
    let mut deferred = 0u64;

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

    let p95 = storage::p95_total_ms(&mongo, base_filter.clone(), 1000).await;

    let outcome_total = delivered + bounced + failed + deferred;
    let success_rate = if outcome_total == 0 {
        0.0
    } else {
        delivered as f64 / outcome_total as f64
    };

    // SMTP queue depth + oldest age
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let queue_coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);
    let pending_queue_filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let queue_depth = queue_coll
        .count_documents(pending_queue_filter.clone())
        .await
        .unwrap_or(0);

    let oldest_pending = queue_coll
        .find_one(pending_queue_filter.clone())
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten();
    let queue_oldest_age_seconds = oldest_pending
        .as_ref()
        .and_then(|d| d.get_datetime("created_at").ok())
        .map(|dt| (Utc::now().timestamp_millis() - dt.timestamp_millis()).max(0) as u64 / 1000);

    // Throughput and SMTP response classes
    let incoming_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "event_type": { "$in": ["accepted", "received"] } },
    )
    .await;
    let outgoing_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "status": { "$in": ["delivered", "bounced", "failed", "deferred"] } },
    )
    .await;

    let smtp_4xx = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "smtp_code": { "$gte": 400, "$lt": 500 } },
    )
    .await;
    let smtp_5xx = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "smtp_code": { "$gte": 500, "$lt": 600 } },
    )
    .await;

    let monitoring_alerts = monitoring::alerts::evaluate_alerts(
        &mongo,
        parse_window(&query.window).num_minutes(),
        &AlertConfig::default(),
    )
    .await;
    let security_alerts = audit::query_active_alerts(&mongo, 300).await;

    let queue_growth_alerts = monitoring_alerts
        .iter()
        .filter(|a| a.kind.contains("queue") || a.message.to_ascii_lowercase().contains("queue"))
        .count();
    let auth_failure_alerts = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("auth") || n.contains("brute") || n.contains("login")
        })
        .count();
    let anomaly_alerts = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("volume")
                || n.contains("spike")
                || n.contains("anormal")
                || n.contains("anomaly")
        })
        .count();

    let dns_issue_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "event_type": "dns_lookup", "status": { "$in": ["failed", "deferred"] } },
    )
    .await;

    let rbl_sources = env::var("RBL_CHECK_HOSTS")
        .unwrap_or_else(|_| "zen.spamhaus.org,bl.spamcop.net".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let rbl_listed_by = env::var("RBL_LISTED_BY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let auth_events_coll = mongo
        .database(&db)
        .collection::<bson::Document>("auth_events");
    let suspicious_login_docs = match auth_events_coll
        .aggregate(vec![
            doc! { "$match": { "ts": { "$gte": &since }, "success": false } },
            doc! { "$group": { "_id": "$ip", "attempts": { "$sum": 1 } } },
            doc! { "$sort": { "attempts": -1 } },
            doc! { "$limit": 10 },
        ])
        .await
    {
        Ok(cursor) => cursor.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let suspicious_logins_top = suspicious_login_docs
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "ip": d.get_str("_id").unwrap_or("unknown"),
                "attempts": d.get_i64("attempts").unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();

    let by_domain_docs = storage::aggregate(
        &mongo,
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

    let per_domain = by_domain_docs
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "domain": d.get_str("_id").unwrap_or("unknown"),
                "count": d.get_i64("count").unwrap_or(0),
                "delivered": d.get_i64("delivered").unwrap_or(0),
                "bounced": d.get_i64("bounced").unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "smtp": {
            "total_events": total,
            "failure_events": failed + bounced,
            "p95_total_ms": p95,
            "by_status": by_status
        },
        "health_realtime": {
            "queue": {
                "depth": queue_depth,
                "oldest_age_seconds": queue_oldest_age_seconds
            },
            "throughput": {
                "incoming_per_min": ((incoming_events as f64 / window_minutes) * 100.0).round() / 100.0,
                "outgoing_per_min": ((outgoing_events as f64 / window_minutes) * 100.0).round() / 100.0
            },
            "delivery": {
                "success_rate": (success_rate * 10000.0).round() / 10000.0,
                "smtp_4xx_rate": if total == 0 { 0.0 } else { ((smtp_4xx as f64 / total as f64) * 10000.0).round() / 10000.0 },
                "smtp_5xx_rate": if total == 0 { 0.0 } else { ((smtp_5xx as f64 / total as f64) * 10000.0).round() / 10000.0 },
                "p95_total_ms": p95
            }
        },
        "proactive_alerting": {
            "threshold_alerts": {
                "queue_growth": queue_growth_alerts,
                "auth_failures": auth_failure_alerts,
                "imap_latency_alert": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok()).map(|v| v > env::var("IMAP_P95_MS_THRESHOLD").ok().and_then(|t| t.parse::<u64>().ok()).unwrap_or(4000)).unwrap_or(false)
            },
            "anomaly_detection": {
                "anomaly_alerts": anomaly_alerts,
                "spam_or_volume_spike": anomaly_alerts > 0,
                "sudden_bounce_signal": monitoring_alerts.iter().any(|a| a.kind == "bounce_rate")
            },
            "correlation": {
                "smtp": { "events": total, "smtp_4xx": smtp_4xx, "smtp_5xx": smtp_5xx },
                "imap": {
                    "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
                    "p95_ms": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok())
                },
                "dns": { "lookup_issue_events": dns_issue_events },
                "blacklist": {
                    "sources": rbl_sources,
                    "listed_by": rbl_listed_by,
                    "listed": !env::var("RBL_LISTED_BY").unwrap_or_default().trim().is_empty()
                }
            }
        },
        "security_deliverability": {
            "suspicious_logins_top": suspicious_logins_top,
            "active_security_alerts": security_alerts.len(),
            "active_monitoring_alerts": monitoring_alerts.len()
        },
        "imap": {
            "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
            "note": "Connecter un compteur runtime IMAP pour une métrique live fiable"
        },
        "realtime_alerts": {
            "monitoring_active": monitoring_alerts.len(),
            "security_active": security_alerts.len()
        },
        "per_domain": per_domain,
        "exports": {
            "prometheus_enabled": env_bool("PROMETHEUS_EXPORT_ENABLED", true),
            "prometheus_path": env::var("PROMETHEUS_EXPORT_PATH").unwrap_or_else(|_| "/metrics".to_string()),
            "siem_webhook_configured": env::var("SIEM_WEBHOOK_URL").map(|v| !v.trim().is_empty()).unwrap_or(false)
        }
    }))
}
