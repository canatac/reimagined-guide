//! Collecteurs pour `api_admin_observability_overview`.
//! Chaque fonction est pure: elle interroge la couche storage/mongo et
//! renvoie les données brutes; l'assemblage JSON reste dans le handler.
#![allow(unused_imports, dead_code)]

use super::super::*;
use simple_smtp_server::security::audit;

/// Agrégats SMTP par statut, plus quatre compteurs typés.
pub(crate) struct SmtpStatusStats {
    pub by_status: serde_json::Map<String, serde_json::Value>,
    pub delivered: u64,
    pub bounced: u64,
    pub failed: u64,
    pub deferred: u64,
}

pub(crate) async fn collect_smtp_status_stats(
    mongo: &Arc<mongodb::Client>,
    base_filter: bson::Document,
) -> SmtpStatusStats {
    let docs = storage::aggregate(
        mongo,
        vec![
            doc! { "$match": base_filter },
            doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
        ],
    )
    .await;
    let mut out = SmtpStatusStats {
        by_status: serde_json::Map::new(),
        delivered: 0,
        bounced: 0,
        failed: 0,
        deferred: 0,
    };
    for d in &docs {
        let status = d.get_str("_id").unwrap_or("unknown").to_string();
        let count = d.get_i64("count").unwrap_or(0) as u64;
        match status.as_str() {
            "delivered" => out.delivered = count,
            "bounced" => out.bounced = count,
            "failed" => out.failed = count,
            "deferred" => out.deferred = count,
            _ => {}
        }
        out.by_status.insert(status, serde_json::json!(count));
    }
    out
}

pub(crate) struct QueueStats {
    pub depth: u64,
    pub oldest_age_seconds: Option<u64>,
}

pub(crate) async fn collect_queue_stats(mongo: &Arc<mongodb::Client>) -> QueueStats {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);
    let filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let depth = coll.count_documents(filter.clone()).await.unwrap_or(0);
    let oldest = coll
        .find_one(filter)
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten();
    let oldest_age_seconds = oldest
        .as_ref()
        .and_then(|d| d.get_datetime("created_at").ok())
        .map(|dt| (Utc::now().timestamp_millis() - dt.timestamp_millis()).max(0) as u64 / 1000);
    QueueStats { depth, oldest_age_seconds }
}

pub(crate) struct ThroughputStats {
    pub incoming: u64,
    pub outgoing: u64,
    pub smtp_4xx: u64,
    pub smtp_5xx: u64,
}

pub(crate) async fn collect_throughput_stats(
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
    ThroughputStats { incoming, outgoing, smtp_4xx, smtp_5xx }
}

pub(crate) struct AlertStats {
    pub monitoring: Vec<monitoring::alerts::ActiveAlert>,
    pub security: Vec<simple_smtp_server::security::SecurityAlert>,
    pub queue_growth: usize,
    pub auth_failure: usize,
    pub anomaly: usize,
}

pub(crate) async fn collect_alert_stats(
    mongo: &Arc<mongodb::Client>,
    window: &str,
) -> AlertStats {
    let monitoring_alerts = monitoring::alerts::evaluate_alerts(
        mongo,
        parse_window(window).num_minutes(),
        &AlertConfig::default(),
    )
    .await;
    let security_alerts = audit::query_active_alerts(mongo, 300).await;

    let queue_growth = monitoring_alerts
        .iter()
        .filter(|a| a.kind.contains("queue") || a.message.to_ascii_lowercase().contains("queue"))
        .count();
    let auth_failure = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("auth") || n.contains("brute") || n.contains("login")
        })
        .count();
    let anomaly = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("volume")
                || n.contains("spike")
                || n.contains("anormal")
                || n.contains("anomaly")
        })
        .count();
    AlertStats {
        monitoring: monitoring_alerts,
        security: security_alerts,
        queue_growth,
        auth_failure,
        anomaly,
    }
}

pub(crate) async fn collect_suspicious_logins(
    mongo: &Arc<mongodb::Client>,
    since: &str,
) -> Vec<serde_json::Value> {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("auth_events");
    let docs = match coll
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

pub(crate) async fn collect_per_domain(
    mongo: &Arc<mongodb::Client>,
    base_filter: bson::Document,
) -> Vec<serde_json::Value> {
    let docs = storage::aggregate(
        mongo,
        vec![
            doc! { "$match": base_filter },
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

pub(crate) fn rbl_env_lists() -> (Vec<String>, Vec<String>) {
    let sources = env::var("RBL_CHECK_HOSTS")
        .unwrap_or_else(|_| "zen.spamhaus.org,bl.spamcop.net".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let listed_by = env::var("RBL_LISTED_BY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    (sources, listed_by)
}
