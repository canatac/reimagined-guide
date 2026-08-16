#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) struct AlertsSnapshot {
    pub(crate) monitoring: Vec<monitoring::alerts::ActiveAlert>,
    pub(crate) security: Vec<simple_smtp_server::security::SecurityAlert>,
    pub(crate) queue_growth: usize,
    pub(crate) auth_failures: usize,
    pub(crate) anomalies: usize,
}

pub(crate) async fn collect_alerts_snapshot(
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

pub(crate) async fn collect_suspicious_logins(
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

pub(crate) async fn collect_per_domain(
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

pub(crate) fn rbl_sources() -> Vec<String> {
    env::var("RBL_CHECK_HOSTS")
        .unwrap_or_else(|_| "zen.spamhaus.org,bl.spamcop.net".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub(crate) fn rbl_listed_by() -> Vec<String> {
    env::var("RBL_LISTED_BY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
