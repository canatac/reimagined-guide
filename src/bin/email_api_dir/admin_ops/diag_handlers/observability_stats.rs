#![allow(unused_imports, dead_code)]
use super::super::*;

/// Résumé des compteurs SMTP par statut sur la fenêtre.
pub(crate) struct SmtpStatusStats {
    pub(crate) total: u64,
    pub(crate) delivered: u64,
    pub(crate) bounced: u64,
    pub(crate) failed: u64,
    pub(crate) deferred: u64,
    pub(crate) by_status: serde_json::Map<String, serde_json::Value>,
    pub(crate) p95: Option<u64>,
}

pub(crate) async fn collect_smtp_stats(
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

pub(crate) struct QueueStats {
    pub(crate) depth: u64,
    pub(crate) oldest_age_seconds: Option<u64>,
}

pub(crate) async fn collect_queue_stats(mongo: &Arc<mongodb::Client>) -> QueueStats {
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

pub(crate) struct ThroughputStats {
    pub(crate) incoming: u64,
    pub(crate) outgoing: u64,
    pub(crate) smtp_4xx: u64,
    pub(crate) smtp_5xx: u64,
    pub(crate) dns_issue_events: u64,
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
    let dns_issue_events = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "event_type": "dns_lookup", "status": { "$in": ["failed", "deferred"] } },
    )
    .await;
    ThroughputStats { incoming, outgoing, smtp_4xx, smtp_5xx, dns_issue_events }
}
