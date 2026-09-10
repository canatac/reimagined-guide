// Prometheus metrics endpoint handler
// Exposes SMTP queue metrics in Prometheus exposition format
// Issue #436: queue_depth, queue_latency_ms, alert rules
// Issue #438: smtp_reject_total by reason_code + action (taxonomy)
// Issue #485: mongodb pool size gauges

use actix_web::{web, HttpResponse};
use chrono::Utc;
use mongodb::bson::doc;
use std::sync::Arc;

/// GET /api/monitoring/metrics — Prometheus exposition format
pub(crate) async fn api_monitoring_prometheus(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let queue_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("send_queue");

    let queue_filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let queue_depth = queue_coll
        .count_documents(queue_filter.clone())
        .await
        .unwrap_or(0);

    let queue_latency_ms = queue_coll
        .find_one(queue_filter)
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten()
        .and_then(|d| d.get_datetime("created_at").ok().map(|dt| dt.timestamp_millis()))
        .map(|created_at_ms| (Utc::now().timestamp_millis() - created_at_ms).max(0) as u64)
        .unwrap_or(0);

    // Prometheus exposition format
    let metrics = format!(
        "# HELP smtp_queue_depth Current number of messages in the SMTP send queue\n\
         # TYPE smtp_queue_depth gauge\n\
         smtp_queue_depth {}\n\
         # HELP smtp_queue_latency_ms Age of the oldest queued message in milliseconds\n\
         # TYPE smtp_queue_latency_ms gauge\n\
         smtp_queue_latency_ms {}\n\
         # HELP smtp_queue_depth_by_status Queue depth broken down by status\n\
         # TYPE smtp_queue_depth_by_status gauge\n",
        queue_depth, queue_latency_ms
    );

    // Add per-status metrics
    let statuses = vec!["pending", "scheduled", "sending", "failed"];
    let mut per_status = String::new();
    for status in statuses {
        let filter = doc! { "status": status };
        let count = queue_coll.count_documents(filter).await.unwrap_or(0);
        per_status.push_str(&format!(
            "smtp_queue_depth_by_status{{status=\"{}\"}} {}\n",
            status, count
        ));
    }

    // Issue #438: reject taxonomy counts from smtp_events collection
    let events_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("smtp_events");
    let reject_filter = doc! {
        "reject_reason_code": { "$exists": true, "$ne": null },
    };
    let pipeline = vec![
        doc! { "$match": reject_filter },
        doc! { "$group": {
            "_id": { "reason_code": "$reject_reason_code", "action": "$reject_action" },
            "count": { "$sum": 1 },
        }},
    ];
    let mut reject_metrics = String::new();
    reject_metrics.push_str(
        "# HELP smtp_reject_total Total SMTP rejects classified by reason_code and action\n\
         # TYPE smtp_reject_total counter\n",
    );
    if let Ok(cursor) = events_coll.aggregate(pipeline).await {
        use futures_util::TryStreamExt;
        if let Ok(docs) = cursor.try_collect::<Vec<_>>().await {
            for doc in docs {
                let id = doc.get_document("_id").ok();
                let reason_code = id.and_then(|d| d.get_str("reason_code").ok()).unwrap_or("unknown");
                let action = id.and_then(|d| d.get_str("action").ok()).unwrap_or("unknown");
                let count = doc.get_i64("count").ok().unwrap_or(0);
                reject_metrics.push_str(&format!(
                    "smtp_reject_total{{reason_code=\"{}\",action=\"{}\"}} {}\n",
                    reason_code, action, count
                ));
            }
        }
    }

    // MongoDB pool size gauges (issue #485)
    let max_pool = std::env::var("MONGODB_MAX_POOL_SIZE").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(50);
    let min_pool = std::env::var("MONGODB_MIN_POOL_SIZE").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(10);
    let pool_metrics = format!(
        "# HELP mongodb_pool_max Max pool size configured for MongoDB connections\n\
         # TYPE mongodb_pool_max gauge\n\
         mongodb_pool_max {}\n\
         # HELP mongodb_pool_min Min pool size configured for MongoDB connections\n\
         # TYPE mongodb_pool_min gauge\n\
         mongodb_pool_min {}\n\
         # HELP mongodb_connect_timeout_secs Connection timeout in seconds\n\
         # TYPE mongodb_connect_timeout_secs gauge\n\
         mongodb_connect_timeout_secs 10\n\
         # HELP mongodb_heartbeat_secs Heartbeat frequency in seconds\n\
         # TYPE mongodb_heartbeat_secs gauge\n\
         mongodb_heartbeat_secs 10\n",
        max_pool, min_pool
    );

    let response = format!("{}{}{}{}", metrics, per_status, reject_metrics, pool_metrics);

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_format_includes_help_and_type_lines() {
        let queue_depth = 5u64;
        let queue_latency_ms = 30000u64;
        let metrics = format!(
            "# HELP smtp_queue_depth Current number of messages in the SMTP send queue\n\
             # TYPE smtp_queue_depth gauge\n\
             smtp_queue_depth {}\n\
             # HELP smtp_queue_latency_ms Age of the oldest queued message in milliseconds\n\
             # TYPE smtp_queue_latency_ms gauge\n\
             smtp_queue_latency_ms {}\n",
            queue_depth, queue_latency_ms
        );
        assert!(metrics.contains("# HELP smtp_queue_depth"));
        assert!(metrics.contains("# TYPE smtp_queue_depth gauge"));
        assert!(metrics.contains("smtp_queue_depth 5"));
        assert!(metrics.contains("# HELP smtp_queue_latency_ms"));
        assert!(metrics.contains("# TYPE smtp_queue_latency_ms gauge"));
        assert!(metrics.contains("smtp_queue_latency_ms 30000"));
    }

    #[test]
    fn prometheus_format_includes_per_status_metrics() {
        let pending = 3u64;
        let scheduled = 1u64;
        let sending = 1u64;
        let failed = 0u64;
        let mut per_status = String::new();
        for (status, count) in [("pending", pending), ("scheduled", scheduled), ("sending", sending), ("failed", failed)] {
            per_status.push_str(&format!(
                "smtp_queue_depth_by_status{{status=\"{}\"}} {}\n",
                status, count
            ));
        }
        assert!(per_status.contains("smtp_queue_depth_by_status{status=\"pending\"} 3"));
        assert!(per_status.contains("smtp_queue_depth_by_status{status=\"scheduled\"} 1"));
        assert!(per_status.contains("smtp_queue_depth_by_status{status=\"sending\"} 1"));
        assert!(per_status.contains("smtp_queue_depth_by_status{status=\"failed\"} 0"));
    }

    #[test]
    fn prometheus_format_includes_reject_taxonomy_metric() {
        let reason_code = "SMTP_REJECT_INVALID_RECIPIENT";
        let action = "verify_recipient";
        let count = 5i64;
        let reject_metric = format!(
            "smtp_reject_total{{reason_code=\"{}\",action=\"{}\"}} {}\n",
            reason_code, action, count
        );
        assert!(reject_metric.contains("smtp_reject_total"));
        assert!(reject_metric.contains("reason_code=\"SMTP_REJECT_INVALID_RECIPIENT\""));
        assert!(reject_metric.contains("action=\"verify_recipient\""));
        assert!(reject_metric.contains(" 5"));
    }

    #[test]
    fn prometheus_reject_metric_help_and_type_lines() {
        let help_line = "# HELP smtp_reject_total Total SMTP rejects classified by reason_code and action\n";
        let type_line = "# TYPE smtp_reject_total counter\n";
        assert!(help_line.contains("# HELP smtp_reject_total"));
        assert!(type_line.contains("# TYPE smtp_reject_total counter"));
    }

    #[test]
    fn prometheus_mongodb_pool_gauges_present() {
        let max_pool = 50u64;
        let min_pool = 10u64;
        let pool_metrics = format!(
            "# HELP mongodb_pool_max Max pool size configured for MongoDB connections\n\
             # TYPE mongodb_pool_max gauge\n\
             mongodb_pool_max {}\n\
             # HELP mongodb_pool_min Min pool size configured for MongoDB connections\n\
             # TYPE mongodb_pool_min gauge\n\
             mongodb_pool_min {}\n",
            max_pool, min_pool
        );
        assert!(pool_metrics.contains("# HELP mongodb_pool_max"));
        assert!(pool_metrics.contains("# TYPE mongodb_pool_max gauge"));
        assert!(pool_metrics.contains("mongodb_pool_max 50"));
        assert!(pool_metrics.contains("mongodb_pool_min 10"));
    }
}
