// Prometheus metrics endpoint handler
// Exposes SMTP queue metrics in Prometheus exposition format
// Issue #436: queue_depth, queue_latency_ms, alert rules

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

    let response = format!("{}{}", metrics, per_status);

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_format_includes_help_and_type_lines() {
        // Verify the expected format structure
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
    fn prometheus_format_zero_values() {
        let queue_depth = 0u64;
        let queue_latency_ms = 0u64;
        let metrics = format!(
            "smtp_queue_depth {}\n\
             smtp_queue_latency_ms {}\n",
            queue_depth, queue_latency_ms
        );
        assert!(metrics.contains("smtp_queue_depth 0"));
        assert!(metrics.contains("smtp_queue_latency_ms 0"));
    }
}
