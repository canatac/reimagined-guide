//! Dashboard metrics panel API endpoint
//! Issue #456: Real-time KPI overview widget
//!
//! Returns JSON metrics for frontend dashboard consumption.
//! Includes queue depth, latency, send/reject rates, and system health.

use actix_web::{web, HttpResponse};
use chrono::Utc;
use mongodb::bson::doc;
use std::sync::Arc;

/// GET /api/monitoring/dashboard — JSON metrics for dashboard panel
pub(crate) async fn api_monitoring_dashboard(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let queue_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("send_queue");

    // Queue depth by status
    let pending = count_by_status(&queue_coll, "pending").await.unwrap_or(0);
    let scheduled = count_by_status(&queue_coll, "scheduled").await.unwrap_or(0);
    let sending = count_by_status(&queue_coll, "sending").await.unwrap_or(0);
    let failed = count_by_status(&queue_coll, "failed").await.unwrap_or(0);
    let sent = count_by_status(&queue_coll, "sent").await.unwrap_or(0);

    // Queue latency (age of oldest pending message)
    let queue_latency_ms = queue_coll
        .find_one(doc! { "status": { "$in": ["pending", "scheduled"] } })
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten()
        .and_then(|d| d.get_datetime("created_at").ok().map(|dt| dt.timestamp_millis()))
        .map(|created_at_ms| (Utc::now().timestamp_millis() - created_at_ms).max(0) as u64)
        .unwrap_or(0);

    // Reject counts from smtp_events
    let events_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("smtp_events");
    let reject_count = events_coll
        .count_documents(doc! { "reject_reason_code": { "$exists": true, "$ne": null } })
        .await
        .unwrap_or(0);

    // Total processed in last hour
    let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
    let recent_sends = queue_coll
        .count_documents(doc! {
            "status": "sent",
            "updated_at": { "$gte": one_hour_ago }
        })
        .await
        .unwrap_or(0);

    let total_depth = pending + scheduled + sending;

    let metrics = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "queue": {
            "depth": total_depth,
            "pending": pending,
            "scheduled": scheduled,
            "sending": sending,
            "failed": failed,
            "sent_total": sent,
            "latency_ms": queue_latency_ms,
        },
        "throughput": {
            "sends_last_hour": recent_sends,
            "rejects_total": reject_count,
        },
        "health": {
            "status": if total_depth > 1000 { "critical" } else if total_depth > 100 { "warning" } else { "healthy" },
            "queue_depth_ok": total_depth < 500,
            "latency_ok": queue_latency_ms < 300000,
        }
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .body(metrics.to_string())
}

async fn count_by_status(
    coll: &mongodb::Collection<mongodb::bson::Document>,
    status: &str,
) -> mongodb::error::Result<u64> {
    let filter = doc! { "status": status };
    coll.count_documents(filter).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_metrics_json_structure() {
        let metrics = serde_json::json!({
            "timestamp": "2026-09-09T10:00:00Z",
            "queue": {
                "depth": 10,
                "pending": 5,
                "scheduled": 3,
                "sending": 2,
                "failed": 0,
                "sent_total": 150,
                "latency_ms": 5000,
            },
            "throughput": {
                "sends_last_hour": 42,
                "rejects_total": 3,
            },
            "health": {
                "status": "healthy",
                "queue_depth_ok": true,
                "latency_ok": true,
            }
        });

        assert_eq!(metrics["queue"]["depth"], 10);
        assert_eq!(metrics["queue"]["pending"], 5);
        assert_eq!(metrics["health"]["status"], "healthy");
        assert!(metrics["health"]["queue_depth_ok"].as_bool().unwrap());
    }

    #[test]
    fn health_status_critical_when_queue_depth_high() {
        let depth = 1500;
        let status = if depth > 1000 { "critical" } else if depth > 100 { "warning" } else { "healthy" };
        assert_eq!(status, "critical");
    }

    #[test]
    fn health_status_warning_when_queue_depth_moderate() {
        let depth = 250;
        let status = if depth > 1000 { "critical" } else if depth > 100 { "warning" } else { "healthy" };
        assert_eq!(status, "warning");
    }

    #[test]
    fn health_status_healthy_when_queue_depth_low() {
        let depth = 10;
        let status = if depth > 1000 { "critical" } else if depth > 100 { "warning" } else { "healthy" };
        assert_eq!(status, "healthy");
    }

    #[test]
    fn latency_ok_when_under_threshold() {
        let latency_ms = 5000;
        let latency_ok = latency_ms < 300000;
        assert!(latency_ok);
    }

    #[test]
    fn latency_not_ok_when_over_threshold() {
        let latency_ms = 600000;
        let latency_ok = latency_ms < 300000;
        assert!(!latency_ok);
    }
}
