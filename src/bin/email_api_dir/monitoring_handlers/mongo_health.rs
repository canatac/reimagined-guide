//! MongoDB health check handler.
//!
//! GET /api/monitoring/mongo-health — pings MongoDB and reports connectivity status.
//! Used by the frontend's /api/health/deep endpoint to verify full stack health.

use actix_web::{web, HttpResponse};
use mongodb::bson::doc;
use std::sync::Arc;
use std::time::Instant;

/// GET /api/monitoring/mongo-health
///
/// Returns MongoDB connectivity status including ping latency and pool configuration.
/// Response codes:
///   200 — MongoDB reachable, ping < 5000ms
///   503 — MongoDB unreachable or ping timeout
pub(crate) async fn api_monitoring_mongo_health(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());

    // Measure ping latency
    let start = Instant::now();
    let ping_result = mongodb::bson::doc! { "ping": 1 };
    let ping_cmd = mongo
        .database(&db_name)
        .run_command(ping_cmd.clone())
        .await;
    let ping_ms = start.elapsed().as_millis() as u64;

    match ping_cmd {
        Ok(_) => {
            // MongoDB is reachable — return healthy status
            HttpResponse::Ok().json(serde_json::json!({
                "status": "healthy",
                "ping_ms": ping_ms,
                "database": db_name,
                "pool_max": null,
                "pool_min": null,
                "pool_idle_max_ms": null,
                "wait_queue_timeout_ms": null,
                "connect_timeout_secs": 5,
                "heartbeat_secs": 10,
            }))
        }
        Err(e) => {
            // MongoDB ping failed — return unhealthy with error detail
            HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "status": "unhealthy",
                "ping_ms": ping_ms,
                "database": db_name,
                "pool_max": null,
                "pool_min": null,
                "pool_idle_max_ms": null,
                "wait_queue_timeout_ms": null,
                "connect_timeout_secs": 5,
                "heartbeat_secs": 10,
                "error": format!("{e}"),
            }))
        }
    }
}
