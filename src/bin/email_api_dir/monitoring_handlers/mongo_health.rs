//! MongoDB health check endpoint.
//! GET /api/monitoring/mongo-health — returns pool stats and connectivity status.

use actix_web::{web, HttpResponse};
use mongodb::bson::doc;
use std::sync::Arc;
use std::time::Instant;

#[derive(serde::Serialize)]
struct MongoHealthResponse {
    status: &'static str,
    ping_ms: u64,
    pool_max: Option<u32>,
    pool_min: Option<u32>,
    pool_idle_max_ms: Option<u64>,
    wait_queue_timeout_ms: Option<u64>,
    connect_timeout_secs: Option<u64>,
    heartbeat_secs: Option<u64>,
    database: String,
}

pub(crate) async fn api_monitoring_mongo_health(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let start = Instant::now();
    let ping_result = mongo
        .database("admin")
        .run_command(doc! {"ping": 1})
        .await;
    let ping_ms = start.elapsed().as_millis() as u64;

    let status = if ping_result.is_ok() { "healthy" } else { "unhealthy" };

    // Read pool config from env (same defaults as build_mongo_options)
    let pool_max = std::env::var("MONGODB_MAX_POOL_SIZE").ok().and_then(|s| s.parse::<u32>().ok());
    let pool_min = std::env::var("MONGODB_MIN_POOL_SIZE").ok().and_then(|s| s.parse::<u32>().ok());
    let pool_idle_max_ms = std::env::var("MONGODB_MAX_IDLE_TIME_MS").ok().and_then(|s| s.parse::<u64>().ok());
    let wait_queue_timeout_ms = std::env::var("MONGODB_WAIT_QUEUE_TIMEOUT_MS").ok().and_then(|s| s.parse::<u64>().ok());
    let connect_timeout_secs = Some(10u64);
    let heartbeat_secs = Some(10u64);

    let response = MongoHealthResponse {
        status,
        ping_ms,
        pool_max,
        pool_min,
        pool_idle_max_ms,
        wait_queue_timeout_ms,
        connect_timeout_secs,
        heartbeat_secs,
        database: db_name,
    };

    if ping_result.is_ok() {
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::ServiceUnavailable().json(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mongo_health_response_shape() {
        let resp = MongoHealthResponse {
            status: "healthy",
            ping_ms: 5,
            pool_max: Some(50),
            pool_min: Some(10),
            pool_idle_max_ms: Some(60000),
            wait_queue_timeout_ms: Some(5000),
            connect_timeout_secs: Some(10),
            heartbeat_secs: Some(10),
            database: "mailserver".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["pool_max"], 50);
        assert_eq!(json["pool_min"], 10);
        assert_eq!(json["database"], "mailserver");
    }
}
