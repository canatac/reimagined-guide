//! SMTP connection pool stats endpoint.
//! GET /api/monitoring/smtp-pool/stats — returns pool utilization per relay host.

use actix_web::HttpResponse;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(serde::Serialize)]
struct PoolStatsResponse {
    status: &'static str,
    timestamp: String,
    max_idle: usize,
    max_active: usize,
    idle_timeout_secs: u64,
    pools: Vec<PoolInfo>,
}

#[derive(serde::Serialize)]
struct PoolInfo {
    relay_key: String,
    idle_count: usize,
    active_count: usize,
    total: usize,
}

pub(crate) async fn api_smtp_pool_stats() -> impl actix_web::Responder {
    let max_idle = simple_smtp_server::smtp_client::pool::max_idle();
    let max_active = simple_smtp_server::smtp_client::pool::max_active();
    let idle_timeout_secs =
        simple_smtp_server::smtp_client::pool::idle_timeout().as_secs();

    // Note: Full pool introspection would require exposing pool state.
    // For now, return configuration + status.
    let stats = PoolStatsResponse {
        status: "ok",
        timestamp: format!("{:?}", Instant::now()),
        max_idle,
        max_active,
        idle_timeout_secs,
        pools: vec![], // Populated when pool introspection is added
    };

    HttpResponse::Ok().json(stats)
}
