//! DMARC aggregate report routes
//! Issue #482: DMARC aggregate report parsing

use actix_web::{web, HttpResponse, Responder};

use crate::monitoring::dmarc::{aggregate_dmarc_stats, parse_dmarc_report};

/// Register DMARC routes
pub(crate) fn register_dmarc_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/dmarc/reports", web::post().to(api_dmarc_import))
        .route("/api/v1/dmarc/stats", web::get().to(api_dmarc_stats));
}

/// Import and parse a DMARC aggregate report
async fn api_dmarc_import(body: web::Bytes) -> impl Responder {
    let xml = String::from_utf8_lossy(&body);
    match parse_dmarc_report(&xml) {
        Ok(report) => {
            let stats = aggregate_dmarc_stats(&report.records);
            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "report_id": report.report_metadata.report_id,
                "domain": report.policy_published.domain,
                "stats": stats,
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "code": "DMARC_PARSE_ERROR",
            "message": e,
        })),
    }
}

/// Get DMARC statistics
async fn api_dmarc_stats() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "DMARC stats endpoint - implement with persistent storage",
    }))
}
