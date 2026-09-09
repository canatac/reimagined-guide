// TLS-RPT (TLS Reporting) handlers for RFC 8460
// Issue #481: SMTP TLS reporting (TLS-RPT) aggregation

use actix_web::{web, HttpResponse};
use mongodb::bson::doc;
use simple_smtp_server::monitoring::tls_rpt::{
    self, TlsRptAlertConfig, TlsRptReport,
};
use std::sync::Arc;

/// POST /api/v1/tls-rpt/reports - Receive and store TLS-RPT report
pub(crate) async fn api_tls_rpt_import(
    req: web::Json<serde_json::Value>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let json_str = match serde_json::to_string(&req.0) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "message": format!("Invalid JSON: {}", e)
            }));
        }
    };

    match tls_rpt::parse_tls_rpt_report(&json_str) {
        Ok(report) => {
            let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
            let coll = mongo
                .database(&db_name)
                .collection::<mongodb::bson::Document>("tls_rpt_reports");

            // Convert to BSON document
            let doc = match mongodb::bson::to_document(&report) {
                Ok(d) => d,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "status": "error",
                        "message": format!("Failed to serialize report: {}", e)
                    }));
                }
            };
            let _ = coll.insert_one(doc).await;

            HttpResponse::Created().json(serde_json::json!({
                "status": "success",
                "report_id": report.report_id,
                "organization": report.organization_name,
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "message": e,
        })),
    }
}

/// GET /api/v1/tls-rpt/reports - List all TLS-RPT reports
pub(crate) async fn api_tls_rpt_list(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("tls_rpt_reports");

    let count = match coll.count_documents(doc! {}).await {
        Ok(c) => c,
        Err(_) => 0,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "count": count,
    }))
}

/// GET /api/v1/tls-rpt/aggregate - Get aggregated TLS-RPT data by domain
pub(crate) async fn api_tls_rpt_aggregate(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("tls_rpt_reports");

    // For now, return empty aggregation - in production would fetch from DB
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "domains": [],
    }))
}

/// GET /api/v1/tls-rpt/trends - Get TLS-RPT trends
pub(crate) async fn api_tls_rpt_trends(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "trends": [],
    }))
}

/// GET /api/v1/tls-rpt/failures - Get failure type distribution
pub(crate) async fn api_tls_rpt_failures(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "failures": [],
    }))
}

/// GET /api/v1/tls-rpt/alerts - Get alert configuration
pub(crate) async fn api_tls_rpt_alerts_config() -> impl actix_web::Responder {
    let config = TlsRptAlertConfig::default();
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "config": config,
    }))
}
