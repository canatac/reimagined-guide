//! TLS-RPT admin dashboard handlers
//!
//! Issue #692: TLS-RPT reporting — admin dashboard endpoints for
//! TLS connection health, failure patterns, and alerts.

use actix_web::{HttpRequest, HttpResponse, Responder, web};
use mongodb::bson::doc;
use std::sync::Arc;

use crate::admin_ops::mongo_db_name;
use crate::monitoring_handlers::{parse_window, since_str, AdminWindowQuery};
use simple_smtp_server::monitoring::tls_rpt_log::{
    self, TlsConnectionRecord, TlsConnectionResult, TlsDomainStats,
};
use simple_smtp_server::monitoring::tls_rpt_report::{self, TlsAlertEvent};

/// GET /api/admin/tls-rpt/summary — dashboard overview
pub(crate) async fn api_admin_tls_rpt_summary(
    req: HttpRequest,
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = crate::admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    tls_rpt_log::init_tls_log();
    let since = since_str(&query.window);
    let stats = tls_rpt_log::get_domain_stats(None);

    let summary = tls_rpt_report::build_dashboard_summary(&stats, &since, &chrono::Utc::now().to_rfc3339());

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "total_domains": summary.total_domains,
        "total_success": summary.total_success,
        "total_failure": summary.total_failure,
        "overall_failure_rate": (summary.overall_failure_rate * 100.0).round() / 100.0,
        "domains_with_failures": summary.domains_with_failures,
        "top_failure_reasons": summary.top_failure_reasons,
        "period_start": summary.period_start,
        "period_end": summary.period_end,
    }))
}

/// GET /api/admin/tls-rpt/domains/{domain} — per-domain details
pub(crate) async fn api_admin_tls_rpt_domain(
    req: HttpRequest,
    path: web::Path<String>,
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = crate::admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let domain = path.into_inner();
    tls_rpt_log::init_tls_log();
    let since = since_str(&query.window);
    let records = tls_rpt_log::get_tls_records(&domain, Some(&since));

    let total = records.len() as i64;
    let success = records.iter().filter(|r| r.result == TlsConnectionResult::Success).count() as i64;
    let failure = records.iter().filter(|r| r.result == TlsConnectionResult::Failed).count() as i64;
    let failure_rate = if total > 0 { (failure as f64 / total as f64) * 100.0 } else { 0.0 };

    // Collect failure reasons
    let mut failure_reasons: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for r in &records {
        if let Some(ref reason) = r.failure_reason {
            *failure_reasons.entry(reason.to_string()).or_insert(0) += 1;
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "domain": domain,
        "window": query.window,
        "total_attempts": total,
        "total_success": success,
        "total_failure": failure,
        "failure_rate": (failure_rate * 100.0).round() / 100.0,
        "failure_reasons": failure_reasons,
        "recent_failures": records.iter()
            .filter(|r| r.result == TlsConnectionResult::Failed)
            .rev()
            .take(20)
            .collect::<Vec<_>>(),
    }))
}

/// GET /api/admin/tls-rpt/alerts — TLS failure alerts
pub(crate) async fn api_admin_tls_rpt_alerts(
    req: HttpRequest,
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = crate::admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    tls_rpt_log::init_tls_log();
    let stats = tls_rpt_log::get_domain_stats(None);

    let failure_rate_threshold = std::env::var("TLS_RPT_ALERT_THRESHOLD_PCT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(10.0);

    let min_failures = std::env::var("TLS_RPT_ALERT_MIN_FAILURES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(5);

    let alerts = tls_rpt_report::check_tls_alerts(&stats, failure_rate_threshold, min_failures);

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "threshold_pct": failure_rate_threshold,
        "min_failures": min_failures,
        "total_alerts": alerts.len(),
        "alerts": alerts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_rpt_summary_response_structure() {
        let response = serde_json::json!({
            "window": "24h",
            "since": "2026-01-01T00:00:00Z",
            "total_domains": 5,
            "total_success": 100,
            "total_failure": 3,
            "overall_failure_rate": 2.91,
            "domains_with_failures": 2,
            "top_failure_reasons": [["certificate-expired", 2], ["connection-timeout", 1]],
            "period_start": "2026-01-01T00:00:00Z",
            "period_end": "2026-01-02T00:00:00Z",
        });
        assert_eq!(response["total_domains"], 5);
        assert_eq!(response["total_success"], 100);
        assert_eq!(response["total_failure"], 3);
    }

    #[test]
    fn tls_rpt_domain_response_structure() {
        let response = serde_json::json!({
            "domain": "example.com",
            "window": "24h",
            "total_attempts": 50,
            "total_success": 48,
            "total_failure": 2,
            "failure_rate": 4.0,
            "failure_reasons": {"certificate-expired": 2},
            "recent_failures": [],
        });
        assert_eq!(response["domain"], "example.com");
        assert_eq!(response["total_attempts"], 50);
    }

    #[test]
    fn tls_rpt_alerts_response_structure() {
        let response = serde_json::json!({
            "window": "24h",
            "threshold_pct": 10.0,
            "min_failures": 5,
            "total_alerts": 1,
            "alerts": [{
                "domain": "bad-ssl.example",
                "severity": "critical",
                "message": "TLS failure rate for bad-ssl.example: 70.0%",
                "failure_rate": 70.0,
                "total_failures": 7,
            }],
        });
        assert_eq!(response["total_alerts"], 1);
        assert_eq!(response["alerts"][0]["severity"], "critical");
    }

    #[test]
    fn failure_rate_threshold_env_default() {
        let threshold = std::env::var("TLS_RPT_ALERT_THRESHOLD_PCT")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(10.0);
        assert_eq!(threshold, 10.0);
    }

    #[test]
    fn min_failures_env_default() {
        let min = std::env::var("TLS_RPT_ALERT_MIN_FAILURES")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(5);
        assert_eq!(min, 5);
    }
}
