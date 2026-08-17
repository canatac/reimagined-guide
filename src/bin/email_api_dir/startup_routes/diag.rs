//! Monitoring / security / diagnostics routes.

use actix_web::web;

use super::super::*;

pub(crate) fn register_diag_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/events", web::get().to(api_events))
        .route("/api/events/stream", web::get().to(api_events_stream))
        .route(
            "/api/monitoring/summary",
            web::get().to(api_monitoring_summary),
        )
        .route(
            "/api/monitoring/events",
            web::get().to(api_monitoring_events),
        )
        .route(
            "/api/monitoring/messages/{message_id}/trace",
            web::get().to(api_monitoring_trace),
        )
        .route(
            "/api/monitoring/bounces",
            web::get().to(api_monitoring_bounces),
        )
        .route(
            "/api/monitoring/providers/top",
            web::get().to(api_monitoring_providers_top),
        )
        .route("/api/monitoring/live", web::get().to(api_monitoring_live))
        .route(
            "/api/monitoring/alerts/active",
            web::get().to(api_monitoring_alerts_active),
        )
        .route(
            "/api/security/alerts/active",
            web::get().to(api_security_alerts_active),
        )
        .route(
            "/api/security/incidents",
            web::get().to(api_security_incidents),
        )
        .route("/api/security/live", web::get().to(api_security_live))
        .route(
            "/api/security/tenant/{id}/status",
            web::get().to(api_security_tenant_status),
        )
        .route(
            "/api/security/remediation/{alert_id}/rollback",
            web::post().to(api_security_rollback),
        );
}
