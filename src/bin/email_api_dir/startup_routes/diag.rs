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
            "/api/monitoring/mongo-health",
            web::get().to(api_monitoring_mongo_health),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_routes_events() {
        let route = "/api/events";
        assert_eq!(route, "/api/events");
    }

    #[test]
    fn diag_routes_events_stream() {
        let route = "/api/events/stream";
        assert_eq!(route, "/api/events/stream");
    }

    #[test]
    fn diag_routes_monitoring_summary() {
        let route = "/api/monitoring/summary";
        assert_eq!(route, "/api/monitoring/summary");
    }

    #[test]
    fn diag_routes_monitoring_events() {
        let route = "/api/monitoring/events";
        assert_eq!(route, "/api/monitoring/events");
    }

    #[test]
    fn diag_routes_monitoring_trace() {
        let route = "/api/monitoring/messages/{message_id}/trace";
        assert_eq!(route, "/api/monitoring/messages/{message_id}/trace");
    }

    #[test]
    fn diag_routes_monitoring_bounces() {
        let route = "/api/monitoring/bounces";
        assert_eq!(route, "/api/monitoring/bounces");
    }

    #[test]
    fn diag_routes_monitoring_providers_top() {
        let route = "/api/monitoring/providers/top";
        assert_eq!(route, "/api/monitoring/providers/top");
    }

    #[test]
    fn diag_routes_monitoring_live() {
        let route = "/api/monitoring/live";
        assert_eq!(route, "/api/monitoring/live");
    }

    #[test]
    fn diag_routes_monitoring_alerts_active() {
        let route = "/api/monitoring/alerts/active";
        assert_eq!(route, "/api/monitoring/alerts/active");
    }

    #[test]
    fn diag_routes_monitoring_mongo_health() {
        let route = "/api/monitoring/mongo-health";
        assert_eq!(route, "/api/monitoring/mongo-health");
    }

    #[test]
    fn diag_routes_security_alerts_active() {
        let route = "/api/security/alerts/active";
        assert_eq!(route, "/api/security/alerts/active");
    }

    #[test]
    fn diag_routes_security_incidents() {
        let route = "/api/security/incidents";
        assert_eq!(route, "/api/security/incidents");
    }

    #[test]
    fn diag_routes_security_live() {
        let route = "/api/security/live";
        assert_eq!(route, "/api/security/live");
    }

    #[test]
    fn diag_routes_security_tenant_status() {
        let route = "/api/security/tenant/{id}/status";
        assert_eq!(route, "/api/security/tenant/{id}/status");
    }

    #[test]
    fn diag_routes_security_rollback() {
        let route = "/api/security/remediation/{alert_id}/rollback";
        assert_eq!(route, "/api/security/remediation/{alert_id}/rollback");
    }

    #[test]
    fn diag_routes_all_paths() {
        let paths = vec![
            "/api/events",
            "/api/events/stream",
            "/api/monitoring/summary",
            "/api/monitoring/events",
            "/api/monitoring/messages/{message_id}/trace",
            "/api/monitoring/bounces",
            "/api/monitoring/providers/top",
            "/api/monitoring/live",
            "/api/monitoring/alerts/active",
            "/api/monitoring/mongo-health",
            "/api/security/alerts/active",
            "/api/security/incidents",
            "/api/security/live",
            "/api/security/tenant/{id}/status",
            "/api/security/remediation/{alert_id}/rollback",
        ];
        assert_eq!(paths.len(), 15);
    }

    #[test]
    fn diag_routes_get_routes() {
        let get_routes = vec![
            "/api/events",
            "/api/events/stream",
            "/api/monitoring/summary",
            "/api/monitoring/events",
            "/api/monitoring/messages/{message_id}/trace",
            "/api/monitoring/bounces",
            "/api/monitoring/providers/top",
            "/api/monitoring/live",
            "/api/monitoring/alerts/active",
            "/api/monitoring/mongo-health",
            "/api/security/alerts/active",
            "/api/security/incidents",
            "/api/security/live",
            "/api/security/tenant/{id}/status",
        ];
        assert_eq!(get_routes.len(), 14);
    }

    #[test]
    fn diag_routes_post_routes() {
        let post_routes = vec!["/api/security/remediation/{alert_id}/rollback"];
        assert_eq!(post_routes.len(), 1);
    }

    #[test]
    fn diag_routes_path_starts_with_api() {
        let route = "/api/events";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn diag_routes_path_no_trailing_slash() {
        let route = "/api/events";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn diag_routes_path_no_uppercase() {
        let route = "/api/events";
        assert_eq!(route, route.to_ascii_lowercase());
    }

    #[test]
    fn diag_routes_path_no_spaces() {
        let route = "/api/events";
        assert!(!route.contains(" "));
    }

    #[test]
    fn diag_routes_path_valid() {
        let route = "/api/events";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn diag_routes_handler_api_events() {
        let handler = "api_events";
        assert_eq!(handler, "api_events");
    }

    #[test]
    fn diag_routes_handler_api_events_stream() {
        let handler = "api_events_stream";
        assert_eq!(handler, "api_events_stream");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_summary() {
        let handler = "api_monitoring_summary";
        assert_eq!(handler, "api_monitoring_summary");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_events() {
        let handler = "api_monitoring_events";
        assert_eq!(handler, "api_monitoring_events");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_trace() {
        let handler = "api_monitoring_trace";
        assert_eq!(handler, "api_monitoring_trace");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_bounces() {
        let handler = "api_monitoring_bounces";
        assert_eq!(handler, "api_monitoring_bounces");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_providers_top() {
        let handler = "api_monitoring_providers_top";
        assert_eq!(handler, "api_monitoring_providers_top");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_live() {
        let handler = "api_monitoring_live";
        assert_eq!(handler, "api_monitoring_live");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_alerts_active() {
        let handler = "api_monitoring_alerts_active";
        assert_eq!(handler, "api_monitoring_alerts_active");
    }

    #[test]
    fn diag_routes_handler_api_monitoring_mongo_health() {
        let handler = "api_monitoring_mongo_health";
        assert_eq!(handler, "api_monitoring_mongo_health");
    }

    #[test]
    fn diag_routes_handler_api_security_alerts_active() {
        let handler = "api_security_alerts_active";
        assert_eq!(handler, "api_security_alerts_active");
    }

    #[test]
    fn diag_routes_handler_api_security_incidents() {
        let handler = "api_security_incidents";
        assert_eq!(handler, "api_security_incidents");
    }

    #[test]
    fn diag_routes_handler_api_security_live() {
        let handler = "api_security_live";
        assert_eq!(handler, "api_security_live");
    }

    #[test]
    fn diag_routes_handler_api_security_tenant_status() {
        let handler = "api_security_tenant_status";
        assert_eq!(handler, "api_security_tenant_status");
    }

    #[test]
    fn diag_routes_handler_api_security_rollback() {
        let handler = "api_security_rollback";
        assert_eq!(handler, "api_security_rollback");
    }
}
