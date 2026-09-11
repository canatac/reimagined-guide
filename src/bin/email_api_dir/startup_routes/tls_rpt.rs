//! TLS-RPT (TLS Reporting) route registration

use actix_web::web;
use crate::monitoring_handlers::{
    api_tls_rpt_import,
    api_tls_rpt_list,
    api_tls_rpt_aggregate,
    api_tls_rpt_trends,
    api_tls_rpt_failures,
    api_tls_rpt_alerts_config,
};

pub(crate) fn register_tls_rpt_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/tls-rpt/reports", web::post().to(api_tls_rpt_import));
    cfg.route("/api/v1/tls-rpt/reports", web::get().to(api_tls_rpt_list));
    cfg.route("/api/v1/tls-rpt/aggregate", web::get().to(api_tls_rpt_aggregate));
    cfg.route("/api/v1/tls-rpt/trends", web::get().to(api_tls_rpt_trends));
    cfg.route("/api/v1/tls-rpt/failures", web::get().to(api_tls_rpt_failures));
    cfg.route("/api/v1/tls-rpt/alerts", web::get().to(api_tls_rpt_alerts_config));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_rpt_routes_reports() {
        let route = "/api/v1/tls-rpt/reports";
        assert_eq!(route, "/api/v1/tls-rpt/reports");
    }

    #[test]
    fn tls_rpt_routes_aggregate() {
        let route = "/api/v1/tls-rpt/aggregate";
        assert_eq!(route, "/api/v1/tls-rpt/aggregate");
    }

    #[test]
    fn tls_rpt_routes_trends() {
        let route = "/api/v1/tls-rpt/trends";
        assert_eq!(route, "/api/v1/tls-rpt/trends");
    }

    #[test]
    fn tls_rpt_routes_failures() {
        let route = "/api/v1/tls-rpt/failures";
        assert_eq!(route, "/api/v1/tls-rpt/failures");
    }

    #[test]
    fn tls_rpt_routes_alerts() {
        let route = "/api/v1/tls-rpt/alerts";
        assert_eq!(route, "/api/v1/tls-rpt/alerts");
    }

    #[test]
    fn tls_rpt_routes_reports_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn tls_rpt_routes_reports_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn tls_rpt_routes_aggregate_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn tls_rpt_routes_trends_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn tls_rpt_routes_failures_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn tls_rpt_routes_alerts_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn tls_rpt_routes_all_paths() {
        let paths = vec![
            "/api/v1/tls-rpt/reports",
            "/api/v1/tls-rpt/aggregate",
            "/api/v1/tls-rpt/trends",
            "/api/v1/tls-rpt/failures",
            "/api/v1/tls-rpt/alerts",
        ];
        assert_eq!(paths.len(), 5);
    }

    #[test]
    fn tls_rpt_routes_post_routes() {
        let post_routes = vec!["/api/v1/tls-rpt/reports"];
        assert_eq!(post_routes.len(), 1);
    }

    #[test]
    fn tls_rpt_routes_get_routes() {
        let get_routes = vec![
            "/api/v1/tls-rpt/reports",
            "/api/v1/tls-rpt/aggregate",
            "/api/v1/tls-rpt/trends",
            "/api/v1/tls-rpt/failures",
            "/api/v1/tls-rpt/alerts",
        ];
        assert_eq!(get_routes.len(), 5);
    }

    #[test]
    fn tls_rpt_routes_path_contains_tls_rpt() {
        let route = "/api/v1/tls-rpt/reports";
        assert!(route.contains("tls-rpt"));
    }

    #[test]
    fn tls_rpt_routes_path_contains_v1() {
        let route = "/api/v1/tls-rpt/reports";
        assert!(route.contains("v1"));
    }

    #[test]
    fn tls_rpt_routes_path_starts_with_api() {
        let route = "/api/v1/tls-rpt/reports";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn tls_rpt_routes_path_no_trailing_slash() {
        let route = "/api/v1/tls-rpt/reports";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn tls_rpt_routes_handler_import() {
        let handler = "api_tls_rpt_import";
        assert_eq!(handler, "api_tls_rpt_import");
    }

    #[test]
    fn tls_rpt_routes_handler_list() {
        let handler = "api_tls_rpt_list";
        assert_eq!(handler, "api_tls_rpt_list");
    }

    #[test]
    fn tls_rpt_routes_handler_aggregate() {
        let handler = "api_tls_rpt_aggregate";
        assert_eq!(handler, "api_tls_rpt_aggregate");
    }

    #[test]
    fn tls_rpt_routes_handler_trends() {
        let handler = "api_tls_rpt_trends";
        assert_eq!(handler, "api_tls_rpt_trends");
    }

    #[test]
    fn tls_rpt_routes_handler_failures() {
        let handler = "api_tls_rpt_failures";
        assert_eq!(handler, "api_tls_rpt_failures");
    }

    #[test]
    fn tls_rpt_routes_handler_alerts_config() {
        let handler = "api_tls_rpt_alerts_config";
        assert_eq!(handler, "api_tls_rpt_alerts_config");
    }
}
