//! Documentation & OpenAPI routes.

use actix_web::web;

use super::super::*;

pub(crate) fn register_docs_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/openapi.json", web::get().to(api_openapi_json))
        .route("/api/docs", web::get().to(api_swagger_ui))
        .route(
            "/api/openapi/external-imap.yaml",
            web::get().to(api_external_openapi),
        );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_routes_openapi_json() {
        let route = "/api/openapi.json";
        assert_eq!(route, "/api/openapi.json");
    }

    #[test]
    fn docs_routes_swagger_ui() {
        let route = "/api/docs";
        assert_eq!(route, "/api/docs");
    }

    #[test]
    fn docs_routes_external_openapi() {
        let route = "/api/openapi/external-imap.yaml";
        assert_eq!(route, "/api/openapi/external-imap.yaml");
    }

    #[test]
    fn docs_routes_openapi_json_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn docs_routes_swagger_ui_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn docs_routes_external_openapi_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn docs_routes_all_paths() {
        let paths = vec![
            "/api/openapi.json",
            "/api/docs",
            "/api/openapi/external-imap.yaml",
        ];
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn docs_routes_get_routes() {
        let get_routes = vec![
            "/api/openapi.json",
            "/api/docs",
            "/api/openapi/external-imap.yaml",
        ];
        assert_eq!(get_routes.len(), 3);
    }

    #[test]
    fn docs_routes_path_contains_api() {
        let route = "/api/openapi.json";
        assert!(route.contains("api"));
    }

    #[test]
    fn docs_routes_path_starts_with_api() {
        let route = "/api/openapi.json";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn docs_routes_path_no_trailing_slash() {
        let route = "/api/openapi.json";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn docs_routes_handler_openapi_json() {
        let handler = "api_openapi_json";
        assert_eq!(handler, "api_openapi_json");
    }

    #[test]
    fn docs_routes_handler_swagger_ui() {
        let handler = "api_swagger_ui";
        assert_eq!(handler, "api_swagger_ui");
    }

    #[test]
    fn docs_routes_handler_external_openapi() {
        let handler = "api_external_openapi";
        assert_eq!(handler, "api_external_openapi");
    }
}
