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
