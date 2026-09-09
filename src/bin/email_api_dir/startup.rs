// Route registration helpers live in `startup_routes.rs`.
use super::startup_routes::{register_admin_routes, register_auth_routes, register_dashboard_routes, register_diag_routes, register_docs_routes, register_external_routes, register_mailbox_routes, register_prometheus_routes, register_webhook_routes};

pub(crate) fn register_http_routes(cfg: &mut web::ServiceConfig) {
    register_docs_routes(cfg);
    register_external_routes(cfg);
    register_auth_routes(cfg);
    register_mailbox_routes(cfg);
    register_diag_routes(cfg);
    register_admin_routes(cfg);
    register_prometheus_routes(cfg);
    register_dashboard_routes(cfg);
    register_webhook_routes(cfg);
}
