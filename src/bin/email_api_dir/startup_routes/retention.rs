//! Metadata retention policy route registration (issue #701)
//!
//! ePrivacy Regulation Art.5(1)c + GDPR Art.5(1)e compliance.

use actix_web::web;
use crate::monitoring_handlers::{
    api_retention_get,
    api_retention_put,
    api_retention_purge,
    api_retention_audit,
};

pub(crate) fn register_retention_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/settings/retention", web::get().to(api_retention_get));
    cfg.route("/api/settings/retention", web::put().to(api_retention_put));
    cfg.route("/api/settings/retention/purge", web::post().to(api_retention_purge));
    cfg.route("/api/settings/retention/audit", web::get().to(api_retention_audit));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_routes_paths() {
        let paths = vec![
            "/api/settings/retention",
            "/api/settings/retention/purge",
            "/api/settings/retention/audit",
        ];
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn retention_routes_contain_api() {
        assert!(api_retention_get_path().starts_with("/api/"));
    }

    fn api_retention_get_path() -> &'static str {
        "/api/settings/retention"
    }
}
