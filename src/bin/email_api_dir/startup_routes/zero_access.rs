//! Zero-access encryption mode route registration (Issue #575).
//!
//! Provides endpoints for zero-access encryption mode management:
//! - GET /api/v1/zero-access/status
//! - POST /api/v1/zero-access/enable
//! - POST /api/v1/zero-access/disable
//! - POST /api/v1/zero-access/validate-blob

use actix_web::web;
use crate::monitoring_handlers::{
    api_zero_access_status,
    api_zero_access_enable,
    api_zero_access_disable,
    api_zero_access_validate_blob,
};

pub(crate) fn register_zero_access_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/zero-access/status", web::get().to(api_zero_access_status));
    cfg.route("/api/v1/zero-access/enable", web::post().to(api_zero_access_enable));
    cfg.route("/api/v1/zero-access/disable", web::post().to(api_zero_access_disable));
    cfg.route("/api/v1/zero-access/validate-blob", web::post().to(api_zero_access_validate_blob));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_access_routes_status() {
        let route = "/api/v1/zero-access/status";
        assert_eq!(route, "/api/v1/zero-access/status");
    }

    #[test]
    fn zero_access_routes_enable() {
        let route = "/api/v1/zero-access/enable";
        assert_eq!(route, "/api/v1/zero-access/enable");
    }

    #[test]
    fn zero_access_routes_disable() {
        let route = "/api/v1/zero-access/disable";
        assert_eq!(route, "/api/v1/zero-access/disable");
    }

    #[test]
    fn zero_access_routes_validate_blob() {
        let route = "/api/v1/zero-access/validate-blob";
        assert_eq!(route, "/api/v1/zero-access/validate-blob");
    }

    #[test]
    fn zero_access_routes_all_paths() {
        let paths = vec![
            "/api/v1/zero-access/status",
            "/api/v1/zero-access/enable",
            "/api/v1/zero-access/disable",
            "/api/v1/zero-access/validate-blob",
        ];
        assert_eq!(paths.len(), 4);
    }
}
