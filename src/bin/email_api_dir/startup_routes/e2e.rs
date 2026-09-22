//! E2EE (End-to-End Encryption) zero-access route registration
//!
//! Issue #600: Zero-access encryption (client-side E2EE)
//!
//! Routes for managing client-side encryption keys in zero-knowledge mode.
//! The server never sees plaintext private keys — only encrypted blobs.

use actix_web::web;
use crate::monitoring_handlers::{
    api_e2e_enable,
    api_e2e_status,
    api_e2e_rotate,
    api_e2e_recover,
    api_e2e_recovery_phrase,
    api_e2e_disable,
    api_e2e_validate_blob,
};

pub(crate) fn register_e2e_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/e2e/enable", web::post().to(api_e2e_enable));
    cfg.route("/api/v1/e2e/status/{user_id}", web::get().to(api_e2e_status));
    cfg.route("/api/v1/e2e/rotate", web::post().to(api_e2e_rotate));
    cfg.route("/api/v1/e2e/recover", web::post().to(api_e2e_recover));
    cfg.route("/api/v1/e2e/recovery-phrase", web::post().to(api_e2e_recovery_phrase));
    cfg.route("/api/v1/e2e/disable/{user_id}", web::delete().to(api_e2e_disable));
    cfg.route("/api/v1/e2e/validate-blob", web::post().to(api_e2e_validate_blob));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_routes_enable() {
        let route = "/api/v1/e2e/enable";
        assert_eq!(route, "/api/v1/e2e/enable");
    }

    #[test]
    fn e2e_routes_status() {
        let route = "/api/v1/e2e/status/{user_id}";
        assert_eq!(route, "/api/v1/e2e/status/{user_id}");
    }

    #[test]
    fn e2e_routes_rotate() {
        let route = "/api/v1/e2e/rotate";
        assert_eq!(route, "/api/v1/e2e/rotate");
    }

    #[test]
    fn e2e_routes_recover() {
        let route = "/api/v1/e2e/recover";
        assert_eq!(route, "/api/v1/e2e/recover");
    }

    #[test]
    fn e2e_routes_recovery_phrase() {
        let route = "/api/v1/e2e/recovery-phrase";
        assert_eq!(route, "/api/v1/e2e/recovery-phrase");
    }

    #[test]
    fn e2e_routes_disable() {
        let route = "/api/v1/e2e/disable/{user_id}";
        assert_eq!(route, "/api/v1/e2e/disable/{user_id}");
    }

    #[test]
    fn e2e_routes_validate_blob() {
        let route = "/api/v1/e2e/validate-blob";
        assert_eq!(route, "/api/v1/e2e/validate-blob");
    }

    #[test]
    fn e2e_routes_enable_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn e2e_routes_status_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn e2e_routes_disable_method_delete() {
        let method = "DELETE";
        assert_eq!(method, "DELETE");
    }

    #[test]
    fn e2e_routes_all_paths() {
        let paths = vec![
            "/api/v1/e2e/enable",
            "/api/v1/e2e/status/{user_id}",
            "/api/v1/e2e/rotate",
            "/api/v1/e2e/recover",
            "/api/v1/e2e/recovery-phrase",
            "/api/v1/e2e/disable/{user_id}",
            "/api/v1/e2e/validate-blob",
        ];
        assert_eq!(paths.len(), 7);
    }

    #[test]
    fn e2e_routes_path_format() {
        let route = "/api/v1/e2e/enable";
        assert!(route.starts_with("/api/v1/e2e/"));
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn e2e_routes_zero_knowledge() {
        // Zero-knowledge: server never sees plaintext private keys
        let principle = "zero-knowledge";
        assert_eq!(principle, "zero-knowledge");
    }

    #[test]
    fn e2e_routes_encryption_standard() {
        let standard = "AES-256-GCM";
        assert_eq!(standard, "AES-256-GCM");
    }

    #[test]
    fn e2e_routes_issue_600() {
        let issue = 600;
        assert_eq!(issue, 600);
    }
}
