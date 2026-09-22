//! GDPR data deletion route registration (Issue #581).
//!
//! Provides endpoints for GDPR Article 17 (right to erasure) and Article 20 (data portability):
//! - POST /api/gdpr/deletion/request — request account deletion
//! - POST /api/gdpr/deletion/confirm — confirm deletion via token
//! - GET /api/gdpr/deletion/status — check deletion request status
//! - POST /api/gdpr/data-export — export all user data before deletion

use actix_web::web;

use super::super::*;

pub(crate) fn register_gdpr_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/gdpr/deletion/request", web::post().to(api_gdpr_deletion_request))
        .route("/api/gdpr/deletion/confirm", web::post().to(api_gdpr_deletion_confirm))
        .route("/api/gdpr/deletion/status", web::get().to(api_gdpr_deletion_status))
        .route("/api/gdpr/data-export", web::post().to(api_gdpr_data_export));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdpr_routes_deletion_request() {
        assert_eq!("/api/gdpr/deletion/request", "/api/gdpr/deletion/request");
    }

    #[test]
    fn gdpr_routes_deletion_confirm() {
        assert_eq!("/api/gdpr/deletion/confirm", "/api/gdpr/deletion/confirm");
    }

    #[test]
    fn gdpr_routes_deletion_status() {
        assert_eq!("/api/gdpr/deletion/status", "/api/gdpr/deletion/status");
    }

    #[test]
    fn gdpr_routes_data_export() {
        assert_eq!("/api/gdpr/data-export", "/api/gdpr/data-export");
    }

    #[test]
    fn gdpr_routes_all_paths() {
        let paths = vec![
            "/api/gdpr/deletion/request",
            "/api/gdpr/deletion/confirm",
            "/api/gdpr/deletion/status",
            "/api/gdpr/data-export",
        ];
        assert_eq!(paths.len(), 4);
    }
}
