//! Admin routes (users, change-requests, deliverability, observability).

use actix_web::web;

use super::super::*;

pub(crate) fn register_admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/admin/users", web::get().to(api_admin_users_list))
        .route("/api/admin/users", web::post().to(api_admin_user_create))
        .route("/api/admin/whoami", web::get().to(api_admin_whoami))
        .route("/api/admin/audit-log", web::get().to(api_admin_audit_log))
        .route("/api/admin/ai-activity", web::get().to(api_admin_ai_activity))
        .route(
            "/api/admin/users/{id}/invite",
            web::post().to(api_admin_user_invite),
        )
        .route(
            "/api/admin/users/{id}/reset-password",
            web::post().to(api_admin_user_reset_password),
        )
        .route(
            "/api/admin/users/{id}/revoke-sessions",
            web::post().to(api_admin_user_revoke_sessions),
        )
        .route("/api/admin/users/{id}", web::get().to(api_admin_user_get))
        .route(
            "/api/admin/users/{id}",
            web::patch().to(api_admin_user_patch),
        )
        .route(
            "/api/admin/users/{id}",
            web::delete().to(api_admin_user_delete),
        )
        .route(
            "/api/admin/change-requests",
            web::get().to(api_admin_change_requests_list),
        )
        .route(
            "/api/admin/change-requests",
            web::post().to(api_admin_change_request_create),
        )
        .route(
            "/api/admin/change-requests/{id}",
            web::get().to(api_admin_change_request_get),
        )
        .route(
            "/api/admin/change-requests/{id}",
            web::patch().to(api_admin_change_request_patch),
        )
        .route(
            "/api/admin/change-requests/{id}",
            web::delete().to(api_admin_change_request_delete),
        )
        .route(
            "/api/admin/security/posture",
            web::get().to(api_admin_security_posture),
        )
        .route(
            "/api/admin/deliverability/diagnostics",
            web::get().to(api_admin_deliverability_diagnostics),
        )
        .route(
            "/api/admin/deliverability/procedure",
            web::get().to(api_admin_deliverability_procedure),
        )
        .route(
            "/api/admin/deliverability/procedure",
            web::post().to(api_admin_deliverability_procedure_update),
        )
        .route(
            "/api/admin/observability/overview",
            web::get().to(api_admin_observability_overview),
        );
}
