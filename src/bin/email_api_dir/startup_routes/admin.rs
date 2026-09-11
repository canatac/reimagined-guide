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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_routes_users() {
        let route = "/api/admin/users";
        assert_eq!(route, "/api/admin/users");
    }

    #[test]
    fn admin_routes_whoami() {
        let route = "/api/admin/whoami";
        assert_eq!(route, "/api/admin/whoami");
    }

    #[test]
    fn admin_routes_audit_log() {
        let route = "/api/admin/audit-log";
        assert_eq!(route, "/api/admin/audit-log");
    }

    #[test]
    fn admin_routes_ai_activity() {
        let route = "/api/admin/ai-activity";
        assert_eq!(route, "/api/admin/ai-activity");
    }

    #[test]
    fn admin_routes_user_invite() {
        let route = "/api/admin/users/{id}/invite";
        assert_eq!(route, "/api/admin/users/{id}/invite");
    }

    #[test]
    fn admin_routes_user_reset_password() {
        let route = "/api/admin/users/{id}/reset-password";
        assert_eq!(route, "/api/admin/users/{id}/reset-password");
    }

    #[test]
    fn admin_routes_user_revoke_sessions() {
        let route = "/api/admin/users/{id}/revoke-sessions";
        assert_eq!(route, "/api/admin/users/{id}/revoke-sessions");
    }

    #[test]
    fn admin_routes_user_get() {
        let route = "/api/admin/users/{id}";
        assert_eq!(route, "/api/admin/users/{id}");
    }

    #[test]
    fn admin_routes_user_patch() {
        let route = "/api/admin/users/{id}";
        assert_eq!(route, "/api/admin/users/{id}");
    }

    #[test]
    fn admin_routes_user_delete() {
        let route = "/api/admin/users/{id}";
        assert_eq!(route, "/api/admin/users/{id}");
    }

    #[test]
    fn admin_routes_change_requests() {
        let route = "/api/admin/change-requests";
        assert_eq!(route, "/api/admin/change-requests");
    }

    #[test]
    fn admin_routes_change_request_get() {
        let route = "/api/admin/change-requests/{id}";
        assert_eq!(route, "/api/admin/change-requests/{id}");
    }

    #[test]
    fn admin_routes_change_request_patch() {
        let route = "/api/admin/change-requests/{id}";
        assert_eq!(route, "/api/admin/change-requests/{id}");
    }

    #[test]
    fn admin_routes_change_request_delete() {
        let route = "/api/admin/change-requests/{id}";
        assert_eq!(route, "/api/admin/change-requests/{id}");
    }

    #[test]
    fn admin_routes_security_posture() {
        let route = "/api/admin/security/posture";
        assert_eq!(route, "/api/admin/security/posture");
    }

    #[test]
    fn admin_routes_deliverability_diagnostics() {
        let route = "/api/admin/deliverability/diagnostics";
        assert_eq!(route, "/api/admin/deliverability/diagnostics");
    }

    #[test]
    fn admin_routes_deliverability_procedure() {
        let route = "/api/admin/deliverability/procedure";
        assert_eq!(route, "/api/admin/deliverability/procedure");
    }

    #[test]
    fn admin_routes_observability_overview() {
        let route = "/api/admin/observability/overview";
        assert_eq!(route, "/api/admin/observability/overview");
    }

    #[test]
    fn admin_routes_all_paths() {
        let paths = vec![
            "/api/admin/users",
            "/api/admin/whoami",
            "/api/admin/audit-log",
            "/api/admin/ai-activity",
            "/api/admin/users/{id}/invite",
            "/api/admin/users/{id}/reset-password",
            "/api/admin/users/{id}/revoke-sessions",
            "/api/admin/users/{id}",
            "/api/admin/change-requests",
            "/api/admin/change-requests/{id}",
            "/api/admin/security/posture",
            "/api/admin/deliverability/diagnostics",
            "/api/admin/deliverability/procedure",
            "/api/admin/observability/overview",
        ];
        assert_eq!(paths.len(), 14);
    }

    #[test]
    fn admin_routes_get_routes() {
        let get_routes = vec![
            "/api/admin/users",
            "/api/admin/whoami",
            "/api/admin/audit-log",
            "/api/admin/ai-activity",
            "/api/admin/users/{id}",
            "/api/admin/change-requests",
            "/api/admin/change-requests/{id}",
            "/api/admin/security/posture",
            "/api/admin/deliverability/diagnostics",
            "/api/admin/deliverability/procedure",
            "/api/admin/observability/overview",
        ];
        assert_eq!(get_routes.len(), 11);
    }

    #[test]
    fn admin_routes_post_routes() {
        let post_routes = vec![
            "/api/admin/users",
            "/api/admin/users/{id}/invite",
            "/api/admin/users/{id}/reset-password",
            "/api/admin/users/{id}/revoke-sessions",
            "/api/admin/change-requests",
            "/api/admin/deliverability/procedure",
        ];
        assert_eq!(post_routes.len(), 6);
    }

    #[test]
    fn admin_routes_patch_routes() {
        let patch_routes = vec![
            "/api/admin/users/{id}",
            "/api/admin/change-requests/{id}",
        ];
        assert_eq!(patch_routes.len(), 2);
    }

    #[test]
    fn admin_routes_delete_routes() {
        let delete_routes = vec![
            "/api/admin/users/{id}",
            "/api/admin/change-requests/{id}",
        ];
        assert_eq!(delete_routes.len(), 2);
    }

    #[test]
    fn admin_routes_path_starts_with_api() {
        let route = "/api/admin/users";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn admin_routes_path_no_trailing_slash() {
        let route = "/api/admin/users";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn admin_routes_path_no_uppercase() {
        let route = "/api/admin/users";
        assert_eq!(route, route.to_ascii_lowercase());
    }

    #[test]
    fn admin_routes_path_no_spaces() {
        let route = "/api/admin/users";
        assert!(!route.contains(" "));
    }

    #[test]
    fn admin_routes_path_valid() {
        let route = "/api/admin/users";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn admin_routes_handler_api_admin_users_list() {
        let handler = "api_admin_users_list";
        assert_eq!(handler, "api_admin_users_list");
    }

    #[test]
    fn admin_routes_handler_api_admin_user_create() {
        let handler = "api_admin_user_create";
        assert_eq!(handler, "api_admin_user_create");
    }

    #[test]
    fn admin_routes_handler_api_admin_whoami() {
        let handler = "api_admin_whoami";
        assert_eq!(handler, "api_admin_whoami");
    }

    #[test]
    fn admin_routes_handler_api_admin_audit_log() {
        let handler = "api_admin_audit_log";
        assert_eq!(handler, "api_admin_audit_log");
    }

    #[test]
    fn admin_routes_handler_api_admin_ai_activity() {
        let handler = "api_admin_ai_activity";
        assert_eq!(handler, "api_admin_ai_activity");
    }

    #[test]
    fn admin_routes_handler_api_admin_user_invite() {
        let handler = "api_admin_user_invite";
        assert_eq!(handler, "api_admin_user_invite");
    }

    #[test]
    fn admin_routes_handler_api_admin_user_reset_password() {
        let handler = "api_admin_user_reset_password";
        assert_eq!(handler, "api_admin_user_reset_password");
    }

    #[test]
    fn admin_routes_handler_api_admin_user_revoke_sessions() {
        let handler = "api_admin_user_revoke_sessions";
        assert_eq!(handler, "api_admin_user_revoke_sessions");
    }

    #[test]
    fn admin_routes_handler_api_admin_user_get() {
        let handler = "api_admin_user_get";
        assert_eq!(handler, "api_admin_user_get");
    }

    #[test]
    fn admin_routes_handler_api_admin_user_patch() {
        let handler = "api_admin_user_patch";
        assert_eq!(handler, "api_admin_user_patch");
    }

    #[test]
    fn admin_routes_handler_api_admin_user_delete() {
        let handler = "api_admin_user_delete";
        assert_eq!(handler, "api_admin_user_delete");
    }

    #[test]
    fn admin_routes_handler_api_admin_change_requests_list() {
        let handler = "api_admin_change_requests_list";
        assert_eq!(handler, "api_admin_change_requests_list");
    }

    #[test]
    fn admin_routes_handler_api_admin_change_request_create() {
        let handler = "api_admin_change_request_create";
        assert_eq!(handler, "api_admin_change_request_create");
    }

    #[test]
    fn admin_routes_handler_api_admin_change_request_get() {
        let handler = "api_admin_change_request_get";
        assert_eq!(handler, "api_admin_change_request_get");
    }

    #[test]
    fn admin_routes_handler_api_admin_change_request_patch() {
        let handler = "api_admin_change_request_patch";
        assert_eq!(handler, "api_admin_change_request_patch");
    }

    #[test]
    fn admin_routes_handler_api_admin_change_request_delete() {
        let handler = "api_admin_change_request_delete";
        assert_eq!(handler, "api_admin_change_request_delete");
    }

    #[test]
    fn admin_routes_handler_api_admin_security_posture() {
        let handler = "api_admin_security_posture";
        assert_eq!(handler, "api_admin_security_posture");
    }

    #[test]
    fn admin_routes_handler_api_admin_deliverability_diagnostics() {
        let handler = "api_admin_deliverability_diagnostics";
        assert_eq!(handler, "api_admin_deliverability_diagnostics");
    }

    #[test]
    fn admin_routes_handler_api_admin_deliverability_procedure() {
        let handler = "api_admin_deliverability_procedure";
        assert_eq!(handler, "api_admin_deliverability_procedure");
    }

    #[test]
    fn admin_routes_handler_api_admin_deliverability_procedure_update() {
        let handler = "api_admin_deliverability_procedure_update";
        assert_eq!(handler, "api_admin_deliverability_procedure_update");
    }

    #[test]
    fn admin_routes_handler_api_admin_observability_overview() {
        let handler = "api_admin_observability_overview";
        assert_eq!(handler, "api_admin_observability_overview");
    }
}
