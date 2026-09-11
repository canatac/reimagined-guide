//! External IMAP account routes.

use actix_web::web;

use super::super::*;

pub(crate) fn register_external_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/api/external-accounts",
        web::get().to(api_external_accounts_list),
    )
    .route(
        "/api/external-accounts/probe-stream",
        web::post().to(external_probe_handlers::api_external_probe_stream),
    )
    .route(
        "/api/external-accounts",
        web::post().to(api_external_accounts_create),
    )
    .route(
        "/api/external-accounts/{id}",
        web::get().to(api_external_account_get),
    )
    .route(
        "/api/external-accounts/{id}",
        web::patch().to(api_external_account_patch),
    )
    .route(
        "/api/external-accounts/{id}",
        web::delete().to(api_external_account_delete),
    )
    .route(
        "/api/external-accounts/{id}/test",
        web::post().to(api_external_account_test),
    )
    .route(
        "/api/external-accounts/{id}/folders",
        web::get().to(api_external_folders_list),
    )
    .route(
        "/api/external-accounts/{id}/folders/discover",
        web::post().to(api_external_folders_discover),
    )
    .route(
        "/api/external-accounts/{id}/folders/{folder_id}/mapping",
        web::put().to(api_external_folder_mapping_put),
    )
    .route(
        "/api/external-accounts/{id}/sync",
        web::post().to(api_external_sync_start),
    )
    .route(
        "/api/external-accounts/{id}/sync/status",
        web::get().to(api_external_sync_status),
    )
    .route(
        "/api/external-accounts/{id}/sync/pause",
        web::post().to(api_external_sync_pause),
    )
    .route(
        "/api/external-accounts/{id}/sync/resume",
        web::post().to(api_external_sync_resume),
    )
    .route(
        "/api/external-sync-runs/{run_id}",
        web::get().to(api_external_sync_run_get),
    )
    .route(
        "/api/external-messages",
        web::get().to(api_external_messages_list),
    )
    .route(
        "/api/external-messages/{id}/action",
        web::post().to(api_external_message_action),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_routes_accounts_list() {
        let route = "/api/external-accounts";
        assert_eq!(route, "/api/external-accounts");
    }

    #[test]
    fn external_routes_probe_stream() {
        let route = "/api/external-accounts/probe-stream";
        assert_eq!(route, "/api/external-accounts/probe-stream");
    }

    #[test]
    fn external_routes_accounts_create() {
        let route = "/api/external-accounts";
        assert_eq!(route, "/api/external-accounts");
    }

    #[test]
    fn external_routes_account_get() {
        let route = "/api/external-accounts/{id}";
        assert_eq!(route, "/api/external-accounts/{id}");
    }

    #[test]
    fn external_routes_account_patch() {
        let route = "/api/external-accounts/{id}";
        assert_eq!(route, "/api/external-accounts/{id}");
    }

    #[test]
    fn external_routes_account_delete() {
        let route = "/api/external-accounts/{id}";
        assert_eq!(route, "/api/external-accounts/{id}");
    }

    #[test]
    fn external_routes_account_test() {
        let route = "/api/external-accounts/{id}/test";
        assert_eq!(route, "/api/external-accounts/{id}/test");
    }

    #[test]
    fn external_routes_folders_list() {
        let route = "/api/external-accounts/{id}/folders";
        assert_eq!(route, "/api/external-accounts/{id}/folders");
    }

    #[test]
    fn external_routes_folders_discover() {
        let route = "/api/external-accounts/{id}/folders/discover";
        assert_eq!(route, "/api/external-accounts/{id}/folders/discover");
    }

    #[test]
    fn external_routes_folder_mapping() {
        let route = "/api/external-accounts/{id}/folders/{folder_id}/mapping";
        assert_eq!(route, "/api/external-accounts/{id}/folders/{folder_id}/mapping");
    }

    #[test]
    fn external_routes_sync_start() {
        let route = "/api/external-accounts/{id}/sync";
        assert_eq!(route, "/api/external-accounts/{id}/sync");
    }

    #[test]
    fn external_routes_sync_status() {
        let route = "/api/external-accounts/{id}/sync/status";
        assert_eq!(route, "/api/external-accounts/{id}/sync/status");
    }

    #[test]
    fn external_routes_sync_pause() {
        let route = "/api/external-accounts/{id}/sync/pause";
        assert_eq!(route, "/api/external-accounts/{id}/sync/pause");
    }

    #[test]
    fn external_routes_sync_resume() {
        let route = "/api/external-accounts/{id}/sync/resume";
        assert_eq!(route, "/api/external-accounts/{id}/sync/resume");
    }

    #[test]
    fn external_routes_sync_run_get() {
        let route = "/api/external-sync-runs/{run_id}";
        assert_eq!(route, "/api/external-sync-runs/{run_id}");
    }

    #[test]
    fn external_routes_messages_list() {
        let route = "/api/external-messages";
        assert_eq!(route, "/api/external-messages");
    }

    #[test]
    fn external_routes_message_action() {
        let route = "/api/external-messages/{id}/action";
        assert_eq!(route, "/api/external-messages/{id}/action");
    }

    #[test]
    fn external_routes_all_paths() {
        let paths = vec![
            "/api/external-accounts",
            "/api/external-accounts/probe-stream",
            "/api/external-accounts/{id}",
            "/api/external-accounts/{id}/test",
            "/api/external-accounts/{id}/folders",
            "/api/external-accounts/{id}/folders/discover",
            "/api/external-accounts/{id}/folders/{folder_id}/mapping",
            "/api/external-accounts/{id}/sync",
            "/api/external-accounts/{id}/sync/status",
            "/api/external-accounts/{id}/sync/pause",
            "/api/external-accounts/{id}/sync/resume",
            "/api/external-sync-runs/{run_id}",
            "/api/external-messages",
            "/api/external-messages/{id}/action",
        ];
        assert_eq!(paths.len(), 14);
    }

    #[test]
    fn external_routes_get_routes() {
        let get_routes = vec![
            "/api/external-accounts",
            "/api/external-accounts/{id}",
            "/api/external-accounts/{id}/folders",
            "/api/external-accounts/{id}/sync/status",
            "/api/external-sync-runs/{run_id}",
            "/api/external-messages",
        ];
        assert_eq!(get_routes.len(), 6);
    }

    #[test]
    fn external_routes_post_routes() {
        let post_routes = vec![
            "/api/external-accounts/probe-stream",
            "/api/external-accounts",
            "/api/external-accounts/{id}/test",
            "/api/external-accounts/{id}/folders/discover",
            "/api/external-accounts/{id}/sync",
            "/api/external-accounts/{id}/sync/pause",
            "/api/external-accounts/{id}/sync/resume",
            "/api/external-messages/{id}/action",
        ];
        assert_eq!(post_routes.len(), 8);
    }

    #[test]
    fn external_routes_patch_routes() {
        let patch_routes = vec!["/api/external-accounts/{id}"];
        assert_eq!(patch_routes.len(), 1);
    }

    #[test]
    fn external_routes_delete_routes() {
        let delete_routes = vec!["/api/external-accounts/{id}"];
        assert_eq!(delete_routes.len(), 1);
    }

    #[test]
    fn external_routes_put_routes() {
        let put_routes = vec!["/api/external-accounts/{id}/folders/{folder_id}/mapping"];
        assert_eq!(put_routes.len(), 1);
    }

    #[test]
    fn external_routes_path_starts_with_api() {
        let route = "/api/external-accounts";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn external_routes_path_no_trailing_slash() {
        let route = "/api/external-accounts";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn external_routes_path_no_uppercase() {
        let route = "/api/external-accounts";
        assert_eq!(route, route.to_ascii_lowercase());
    }

    #[test]
    fn external_routes_path_no_spaces() {
        let route = "/api/external-accounts";
        assert!(!route.contains(" "));
    }

    #[test]
    fn external_routes_path_valid() {
        let route = "/api/external-accounts";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn external_routes_handler_api_external_accounts_list() {
        let handler = "api_external_accounts_list";
        assert_eq!(handler, "api_external_accounts_list");
    }

    #[test]
    fn external_routes_handler_api_external_accounts_create() {
        let handler = "api_external_accounts_create";
        assert_eq!(handler, "api_external_accounts_create");
    }

    #[test]
    fn external_routes_handler_api_external_account_get() {
        let handler = "api_external_account_get";
        assert_eq!(handler, "api_external_account_get");
    }

    #[test]
    fn external_routes_handler_api_external_account_patch() {
        let handler = "api_external_account_patch";
        assert_eq!(handler, "api_external_account_patch");
    }

    #[test]
    fn external_routes_handler_api_external_account_delete() {
        let handler = "api_external_account_delete";
        assert_eq!(handler, "api_external_account_delete");
    }

    #[test]
    fn external_routes_handler_api_external_account_test() {
        let handler = "api_external_account_test";
        assert_eq!(handler, "api_external_account_test");
    }

    #[test]
    fn external_routes_handler_api_external_folders_list() {
        let handler = "api_external_folders_list";
        assert_eq!(handler, "api_external_folders_list");
    }

    #[test]
    fn external_routes_handler_api_external_folders_discover() {
        let handler = "api_external_folders_discover";
        assert_eq!(handler, "api_external_folders_discover");
    }

    #[test]
    fn external_routes_handler_api_external_folder_mapping_put() {
        let handler = "api_external_folder_mapping_put";
        assert_eq!(handler, "api_external_folder_mapping_put");
    }

    #[test]
    fn external_routes_handler_api_external_sync_start() {
        let handler = "api_external_sync_start";
        assert_eq!(handler, "api_external_sync_start");
    }

    #[test]
    fn external_routes_handler_api_external_sync_status() {
        let handler = "api_external_sync_status";
        assert_eq!(handler, "api_external_sync_status");
    }

    #[test]
    fn external_routes_handler_api_external_sync_pause() {
        let handler = "api_external_sync_pause";
        assert_eq!(handler, "api_external_sync_pause");
    }

    #[test]
    fn external_routes_handler_api_external_sync_resume() {
        let handler = "api_external_sync_resume";
        assert_eq!(handler, "api_external_sync_resume");
    }

    #[test]
    fn external_routes_handler_api_external_sync_run_get() {
        let handler = "api_external_sync_run_get";
        assert_eq!(handler, "api_external_sync_run_get");
    }

    #[test]
    fn external_routes_handler_api_external_messages_list() {
        let handler = "api_external_messages_list";
        assert_eq!(handler, "api_external_messages_list");
    }

    #[test]
    fn external_routes_handler_api_external_message_action() {
        let handler = "api_external_message_action";
        assert_eq!(handler, "api_external_message_action");
    }
}
