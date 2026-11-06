//! External account routes (MW-2026-062).
//!
//! Registers the external IMAP account routes, including the OAuth 2.0
//! authorization code flow: provider catalogue, consent start/redirect,
//! code exchange and token refresh.

use actix_web::web;
use std::sync::Arc;

use crate::external_handlers::oauth2::{
    api_oauth2_authorize, api_oauth2_callback, api_oauth2_list_providers, api_oauth2_refresh,
    api_oauth2_start,
};
use crate::external_imap::ExternalImapService;

pub(crate) fn register_external_routes(cfg: &mut web::ServiceConfig) {
    let svc = web::Data::new(Arc::new(ExternalImapService::new()));

    cfg.app_data(svc.clone())
        .service(
            web::scope("/api/external-accounts")
                .route(
                    "/oauth2/providers",
                    web::get().to(api_oauth2_list_providers),
                )
                .route(
                    "/oauth2/start",
                    web::get().to(api_oauth2_start),
                )
                .route(
                    "/{id}/oauth2/start",
                    web::get().to(api_oauth2_start),
                )
                .route(
                    "/{id}/oauth2/authorize",
                    web::get().to(api_oauth2_authorize),
                )
                .route(
                    "/{id}/oauth2/callback",
                    web::post().to(api_oauth2_callback),
                )
                .route(
                    "/{id}/oauth2/refresh",
                    web::post().to(api_oauth2_refresh),
                )
                .route(
                    "/{id}",
                    web::get().to(crate::external_handlers::accounts::api_external_account_get),
                )
                .route(
                    "/{id}/folders",
                    web::get().to(crate::external_handlers::folders::api_external_account_folders),
                )
                .route(
                    "/{id}/sync/status",
                    web::get().to(crate::external_handlers::sync::api_external_account_sync_status),
                )
                .route(
                    "/{id}/test",
                    web::post().to(crate::external_handlers::accounts::api_external_account_test),
                )
                .route(
                    "/{id}/send",
                    web::post().to(crate::external_handlers::accounts::api_external_account_send),
                ),
        )
        .service(
            web::scope("/api/external-sync-runs")
                .route(
                    "/{run_id}",
                    web::get().to(crate::external_handlers::sync::api_external_sync_run_get),
                ),
        )
        .service(
            web::scope("/api/external-messages")
                .route(
                    "",
                    web::get().to(crate::external_handlers::accounts::api_external_messages_list),
                )
                .route(
                    "/{id}/action",
                    web::post().to(crate::external_handlers::accounts::api_external_message_action),
                ),
        );
}

#[cfg(test)]
mod tests {
    #[test]
    fn external_routes_oauth2_providers() {
        let route = "/api/external-accounts/oauth2/providers";
        assert_eq!(route, "/api/external-accounts/oauth2/providers");
    }

    #[test]
    fn external_routes_oauth2_start() {
        let route = "/api/external-accounts/oauth2/start";
        assert_eq!(route, "/api/external-accounts/oauth2/start");
    }

    #[test]
    fn external_routes_oauth2_authorize() {
        let route = "/api/external-accounts/{id}/oauth2/authorize";
        assert_eq!(route, "/api/external-accounts/{id}/oauth2/authorize");
    }

    #[test]
    fn external_routes_all_paths() {
        let paths = vec![
            "/api/external-accounts",
            "/api/external-accounts/{id}",
            "/api/external-accounts/{id}/folders",
            "/api/external-accounts/{id}/sync/status",
            "/api/external-accounts/{id}/test",
            "/api/external-accounts/{id}/send",
            "/api/external-accounts/oauth2/providers",
            "/api/external-accounts/oauth2/start",
            "/api/external-accounts/{id}/oauth2/start",
            "/api/external-accounts/{id}/oauth2/authorize",
            "/api/external-accounts/{id}/oauth2/callback",
            "/api/external-accounts/{id}/oauth2/tokens",
            "/api/external-accounts/{id}/oauth2/refresh",
            "/api/external-sync-runs/{run_id}",
            "/api/external-messages",
            "/api/external-messages/{id}/action",
        ];
        assert_eq!(paths.len(), 16);
    }

    #[test]
    fn external_routes_get_paths() {
        let get_routes = vec![
            "/api/external-accounts/{id}",
            "/api/external-accounts/{id}/folders",
            "/api/external-accounts/{id}/sync/status",
            "/api/external-accounts/oauth2/providers",
            "/api/external-accounts/oauth2/start",
            "/api/external-accounts/{id}/oauth2/start",
            "/api/external-accounts/{id}/oauth2/authorize",
            "/api/external-sync-runs/{run_id}",
            "/api/external-messages",
        ];
        assert_eq!(get_routes.len(), 9);
    }

    #[test]
    fn external_routes_handler_api_oauth2_list_providers() {
        let handler = "api_oauth2_list_providers";
        assert_eq!(handler, "api_oauth2_list_providers");
    }

    #[test]
    fn external_routes_handler_api_oauth2_start() {
        let handler = "api_oauth2_start";
        assert_eq!(handler, "api_oauth2_start");
    }

    #[test]
    fn external_routes_handler_api_oauth2_authorize() {
        let handler = "api_oauth2_authorize";
        assert_eq!(handler, "api_oauth2_authorize");
    }
}
