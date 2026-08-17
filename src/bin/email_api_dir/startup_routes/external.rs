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
