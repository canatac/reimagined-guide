//! Startup helpers for the email_api binary.
//!
//! Extracted from `main.rs` to keep `main()` under the 150 LOC budget imposed
//! by `scripts/arch_guard.sh`. No behaviour change: these helpers reproduce
//! the exact same logic (env vars, URI shape, CORS config, HTTP route table)
//! that previously lived inline in `main`.

use actix_cors::Cors;
use actix_web::web;
use std::env;
use std::sync::Arc;

use super::*;

/// Build the MongoDB client URI from env vars, matching the historical logic.
pub(crate) fn build_mongo_uri() -> String {
    let mongo_user = env::var("MONGODB_USERNAME").unwrap_or_default();
    let mongo_pass = env::var("MONGODB_PASSWORD").unwrap_or_default();
    let mongo_cluster =
        env::var("MONGODB_CLUSTER_URL").unwrap_or_else(|_| "mongodb:27017".to_string());
    let mongo_app = env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    if mongo_cluster.starts_with("mongodb://") || mongo_cluster.starts_with("mongodb+srv://") {
        let base = mongo_cluster.trim_end_matches('&').trim_end_matches('?');
        let sep = if base.contains('?') { "&" } else { "?" };
        format!(
            "{}{}appName={}&serverSelectionTimeoutMS=5000",
            base, sep, mongo_app
        )
    } else if mongo_cluster.contains(".mongodb.net") {
        format!("mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000", mongo_user, mongo_pass, mongo_cluster, mongo_app)
    } else {
        format!(
            "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
            mongo_user, mongo_pass, mongo_cluster, mongo_app
        )
    }
}

/// Attempt to connect to MongoDB (with warm-up ping) if enabled via env.
pub(crate) async fn connect_mongo_optional(
    client_uri: &str,
) -> Option<Arc<mongodb::Client>> {
    let mongo_user = env::var("MONGODB_USERNAME").unwrap_or_default();
    let use_mongodb = env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true";
    if !(use_mongodb && !mongo_user.is_empty()) {
        return None;
    }
    match mongodb::Client::with_uri_str(client_uri).await {
        Ok(c) => {
            let c = Arc::new(c);
            if let Err(e) = c
                .database("admin")
                .run_command(mongodb::bson::doc! {"ping": 1})
                .await
            {
                eprintln!("MongoDB warm-up ping failed (non-fatal): {}", e);
            } else {
                println!("MongoDB connection ready.");
            }
            Some(c)
        }
        Err(e) => {
            eprintln!("MongoDB connection failed: {}, auth will use env vars", e);
            None
        }
    }
}

/// Build the permissive CORS layer used by both HTTP and HTTPS servers.
pub(crate) fn build_cors_layer() -> Cors {
    Cors::permissive()
        .allow_any_origin()
        .allow_any_method()
        .allow_any_header()
        .supports_credentials()
        .max_age(3600)
}

/// Documentation & OpenAPI routes.
fn register_docs_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/openapi.json", web::get().to(api_openapi_json))
        .route("/api/docs", web::get().to(api_swagger_ui))
        .route(
            "/api/openapi/external-imap.yaml",
            web::get().to(api_external_openapi),
        );
}

/// External IMAP account routes.
fn register_external_routes(cfg: &mut web::ServiceConfig) {
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

/// Auth & user session routes.
fn register_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/auth/login", web::post().to(auth_login))
        .route("/api/auth/register", web::post().to(auth_register))
        .route("/api/auth/logout", web::post().to(auth_logout))
        .route("/api/auth/refresh", web::post().to(auth_refresh))
        .route("/api/auth/2fa/verify", web::post().to(api_2fa_verify))
        .route(
            "/api/auth/password-reset/request",
            web::post().to(api_password_reset_request),
        )
        .route(
            "/api/auth/password-reset/confirm",
            web::post().to(api_password_reset_confirm),
        )
        .route("/api/user/locale", web::patch().to(api_patch_user_locale))
        .route(
            "/api/auth/oauth/{provider}",
            web::get().to(auth_oauth_start),
        )
        .route(
            "/api/auth/oauth/{provider}/start",
            web::get().to(auth_oauth_start),
        )
        .route(
            "/api/auth/oauth/{provider}/callback",
            web::get().to(auth_oauth_callback),
        );
}

/// Mailbox / send / drafts / templates / hermes / calendar routes.
fn register_mailbox_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/emails", web::get().to(api_emails))
        .route("/api/emails/{id}", web::get().to(api_email_by_id))
        .route(
            "/api/emails/{id}/attachments/{attachment_id}",
            web::get().to(api_email_attachment_download),
        )
        .route("/api/emails/{id}/action", web::post().to(api_email_action))
        .route("/api/tags", web::get().to(api_tags))
        .route("/api/send", web::post().to(api_send))
        .route("/api/send/{id}/status", web::get().to(api_send_status))
        .route("/api/drafts", web::get().to(api_drafts_list))
        .route("/api/drafts", web::post().to(api_drafts_upsert))
        .route("/api/drafts/{id}", web::delete().to(api_drafts_delete))
        .route("/api/templates", web::get().to(api_templates))
        .route("/api/settings/ai", web::get().to(api_get_ai_settings))
        .route("/api/settings/ai", web::put().to(api_put_ai_settings))
        .route("/api/hermes/chat", web::post().to(api_hermes_chat))
        .route("/api/hermes/runs", web::get().to(api_hermes_runs_list))
        .route("/api/hermes/runs", web::post().to(api_hermes_runs))
        .route(
            "/api/hermes/runs/{run_id}",
            web::get().to(api_hermes_run_status),
        )
        .route(
            "/api/hermes/runs/{run_id}/events",
            web::get().to(api_hermes_run_events),
        )
        .route("/api/send/undo", web::post().to(api_send_undo))
        .route("/api/send/schedule", web::post().to(api_send_schedule))
        .route(
            "/api/calendar/events",
            web::post().to(calendar_create_event),
        )
        .route("/api/calendar/events", web::get().to(calendar_list_events))
        .route(
            "/api/calendar/events/{id}",
            web::get().to(calendar_get_event),
        )
        .route(
            "/api/calendar/events/{id}",
            web::put().to(calendar_update_event),
        )
        .route(
            "/api/calendar/events/{id}",
            web::delete().to(calendar_delete_event),
        )
        .route("/send-email", web::post().to(send_email_handler))
        .route("/create-mailing-list", web::post().to(create_mailing_list))
        .route(
            "/send-to-mailing-list",
            web::post().to(send_to_mailing_list),
        );
}

/// Monitoring / security / diagnostics routes.
fn register_diag_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/events", web::get().to(api_events))
        .route("/api/events/stream", web::get().to(api_events_stream))
        .route(
            "/api/monitoring/summary",
            web::get().to(api_monitoring_summary),
        )
        .route(
            "/api/monitoring/events",
            web::get().to(api_monitoring_events),
        )
        .route(
            "/api/monitoring/messages/{message_id}/trace",
            web::get().to(api_monitoring_trace),
        )
        .route(
            "/api/monitoring/bounces",
            web::get().to(api_monitoring_bounces),
        )
        .route(
            "/api/monitoring/providers/top",
            web::get().to(api_monitoring_providers_top),
        )
        .route("/api/monitoring/live", web::get().to(api_monitoring_live))
        .route(
            "/api/monitoring/alerts/active",
            web::get().to(api_monitoring_alerts_active),
        )
        .route(
            "/api/security/alerts/active",
            web::get().to(api_security_alerts_active),
        )
        .route(
            "/api/security/incidents",
            web::get().to(api_security_incidents),
        )
        .route("/api/security/live", web::get().to(api_security_live))
        .route(
            "/api/security/tenant/{id}/status",
            web::get().to(api_security_tenant_status),
        )
        .route(
            "/api/security/remediation/{alert_id}/rollback",
            web::post().to(api_security_rollback),
        );
}

/// Admin routes (users, change-requests, deliverability, observability).
fn register_admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/admin/users", web::get().to(api_admin_users_list))
        .route("/api/admin/users", web::post().to(api_admin_user_create))
        .route("/api/admin/whoami", web::get().to(api_admin_whoami))
        .route("/api/admin/audit-log", web::get().to(api_admin_audit_log))
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

/// Register all HTTP routes on the given ServiceConfig.
///
/// Composed from domain-specific registrations to keep each helper small.
pub(crate) fn register_http_routes(cfg: &mut web::ServiceConfig) {
    register_docs_routes(cfg);
    register_external_routes(cfg);
    register_auth_routes(cfg);
    register_mailbox_routes(cfg);
    register_diag_routes(cfg);
    register_admin_routes(cfg);
}
