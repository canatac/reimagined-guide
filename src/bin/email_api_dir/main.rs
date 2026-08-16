/*
This is an API server implementation for the SMTP service.

To run this API server, use the following command from the project root:

cargo run --bin email_api

Make sure you have set the necessary environment variables in your .env file:
    API_SERVER_ADDR: The address and port for the API server (e.g., "127.0.0.1:3000")
    SMTP_USERNAME: Your SMTP username
    SMTP_PASSWORD: Your SMTP password
    FULLCHAIN_PATH: Path to your SSL certificate chain file

The API server provides the following endpoint:

POST /send_email
    Accepts JSON payload with the following structure:
    {
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Test Email",
        "body": "This is a test email sent via the API server."
    }

Example usage with curl:
curl -X POST http://localhost:3000/send_email \
     -H "Content-Type: application/json" \
     -d '{
         "from": "sender@example.com",
         "to": "recipient@example.com",
         "subject": "Test Email",
         "body": "This is a test email sent via the API server."
     }'

The API server will attempt to send the email using the SMTP client and return the result.
*/

use actix_cors::Cors;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::{engine::general_purpose, Engine as _};
use bcrypt;
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

// PR1 (RBAC admin) — module local, gated par ADMIN_RBAC_ENFORCE (feature flag).
// Ne modifie AUCUN comportement tant que le flag est OFF (défaut).
#[path = "admin_auth.rs"]
mod admin_auth;
mod auth_handlers;
mod monitoring_handlers;
mod mailbox;
mod admin_ops;
mod external_handlers;
mod external_probe_handlers;
mod helpers;
mod event_bus;
mod deliverability_dto;
mod mailing_list;
mod dkim_service;
#[cfg(test)] mod main_tests;
pub use event_bus::*;
pub use deliverability_dto::*;
pub use mailing_list::*;
pub use dkim_service::*;
use helpers::{normalize_segment, build_misfits_local, normalize_oauth_provider, req_ip_str, get_accept_language, welcome_email_html};

pub use auth_handlers::*;
pub use monitoring_handlers::*;
pub use mailbox::*;
pub use admin_ops::*;
pub use external_handlers::*;

use sha1::Sha1;

use chrono::{DateTime, Utc};
use dotenv::dotenv;
use futures_util::{stream, TryStreamExt};
use mongodb::bson;
use mongodb::bson::doc;
use reqwest;
use simple_smtp_server::entities::{
    AdminUserActivity, AdminUserRecord, CalendarEvent, ChangeRequestItem, Email, WorkflowEvent,
    WorkflowStage,
};
use simple_smtp_server::external_imap::{
    CreateExternalAccountInput, ExternalFolderMappingInput, ExternalImapService,
    ExternalMessageActionInput, StartSyncInput, UpdateExternalAccountInput,
};
use simple_smtp_server::i18n;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::smtp_client::send_outgoing_email;
use std::collections::HashMap;
use std::env;
use std::fs::{create_dir_all, File};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

// --- Mail event monitoring ---
// event bus + auth DTOs → event_bus.rs

// ===========================================================================
// SMTP Monitoring endpoints
// ===========================================================================

use simple_smtp_server::monitoring;
use simple_smtp_server::monitoring::alerts::AlertConfig;
use simple_smtp_server::monitoring::storage;
use simple_smtp_server::security;

// parse_window, since_str, env_bool, monitoring query types, dns_txt_lookup
// api_monitoring_*, SecurityAlertsQuery, api_security_*
// → moved to monitoring_handlers module



// ↑ monitoring/security handlers moved to monitoring_handlers module ↑



// deliverability DTOs → deliverability_dto.rs

/// GET /api/monitoring/summary?window=15m
// monitoring + security handlers → monitoring_handlers module


#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct EmailRequest {
    from: String,
    to: String,
    subject: String,
    body: String,
}

// mailing list → mailing_list.rs

async fn send_email_handler(
    email_req: web::Json<EmailRequest>,
    dkim_service: web::Data<Box<dyn DkimService>>,
) -> impl Responder {
    println!("Received email request");

    match dkim_service.sign_email(&email_req).await {
        Ok(dkim_result) => {
            println!("DKIM service returned success");
            let message_id = dkim_result["messageId"].as_str().unwrap_or("");
            match dkim_result["status"].as_str() {
                Some("success") => {
                    let sig = dkim_result["dkimSignature"]
                        .as_str()
                        .or_else(|| dkim_result["dkim_signature"].as_str())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if sig.is_empty() {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "status": "error",
                            "message": "DKIM service returned success without a DKIM signature",
                        }));
                    }

                    // Construct the email with DKIM signature
                    let email = Email {
                        id: Uuid::new_v4().to_string(),
                        from: email_req.from.clone(),
                        to: email_req.to.clone(),
                        subject: email_req.subject.clone(),
                        body: email_req.body.clone(),
                        headers: vec![("DKIM-Signature".to_string(), sig.clone())],
                        flags: vec![],
                        sequence_number: 0,
                        uid: 0,
                        internal_date: mongodb::bson::DateTime::from_millis(
                            Utc::now().timestamp_millis(),
                        ),
                        dkim_signature: Some(sig),
                    };

                    // Send the email
                    match send_outgoing_email(&email).await {
                        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                            "status": "success",
                            "message": "Email signed and sent successfully",
                            "messageId": message_id
                        })),
                        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to send email: {}", e)
                        })),
                    }
                }
                _ => {
                    let error_message = dkim_result["message"].as_str().unwrap_or("Unknown error");
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "status": "error",
                        "message": format!("Failed to sign email: {}", error_message)
                    }))
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to call DKIM service: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": "Failed to generate DKIM signature"
            }))
        }
    }
}

// --- Auth handlers ---

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // rustls 0.23 requires an explicit process-level CryptoProvider.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Connect to MongoDB for auth
    let mongo_user = env::var("MONGODB_USERNAME").unwrap_or_default();
    let mongo_pass = env::var("MONGODB_PASSWORD").unwrap_or_default();
    let mongo_cluster =
        env::var("MONGODB_CLUSTER_URL").unwrap_or_else(|_| "mongodb:27017".to_string());
    let mongo_app = env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    // If MONGODB_CLUSTER_URL is already a full URI (e.g. from 1Password), use it directly.
    let client_uri = if mongo_cluster.starts_with("mongodb://")
        || mongo_cluster.starts_with("mongodb+srv://")
    {
        let base = mongo_cluster.trim_end_matches('&').trim_end_matches('?');
        // Use ? or & depending on whether query params already exist
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
    };

    let use_mongodb = env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true";

    let mongo_client = if use_mongodb && !mongo_user.is_empty() {
        match mongodb::Client::with_uri_str(&client_uri).await {
            Ok(c) => {
                let c = Arc::new(c);
                // Warm-up: force DNS resolution + TLS + MongoDB handshake at startup
                // so the first user login is not delayed by 10-30s.
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
    } else {
        None
    };

    let fallback_client = Arc::new(
        mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await
            .unwrap(),
    );
    let shared_mongo = mongo_client
        .clone()
        .unwrap_or_else(|| fallback_client.clone());
    let logic = web::Data::new(Arc::new(Logic::new(
        mongo_client.unwrap_or(fallback_client),
    )));
    let mongo_data = web::Data::new(shared_mongo.clone());
    let external_imap_service =
        web::Data::new(Arc::new(ExternalImapService::new(shared_mongo.clone())));

    let (event_tx, _) = broadcast::channel::<MailEvent>(256);
    let event_bus = web::Data::new(event_tx);

    // Init global SMTP monitoring bus + background persistence task
    monitoring::init_bus();
    monitoring::storage::start_persistence_task(shared_mongo.clone());
    let shared_mongo_idx = shared_mongo.clone();
    tokio::spawn(async move {
        monitoring::storage::ensure_indexes(&shared_mongo_idx).await;
    });

    // Init security monitoring bus + background evaluation engine
    security::init_bus();
    let sec_mongo = shared_mongo.clone();
    tokio::spawn(async move {
        security::audit::ensure_indexes(&sec_mongo).await;
    });
    security::audit::start_engine(shared_mongo.clone());

    // Start send queue background worker
    let sq_mongo = shared_mongo.clone();
    tokio::spawn(send_queue_worker(sq_mongo));

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(
            env::var("PRIVKEY_PATH").expect("PRIVKEY_PATH must be set"),
            SslFiletype::PEM,
        )
        .unwrap();
    builder
        .set_certificate_chain_file(env::var("FULLCHAIN_PATH").expect("FULLCHAIN_PATH must be set"))
        .unwrap();

    // Start HTTP server on 8000 (for frontend proxy, no TLS)
    let http_logic = logic.clone();
    let http_mongo = mongo_data.clone();
    let http_event_bus = event_bus.clone();
    let http_external_imap = external_imap_service.clone();
    let http_addr = env::var("API_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".to_string());
    let http_server = actix_web::rt::spawn(async move {
        HttpServer::new(move || {
            let cors = Cors::permissive()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .supports_credentials()
                .max_age(3600);

            App::new()
                .wrap(cors)
                .app_data(http_logic.clone())
                .app_data(http_mongo.clone())
                .app_data(http_event_bus.clone())
                .app_data(http_external_imap.clone())
                .route("/api/openapi.json", web::get().to(api_openapi_json))
                .route("/api/docs", web::get().to(api_swagger_ui))
                .route(
                    "/api/openapi/external-imap.yaml",
                    web::get().to(api_external_openapi),
                )
                .route(
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
                )
                .route("/api/auth/login", web::post().to(auth_login))
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
                )
                .route("/api/emails", web::get().to(api_emails))
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
                )
                .route("/api/events", web::get().to(api_events))
                .route("/api/events/stream", web::get().to(api_events_stream))
                // SMTP monitoring
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
                // Security endpoints
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
                )
                .route("/api/admin/users", web::get().to(api_admin_users_list))
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
                )
        })
        .bind(http_addr)
        .expect("Failed to bind HTTP on 8000")
        .run()
        .await
        .expect("HTTP server error");
    });

    // Start HTTPS server on 8443 (original API)
    HttpServer::new(|| {
        let cors = Cors::permissive()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .app_data(web::Data::new(RealDkimService))
            .route("/send-email", web::post().to(send_email_handler))
            .route("/create-mailing-list", web::post().to(create_mailing_list))
            .route(
                "/send-to-mailing-list",
                web::post().to(send_to_mailing_list),
            )
    })
    .bind_openssl("0.0.0.0:8443", builder)?
    .run()
    .await
}

// tests → main_tests.rs

// impl DkimService → dkim_service.rs
