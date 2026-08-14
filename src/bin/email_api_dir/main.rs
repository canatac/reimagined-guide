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
mod mailbox_handlers;
mod admin_ops;
mod external_handlers;

pub use auth_handlers::*;
pub use monitoring_handlers::*;
pub use mailbox_handlers::*;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MailEventKind {
    Sent,
    Received,
    Read,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MailEvent {
    id: String,
    kind: MailEventKind,
    user_id: String,
    email_id: String,
    subject: String,
    from: String,
    to: String,
    timestamp: String,
}

type EventBus = broadcast::Sender<MailEvent>;

// --- Shared auth types (moved to auth_handlers.rs) ---
// LoginRequest, RegisterRequest, OAuthCallbackQuery, TwoFactorVerifyRequest
// PasswordResetRequestBody, PasswordResetConfirmBody are in auth_handlers module.

// --- 2FA default helper (still needed by main.rs serde defaults) ---

// --- Send queue types ---

const SEND_QUEUE_COLL: &str = "send_queue";

#[derive(Deserialize)]
struct UndoSendRequest {
    id: String,
}

#[derive(Deserialize)]
struct ScheduleSendBody {
    #[serde(default)]
    to: Vec<ComposerRecipient>,
    #[serde(default)]
    cc: Vec<ComposerRecipient>,
    #[serde(default)]
    bcc: Vec<ComposerRecipient>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    from: Option<String>,
    send_at: String,
}

// --- OAuth provider response types ---

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    email: String,
    display_name: String,
    role: String,
    two_factor_enabled: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct SessionResponse {
    id: String,
    user: UserResponse,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    refresh_expires_at: u64,
    issued_at: u64,
}

#[derive(Serialize)]
struct AuthResponse {
    session: SessionResponse,
}

// make_session, verify_totp, generate_totp_secret, generate_otp_code
// → moved to auth_handlers module



async fn persist_event(mongo: &mongodb::Client, event: &MailEvent) {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("mail_events");
    if let Ok(doc) = bson::to_document(event) {
        if let Err(e) = coll.insert_one(doc).await {
            eprintln!("persist_event error: {}", e);
        }
    }
}

async fn emit_event(bus: &EventBus, mongo: &mongodb::Client, event: MailEvent) {
    persist_event(mongo, &event).await;
    let _ = bus.send(event);
}

async fn api_events(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("mail_events");
    let filter = doc! { "user_id": &user_id };
    match coll
        .find(filter)
        .sort(doc! { "timestamp": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => match cursor.try_collect::<Vec<_>>().await {
            Ok(docs) => {
                let events: Vec<serde_json::Value> = docs
                    .into_iter()
                    .filter_map(|d| bson::from_document::<MailEvent>(d).ok())
                    .filter_map(|e| serde_json::to_value(&e).ok())
                    .collect();
                HttpResponse::Ok().json(serde_json::json!({ "events": events }))
            }
            Err(e) => HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() })),
        },
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

async fn api_events_stream(bus: web::Data<EventBus>, req: actix_web::HttpRequest) -> HttpResponse {
    let user_id = resolve_user_id(&req);
    let rx = bus.subscribe();
    let event_stream = stream::unfold((rx, user_id), |(mut rx, uid)| async move {
        loop {
            match rx.recv().await {
                Ok(event) if event.user_id == uid => {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    let chunk = format!("data: {}\n\n", data);
                    return Some((
                        Ok::<web::Bytes, actix_web::Error>(web::Bytes::from(chunk)),
                        (rx, uid),
                    ));
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(event_stream)
}

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



#[derive(Deserialize)]
struct DeliverabilityDiagnosticsQuery {
    #[serde(default = "default_window")]
    window: String,
    domain: Option<String>,
}

#[derive(Deserialize)]
struct DeliverabilityProcedureUpdateRequest {
    checklist: Option<Vec<DeliverabilityChecklistUpdate>>,
    reminder: Option<DeliverabilityReminderUpdate>,
}

#[derive(Deserialize)]
struct DeliverabilityChecklistUpdate {
    id: String,
    checked: bool,
    note: Option<String>,
}

#[derive(Deserialize)]
struct DeliverabilityReminderUpdate {
    enabled: bool,
    cadence_hours: u32,
}

/// GET /api/monitoring/summary?window=15m
// monitoring + security handlers → monitoring_handlers module


fn normalize_segment(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' => 'i',
            'ô' | 'ö' => 'o',
            'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            'æ' => 'a',
            'œ' => 'o',
            _ => c,
        })
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Retourne `prenom.nom` normalisé, ou None si prénom ou nom est absent.
fn build_misfits_local(first_name: &str, last_name: &str) -> Option<String> {
    let first = normalize_segment(first_name.trim());
    let last = normalize_segment(last_name.trim());
    if first.is_empty() || last.is_empty() {
        return None;
    }
    Some(format!("{}.{}", first, last))
}

fn normalize_oauth_provider(provider: &str) -> Option<String> {
    let p = provider.trim().to_ascii_lowercase();
    match p.as_str() {
        "github" => Some(p),
        _ => None,
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct EmailRequest {
    from: String,
    to: String,
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct MailingListRequest {
    label: String,
    emails: Vec<String>,
}

#[derive(Deserialize)]
struct MailingListEmailRequest {
    from: String,
    subject: String,
    body: String,
    mailing_list: String,
}

async fn create_mailing_list(mailing_list: web::Json<MailingListRequest>) -> impl Responder {
    let mailing_list_dir = Path::new("mailing-lists");
    if !mailing_list_dir.exists() {
        if let Err(e) = create_dir_all(mailing_list_dir) {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to create mailing list directory: {}", e)
            }));
        }
    }

    let file_path = mailing_list_dir.join(format!("{}.csv", mailing_list.label));
    let mut file = match File::create(&file_path) {
        Ok(file) => file,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to create file: {}", e)
            }))
        }
    };

    for email in &mailing_list.emails {
        if let Err(e) = writeln!(file, "{}", email) {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to write to file: {}", e)
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Mailing list '{}' created successfully", mailing_list.label)
    }))
}

async fn send_to_mailing_list(email_req: web::Json<MailingListEmailRequest>) -> impl Responder {
    let mailing_list_path =
        Path::new("mailing-lists").join(format!("{}.csv", email_req.mailing_list));

    if !mailing_list_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "status": "error",
            "message": format!("Mailing list '{}' not found", email_req.mailing_list)
        }));
    }

    let file = match File::open(&mailing_list_path) {
        Ok(file) => file,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to open mailing list file: {}", e)
            }))
        }
    };

    let reader = BufReader::new(file);
    let mut success_count = 0;
    let mut failure_count = 0;

    for line in reader.lines() {
        let to_email = match line {
            Ok(email) => email.trim().to_string(),
            Err(_e) => {
                failure_count += 1;
                continue;
            }
        };

        let from = email_req.from.clone();
        let to = to_email;
        let subject = email_req.subject.clone();
        let body = email_req.body.clone();

        let _email_content = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
            from, to, subject, body
        );
        let client = reqwest::Client::new();
        let dkim_service_url = env::var("DKIM_SERVICE_URL").expect("DKIM_SERVICE_URL not set");

        let _dkim_response = match client
            .post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": from,
                "to": to,
                "subject": subject,
                "text": body
            }))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    success_count += 1;
                } else {
                    failure_count += 1;
                }
            }
            Err(_) => {
                failure_count += 1;
            }
        };
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Emails sent to mailing list '{}'. Successful: {}, Failed: {}",
                           email_req.mailing_list, success_count, failure_count)
    }))
}

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

fn req_ip_str(req: &actix_web::HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn get_accept_language(req: &actix_web::HttpRequest) -> String {
    req.headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn welcome_email_html(
    locale: &str,
    display_name: &str,
    primary_email: &str,
    alias_email: Option<&str>,
) -> String {
    let dir = if i18n::is_rtl(locale) { "rtl" } else { "ltr" };
    let text_align = if i18n::is_rtl(locale) {
        "right"
    } else {
        "left"
    };
    let greeting = i18n::t(locale, "email-welcome-greeting", &[("name", display_name)]);
    let intro = i18n::t(locale, "email-welcome-intro", &[]);
    let primary_label = i18n::t(locale, "email-welcome-primary-label", &[]);
    let cta = i18n::t(locale, "email-welcome-cta", &[]);
    let signature = i18n::t(locale, "email-welcome-signature", &[]);
    let alias_row = alias_email
        .map(|a| {
            let lbl = i18n::t(locale, "email-welcome-alias-label", &[]);
            let detail = i18n::t(locale, "email-welcome-alias-detail", &[]);
            format!(
                "<tr><td style=\"padding:4px 0\"><b>{lbl}</b> \
                 <span class=\"addr\">{a}</span> {detail}</td></tr>"
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html lang="{locale}" dir="{dir}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <style>
    body{{font-family:Tahoma,Arial,sans-serif;direction:{dir};text-align:{text_align};color:#222;background:#f5f5f5;margin:0;padding:0}}
    .wrap{{max-width:600px;margin:40px auto;background:#fff;border-radius:8px;padding:40px}}
    .addr{{font-family:monospace;background:#f0f0f0;padding:2px 6px;border-radius:3px}}
  </style>
</head>
<body><div class="wrap">
  <h2>{greeting}</h2>
  <p>{intro}</p>
  <table cellpadding="0" cellspacing="0">
    <tr><td style="padding:4px 0"><b>{primary_label}</b> <span class="addr">{primary_email}</span></td></tr>
    {alias_row}
  </table>
  <p>{cta}</p>
  <p>{signature}</p>
</div></body>
</html>"#,
    )
}

// auth_login..api_password_reset_confirm → auth_handlers module

// mailbox + send + drafts → mailbox_handlers module
// admin CRUD + change-requests + deliverability → admin_ops_handlers module

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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use dotenv::dotenv;
    use mockall::mock;
    use mockall::predicate::eq;

    mock! {
        pub DkimService {
            pub async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
        }
    }

    #[async_trait::async_trait]
    impl DkimService for MockDkimService {
        async fn sign_email(
            &self,
            email: &EmailRequest,
        ) -> Result<serde_json::Value, std::io::Error> {
            self.sign_email(email).await
        }
    }

    #[actix_web::test]
    async fn test_send_email() {
        dotenv::from_filename(".env.test").ok();

        let mut mock_dkim_service = MockDkimService::new();
        mock_dkim_service
            .expect_sign_email()
            .with(eq(EmailRequest {
                from: "sender@example.com".to_string(),
                to: "recipient@example.com".to_string(),
                subject: "Test Email".to_string(),
                body: "This is a test email.".to_string(),
            }))
            .times(1)
            .returning(|_| Ok(serde_json::json!({"status": "success", "messageId": "12345"})));

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(
                    Box::new(mock_dkim_service) as Box<dyn DkimService>
                ))
                .route("/send-email", web::post().to(send_email_handler)),
        )
        .await;

        let email_request = EmailRequest {
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test Email".to_string(),
            body: "This is a test email.".to_string(),
        };
        println!("Sending test request to /send-email");

        let req = test::TestRequest::post()
            .uri("/send-email")
            .set_json(&email_request)
            .to_request();
        let resp = test::call_service(&app, req).await;
        println!("Response status: {:?}", resp.status());
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_api_hermes_chat_requires_messages() {
        let app = test::init_service(
            App::new().route("/api/hermes/chat", web::post().to(api_hermes_chat)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/hermes/chat")
            .set_json(serde_json::json!({ "messages": [] }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_hermes_chat_request_accepts_explicit_session_overrides() {
        let parsed: HermesChatProxyRequest = serde_json::from_value(serde_json::json!({
            "messages": [{"role":"user","content":"hello"}],
            "threadId": "thread-123",
            "userId": "admin",
            "sessionId": "mail-thread-explicit",
            "sessionKey": "user-explicit",
            "maxTokens": 1200
        }))
        .expect("HermesChatProxyRequest should deserialize");

        assert_eq!(parsed.thread_id.as_deref(), Some("thread-123"));
        assert_eq!(parsed.user_id.as_deref(), Some("admin"));
        assert_eq!(parsed.session_id.as_deref(), Some("mail-thread-explicit"));
        assert_eq!(parsed.session_key.as_deref(), Some("user-explicit"));
        assert_eq!(parsed.max_tokens, Some(1200));
    }
    #[actix_web::test]
    async fn test_api_hermes_runs_requires_input() {
        let app = test::init_service(
            App::new().route("/api/hermes/runs", web::post().to(api_hermes_runs)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/hermes/runs")
            .set_json(serde_json::json!({}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_hermes_runs_request_accepts_explicit_session_overrides() {
        let parsed: HermesRunsProxyRequest = serde_json::from_value(serde_json::json!({
            "input": [{"role":"user","content":"hello"}],
            "threadId": "thread-123",
            "userId": "admin",
            "sessionId": "mail-thread-explicit",
            "sessionKey": "user-explicit",
            "model": "hermes-agent"
        }))
        .expect("HermesRunsProxyRequest should deserialize");

        assert!(parsed.input.is_some());
        assert_eq!(parsed.thread_id.as_deref(), Some("thread-123"));
        assert_eq!(parsed.user_id.as_deref(), Some("admin"));
        assert_eq!(parsed.session_id.as_deref(), Some("mail-thread-explicit"));
        assert_eq!(parsed.session_key.as_deref(), Some("user-explicit"));
        assert_eq!(parsed.model.as_deref(), Some("hermes-agent"));
    }

    #[test]
    fn test_normalize_hermes_base_url_strips_v1_and_slashes() {
        assert_eq!(
            normalize_hermes_base_url("http://172.16.12.2:8642/v1/"),
            "http://172.16.12.2:8642"
        );
        assert_eq!(
            normalize_hermes_base_url("http://172.16.12.2:8642/v1"),
            "http://172.16.12.2:8642"
        );
        assert_eq!(
            normalize_hermes_base_url("http://172.16.12.2:8642"),
            "http://172.16.12.2:8642"
        );
    }

    // ─── Sprint 1: Integration tests on critical flows ────────────────────────
    //
    // These tests exercise the HTTP handler shape (status codes, response
    // structure) without a live MongoDB or SMTP server. They verify:
    //  - Correct 4xx on bad / missing input
    //  - Response JSON shape on valid input (where the handler does not
    //    require a DB connection at the validation stage)
    //
    // Flow 1: POST /api/auth/login — rejects empty password
    #[actix_web::test]
    async fn test_auth_login_rejects_empty_password() {
        let app = test::init_service(
            App::new()
                .app_data(
                    web::JsonConfig::default()
                        .error_handler(|err, req| {
                            let resp = actix_web::HttpResponse::BadRequest()
                                .json(serde_json::json!({ "code": "INVALID_JSON", "message": err.to_string() }));
                            actix_web::error::InternalError::from_response(err, resp).into()
                        })
                )
                .route("/api/auth/login", web::post().to(auth_login)),
        )
        .await;

        // Missing password field → JSON parse error → 400
        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(serde_json::json!({ "email": "test@misfits.ai" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    // Flow 1b: POST /api/auth/login — correct shape → 200 or 401 (never 500)
    #[actix_web::test]
    async fn test_auth_login_valid_shape_returns_200_or_401() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return, // Skip if no test DB
        };
        let logic = web::Data::new(Arc::new(Logic::new(mongo.clone())));
        let mongo_data = web::Data::new(mongo);
        let bus_data = web::Data::new(EventBus::new());

        let app = test::init_service(
            App::new()
                .app_data(logic)
                .app_data(mongo_data)
                .app_data(bus_data)
                .route("/api/auth/login", web::post().to(auth_login)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(serde_json::json!({
                "email": "nonexistent@misfits.ai",
                "password": "wrongpassword"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status().as_u16();
        assert!(
            status == 200 || status == 401,
            "Expected 200 or 401, got {}",
            status
        );
    }

    // Flow 2: POST /api/auth/2fa/verify — rejects missing fields
    #[actix_web::test]
    async fn test_2fa_verify_rejects_missing_fields() {
        let app = test::init_service(
            App::new()
                .app_data(
                    web::JsonConfig::default().error_handler(|err, _req| {
                        let resp = actix_web::HttpResponse::BadRequest()
                            .json(serde_json::json!({ "verified": false, "error": err.to_string() }));
                        actix_web::error::InternalError::from_response(err, resp).into()
                    })
                )
                .route("/api/auth/2fa/verify", web::post().to(api_2fa_verify)),
        )
        .await;

        // Missing code → 400
        let req = test::TestRequest::post()
            .uri("/api/auth/2fa/verify")
            .set_json(serde_json::json!({ "email": "test@misfits.ai", "method": "email" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    // Flow 3: GET /api/emails — rejects request with no user identity (empty folder)
    #[actix_web::test]
    async fn test_api_emails_empty_folder_returns_empty_list() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let logic = web::Data::new(Arc::new(Logic::new(mongo.clone())));

        let app = test::init_service(
            App::new()
                .app_data(logic)
                .route("/api/emails", web::get().to(api_emails)),
        )
        .await;

        // No x-user-id header → resolve_user_id returns empty string → returns empty list
        let req = test::TestRequest::get()
            .uri("/api/emails?folder=inbox&page=1&page_size=5")
            .to_request();
        let resp = test::call_service(&app, req).await;
        // Handler always returns 200 (empty list for unknown user)
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["emails"].is_array(), "Expected emails array");
    }

    // Flow 4: POST /api/send — rejects missing recipients
    #[actix_web::test]
    async fn test_api_send_rejects_empty_recipients() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let logic = web::Data::new(Arc::new(Logic::new(mongo.clone())));
        let mongo_data = web::Data::new(mongo);
        let bus_data = web::Data::new(EventBus::new());

        let app = test::init_service(
            App::new()
                .app_data(logic)
                .app_data(mongo_data)
                .app_data(bus_data)
                .route("/api/send", web::post().to(api_send)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/send")
            .set_json(serde_json::json!({
                "to": [],
                "subject": "Test",
                "body": "Hello"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["sent"], false);
        assert!(body["message"].is_string());
    }

    // Flow 5: GET /api/monitoring/summary — returns required fields
    #[actix_web::test]
    async fn test_monitoring_summary_shape() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let mongo_data = web::Data::new(mongo);

        let app = test::init_service(
            App::new()
                .app_data(mongo_data)
                .route("/api/monitoring/summary", web::get().to(api_monitoring_summary)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/monitoring/summary?window=1h")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        // Shape assertions: all required fields present
        assert!(body["total"].is_number(), "Expected total field");
        assert!(body["deliveryRate"].is_number(), "Expected deliveryRate field");
        assert!(body["bounceRate"].is_number(), "Expected bounceRate field");
        assert!(body["byStatus"].is_object(), "Expected byStatus object");
    }

    // Flow 6: GET /api/admin/users — returns 200 with users array (RBAC flag off)
    #[actix_web::test]
    async fn test_admin_users_list_shape() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let mongo_data = web::Data::new(mongo);

        let app = test::init_service(
            App::new()
                .app_data(mongo_data)
                .route("/api/admin/users", web::get().to(api_admin_users_list)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/admin/users")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["users"].is_array(), "Expected users array");
        assert!(body["generatedAt"].is_string(), "Expected generatedAt");
    }

    // Flow 6b: GET /api/admin/whoami — returns enforced flag
    #[actix_web::test]
    async fn test_admin_whoami_returns_enforced_flag() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let mongo_data = web::Data::new(mongo);

        let app = test::init_service(
            App::new()
                .app_data(mongo_data)
                .route("/api/admin/whoami", web::get().to(api_admin_whoami)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/admin/whoami")
            .insert_header(("Authorization", "Bearer test-token"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        // Either 200 (flag off, system user) or 401 (flag on, token unknown)
        let status = resp.status().as_u16();
        assert!(
            status == 200 || status == 401,
            "Expected 200 or 401, got {}",
            status
        );
    }
} // end mod tests

#[async_trait::async_trait]
pub trait DkimService: Send + Sync {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
}

pub struct RealDkimService;

#[async_trait::async_trait]
impl DkimService for RealDkimService {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error> {
        let dkim_service_url = env::var("DKIM_SERVICE_URL").map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "DKIM_SERVICE_URL not set")
        })?;
        let client = reqwest::Client::new();

        let response = client
            .post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": email.from,
                "to": email.to,
                "subject": email.subject,
                "text": email.body,
                "html": email.body
            }))
            .send()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if status.is_success() {
            serde_json::from_str::<serde_json::Value>(&body)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        } else {
            let snippet = if body.len() > 1200 {
                &body[..1200]
            } else {
                &body
            };
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("DKIM service HTTP {}: {}", status.as_u16(), snippet),
            ))
        }
    }
}
