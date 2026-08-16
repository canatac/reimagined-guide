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
mod startup;
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

    // Connect to MongoDB for auth (URI build + optional warm-up ping → startup.rs).
    let client_uri = startup::build_mongo_uri();
    let mongo_client = startup::connect_mongo_optional(&client_uri).await;

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
            App::new()
                .wrap(startup::build_cors_layer())
                .app_data(http_logic.clone())
                .app_data(http_mongo.clone())
                .app_data(http_event_bus.clone())
                .app_data(http_external_imap.clone())
                .configure(startup::register_http_routes)
        })
        .bind(http_addr)
        .expect("Failed to bind HTTP on 8000")
        .run()
        .await
        .expect("HTTP server error");
    });

    // Start HTTPS server on 8443 (original API)
    HttpServer::new(|| {
        App::new()
            .wrap(startup::build_cors_layer())
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
