/*
SMTP Server Implementation

This file contains the main SMTP server implementation for a custom email handling system.

Key features:
- Supports both plain (SMTP) and TLS (SMTPS) connections
- Implements basic SMTP commands (HELO/EHLO, MAIL FROM, RCPT TO, DATA, QUIT, etc.)
- Handles STARTTLS for upgrading plain connections to TLS
- Supports basic authentication (AUTH LOGIN and AUTH PLAIN)
- Stores received emails in a local directory

Known Issues:
- **DATA command handling**: The server closes the connection unexpectedly after receiving email data.
  This is a known bug and should be fixed in a future update.

Usage:
To run the SMTP server, use the following command from the project root:
    cargo run --bin smtp_server

The server listens on two ports:
1. TLS port (default: 8465) for secure connections
2. Plain port (default: 8025) for non-secure connections and STARTTLS

Environment variables (set in .env file):
- SMTP_TLS_ADDR: Address for TLS connections (default: "0.0.0.0:8465")
- SMTP_PLAIN_ADDR: Address for plain connections (default: "0.0.0.0:8025")
- SMTP_REQUIRE_STARTTLS: Require STARTTLS before AUTH on plain SMTP port (default: true)
- CERT_PATH: Path to SSL certificate file
- KEY_PATH: Path to SSL private key file
- SMTP_USERNAME: Username for SMTP authentication
- SMTP_PASSWORD: Password for SMTP authentication

Note: This server is intended for development and testing purposes.
For production use, additional security measures and optimizations should be implemented.
*/

use dotenv::dotenv;

use base64::{engine::general_purpose, Engine as _};

use std::io::BufReader;
use std::io::{Error as IoError, ErrorKind};

use chrono::Utc;
use log::{debug, error, info, warn};
use rustls::ServerConfig;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use constant_time_eq::constant_time_eq;
use mailparse::parse_mail;
use rustls_pemfile::{certs, private_key};
use std::env;
use std::error::Error;
use std::fmt;
use tokio_rustls::server::TlsStream;

use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::monitoring;
use simple_smtp_server::session::SessionManager;
use simple_smtp_server::smtp_client::{extract_email_address, send_outgoing_email};

// Custom error type for the main function
#[derive(Debug)]
struct MainError(String);

// Implement Display trait for MainError
impl fmt::Display for MainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implement Error trait for MainError
impl Error for MainError {}

// Implement conversion from std::io::Error to MainError
impl From<std::io::Error> for MainError {
    fn from(err: std::io::Error) -> Self {
        MainError(err.to_string())
    }
}

#[path = "smtp_server_dir/stream.rs"]
mod stream_helpers;
use stream_helpers::StreamType;

#[path = "smtp_server_dir/recipient.rs"]
mod recipient_helpers;
#[path = "smtp_server_dir/tls.rs"]
mod tls_helpers;
#[path = "smtp_server_dir/auth.rs"]
mod auth_helpers;
#[path = "smtp_server_dir/session_helpers.rs"]
mod session_helpers;
#[path = "smtp_server_dir/session_core.rs"]
mod session_core;
#[path = "smtp_server_dir/session.rs"]
mod session_handlers;
#[path = "smtp_server_dir/headers.rs"]
mod headers_helpers;
#[path = "smtp_server_dir/commands.rs"]
mod commands_helpers;
use recipient_helpers::{recipient_domain, is_local_recipient, recipient_local_part};
use tls_helpers::{load_certs, load_key};
use auth_helpers::{check_credentials, handle_auth_login, handle_auth_plain};
use session_handlers::{handle_plain_client, handle_tls_client};
use headers_helpers::{
    apply_parsed_header, extract_email_content, extract_session_id_from_response,
    parse_header_line, parse_message_id_header,
};
use commands_helpers::process_command;

#[path = "smtp_server_dir/mailserver.rs"]
mod mailserver_helpers;
use mailserver_helpers::{env_bool, write_response, MailServer};

// Load SSL certificates
// (moved to tls_helpers.rs)

// Main function
#[tokio::main]
async fn main() -> Result<(), MainError> {
    // Load environment variables from .env file
    dotenv().ok();

    // rustls 0.23 requires an explicit process-level CryptoProvider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Initialize logger
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // Get server addresses from environment variables or use defaults
    let tls_addr = env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string());
    let plain_addr = env::var("SMTP_PLAIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8025".to_string());

    // Get SSL certificate and key paths
    let cert_path: PathBuf =
        PathBuf::from(env::var("CERT_PATH").unwrap_or_else(|_| "localhost.crt".to_string()));
    let key_path: PathBuf =
        PathBuf::from(env::var("KEY_PATH").unwrap_or_else(|_| "localhost.key".to_string()));

    // Load SSL certificates and key
    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;

    // Create TLS configuration
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    config.alpn_protocols = vec![b"smtp".to_vec()];

    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(config)));

    // Bind TCP listeners for TLS and plain connections
    let tls_listener = TcpListener::bind(tls_addr.clone()).await?;
    let plain_listener = TcpListener::bind(plain_addr.clone()).await?;

    // Log server start information
    info!("TLS Server listening on {}", tls_addr);
    info!("Plain Server listening on {}", plain_addr);

    // MongoDB is optional (filesystem storage is the default for staging).
    // Client creation is lazy; a dummy URI is enough when USE_MONGODB=false.
    let use_mongodb = env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true";
    let client_uri = if use_mongodb {
        let cluster_url = env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set");
        let mongodb_username = env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set");
        let mongodb_password = env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set");
        let mongodb_app_name =
            env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());
        if cluster_url.starts_with("mongodb://") || cluster_url.starts_with("mongodb+srv://") {
            // Full URI from 1Password — use directly
            let base = cluster_url.trim_end_matches('&').trim_end_matches('?');
            let sep = if base.contains('?') { "&" } else { "?" };
            format!("{}{}appName={}&serverSelectionTimeoutMS=5000", base, sep, mongodb_app_name)
        } else if cluster_url.contains(".mongodb.net") {
            format!(
                "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000",
                mongodb_username, mongodb_password, cluster_url, mongodb_app_name
            )
        } else {
            format!(
                "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
                mongodb_username, mongodb_password, cluster_url, mongodb_app_name
            )
        }
    } else {
        info!("USE_MONGODB=false — using local filesystem email storage");
        "mongodb://127.0.0.1:27017".to_string()
    };

    let client = Arc::new(mongodb::Client::with_uri_str(&client_uri).await.unwrap());
    // Warm-up: force DNS resolution + TLS + MongoDB handshake at startup
    // so the first user authentication is not delayed by 10-30s.
    if use_mongodb {
        if let Err(e) = client
            .database("admin")
            .run_command(mongodb::bson::doc! {"ping": 1})
            .await
        {
            warn!("MongoDB warm-up ping failed (non-fatal): {}", e);
        } else {
            info!("MongoDB connection ready.");
        }
    }
    let logic = Arc::new(Logic::new(client.clone()));
    let session_manager = Arc::new(SessionManager::new());

    if monitoring::monitoring_enabled() {
        monitoring::init_bus();
        monitoring::storage::start_persistence_task(client.clone());
        let monitor_idx_client = client.clone();
        tokio::spawn(async move {
            monitoring::storage::ensure_indexes(&monitor_idx_client).await;
        });
        info!("SMTP monitoring bus initialized in smtp_server");
    }

    loop {
        tokio::select! {
            // Handle incoming TLS connections
            result = tls_listener.accept() => {
                if let Ok((stream, peer_addr)) = result {
                    info!("New TLS client connected from {}", peer_addr);
                    let acceptor = tls_acceptor.clone();
                    let logic_clone = logic.clone(); // Clone the Arc before moving into the closure
                    let session_manager_clone = session_manager.clone(); // Clone the Arc before moving into the closure
                    tokio::spawn(async move {
                        let tls_stream = acceptor.accept(stream).await.unwrap();
                        if let Err(e) = handle_tls_client(tls_stream, logic_clone, session_manager_clone).await {
                            error!("Error handling plain client {}: {}", peer_addr, e);
                        } else {
                            info!("Plain client session completed successfully");
                        }
                    });
                }
            }

            // Handle incoming plain connections
            result = plain_listener.accept() => {
                if let Ok((stream, peer_addr)) = result {
                    info!("New plain client connected from {}", peer_addr);
                    let acceptor = tls_acceptor.clone();
                    let logic_clone = logic.clone(); // Clone the Arc before moving into the closure
                    let session_manager_clone = session_manager.clone(); // Clone the Arc before moving into the closure
                    tokio::spawn(async move {
                        if let Err(e) = handle_plain_client(stream, acceptor, logic_clone, session_manager_clone).await {
                            error!("Error handling plain client {}: {}", peer_addr, e);
                        } else {
                            info!("Plain client session completed successfully");
                        }
                    });
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok(())
}

struct CustomEmail {
    email: Email,
    raw_content: String,
    dkim_signature: Option<String>,
}

