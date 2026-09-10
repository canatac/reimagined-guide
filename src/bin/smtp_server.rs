#![allow(unused_imports)]
#![allow(unreachable_code)]
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
use recipient_helpers::{is_local_recipient, recipient_domain, recipient_local_part};
use tls_helpers::{load_certs, load_key};
use auth_helpers::{check_credentials, handle_auth_login, handle_auth_plain};
use headers_helpers::{
    apply_parsed_header, extract_email_content, extract_session_id_from_response, parse_header_line,
    parse_message_id_header,
};
use session_handlers::{handle_plain_client, handle_tls_client};
use commands_helpers::process_command;
#[path = "smtp_server_dir/mailserver.rs"]
mod mailserver_helpers;
use mailserver_helpers::{env_bool, write_response, MailServer};
struct Startup {
    tls_addr: String,
    plain_addr: String,
    tls_acceptor: Arc<TlsAcceptor>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
}
// Main function
#[tokio::main]
async fn main() -> Result<(), MainError> {
    dotenv().ok();
    install_crypto_provider()?;
    init_logger();
    let tls_addr = env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string());
    let plain_addr = env::var("SMTP_PLAIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8025".to_string());
    let cert_path = PathBuf::from(env::var("CERT_PATH").unwrap_or_else(|_| "localhost.crt".to_string()));
    let key_path = PathBuf::from(env::var("KEY_PATH").unwrap_or_else(|_| "localhost.key".to_string()));
    let tls_acceptor = build_tls_acceptor(&cert_path, &key_path)?;
    let use_mongodb = env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true";
    let client_uri = build_client_uri(use_mongodb)?;
    let client = init_mongo_client(&client_uri).await?;
    warmup_mongo_if_enabled(&client, use_mongodb).await;
    let logic = Arc::new(Logic::new(client.clone()));
    let session_manager = Arc::new(SessionManager::new());
    init_monitoring_if_enabled(client.clone());
    let startup = Startup {
        tls_addr,
        plain_addr,
        tls_acceptor,
        logic,
        session_manager,
    };
    run_accept_loop(startup).await
}
fn install_crypto_provider() -> Result<(), MainError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| MainError("failed to install rustls CryptoProvider".to_string()))
}
fn init_logger() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();
}
fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<Arc<TlsAcceptor>, MainError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    config.alpn_protocols = vec![b"smtp".to_vec()];
    Ok(Arc::new(TlsAcceptor::from(Arc::new(config))))
}
fn build_client_uri(use_mongodb: bool) -> Result<String, MainError> {
    if !use_mongodb {
        info!("USE_MONGODB=false — using local filesystem email storage");
        return Ok("mongodb://127.0.0.1:27017".to_string());
    }
    let cluster_url =
        env::var("MONGODB_CLUSTER_URL").map_err(|_| MainError("MONGODB_CLUSTER_URL must be set".to_string()))?;
    let mongodb_username =
        env::var("MONGODB_USERNAME").map_err(|_| MainError("MONGODB_USERNAME must be set".to_string()))?;
    let mongodb_password =
        env::var("MONGODB_PASSWORD").map_err(|_| MainError("MONGODB_PASSWORD must be set".to_string()))?;
    let mongodb_app_name = env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());
    Ok(format_cluster_uri(
        &cluster_url,
        &mongodb_username,
        &mongodb_password,
        &mongodb_app_name,
    ))
}
fn format_cluster_uri(cluster_url: &str, username: &str, password: &str, app_name: &str) -> String {
    if cluster_url.starts_with("mongodb://") || cluster_url.starts_with("mongodb+srv://") {
        let base = cluster_url.trim_end_matches('&').trim_end_matches('?');
        let sep = if base.contains('?') { "&" } else { "?" };
        return format!("{}{}appName={}&serverSelectionTimeoutMS=5000", base, sep, app_name);
    }
    if cluster_url.contains(".mongodb.net") {
        return format!(
            "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000",
            username, password, cluster_url, app_name
        );
    }
    format!(
        "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
        username, password, cluster_url, app_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only credential values — not production secrets.
    const TEST_PASSWORD: &str = "testpass";

    #[test]
    fn format_cluster_uri_mongodb_srv() {
        let result = format_cluster_uri(
            "mongodb+srv://cluster.example.net",
            "user",
            TEST_PASSWORD,
            "myapp"
        );
        assert!(result.contains("mongodb+srv://user:***@cluster.example.net"));
        assert!(result.contains("appName=myapp"));
        assert!(result.contains("retryWrites=true"));
    }

    #[test]
    fn format_cluster_uri_standard() {
        let result = format_cluster_uri(
            "mongodb://host.example.com:27017",
            "user",
            TEST_PASSWORD,
            "myapp"
        );
        assert!(result.contains("mongodb://user:***@host.example.com:27017"));
        assert!(result.contains("authSource=admin"));
        assert!(result.contains("appName=myapp"));
    }

    #[test]
    fn format_cluster_uri_with_existing_params() {
        let result = format_cluster_uri(
            "mongodb://host.example.com:27017?replicaSet=rs0",
            "user",
            TEST_PASSWORD,
            "myapp"
        );
        assert!(result.contains("appName=myapp"));
        assert!(result.contains("replicaSet=rs0"));
    }

    #[test]
    fn format_cluster_uri_atlas_style() {
        let result = format_cluster_uri(
            "cluster0.abc123.mongodb.net",
            "admin",
            TEST_PASSWORD,
            "testapp"
        );
        assert!(result.contains("mongodb+srv://admin:***@cluster0.abc123.mongodb.net"));
        assert!(result.contains("appName=testapp"));
    }
}
async fn init_mongo_client(client_uri: &str) -> Result<Arc<mongodb::Client>, MainError> {
    let options = build_mongo_options(client_uri).await.map_err(|e| MainError(format!("MongoDB options parse failed: {e}")))?;
    let client = mongodb::Client::with_options(options)
        .map_err(|e| MainError(format!("MongoDB client initialization failed: {e}")))?;
    Ok(Arc::new(client))
}

/// Build MongoDB client options with connection pool configuration.
async fn build_mongo_options(client_uri: &str) -> Result<mongodb::options::ClientOptions, mongodb::error::Error> {
    let mut options = mongodb::options::ClientOptions::parse(client_uri).await?;
    let max_pool_size = std::env::var("MONGODB_MAX_POOL_SIZE")
        .ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(50);
    let min_pool_size = std::env::var("MONGODB_MIN_POOL_SIZE")
        .ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(10);
    let _max_idle_time_ms = std::env::var("MONGODB_MAX_IDLE_TIME_MS")
        .ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60000);

    options.max_pool_size = Some(max_pool_size);
    options.min_pool_size = Some(min_pool_size);
    options.max_idle_time = Some(std::time::Duration::from_millis(_max_idle_time_ms));
    options.connect_timeout = Some(std::time::Duration::from_secs(10));
    options.heartbeat_freq = Some(std::time::Duration::from_secs(10));

    Ok(options)
}
async fn warmup_mongo_if_enabled(client: &mongodb::Client, use_mongodb: bool) {
    if !use_mongodb {
        return;
    }
    match client.database("admin").run_command(mongodb::bson::doc! {"ping": 1}).await {
        Ok(_) => info!("MongoDB connection ready."),
        Err(e) => warn!("MongoDB warm-up ping failed (non-fatal): {}", e),
    }
}
fn init_monitoring_if_enabled(client: Arc<mongodb::Client>) {
    if !monitoring::monitoring_enabled() {
        return;
    }
    monitoring::init_bus();
    monitoring::storage::start_persistence_task(client.clone());
    tokio::spawn(async move {
        monitoring::storage::ensure_indexes(&client).await;
    });
    info!("SMTP monitoring bus initialized in smtp_server");
}
async fn run_accept_loop(startup: Startup) -> Result<(), MainError> {
    let tls_listener = TcpListener::bind(startup.tls_addr.clone()).await?;
    let plain_listener = TcpListener::bind(startup.plain_addr.clone()).await?;
    info!("TLS Server listening on {}", startup.tls_addr);
    info!("Plain Server listening on {}", startup.plain_addr);
    loop {
        tokio::select! {
            result = tls_listener.accept() => {
                handle_tls_accept(
                    result,
                    startup.tls_acceptor.clone(),
                    startup.logic.clone(),
                    startup.session_manager.clone(),
                );
            }
            result = plain_listener.accept() => {
                handle_plain_accept(
                    result,
                    startup.tls_acceptor.clone(),
                    startup.logic.clone(),
                    startup.session_manager.clone(),
                );
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
fn handle_tls_accept(
    result: Result<(TcpStream, std::net::SocketAddr), std::io::Error>,
    acceptor: Arc<TlsAcceptor>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) {
    let Ok((stream, peer_addr)) = result else {
        return;
    };
    info!("New TLS client connected from {}", peer_addr);
    tokio::spawn(async move {
        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                if let Err(e) = handle_tls_client(tls_stream, logic, session_manager).await {
                    error!("Error handling TLS client {}: {}", peer_addr, e);
                } else {
                    info!("TLS client session completed successfully");
                }
            }
            Err(e) => error!("TLS handshake failed for {}: {}", peer_addr, e),
        }
    });
}
fn handle_plain_accept(
    result: Result<(TcpStream, std::net::SocketAddr), std::io::Error>,
    acceptor: Arc<TlsAcceptor>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) {
    let Ok((stream, peer_addr)) = result else {
        return;
    };
    info!("New plain client connected from {}", peer_addr);
    tokio::spawn(async move {
        if let Err(e) = handle_plain_client(stream, acceptor, logic, session_manager).await {
            error!("Error handling plain client {}: {}", peer_addr, e);
        } else {
            info!("Plain client session completed successfully");
        }
    });
}
struct CustomEmail {
    email: Email,
    raw_content: String,
    dkim_signature: Option<String>,
}
