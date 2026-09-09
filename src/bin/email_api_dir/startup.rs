//! Startup helpers for the email_api binary.
//!
//! Extracted from `main.rs` to keep `main()` under the 150 LOC budget imposed
//! by `scripts/arch_guard.sh`. No behaviour change: these helpers reproduce
//! the exact same logic (env vars, URI shape, CORS config, HTTP route table)
//! that previously lived inline in `main`.

use actix_cors::Cors;
use actix_web::web;
use mongodb::options::ClientOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;

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
        let sep = if base.contains('?') { "&" } : "?";
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

/// Build MongoDB client options with connection pool configuration.
/// Configurable via env vars:
/// - MONGODB_MAX_POOL_SIZE (default: 50)
/// - MONGODB_MIN_POOL_SIZE (default: 10)
/// - MONGODB_MAX_IDLE_TIME_MS (default: 60000)
/// - MONGODB_WAIT_QUEUE_TIMEOUT_MS (default: 5000)
pub(crate) async fn build_mongo_options(
    client_uri: &str,
) -> Result<ClientOptions, mongodb::error::Error> {
    let mut options = ClientOptions::parse(client_uri).await?;
    let max_pool_size = env::var("MONGODB_MAX_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(50);
    let min_pool_size = env::var("MONGODB_MIN_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);
    let max_idle_time_ms = env::var("MONGODB_MAX_IDLE_TIME_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60000);

    options.max_pool_size = Some(max_pool_size);
    options.min_pool_size = Some(min_pool_size);
    options.max_idle_time = Some(Duration::from_millis(max_idle_time_ms));
    options.connect_timeout = Some(Duration::from_secs(10));
    options.heartbeat_freq = Some(Duration::from_secs(10));

    Ok(options)
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
    let options = match build_mongo_options(client_uri).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("MongoDB options parse failed: {}, falling back to URI", e);
            return match mongodb::Client::with_uri_str(client_uri).await {
                Ok(c) => {
                    let c = Arc::new(c);
                    warm_up_mongo(&c).await;
                    Some(c)
                }
                Err(e) => {
                    eprintln!("MongoDB connection failed: {}, auth will use env vars", e);
                    None
                }
            };
        }
    };
    match mongodb::Client::with_options(options) {
        Ok(c) => {
            let c = Arc::new(c);
            warm_up_mongo(&c).await;
            Some(c)
        }
        Err(e) => {
            eprintln!("MongoDB connection failed: {}, auth will use env vars", e);
            None
        }
    }
}

async fn warm_up_mongo(client: &Arc<mongodb::Client>) {
    if let Err(e) = client
        .database("admin")
        .run_command(mongodb::bson::doc! {"ping": 1})
        .await
    {
        eprintln!("MongoDB warm-up ping failed (non-fatal): {}", e);
    } else {
        println!("MongoDB connection ready.");
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

// Route registration helpers live in `startup_routes.rs`.
use super::startup_routes::{register_admin_routes, register_auth_routes, register_dashboard_routes, register_dmarc_routes, register_diag_routes, register_docs_routes, register_external_routes, register_mailbox_routes, register_prometheus_routes, register_webhook_routes};

pub(crate) fn register_http_routes(cfg: &mut web::ServiceConfig) {
    register_docs_routes(cfg);
    register_external_routes(cfg);
    register_auth_routes(cfg);
    register_mailbox_routes(cfg);
    register_diag_routes(cfg);
    register_admin_routes(cfg);
    register_prometheus_routes(cfg);
    register_dashboard_routes(cfg);
    register_dmarc_routes(cfg);
    register_webhook_routes(cfg);
}
