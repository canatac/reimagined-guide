use simple_smtp_server::imap_server::ImapServer;
use simple_smtp_server::logic::Logic;
use std::env;
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let cluster_url = env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set");
    let mongodb_username = env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set");
    let mongodb_password = env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set");
    let mongodb_app_name =
        env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    let client_uri = if cluster_url.starts_with("mongodb://") || cluster_url.starts_with("mongodb+srv://") {
        // Full URI from 1Password — use directly
        let base = cluster_url.trim_end_matches('&').trim_end_matches('?');
        let sep = if base.contains('?') { "&" } else { "?" };
        format!("{}{}appName={}&serverSelectionTimeoutMS=5000", base, sep, mongodb_app_name)
    } else if cluster_url.contains(".mongodb.net") {
        // MongoDB Atlas (SRV)
        format!(
            "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000",
            mongodb_username, mongodb_password, cluster_url, mongodb_app_name
        )
    } else {
        // MongoDB local ou auto-hébergé
        format!(
            "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
            mongodb_username, mongodb_password, cluster_url, mongodb_app_name
        )
    };

    let client = Arc::new(
        match mongodb::options::ClientOptions::parse(&client_uri).await {
            Ok(mut opts) => {
                opts.max_pool_size = std::env::var("MONGODB_MAX_POOL_SIZE").ok().and_then(|s| s.parse::<u32>().ok()).or(Some(50));
                opts.min_pool_size = std::env::var("MONGODB_MIN_POOL_SIZE").ok().and_then(|s| s.parse::<u32>().ok()).or(Some(10));
                opts.max_idle_time = Some(std::time::Duration::from_millis(
                    std::env::var("MONGODB_MAX_IDLE_TIME_MS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60000),
                ));
                opts.connect_timeout = Some(std::time::Duration::from_secs(10));
                opts.heartbeat_freq = Some(std::time::Duration::from_secs(10));
                mongodb::Client::with_options(opts)
                    .or_else(|_| mongodb::Client::with_uri_str(&client_uri))
                    .unwrap()
            }
            Err(_) => mongodb::Client::with_uri_str(&client_uri).unwrap(),
        },
    );

    // Warm-up: force DNS resolution + TLS handshake + MongoDB handshake at startup
    // so the first user login is not delayed by 10-30s.
    if let Err(e) = client
        .database("admin")
        .run_command(mongodb::bson::doc! {"ping": 1})
        .await
    {
        eprintln!("MongoDB warm-up ping failed (non-fatal): {}", e);
    } else {
        println!("MongoDB connection ready.");
    }

    let logic = Arc::new(Logic::new(client));
    let mut server = ImapServer::new(logic);
    let imap_server_address = env::var("IMAP_SERVER").expect("IMAP_SERVER must be set");
    server.run(&imap_server_address).await.unwrap();

    Ok(())
}
