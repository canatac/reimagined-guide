use std::sync::Arc;
use std::env;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::imap_server::ImapServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let cluster_url = env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set");
    let mongodb_username = env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set");
    let mongodb_password = env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set");
    let mongodb_app_name = env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    let client_uri = if cluster_url.contains(".mongodb.net") {
        // MongoDB Atlas (SRV)
        format!(
            "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}",
            mongodb_username, mongodb_password, cluster_url, mongodb_app_name
        )
    } else {
        // MongoDB local ou auto-hébergé
        format!(
            "mongodb://{}:{}@{}/?authSource=admin&appName={}",
            mongodb_username, mongodb_password, cluster_url, mongodb_app_name
        )
    };

    let client = Arc::new(
        mongodb::Client::with_uri_str(&client_uri)
            .await.unwrap()
    );
    
    let logic = Arc::new(Logic::new(client));
    let mut server = ImapServer::new(logic);
    let imap_server_address = env::var("IMAP_SERVER").expect("IMAP_SERVER must be set");
    server.run(&imap_server_address).await.unwrap();

    Ok(())
} 