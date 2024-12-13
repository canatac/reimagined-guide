use std::sync::Arc;
use std::env;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::imap_server::ImapServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let client_uri = format!(
        "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}",
        env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set"),
        env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set"),
        env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set"),
        env::var("MONGODB_APP_NAME").expect("MONGODB_APP_NAME must be set")
    );

    let client = Arc::new(
        mongodb::Client::with_uri_str(&client_uri)
            .await.unwrap()
    );
    
    let logic = Arc::new(Logic::new(client));
    let server = ImapServer::new(logic);
    let imap_server_address = env::var("IMAP_SERVER").expect("IMAP_SERVER must be set");
    server.run(&imap_server_address).await.unwrap();

    Ok(())
} 