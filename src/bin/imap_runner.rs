use std::sync::Arc;
use mongodb::{Client, options::ClientOptions};
use dotenv::dotenv;
use std::env;

mod api;

use simple_smtp_server::logic::Logic;
use simple_smtp_server::imap_server::ImapServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let client_uri = format!(
        "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}",
        env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set"),
        env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set"),
        env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set"),
        env::var("MONGODB_APP_NAME").expect("MONGODB_APP_NAME must be set")
    );

    // Mongo client
    let mongo_client_options = ClientOptions::parse(&client_uri).await.unwrap();
    let mongo_client = Arc::new(Client::with_options(mongo_client_options).unwrap());

    let logic = Arc::new(Logic::new(mongo_client.clone()));

    let api = api::api_routes(mongo_client.clone());

    let api_port = env::var("IMAP_SERVER_API_PORT").expect("IMAP_SERVER_API_PORT must be set");
    tokio::spawn(async move {
        warp::serve(api).run(([0, 0, 0, 0], api_port.parse::<u16>().unwrap())).await;
    });

    let mut imap_server = ImapServer::new(logic);
    let imap_server_address = env::var("IMAP_SERVER").expect("IMAP_SERVER must be set");
    imap_server.run(&imap_server_address).await?;

    Ok(())
} 