use warp::Filter;
use std::sync::Arc;
use mongodb::{Client, options::ClientOptions};
use dotenv::dotenv;
use std::env;
use log::info;

mod api;
mod logic;
mod imap_server;

use crate::logic::Logic;
use crate::imap_server::ImapServer;
#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let client_uri = format!(
        "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority",
        env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set"),
        env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set"),
        env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set")
    );

    let client_options = ClientOptions::parse(&client_uri).await.unwrap();
    let client = Arc::new(Client::with_options(client_options).unwrap());

    let logic = Arc::new(Logic::new(client.clone()));

    let api = api::api_routes(client.clone());

    tokio::spawn(async move {
        warp::serve(api).run(([0, 0, 0, 0], 3030)).await;
    });

    let imap_server = ImapServer::new(logic);
    imap_server.run("0.0.0.0:143").await?;

    Ok(())
} 