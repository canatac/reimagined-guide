// Entry point of the email API binary.
// Module declarations are grouped by domain; each module owns its routes.

mod admin_auth;
mod admin_ops;
mod auth_handlers;
mod crypto_handlers;
mod deliverability_dto;
mod mailing_list;
mod dkim_service;
mod event_bus;
mod external_handlers;
mod external_probe_handlers;
mod helpers;
mod jmap;
mod mailbox;
mod monitoring_handlers;
mod send_email_handler;
mod startup;
mod startup_routes;
mod subscription_handlers;

pub use admin_ops::*;
pub use auth_handlers::*;
pub use crypto_handlers::*;
pub use external_handlers::*;
pub use jmap::*;
pub use mailbox::*;
pub use monitoring_handlers::*;
pub use subscription_handlers::*;

use actix_web::{web, App, HttpServer};
use sha1::Sha1;
use sha1::Digest;
use std::sync::Arc;

use crate::admin_auth;
use crate::event_bus::EventBus;
use crate::startup::run_startup_tasks;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    dotenv::dotenv().ok();

    let mongo_client = match startup::connect_mongo().await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("MongoDB connection failed: {e}");
            std::process::exit(1);
        }
    };

    let bus = web::Data::new(EventBus::new());
    let mongo = web::Data::new(mongo_client.clone());

    run_startup_tasks(&mongo_client, &bus).await;

    let bind_addr =
        std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    tracing::info!("email API listening on {bind_addr}");

    HttpServer::new(move || {
        App::new()
            .app_data(mongo.clone())
            .app_data(bus.clone())
            .configure(startup_routes::register_routes)
    })
    .bind(bind_addr)?
    .run()
    .await
}

#[cfg(test)]
mod main_tests;
