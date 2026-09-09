//! Incoming webhook signature verification routes.
//!
//! Issue #486: webhook signature verification.

use actix_web::web;

use crate::incoming_webhook_handlers::{
    api_incoming_webhook_list_sources, api_incoming_webhook_register,
    api_incoming_webhook_remove_source, api_incoming_webhook_verify,
};

pub(crate) fn register_incoming_webhook_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/api/incoming-webhooks/verify",
        web::post().to(api_incoming_webhook_verify),
    )
    .route(
        "/api/incoming-webhooks/sources",
        web::post().to(api_incoming_webhook_register),
    )
    .route(
        "/api/incoming-webhooks/sources",
        web::get().to(api_incoming_webhook_list_sources),
    )
    .route(
        "/api/incoming-webhooks/sources/{id}",
        web::delete().to(api_incoming_webhook_remove_source),
    );
}
