//! Webhook subscriber management routes.
//!
//! Issue #455: webhook notification on PR merge.

use actix_web::web;

use crate::monitoring_handlers::{api_webhook_dispatch, api_webhook_list, api_webhook_subscribe, api_webhook_unsubscribe};

pub(crate) fn register_webhook_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/webhooks", web::post().to(api_webhook_subscribe))
        .route("/api/webhooks", web::get().to(api_webhook_list))
        .route("/api/webhooks/{id}", web::delete().to(api_webhook_unsubscribe))
        .route("/api/webhooks/dispatch", web::post().to(api_webhook_dispatch))
        .route("/api/webhooks/incoming", web::post().to(api_webhook_incoming));
}
