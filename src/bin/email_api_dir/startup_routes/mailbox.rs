//! Mailbox / send / drafts / templates / hermes / calendar routes.

use actix_web::web;

use super::super::*;

pub(crate) fn register_mailbox_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/emails", web::get().to(api_emails))
        .route("/api/emails/{id}", web::get().to(api_email_by_id))
        .route(
            "/api/emails/{id}/attachments/{attachment_id}",
            web::get().to(api_email_attachment_download),
        )
        .route("/api/emails/{id}/action", web::post().to(api_email_action))
        .route("/api/tags", web::get().to(api_tags))
        .route("/api/send", web::post().to(api_send))
        .route("/api/send/{id}/status", web::get().to(api_send_status))
        .route("/api/drafts", web::get().to(api_drafts_list))
        .route("/api/drafts", web::post().to(api_drafts_upsert))
        .route("/api/drafts/{id}", web::delete().to(api_drafts_delete))
        .route(
            "/api/newsletters/sources",
            web::get().to(api_newsletter_sources_list),
        )
        .route(
            "/api/newsletters/sources",
            web::post().to(api_newsletter_sources_create),
        )
        .route(
            "/api/newsletters/sources/{id}",
            web::patch().to(api_newsletter_sources_update),
        )
        .route(
            "/api/newsletters/sources/{id}",
            web::delete().to(api_newsletter_sources_delete),
        )
        .route(
            "/api/newsletters/items",
            web::get().to(api_newsletter_items_list),
        )
        .route(
            "/api/newsletters/items",
            web::post().to(api_newsletter_items_create),
        )
        .route("/api/templates", web::get().to(api_templates))
        .route("/api/settings/ai", web::get().to(api_get_ai_settings))
        .route("/api/settings/ai", web::put().to(api_put_ai_settings))
        .route("/api/hermes/chat", web::post().to(api_hermes_chat))
        .route("/api/hermes/runs", web::get().to(api_hermes_runs_list))
        .route("/api/hermes/runs", web::post().to(api_hermes_runs))
        .route(
            "/api/hermes/runs/{run_id}",
            web::get().to(api_hermes_run_status),
        )
        .route(
            "/api/hermes/runs/{run_id}/events",
            web::get().to(api_hermes_run_events),
        )
        .route("/api/send/undo", web::post().to(api_send_undo))
        .route("/api/send/schedule", web::post().to(api_send_schedule))
        .route(
            "/api/calendar/events",
            web::post().to(calendar_create_event),
        )
        .route("/api/calendar/events", web::get().to(calendar_list_events))
        .route(
            "/api/calendar/events/{id}",
            web::get().to(calendar_get_event),
        )
        .route(
            "/api/calendar/events/{id}",
            web::put().to(calendar_update_event),
        )
        .route(
            "/api/calendar/events/{id}",
            web::delete().to(calendar_delete_event),
        )
        .route("/send-email", web::post().to(send_email_handler))
        .route("/create-mailing-list", web::post().to(create_mailing_list))
        .route(
            "/send-to-mailing-list",
            web::post().to(send_to_mailing_list),
        );
}
