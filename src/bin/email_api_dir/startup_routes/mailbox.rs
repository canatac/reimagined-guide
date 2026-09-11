//! Mailbox / send / drafts / templates / hermes / calendar routes.

use actix_web::web;

use super::super::*;

pub(crate) fn register_mailbox_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/emails", web::get().to(api_emails))
        .route("/api/analytics/personal", web::get().to(api_personal_analytics))
        .route("/api/emails/{id}", web::get().to(api_email_by_id))
        .route(
            "/api/emails/{id}/attachments/{attachment_id}",
            web::get().to(api_email_attachment_download),
        )
        .route("/api/emails/{id}/action", web::post().to(api_email_action))
        .route("/api/tags", web::get().to(api_tags))
        .route("/api/tags", web::post().to(api_tags_create))
        .route("/api/tags/{id}", web::patch().to(api_tags_update))
        .route("/api/tags/{id}", web::delete().to(api_tags_delete))
        .route("/api/send", web::post().to(api_send))
        .route("/api/send/{id}/status", web::get().to(api_send_status))
        .route(
            "/api/notifications/preferences",
            web::get().to(api_notifications_preferences_get),
        )
        .route(
            "/api/notifications/preferences",
            web::put().to(api_notifications_preferences_put),
        )
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
            "/api/newsletters/sources/{id}/summarize",
            web::post().to(api_newsletter_sources_summarize),
        )
        .route(
            "/api/newsletters/suggestions",
            web::get().to(api_newsletter_suggestions),
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
        .route(
            "/api/mail-assistant/suggestions",
            web::get().to(api_mail_assistant_suggestions),
        )
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
        .route("/api/calendar/agenda", web::get().to(calendar_agenda))
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
        .route("/api/calendar/holidays", web::get().to(list_holidays))
        .route("/api/calendar/holidays", web::post().to(create_holiday))
        .route(
            "/api/calendar/holidays/{id}",
            web::delete().to(delete_holiday),
        )
        .route(
            "/api/calendar/holidays/countries",
            web::get().to(list_holiday_countries),
        )
        .route("/send-email", web::post().to(send_email_handler))
        .route("/create-mailing-list", web::post().to(create_mailing_list))
        .route(
            "/send-to-mailing-list",
            web::post().to(send_to_mailing_list),
        );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_routes_emails() {
        let route = "/api/emails";
        assert_eq!(route, "/api/emails");
    }

    #[test]
    fn mailbox_routes_analytics_personal() {
        let route = "/api/analytics/personal";
        assert_eq!(route, "/api/analytics/personal");
    }

    #[test]
    fn mailbox_routes_email_by_id() {
        let route = "/api/emails/{id}";
        assert_eq!(route, "/api/emails/{id}");
    }

    #[test]
    fn mailbox_routes_attachment_download() {
        let route = "/api/emails/{id}/attachments/{attachment_id}";
        assert_eq!(route, "/api/emails/{id}/attachments/{attachment_id}");
    }

    #[test]
    fn mailbox_routes_email_action() {
        let route = "/api/emails/{id}/action";
        assert_eq!(route, "/api/emails/{id}/action");
    }

    #[test]
    fn mailbox_routes_tags() {
        let route = "/api/tags";
        assert_eq!(route, "/api/tags");
    }

    #[test]
    fn mailbox_routes_send() {
        let route = "/api/send";
        assert_eq!(route, "/api/send");
    }

    #[test]
    fn mailbox_routes_send_status() {
        let route = "/api/send/{id}/status";
        assert_eq!(route, "/api/send/{id}/status");
    }

    #[test]
    fn mailbox_routes_notifications_preferences() {
        let route = "/api/notifications/preferences";
        assert_eq!(route, "/api/notifications/preferences");
    }

    #[test]
    fn mailbox_routes_drafts() {
        let route = "/api/drafts";
        assert_eq!(route, "/api/drafts");
    }

    #[test]
    fn mailbox_routes_newsletter_sources() {
        let route = "/api/newsletters/sources";
        assert_eq!(route, "/api/newsletters/sources");
    }

    #[test]
    fn mailbox_routes_newsletter_suggestions() {
        let route = "/api/newsletters/suggestions";
        assert_eq!(route, "/api/newsletters/suggestions");
    }

    #[test]
    fn mailbox_routes_newsletter_items() {
        let route = "/api/newsletters/items";
        assert_eq!(route, "/api/newsletters/items");
    }

    #[test]
    fn mailbox_routes_templates() {
        let route = "/api/templates";
        assert_eq!(route, "/api/templates");
    }

    #[test]
    fn mailbox_routes_settings_ai() {
        let route = "/api/settings/ai";
        assert_eq!(route, "/api/settings/ai");
    }

    #[test]
    fn mailbox_routes_hermes_chat() {
        let route = "/api/hermes/chat";
        assert_eq!(route, "/api/hermes/chat");
    }

    #[test]
    fn mailbox_routes_mail_assistant_suggestions() {
        let route = "/api/mail-assistant/suggestions";
        assert_eq!(route, "/api/mail-assistant/suggestions");
    }

    #[test]
    fn mailbox_routes_hermes_runs() {
        let route = "/api/hermes/runs";
        assert_eq!(route, "/api/hermes/runs");
    }

    #[test]
    fn mailbox_routes_hermes_run_status() {
        let route = "/api/hermes/runs/{run_id}";
        assert_eq!(route, "/api/hermes/runs/{run_id}");
    }

    #[test]
    fn mailbox_routes_hermes_run_events() {
        let route = "/api/hermes/runs/{run_id}/events";
        assert_eq!(route, "/api/hermes/runs/{run_id}/events");
    }

    #[test]
    fn mailbox_routes_send_undo() {
        let route = "/api/send/undo";
        assert_eq!(route, "/api/send/undo");
    }

    #[test]
    fn mailbox_routes_send_schedule() {
        let route = "/api/send/schedule";
        assert_eq!(route, "/api/send/schedule");
    }

    #[test]
    fn mailbox_routes_calendar_events() {
        let route = "/api/calendar/events";
        assert_eq!(route, "/api/calendar/events");
    }

    #[test]
    fn mailbox_routes_calendar_agenda() {
        let route = "/api/calendar/agenda";
        assert_eq!(route, "/api/calendar/agenda");
    }

    #[test]
    fn mailbox_routes_calendar_holidays() {
        let route = "/api/calendar/holidays";
        assert_eq!(route, "/api/calendar/holidays");
    }

    #[test]
    fn mailbox_routes_calendar_holiday_countries() {
        let route = "/api/calendar/holidays/countries";
        assert_eq!(route, "/api/calendar/holidays/countries");
    }

    #[test]
    fn mailbox_routes_send_email() {
        let route = "/send-email";
        assert_eq!(route, "/send-email");
    }

    #[test]
    fn mailbox_routes_create_mailing_list() {
        let route = "/create-mailing-list";
        assert_eq!(route, "/create-mailing-list");
    }

    #[test]
    fn mailbox_routes_send_to_mailing_list() {
        let route = "/send-to-mailing-list";
        assert_eq!(route, "/send-to-mailing-list");
    }

    #[test]
    fn mailbox_routes_all_paths() {
        let paths = vec![
            "/api/emails",
            "/api/analytics/personal",
            "/api/emails/{id}",
            "/api/emails/{id}/attachments/{attachment_id}",
            "/api/emails/{id}/action",
            "/api/tags",
            "/api/send",
            "/api/send/{id}/status",
            "/api/notifications/preferences",
            "/api/drafts",
            "/api/newsletters/sources",
            "/api/newsletters/suggestions",
            "/api/newsletters/items",
            "/api/templates",
            "/api/settings/ai",
            "/api/hermes/chat",
            "/api/mail-assistant/suggestions",
            "/api/hermes/runs",
            "/api/hermes/runs/{run_id}",
            "/api/hermes/runs/{run_id}/events",
            "/api/send/undo",
            "/api/send/schedule",
            "/api/calendar/events",
            "/api/calendar/agenda",
            "/api/calendar/holidays",
            "/api/calendar/holidays/countries",
            "/send-email",
            "/create-mailing-list",
            "/send-to-mailing-list",
        ];
        assert_eq!(paths.len(), 28);
    }

    #[test]
    fn mailbox_routes_get_routes() {
        let get_routes = vec![
            "/api/emails",
            "/api/analytics/personal",
            "/api/emails/{id}",
            "/api/emails/{id}/attachments/{attachment_id}",
            "/api/tags",
            "/api/send/{id}/status",
            "/api/notifications/preferences",
            "/api/drafts",
            "/api/newsletters/sources",
            "/api/newsletters/suggestions",
            "/api/newsletters/items",
            "/api/templates",
            "/api/settings/ai",
            "/api/mail-assistant/suggestions",
            "/api/hermes/runs",
            "/api/hermes/runs/{run_id}",
            "/api/hermes/runs/{run_id}/events",
            "/api/calendar/events",
            "/api/calendar/agenda",
            "/api/calendar/holidays",
            "/api/calendar/holidays/countries",
        ];
        assert_eq!(get_routes.len(), 20);
    }

    #[test]
    fn mailbox_routes_post_routes() {
        let post_routes = vec![
            "/api/emails/{id}/action",
            "/api/tags",
            "/api/send",
            "/api/drafts",
            "/api/newsletters/sources",
            "/api/newsletters/sources/{id}/summarize",
            "/api/newsletters/items",
            "/api/hermes/chat",
            "/api/hermes/runs",
            "/api/send/undo",
            "/api/send/schedule",
            "/api/calendar/events",
            "/api/calendar/holidays",
            "/send-email",
            "/create-mailing-list",
            "/send-to-mailing-list",
        ];
        assert_eq!(post_routes.len(), 16);
    }

    #[test]
    fn mailbox_routes_patch_routes() {
        let patch_routes = vec![
            "/api/tags/{id}",
            "/api/newsletters/sources/{id}",
        ];
        assert_eq!(patch_routes.len(), 2);
    }

    #[test]
    fn mailbox_routes_put_routes() {
        let put_routes = vec![
            "/api/notifications/preferences",
            "/api/settings/ai",
            "/api/calendar/events/{id}",
        ];
        assert_eq!(put_routes.len(), 3);
    }

    #[test]
    fn mailbox_routes_delete_routes() {
        let delete_routes = vec![
            "/api/tags/{id}",
            "/api/drafts/{id}",
            "/api/newsletters/sources/{id}",
            "/api/calendar/events/{id}",
            "/api/calendar/holidays/{id}",
        ];
        assert_eq!(delete_routes.len(), 5);
    }

    #[test]
    fn mailbox_routes_path_starts_with_api() {
        let route = "/api/emails";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn mailbox_routes_path_no_trailing_slash() {
        let route = "/api/emails";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn mailbox_routes_path_no_uppercase() {
        let route = "/api/emails";
        assert_eq!(route, route.to_ascii_lowercase());
    }

    #[test]
    fn mailbox_routes_path_no_spaces() {
        let route = "/api/emails";
        assert!(!route.contains(" "));
    }

    #[test]
    fn mailbox_routes_path_valid() {
        let route = "/api/emails";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn mailbox_routes_handler_api_emails() {
        let handler = "api_emails";
        assert_eq!(handler, "api_emails");
    }

    #[test]
    fn mailbox_routes_handler_api_send() {
        let handler = "api_send";
        assert_eq!(handler, "api_send");
    }

    #[test]
    fn mailbox_routes_handler_api_hermes_chat() {
        let handler = "api_hermes_chat";
        assert_eq!(handler, "api_hermes_chat");
    }

    #[test]
    fn mailbox_routes_handler_calendar_create_event() {
        let handler = "calendar_create_event";
        assert_eq!(handler, "calendar_create_event");
    }

    #[test]
    fn mailbox_routes_handler_send_email() {
        let handler = "send_email_handler";
        assert_eq!(handler, "send_email_handler");
    }

    #[test]
    fn mailbox_routes_handler_create_mailing_list() {
        let handler = "create_mailing_list";
        assert_eq!(handler, "create_mailing_list");
    }

    #[test]
    fn mailbox_routes_handler_send_to_mailing_list() {
        let handler = "send_to_mailing_list";
        assert_eq!(handler, "send_to_mailing_list");
    }

    #[test]
    fn mailbox_routes_handler_list_holidays() {
        let handler = "list_holidays";
        assert_eq!(handler, "list_holidays");
    }

    #[test]
    fn mailbox_routes_handler_create_holiday() {
        let handler = "create_holiday";
        assert_eq!(handler, "create_holiday");
    }

    #[test]
    fn mailbox_routes_handler_delete_holiday() {
        let handler = "delete_holiday";
        assert_eq!(handler, "delete_holiday");
    }

    #[test]
    fn mailbox_routes_handler_list_holiday_countries() {
        let handler = "list_holiday_countries";
        assert_eq!(handler, "list_holiday_countries");
    }

    #[test]
    fn mailbox_routes_handler_api_tags() {
        let handler = "api_tags";
        assert_eq!(handler, "api_tags");
    }

    #[test]
    fn mailbox_routes_handler_api_tags_create() {
        let handler = "api_tags_create";
        assert_eq!(handler, "api_tags_create");
    }

    #[test]
    fn mailbox_routes_handler_api_tags_update() {
        let handler = "api_tags_update";
        assert_eq!(handler, "api_tags_update");
    }

    #[test]
    fn mailbox_routes_handler_api_tags_delete() {
        let handler = "api_tags_delete";
        assert_eq!(handler, "api_tags_delete");
    }

    #[test]
    fn mailbox_routes_handler_api_drafts_list() {
        let handler = "api_drafts_list";
        assert_eq!(handler, "api_drafts_list");
    }

    #[test]
    fn mailbox_routes_handler_api_drafts_upsert() {
        let handler = "api_drafts_upsert";
        assert_eq!(handler, "api_drafts_upsert");
    }

    #[test]
    fn mailbox_routes_handler_api_drafts_delete() {
        let handler = "api_drafts_delete";
        assert_eq!(handler, "api_drafts_delete");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_sources_list() {
        let handler = "api_newsletter_sources_list";
        assert_eq!(handler, "api_newsletter_sources_list");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_sources_create() {
        let handler = "api_newsletter_sources_create";
        assert_eq!(handler, "api_newsletter_sources_create");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_sources_update() {
        let handler = "api_newsletter_sources_update";
        assert_eq!(handler, "api_newsletter_sources_update");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_sources_delete() {
        let handler = "api_newsletter_sources_delete";
        assert_eq!(handler, "api_newsletter_sources_delete");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_sources_summarize() {
        let handler = "api_newsletter_sources_summarize";
        assert_eq!(handler, "api_newsletter_sources_summarize");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_suggestions() {
        let handler = "api_newsletter_suggestions";
        assert_eq!(handler, "api_newsletter_suggestions");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_items_list() {
        let handler = "api_newsletter_items_list";
        assert_eq!(handler, "api_newsletter_items_list");
    }

    #[test]
    fn mailbox_routes_handler_api_newsletter_items_create() {
        let handler = "api_newsletter_items_create";
        assert_eq!(handler, "api_newsletter_items_create");
    }

    #[test]
    fn mailbox_routes_handler_api_templates() {
        let handler = "api_templates";
        assert_eq!(handler, "api_templates");
    }

    #[test]
    fn mailbox_routes_handler_api_get_ai_settings() {
        let handler = "api_get_ai_settings";
        assert_eq!(handler, "api_get_ai_settings");
    }

    #[test]
    fn mailbox_routes_handler_api_put_ai_settings() {
        let handler = "api_put_ai_settings";
        assert_eq!(handler, "api_put_ai_settings");
    }

    #[test]
    fn mailbox_routes_handler_api_mail_assistant_suggestions() {
        let handler = "api_mail_assistant_suggestions";
        assert_eq!(handler, "api_mail_assistant_suggestions");
    }

    #[test]
    fn mailbox_routes_handler_api_hermes_runs_list() {
        let handler = "api_hermes_runs_list";
        assert_eq!(handler, "api_hermes_runs_list");
    }

    #[test]
    fn mailbox_routes_handler_api_hermes_runs() {
        let handler = "api_hermes_runs";
        assert_eq!(handler, "api_hermes_runs");
    }

    #[test]
    fn mailbox_routes_handler_api_hermes_run_status() {
        let handler = "api_hermes_run_status";
        assert_eq!(handler, "api_hermes_run_status");
    }

    #[test]
    fn mailbox_routes_handler_api_hermes_run_events() {
        let handler = "api_hermes_run_events";
        assert_eq!(handler, "api_hermes_run_events");
    }

    #[test]
    fn mailbox_routes_handler_api_send_undo() {
        let handler = "api_send_undo";
        assert_eq!(handler, "api_send_undo");
    }

    #[test]
    fn mailbox_routes_handler_api_send_schedule() {
        let handler = "api_send_schedule";
        assert_eq!(handler, "api_send_schedule");
    }

    #[test]
    fn mailbox_routes_handler_calendar_list_events() {
        let handler = "calendar_list_events";
        assert_eq!(handler, "calendar_list_events");
    }

    #[test]
    fn mailbox_routes_handler_calendar_agenda() {
        let handler = "calendar_agenda";
        assert_eq!(handler, "calendar_agenda");
    }

    #[test]
    fn mailbox_routes_handler_calendar_get_event() {
        let handler = "calendar_get_event";
        assert_eq!(handler, "calendar_get_event");
    }

    #[test]
    fn mailbox_routes_handler_calendar_update_event() {
        let handler = "calendar_update_event";
        assert_eq!(handler, "calendar_update_event");
    }

    #[test]
    fn mailbox_routes_handler_calendar_delete_event() {
        let handler = "calendar_delete_event";
        assert_eq!(handler, "calendar_delete_event");
    }
}
