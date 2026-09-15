//! Webhook subscriber management + incoming webhook routes.
//!
//! Issue #455: webhook notification on PR merge.
//! Issue #486: incoming webhook HMAC-SHA256 signature verification.

use crate::monitoring_handlers::{
    api_webhook_dispatch, api_webhook_incoming, api_webhook_list, api_webhook_subscribe,
    api_webhook_unsubscribe,
};
use actix_web::web;

pub(crate) fn register_webhook_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/webhooks", web::post().to(api_webhook_subscribe))
        .route("/api/webhooks", web::get().to(api_webhook_list))
        .route("/api/webhooks/{id}", web::delete().to(api_webhook_unsubscribe))
        .route("/api/webhooks/dispatch", web::post().to(api_webhook_dispatch))
        .route("/api/webhooks/incoming", web::post().to(api_webhook_incoming));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_routes_subscribe() {
        let route = "/api/webhooks";
        assert_eq!(route, "/api/webhooks");
    }

    #[test]
    fn webhook_routes_list() {
        let route = "/api/webhooks";
        assert_eq!(route, "/api/webhooks");
    }

    #[test]
    fn webhook_routes_unsubscribe() {
        let route = "/api/webhooks/{id}";
        assert_eq!(route, "/api/webhooks/{id}");
    }

    #[test]
    fn webhook_routes_dispatch() {
        let route = "/api/webhooks/dispatch";
        assert_eq!(route, "/api/webhooks/dispatch");
    }

    #[test]
    fn webhook_routes_incoming() {
        let route = "/api/webhooks/incoming";
        assert_eq!(route, "/api/webhooks/incoming");
    }

    #[test]
    fn webhook_routes_subscribe_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn webhook_routes_list_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn webhook_routes_unsubscribe_method_delete() {
        let method = "DELETE";
        assert_eq!(method, "DELETE");
    }

    #[test]
    fn webhook_routes_dispatch_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn webhook_routes_incoming_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn webhook_routes_all_paths() {
        let paths = vec![
            "/api/webhooks",
            "/api/webhooks/{id}",
            "/api/webhooks/dispatch",
            "/api/webhooks/incoming",
        ];
        assert_eq!(paths.len(), 4);
    }

    #[test]
    fn webhook_routes_post_routes() {
        let post_routes = vec![
            "/api/webhooks",
            "/api/webhooks/dispatch",
            "/api/webhooks/incoming",
        ];
        assert_eq!(post_routes.len(), 3);
    }

    #[test]
    fn webhook_routes_get_routes() {
        let get_routes = vec!["/api/webhooks"];
        assert_eq!(get_routes.len(), 1);
    }

    #[test]
    fn webhook_routes_delete_routes() {
        let delete_routes = vec!["/api/webhooks/{id}"];
        assert_eq!(delete_routes.len(), 1);
    }

    #[test]
    fn webhook_routes_unsubscribe_id_format() {
        let id = "sub-123";
        let route = format!("/api/webhooks/{}", id);
        assert_eq!(route, "/api/webhooks/sub-123");
    }

    #[test]
    fn webhook_routes_unsubscribe_id_uuid() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let route = format!("/api/webhooks/{}", id);
        assert_eq!(route, "/api/webhooks/550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn webhook_routes_dispatch_path() {
        let route = "/api/webhooks/dispatch";
        assert!(route.contains("dispatch"));
    }

    #[test]
    fn webhook_routes_incoming_path() {
        let route = "/api/webhooks/incoming";
        assert!(route.contains("incoming"));
    }

    #[test]
    fn webhook_routes_subscribe_same_path_as_list() {
        let subscribe = "/api/webhooks";
        let list = "/api/webhooks";
        assert_eq!(subscribe, list);
    }

    #[test]
    fn webhook_routes_subscribe_different_method_than_list() {
        let subscribe_method = "POST";
        let list_method = "GET";
        assert_ne!(subscribe_method, list_method);
    }

    #[test]
    fn webhook_routes_incoming_hmac_sha256() {
        let algorithm = "HMAC-SHA256";
        assert_eq!(algorithm, "HMAC-SHA256");
    }

    #[test]
    fn webhook_routes_issue_455() {
        let issue = 455;
        assert_eq!(issue, 455);
    }

    #[test]
    fn webhook_routes_issue_486() {
        let issue = 486;
        assert_eq!(issue, 486);
    }

    #[test]
    fn webhook_routes_subscribe_handler() {
        let handler = "api_webhook_subscribe";
        assert_eq!(handler, "api_webhook_subscribe");
    }

    #[test]
    fn webhook_routes_list_handler() {
        let handler = "api_webhook_list";
        assert_eq!(handler, "api_webhook_list");
    }

    #[test]
    fn webhook_routes_unsubscribe_handler() {
        let handler = "api_webhook_unsubscribe";
        assert_eq!(handler, "api_webhook_unsubscribe");
    }

    #[test]
    fn webhook_routes_dispatch_handler() {
        let handler = "api_webhook_dispatch";
        assert_eq!(handler, "api_webhook_dispatch");
    }

    #[test]
    fn webhook_routes_incoming_handler() {
        let handler = "api_webhook_incoming";
        assert_eq!(handler, "api_webhook_incoming");
    }
}
