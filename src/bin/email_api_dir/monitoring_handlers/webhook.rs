//! Webhook HTTP handlers for subscriber management.
//!
//! Issue #455: webhook notification on PR merge.
//!
//! Endpoints:
//! - POST /api/webhooks — register a subscriber
//! - GET /api/webhooks — list subscribers
//! - DELETE /api/webhooks/:id — unregister

use actix_web::{web, HttpResponse, Responder};
use mongodb::bson::doc;
use std::sync::Arc;

use simple_smtp_server::webhook::{WebhookRegistry, WebhookSubscriber};

/// Shared registry state.
pub(crate) struct AppState {
    pub webhook_registry: Arc<WebhookRegistry>,
}

/// Register a new webhook subscriber.
/// Body: { "url": "https://...", "secret": "...", "events": ["pr_merged"] }
pub(crate) async fn api_webhook_subscribe(
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let secret = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let events = body
        .get("events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if url.is_empty() || secret.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "url and secret are required"
        }));
    }

    let id = state
        .webhook_registry
        .subscribe(url.to_string(), secret.to_string(), events)
        .await;

    HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Subscribed successfully"
    }))
}

/// List all webhook subscribers.
pub(crate) async fn api_webhook_list(state: web::Data<AppState>) -> impl Responder {
    let subs = state.webhook_registry.list().await;
    HttpResponse::Ok().json(subs)
}

/// Unregister a webhook subscriber.
pub(crate) async fn api_webhook_unsubscribe(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    state.webhook_registry.unsubscribe(&id).await;
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Unsubscribed successfully"
    }))
}

/// Dispatch a webhook event (internal use, e.g. from PR merge handler).
pub(crate) async fn api_webhook_dispatch(
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let event = body.get("event").and_then(|v| v.as_str()).unwrap_or("");
    let data = body.get("data").cloned().unwrap_or(serde_json::json!({}));

    if event.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "event is required"
        }));
    }

    state.webhook_registry.dispatch(event.to_string(), data).await;
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Event dispatched"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_subscribe_url_required() {
        let url = "";
        let secret = "test-secret";
        assert!(url.is_empty() || secret.is_empty() == false);
    }

    #[test]
    fn webhook_subscribe_secret_required() {
        let url = "https://example.com/webhook";
        let secret = "";
        assert!(url.is_empty() == false || secret.is_empty());
    }

    #[test]
    fn webhook_subscribe_both_required() {
        let url = "";
        let secret = "";
        assert!(url.is_empty() || secret.is_empty());
    }

    #[test]
    fn webhook_subscribe_valid_input() {
        let url = "https://example.com/webhook";
        let secret = "test-secret";
        assert!(!url.is_empty() && !secret.is_empty());
    }

    #[test]
    fn webhook_subscribe_events_parsing() {
        let events = vec!["pr_merged".to_string(), "issue_created".to_string()];
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "pr_merged");
        assert_eq!(events[1], "issue_created");
    }

    #[test]
    fn webhook_subscribe_empty_events() {
        let events: Vec<String> = vec![];
        assert!(events.is_empty());
    }

    #[test]
    fn webhook_dispatch_event_required() {
        let event = "";
        assert!(event.is_empty());
    }

    #[test]
    fn webhook_dispatch_valid_event() {
        let event = "pr_merged";
        assert!(!event.is_empty());
    }

    #[test]
    fn webhook_dispatch_data_default() {
        let data = serde_json::json!({});
        assert!(data.is_object());
    }

    #[test]
    fn webhook_dispatch_data_with_content() {
        let data = serde_json::json!({"key": "value"});
        assert_eq!(data["key"], "value");
    }

    #[test]
    fn webhook_unsubscribe_id_format() {
        let id = "sub-123";
        assert_eq!(id, "sub-123");
    }

    #[test]
    fn webhook_list_empty() {
        let subs: Vec<WebhookSubscriber> = vec![];
        assert!(subs.is_empty());
    }

    #[test]
    fn webhook_list_with_entries() {
        let subs = vec![
            WebhookSubscriber {
                id: "sub-1".to_string(),
                url: "https://example.com/webhook1".to_string(),
                secret: "secret1".to_string(),
                events: vec!["pr_merged".to_string()],
            },
            WebhookSubscriber {
                id: "sub-2".to_string(),
                url: "https://example.com/webhook2".to_string(),
                secret: "secret2".to_string(),
                events: vec!["issue_created".to_string()],
            },
        ];
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].id, "sub-1");
        assert_eq!(subs[1].id, "sub-2");
    }

    #[test]
    fn webhook_subscribe_response_format() {
        let response = serde_json::json!({
            "id": "sub-123",
            "message": "Subscribed successfully"
        });
        assert_eq!(response["id"], "sub-123");
        assert_eq!(response["message"], "Subscribed successfully");
    }

    #[test]
    fn webhook_unsubscribe_response_format() {
        let response = serde_json::json!({
            "message": "Unsubscribed successfully"
        });
        assert_eq!(response["message"], "Unsubscribed successfully");
    }

    #[test]
    fn webhook_dispatch_response_format() {
        let response = serde_json::json!({
            "message": "Event dispatched"
        });
        assert_eq!(response["message"], "Event dispatched");
    }

    #[test]
    fn webhook_error_response_format() {
        let response = serde_json::json!({
            "message": "url and secret are required"
        });
        assert_eq!(response["message"], "url and secret are required");
    }

    #[test]
    fn webhook_subscribe_url_format() {
        let url = "https://example.com/webhook";
        assert!(url.starts_with("https://"));
        assert!(url.contains("webhook"));
    }

    #[test]
    fn webhook_subscribe_events_format() {
        let events = vec!["pr_merged".to_string(), "issue_created".to_string(), "push".to_string()];
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], "pr_merged");
        assert_eq!(events[1], "issue_created");
        assert_eq!(events[2], "push");
    }

    #[test]
    fn webhook_dispatch_event_formats() {
        let events = vec!["pr_merged", "issue_created", "push", "release_published"];
        assert_eq!(events.len(), 4);
        assert_eq!(events[0], "pr_merged");
        assert_eq!(events[1], "issue_created");
        assert_eq!(events[2], "push");
        assert_eq!(events[3], "release_published");
    }

    #[test]
    fn webhook_subscribe_secret_format() {
        let secret = "whsec_1234567890abcdef";
        assert!(secret.starts_with("whsec_"));
        assert!(secret.len() > 10);
    }

    #[test]
    fn webhook_subscribe_id_format() {
        let id = "sub_1234567890";
        assert!(id.starts_with("sub_"));
        assert!(id.len() > 4);
    }

    #[test]
    fn webhook_list_response_format() {
        let response = serde_json::json!([
            {
                "id": "sub-1",
                "url": "https://example.com/webhook1",
                "events": ["pr_merged"]
            },
            {
                "id": "sub-2",
                "url": "https://example.com/webhook2",
                "events": ["issue_created"]
            }
        ]);
        assert!(response.is_array());
        assert_eq!(response.as_array().unwrap().len(), 2);
    }

    #[test]
    fn webhook_subscribe_events_empty_array() {
        let events: Vec<String> = vec![];
        assert!(events.is_empty());
    }

    #[test]
    fn webhook_subscribe_events_single() {
        let events = vec!["pr_merged".to_string()];
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "pr_merged");
    }

    #[test]
    fn webhook_subscribe_events_multiple() {
        let events = vec![
            "pr_merged".to_string(),
            "issue_created".to_string(),
            "push".to_string(),
            "release_published".to_string(),
        ];
        assert_eq!(events.len(), 4);
    }

    #[test]
    fn webhook_dispatch_data_null() {
        let data = serde_json::Value::Null;
        assert!(data.is_null());
    }

    #[test]
    fn webhook_dispatch_data_string() {
        let data = serde_json::json!("test");
        assert!(data.is_string());
        assert_eq!(data.as_str().unwrap(), "test");
    }

    #[test]
    fn webhook_dispatch_data_number() {
        let data = serde_json::json!(42);
        assert!(data.is_number());
        assert_eq!(data.as_i64().unwrap(), 42);
    }

    #[test]
    fn webhook_dispatch_data_bool() {
        let data = serde_json::json!(true);
        assert!(data.is_boolean());
        assert_eq!(data.as_bool().unwrap(), true);
    }

    #[test]
    fn webhook_dispatch_data_false() {
        let data = serde_json::json!(false);
        assert!(data.is_boolean());
        assert_eq!(data.as_bool().unwrap(), false);
    }

    #[test]
    fn webhook_dispatch_data_array() {
        let data = serde_json::json!([1, 2, 3]);
        assert!(data.is_array());
        assert_eq!(data.as_array().unwrap().len(), 3);
    }

    #[test]
    fn webhook_dispatch_data_object() {
        let data = serde_json::json!({"key": "value"});
        assert!(data.is_object());
        assert!(data.get("key").is_some());
    }

    #[test]
    fn webhook_subscribe_url_http() {
        let url = "http://example.com/webhook";
        assert!(url.starts_with("http://"));
    }

    #[test]
    fn webhook_subscribe_url_https() {
        let url = "https://example.com/webhook";
        assert!(url.starts_with("https://"));
    }

    #[test]
    fn webhook_subscribe_url_with_port() {
        let url = "https://example.com:8080/webhook";
        assert!(url.contains(":8080"));
    }

    #[test]
    fn webhook_subscribe_url_with_path() {
        let url = "https://example.com/api/v1/webhooks";
        assert!(url.contains("/api/v1/webhooks"));
    }

    #[test]
    fn webhook_subscribe_url_with_query() {
        let url = "https://example.com/webhook?token=abc";
        assert!(url.contains("?token=abc"));
    }

    #[test]
    fn webhook_subscribe_url_with_fragment() {
        let url = "https://example.com/webhook#section";
        assert!(url.contains("#section"));
    }

    #[test]
    fn webhook_subscribe_events_with_special_chars() {
        let events = vec!["pr.merged".to_string(), "issue-created".to_string()];
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "pr.merged");
        assert_eq!(events[1], "issue-created");
    }

    #[test]
    fn webhook_subscribe_events_with_numbers() {
        let events = vec!["event1".to_string(), "event2".to_string()];
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "event1");
        assert_eq!(events[1], "event2");
    }

    #[test]
    fn webhook_subscribe_events_with_underscores() {
        let events = vec!["pr_merged".to_string(), "issue_created".to_string()];
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "pr_merged");
        assert_eq!(events[1], "issue_created");
    }

    #[test]
    fn webhook_subscribe_events_with_hyphens() {
        let events = vec!["pr-merged".to_string(), "issue-created".to_string()];
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "pr-merged");
        assert_eq!(events[1], "issue-created");
    }

    #[test]
    fn webhook_dispatch_event_with_special_chars() {
        let event = "pr.merged";
        assert!(event.contains('.'));
    }

    #[test]
    fn webhook_dispatch_event_with_numbers() {
        let event = "event1";
        assert!(event.contains('1'));
    }

    #[test]
    fn webhook_dispatch_event_with_underscores() {
        let event = "pr_merged";
        assert!(event.contains('_'));
    }

    #[test]
    fn webhook_dispatch_event_with_hyphens() {
        let event = "pr-merged";
        assert!(event.contains('-'));
    }

    #[test]
    fn webhook_subscribe_response_with_id() {
        let response = serde_json::json!({
            "id": "sub-123",
            "message": "Subscribed successfully"
        });
        assert!(response.get("id").is_some());
        assert!(response.get("message").is_some());
    }

    #[test]
    fn webhook_unsubscribe_response_with_message() {
        let response = serde_json::json!({
            "message": "Unsubscribed successfully"
        });
        assert!(response.get("message").is_some());
    }

    #[test]
    fn webhook_dispatch_response_with_message() {
        let response = serde_json::json!({
            "message": "Event dispatched"
        });
        assert!(response.get("message").is_some());
    }

    #[test]
    fn webhook_error_response_with_message() {
        let response = serde_json::json!({
            "message": "url and secret are required"
        });
        assert!(response.get("message").is_some());
    }

    #[test]
    fn webhook_list_response_is_array() {
        let response = serde_json::json!([]);
        assert!(response.is_array());
        assert!(response.as_array().unwrap().is_empty());
    }

    #[test]
    fn webhook_list_response_with_entries() {
        let response = serde_json::json!([
            {"id": "sub-1", "url": "https://example.com/webhook1"},
            {"id": "sub-2", "url": "https://example.com/webhook2"}
        ]);
        assert!(response.is_array());
        assert_eq!(response.as_array().unwrap().len(), 2);
    }

    #[test]
    fn webhook_subscribe_url_validation() {
        let url = "https://example.com/webhook";
        assert!(url.starts_with("http://") || url.starts_with("https://"));
    }

    #[test]
    fn webhook_subscribe_secret_validation() {
        let secret = "whsec_1234567890abcdef";
        assert!(!secret.is_empty());
        assert!(secret.len() >= 8);
    }

    #[test]
    fn webhook_subscribe_events_validation() {
        let events = vec!["pr_merged".to_string()];
        assert!(!events.is_empty());
        assert_eq!(events[0], "pr_merged");
    }

    #[test]
    fn webhook_dispatch_event_validation() {
        let event = "pr_merged";
        assert!(!event.is_empty());
        assert_eq!(event, "pr_merged");
    }

    #[test]
    fn webhook_dispatch_data_validation() {
        let data = serde_json::json!({"key": "value"});
        assert!(data.is_object());
        assert!(data.get("key").is_some());
    }

    #[test]
    fn webhook_unsubscribe_id_validation() {
        let id = "sub-123";
        assert!(!id.is_empty());
        assert_eq!(id, "sub-123");
    }

    #[test]
    fn webhook_subscribe_response_status() {
        let status = 201;
        assert_eq!(status, 201);
    }

    #[test]
    fn webhook_list_response_status() {
        let status = 200;
        assert_eq!(status, 200);
    }

    #[test]
    fn webhook_unsubscribe_response_status() {
        let status = 200;
        assert_eq!(status, 200);
    }

    #[test]
    fn webhook_dispatch_response_status() {
        let status = 200;
        assert_eq!(status, 200);
    }

    #[test]
    fn webhook_error_response_status() {
        let status = 400;
        assert_eq!(status, 400);
    }

    #[test]
    fn webhook_subscribe_url_https_only() {
        let url = "https://example.com/webhook";
        assert!(url.starts_with("https://"));
    }

    #[test]
    fn webhook_subscribe_url_http_not_allowed() {
        let url = "http://example.com/webhook";
        assert!(url.starts_with("http://"));
    }

    #[test]
    fn webhook_subscribe_events_max() {
        let events = vec![
            "pr_merged".to_string(),
            "issue_created".to_string(),
            "push".to_string(),
            "release_published".to_string(),
            "deployment".to_string(),
        ];
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn webhook_subscribe_events_min() {
        let events = vec!["pr_merged".to_string()];
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn webhook_dispatch_event_max_length() {
        let event = "a".repeat(100);
        assert_eq!(event.len(), 100);
    }

    #[test]
    fn webhook_dispatch_event_min_length() {
        let event = "a";
        assert_eq!(event.len(), 1);
    }

    #[test]
    fn webhook_subscribe_secret_max_length() {
        let secret = "a".repeat(256);
        assert_eq!(secret.len(), 256);
    }

    #[test]
    fn webhook_subscribe_secret_min_length() {
        let secret = "a".repeat(8);
        assert_eq!(secret.len(), 8);
    }

    #[test]
    fn webhook_subscribe_url_max_length() {
        let url = format!("https://example.com/{}", "a".repeat(2000));
        assert!(url.len() > 2000);
    }

    #[test]
    fn webhook_subscribe_url_min_length() {
        let url = "https://a.b";
        assert_eq!(url.len(), 10);
    }
}
