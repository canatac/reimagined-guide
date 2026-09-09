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
