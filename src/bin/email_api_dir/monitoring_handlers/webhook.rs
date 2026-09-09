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

/// Receive an incoming webhook with HMAC-SHA256 signature verification.
///
/// Headers required:
/// - `X-Webhook-Id`: subscriber ID (to look up the shared secret)
/// - `X-Webhook-Signature`: hex-encoded HMAC-SHA256 signature of the body
///
/// On invalid/missing signature → 401 + audit log of the failed attempt.
pub(crate) async fn api_webhook_incoming(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
    body: web::Bytes,
) -> impl Responder {
    let webhook_id = req
        .headers()
        .get("X-Webhook-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let signature = req
        .headers()
        .get("X-Webhook-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or "";

    if webhook_id.is_empty() || signature.is_empty() {
        // Log failed attempt
        eprintln!(
            "webhook_incoming: rejected missing headers (id={}, sig_len={})",
            webhook_id.len(),
            signature.len()
        );
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "X-Webhook-Id and X-Webhook-Signature headers required"
        }));
    }

    // Look up the subscriber to get the shared secret
    let subs = state.webhook_registry.list().await;
    let subscriber = subs.iter().find(|s| s.id == webhook_id && s.active);

    let secret = match subscriber {
        Some(sub) => sub.secret.clone(),
        None => {
            eprintln!(
                "webhook_incoming: rejected unknown/inactive webhook id={}",
                webhook_id
            );
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "Unknown webhook id"
            }));
        }
    };

    // Verify HMAC-SHA256 signature
    let body_str = String::from_utf8_lossy(&body);
    if !simple_smtp_server::webhook::verify(&body_str, &secret, signature) {
        eprintln!(
            "webhook_incoming: rejected invalid signature for webhook id={}",
            webhook_id
        );
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "message": "Invalid signature"
        }));
    }

    // Parse the verified payload
    let payload: serde_json::Value = match serde_json::from_str(&body_str) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": format!("Invalid JSON body: {}", e)
            }));
        }
    };

    // Dispatch internally so downstream handlers can react
    let event = payload
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let data = payload.get("data").cloned().unwrap_or(serde_json::json!({}));
    state.webhook_registry.dispatch(event, data).await;

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Webhook received and verified"
    }))
}
