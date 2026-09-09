//! Incoming webhook signature verification handler.
//!
//! Issue #486: webhook signature verification (HMAC-SHA256).
//!
//! POST /api/webhooks/incoming/:token
//!   - Verifies X-Webhook-Signature HMAC-SHA256 header
//!   - Rejects invalid payloads (401)
//!   - Logs failed attempts to security audit

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use simple_smtp_server::webhook::incoming::{self, VerificationResult};

/// Store of webhook secrets keyed by token.
pub(crate) struct IncomingWebhookSecrets {
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

impl IncomingWebhookSecrets {
    pub fn new() -> Self {
        IncomingWebhookSecrets {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, token: String, secret: String) {
        self.secrets.write().await.insert(token, secret);
    }

    pub async fn get(&self, token: &str) -> Option<String> {
        self.secrets.read().await.get(token).cloned()
    }
}

impl Default for IncomingWebhookSecrets {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle an incoming webhook with signature verification.
pub(crate) async fn api_incoming_webhook(
    state: web::Data<IncomingWebhookSecrets>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Bytes,
) -> impl Responder {
    let token = path.into_inner();

    let secret = match state.get(&token).await {
        Some(s) => s,
        None => {
            log_failed_attempt(&token, &req, "unknown_token");
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Unknown webhook endpoint"
            }));
        }
    };

    let signature = req
        .headers()
        .get("X-Webhook-Signature")
        .and_then(|v| v.to_str().ok());

    let result = incoming::verify_incoming(&body, &secret, signature);

    match result {
        VerificationResult::Valid => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Webhook verified",
                "token": token
            }))
        }
        VerificationResult::InvalidSignature => {
            log_failed_attempt(&token, &req, "invalid_signature");
            HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "Invalid signature"
            }))
        }
        VerificationResult::MissingHeader => {
            log_failed_attempt(&token, &req, "missing_header");
            HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "Missing X-Webhook-Signature header"
            }))
        }
        VerificationResult::MissingSecret => {
            log_failed_attempt(&token, &req, "missing_secret");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Webhook secret not configured"
            }))
        }
    }
}

/// Register a new incoming webhook secret.
pub(crate) async fn api_incoming_webhook_register(
    state: web::Data<IncomingWebhookSecrets>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let secret = body.get("secret").and_then(|v| v.as_str()).unwrap_or("");

    if token.is_empty() || secret.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "token and secret are required"
        }));
    }

    state.register(token.to_string(), secret.to_string()).await;
    HttpResponse::Created().json(serde_json::json!({
        "message": "Webhook registered",
        "token": token
    }))
}

fn log_failed_attempt(token: &str, req: &HttpRequest, reason: &str) {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown");
    eprintln!(
        "[WEBHOOK-AUDIT] failed verification: token={} reason={} ip={}",
        token, reason, ip
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_get_secret() {
        let state = IncomingWebhookSecrets::new();
        state.register("tok123".to_string(), "secret456".to_string()).await;
        assert_eq!(state.get("tok123").await, Some("secret456".to_string()));
        assert_eq!(state.get("unknown").await, None);
    }
}
