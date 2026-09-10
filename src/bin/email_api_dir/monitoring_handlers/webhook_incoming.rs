//! Incoming webhook handler with HMAC-SHA256 signature verification.
//!
//! Issue #486: webhook signature verification (incoming).
//!
//! Endpoint:
//! - POST /api/webhooks/incoming — receive external webhook payloads
//!
//! Security:
//! - HMAC-SHA256 signature verification via X-Webhook-Signature header
//! - Constant-time comparison to prevent timing attacks
//! - Rejects payloads missing or with invalid signatures
//! - Logs failed verification attempts

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

/// Stores registered secrets for incoming webhook verification.
/// Maps provider name → secret key.
pub struct IncomingWebhookSecrets {
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

impl IncomingWebhookSecrets {
    pub fn new() -> Self {
        IncomingWebhookSecrets {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a secret for a given provider (e.g. "github", "stripe").
    pub async fn register(&self, provider: String, secret: String) {
        self.secrets.write().await.insert(provider, secret);
    }

    /// Get the secret for a provider.
    pub async fn get(&self, provider: &str) -> Option<String> {
        self.secrets.read().await.get(provider).cloned()
    }
}

impl Default for IncomingWebhookSecrets {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute HMAC-SHA256 signature for a body using the secret.
pub fn compute_signature(body: &[u8], secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC can take key of any size");
    mac.update(body);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify an HMAC-SHA256 signature using constant-time comparison.
pub fn verify_signature(body: &[u8], secret: &[u8], signature: &str) -> bool {
    let expected = compute_signature(body, secret);
    // Decode hex signature from header
    let sig_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    expected.as_bytes().ct_eq(&sig_bytes).into()
}

/// Response for incoming webhook.
#[derive(Serialize)]
struct IncomingWebhookResponse {
    status: String,
    message: String,
}

/// POST /api/webhooks/incoming — receive and verify an incoming webhook.
///
/// Headers required:
/// - X-Webhook-Signature: hex-encoded HMAC-SHA256 signature
/// - X-Webhook-Provider: provider name (used to look up the secret)
///
/// Returns:
/// - 200: signature valid, payload accepted
/// - 401: missing or invalid signature
/// - 400: missing required headers
pub(crate) async fn api_webhook_incoming(
    secrets: web::Data<IncomingWebhookSecrets>,
    req: HttpRequest,
    body: web::Bytes,
) -> impl Responder {
    let signature = req
        .headers()
        .get("X-Webhook-Signature")
        .and_then(|v| v.to_str().ok());
    let provider = req
        .headers()
        .get("X-Webhook-Provider")
        .and_then(|v| v.to_str().ok());

    let (signature, provider) = match (signature, provider) {
        (Some(s), Some(p)) => (s, p),
        _ => {
            log::warn!(
                "webhook incoming: missing headers (signature={}, provider={})",
                signature.is_some(),
                provider.is_some()
            );
            return HttpResponse::BadRequest().json(IncomingWebhookResponse {
                status: "error".to_string(),
                message: "Missing X-Webhook-Signature or X-Webhook-Provider header".to_string(),
            });
        }
    };

    let secret = match secrets.get(provider).await {
        Some(s) => s,
        None => {
            log::warn!(
                "webhook incoming: unknown provider '{}' — rejecting",
                provider
            );
            return HttpResponse::Unauthorized().json(IncomingWebhookResponse {
                status: "error".to_string(),
                message: format!("Unknown provider: {}", provider),
            });
        }
    };

    if !verify_signature(&body, secret.as_bytes(), signature) {
        log::warn!(
            "webhook incoming: INVALID signature for provider '{}' — rejecting payload",
            provider
        );
        return HttpResponse::Unauthorized().json(IncomingWebhookResponse {
            status: "error".to_string(),
            message: "Invalid signature".to_string(),
        });
    }

    log::info!(
        "webhook incoming: valid signature for provider {} ({} bytes)",
        provider,
        body.len()
    );

    HttpResponse::Ok().json(IncomingWebhookResponse {
        status: "ok".to_string(),
        message: "Webhook received and verified".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_signature_produces_64_hex_chars() {
        let sig = compute_signature(b"test payload", b"secret-key");
        assert_eq!(sig.len(), 64);
        // Must be valid hex
        assert!(hex::decode(&sig).is_ok());
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let body = b"hello webhook";
        let secret = b"my-secret";
        let sig = compute_signature(body, secret);
        assert!(verify_signature(body, secret, &sig));
    }

    #[test]
    fn verify_rejects_wrong_signature() {
        let body = b"hello webhook";
        let secret = b"my-secret";
        assert!(!verify_signature(body, secret, "deadbeef"));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let body = b"hello webhook";
        let sig = compute_signature(body, b"secret-a");
        assert!(!verify_signature(body, b"secret-b", &sig));
    }

    #[test]
    fn verify_rejects_invalid_hex() {
        let body = b"hello webhook";
        let secret = b"my-secret";
        assert!(!verify_signature(body, secret, "not-valid-hex!"));
    }

    #[test]
    fn verify_is_case_sensitive() {
        let body = b"hello webhook";
        let secret = b"my-secret";
        let sig_upper = compute_signature(body, secret).to_uppercase();
        // Hex decode is case-insensitive but our comparison uses raw bytes
        // The expected is lowercase hex, so uppercase should still match
        // because hex::decode handles both cases.
        assert!(verify_signature(body, secret, &sig_upper));
    }

    #[tokio::test]
    async fn secrets_register_and_get() {
        let secrets = IncomingWebhookSecrets::new();
        secrets.register("github".to_string(), "gh-secret".to_string()).await;
        assert_eq!(secrets.get("github").await, Some("gh-secret".to_string()));
        assert_eq!(secrets.get("unknown").await, None);
    }
}
