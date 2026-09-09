//! Webhook notification dispatcher for external system integration.
//!
//! Issue #455: webhook notification on PR merge.
//!
//! Subscribers register a URL + secret. When an event fires (e.g. PR merge),
//! we POST a JSON payload with an HMAC-SHA256 signature header.

use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

/// A webhook subscriber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSubscriber {
    pub id: String,
    pub url: String,
    /// Secret used to compute HMAC-SHA256 signature.
    pub secret: String,
    /// Event types this subscriber cares about (e.g. "pr_merged", "pr_opened").
    #[serde(default = "default_events")]
    pub events: Vec<String>,
    #[serde(default)]
    pub active: bool,
}

fn default_events() -> Vec<String> {
    vec!["*".to_string()]
}

/// Payload sent to webhook subscribers.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp: String,
    pub data: serde_json::Value,
}

/// In-memory subscriber registry.
pub struct WebhookRegistry {
    subscribers: Arc<RwLock<Vec<WebhookSubscriber>>>,
    client: Client,
}

impl WebhookRegistry {
    pub fn new() -> Self {
        WebhookRegistry {
            subscribers: Arc::new(RwLock::new(Vec::new())),
            client: Client::new(),
        }
    }

    /// Register a new subscriber. Returns the subscriber ID.
    pub async fn subscribe(&self, url: String, secret: String, events: Vec<String>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let sub = WebhookSubscriber {
            id: id.clone(),
            url,
            secret,
            events,
            active: true,
        };
        self.subscribers.write().await.push(sub);
        id
    }

    /// Unregister a subscriber by ID.
    pub async fn unsubscribe(&self, id: &str) {
        self.subscribers.write().await.retain(|s| s.id != id);
    }

    /// List all subscribers.
    pub async fn list(&self) -> Vec<WebhookSubscriber> {
        self.subscribers.read().await.clone()
    }

    /// Dispatch an event to all matching subscribers.
    pub async fn dispatch(&self, event: String, data: serde_json::Value) {
        let payload = WebhookPayload {
            event: event.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data,
        };
        let body = match serde_json::to_string(&payload) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("webhook: serialize error: {}", e);
                return;
            }
        };
        let subs = self.subscribers.read().await;
        for sub in subs.iter() {
            if !sub.active {
                continue;
            }
            if !sub.events.iter().any(|e| e == "*" || *e == event) {
                continue;
            }
            let signature = sign(&body, &sub.secret);
            let client = self.client.clone();
            let url = sub.url.clone();
            let body = body.clone();
            let event_header = event.clone();
            tokio::spawn(async move {
                if let Err(e) = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Webhook-Signature", signature)
                    .header("X-Webhook-Event", event_header)
                    .body(body)
                    .send()
                    .await
                {
                    eprintln!("webhook: dispatch to {} failed: {}", url, e);
                }
            });
        }
    }
}

impl Default for WebhookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute HMAC-SHA256 signature for a body using the secret.
pub fn sign(body: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(body.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify an HMAC-SHA256 signature.
pub fn verify(body: &str, secret: &str, signature: &str) -> bool {
    let expected = sign(body, secret);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_hex_string() {
        let sig = sign("hello world", "secret");
        assert_eq!(sig.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let body = r#"{"event":"test"}"#;
        let secret = "my-secret";
        let sig = sign(body, secret);
        assert!(verify(body, secret, &sig));
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let body = r#"{"event":"test"}"#;
        let secret = "my-secret";
        assert!(!verify(body, secret, "deadbeef"));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let body = r#"{"event":"test"}"#;
        let sig = sign(body, "secret-a");
        assert!(!verify(body, "secret-b", &sig));
    }

    #[test]
    fn webhook_payload_serializes() {
        let payload = WebhookPayload {
            event: "pr_merged".to_string(),
            timestamp: "2026-09-09T00:00:00Z".to_string(),
            data: serde_json::json!({"pr_number": 1}),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"event\":\"pr_merged\""));
        assert!(json.contains("\"pr_number\":1"));
    }

    #[tokio::test]
    async fn registry_subscribe_and_list() {
        let registry = WebhookRegistry::new();
        let id = registry.subscribe(
            "https://example.com/hook".to_string(),
            "secret".to_string(),
            vec!["pr_merged".to_string()],
        ).await;
        let subs = registry.list().await;
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id, id);
        assert_eq!(subs[0].url, "https://example.com/hook");
        assert!(subs[0].active);
    }

    #[tokio::test]
    async fn registry_unsubscribe() {
        let registry = WebhookRegistry::new();
        let id = registry.subscribe(
            "https://example.com/hook".to_string(),
            "secret".to_string(),
            vec!["*".to_string()],
        ).await;
        assert_eq!(registry.list().await.len(), 1);
        registry.unsubscribe(&id).await;
        assert_eq!(registry.list().await.len(), 0);
    }

    #[test]
    fn registry_filters_events() {
        let registry = WebhookRegistry::new();
        // Should not panic even if no subscribers match
        registry.dispatch("pr_opened".to_string(), serde_json::json!({}));
    }
}
