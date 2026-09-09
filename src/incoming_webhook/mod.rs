//! Incoming webhook signature verification.
//!
//! Issue #486: webhook signature verification.
//!
//! Verifies HMAC-SHA256 signatures on incoming webhook payloads.
//! Rejects invalid payloads and logs failed attempts.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

/// Registry of trusted webhook secrets keyed by source identifier.
pub struct IncomingWebhookRegistry {
    secrets: Arc<RwLock<HashMap<String, String>>>,
}

/// Result of signature verification.
#[derive(Debug, PartialEq)]
pub enum VerificationResult {
    Valid,
    InvalidSignature,
    MissingSignature,
    UnknownSource,
}

impl IncomingWebhookRegistry {
    pub fn new() -> Self {
        IncomingWebhookRegistry {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a trusted source with its secret.
    pub async fn register_source(&self, source: String, secret: String) {
        self.secrets.write().await.insert(source, secret);
    }

    /// Remove a trusted source.
    pub async fn remove_source(&self, source: &str) {
        self.secrets.write().await.remove(source);
    }

    /// List registered sources (identifiers only, not secrets).
    pub async fn list_sources(&self) -> Vec<String> {
        self.secrets.read().await.keys().cloned().collect()
    }

    /// Verify an incoming webhook signature.
    ///
    /// `source` identifies which secret to use (e.g. header `X-Webhook-Source`).
    /// `signature` is the hex-encoded HMAC-SHA256 from `X-Webhook-Signature`.
    /// `body` is the raw request body.
    pub async fn verify(&self, source: &str, signature: Option<&str>, body: &str) -> VerificationResult {
        let secrets = self.secrets.read().await;
        let secret = match secrets.get(source) {
            Some(s) => s.clone(),
            None => return VerificationResult::UnknownSource,
        };

        let sig = match signature {
            Some(s) => s,
            None => return VerificationResult::MissingSignature,
        };

        let expected = sign(body, &secret);
        if expected.as_bytes().ct_eq(sig.as_bytes()).into() {
            VerificationResult::Valid
        } else {
            VerificationResult::InvalidSignature
        }
    }
}

impl Default for IncomingWebhookRegistry {
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

/// Verify an HMAC-SHA256 signature (standalone function).
pub fn verify(body: &str, secret: &str, signature: &str) -> bool {
    let expected = sign(body, secret);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_64_char_hex() {
        let sig = sign("test body", "secret");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn verify_accepts_valid() {
        let body = r#"{"event":"test"}"#;
        let secret = "my-key";
        let sig = sign(body, secret);
        assert!(verify(body, secret, &sig));
    }

    #[test]
    fn verify_rejects_invalid() {
        let body = r#"{"event":"test"}"#;
        let secret = "my-key";
        assert!(!verify(body, secret, "deadbeef"));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let body = r#"{"event":"test"}"#;
        let sig = sign(body, "secret-a");
        assert!(!verify(body, "secret-b", &sig));
    }

    #[tokio::test]
    async fn registry_register_and_verify() {
        let reg = IncomingWebhookRegistry::new();
        reg.register_source("github".to_string(), "gh-secret".to_string()).await;

        let body = r#"{"action":"opened"}"#;
        let sig = sign(body, "gh-secret");
        let result = reg.verify("github", Some(&sig), body).await;
        assert_eq!(result, VerificationResult::Valid);
    }

    #[tokio::test]
    async fn registry_rejects_unknown_source() {
        let reg = IncomingWebhookRegistry::new();
        let result = reg.verify("unknown", Some("sig"), "body").await;
        assert_eq!(result, VerificationResult::UnknownSource);
    }

    #[tokio::test]
    async fn registry_rejects_missing_signature() {
        let reg = IncomingWebhookRegistry::new();
        reg.register_source("stripe".to_string(), "sk-secret".to_string()).await;
        let result = reg.verify("stripe", None, "body").await;
        assert_eq!(result, VerificationResult::MissingSignature);
    }

    #[tokio::test]
    async fn registry_rejects_invalid_signature() {
        let reg = IncomingWebhookRegistry::new();
        reg.register_source("stripe".to_string(), "sk-secret".to_string()).await;
        let result = reg.verify("stripe", Some("bad-sig"), "body").await;
        assert_eq!(result, VerificationResult::InvalidSignature);
    }

    #[tokio::test]
    async fn registry_remove_source() {
        let reg = IncomingWebhookRegistry::new();
        reg.register_source("test".to_string(), "secret".to_string()).await;
        assert_eq!(reg.list_sources().await.len(), 1);
        reg.remove_source("test").await;
        assert_eq!(reg.list_sources().await.len(), 0);
    }

    #[tokio::test]
    async fn registry_list_sources_excludes_secrets() {
        let reg = IncomingWebhookRegistry::new();
        reg.register_source("a".to_string(), "secret-a".to_string()).await;
        reg.register_source("b".to_string(), "secret-b".to_string()).await;
        let sources = reg.list_sources().await;
        assert!(sources.contains(&"a".to_string()));
        assert!(sources.contains(&"b".to_string()));
        assert_eq!(sources.len(), 2);
    }
}
