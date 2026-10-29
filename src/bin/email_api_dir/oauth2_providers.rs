// OAuth2 provider configurations and token management for IMAP authentication.
// Supports Google (Gmail), Microsoft (Outlook), and generic OAuth2 providers.
// Implements RFC 7628 (OAuth 2.0 for IMAP) and XOAUTH2 SASL mechanism.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OAuth2 provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2ProviderConfig {
    pub provider: String,
    pub display_name: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub scopes: Vec<String>,
    pub imap_host: String,
    pub imap_port: u16,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
}

/// OAuth2 token response from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obtained_at: Option<String>,
}

/// Stored OAuth2 token (encrypted at rest)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredOAuth2Token {
    pub account_id: String,
    pub provider: String,
    /// Encrypted access token (base64-encoded ciphertext + nonce)
    pub encrypted_access_token: String,
    /// Encrypted refresh token (base64-encoded ciphertext + nonce)
    pub encrypted_refresh_token: String,
    /// Token expiry timestamp (RFC3339)
    pub expires_at: String,
    /// When the token was last refreshed (RFC3339)
    pub refreshed_at: String,
    /// Key version for rotation support
    pub key_version: u32,
}

/// Input to start OAuth2 authorization flow
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2StartAuthInput {
    pub provider: String,
    pub email: String,
    pub imap_host: Option<String>,
    pub imap_port: Option<u16>,
    pub redirect_uri: Option<String>,
}

/// Response from starting OAuth2 authorization flow
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2StartAuthResponse {
    pub authorization_url: String,
    pub state: String,
    pub provider: String,
}

/// Input to complete OAuth2 authorization (callback)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2CallbackInput {
    pub state: String,
    pub code: String,
    pub provider: String,
    pub email: String,
    pub imap_host: Option<String>,
    pub imap_port: Option<u16>,
    pub imap_tls: Option<bool>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_tls: Option<bool>,
}

/// Response from OAuth2 callback
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2CallbackResponse {
    pub account_id: String,
    pub provider: String,
    pub email: String,
    pub status: String,
    pub expires_at: String,
}

/// OAuth2 token status for an account
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2TokenStatus {
    pub account_id: String,
    pub provider: String,
    pub has_token: bool,
    pub expires_at: Option<String>,
    pub is_expired: bool,
    pub status: String,
}

/// Get the list of supported OAuth2 providers
pub fn get_supported_providers() -> Vec<OAuth2ProviderConfig> {
    vec![
        OAuth2ProviderConfig {
            provider: "google".to_string(),
            display_name: "Google (Gmail)".to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            scopes: vec![
                "https://mail.google.com/".to_string(),
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            imap_host: "imap.gmail.com".to_string(),
            imap_port: 993,
            smtp_host: Some("smtp.gmail.com".to_string()),
            smtp_port: Some(587),
        },
        OAuth2ProviderConfig {
            provider: "microsoft".to_string(),
            display_name: "Microsoft (Outlook/Office365)".to_string(),
            authorization_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                .to_string(),
            token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token"
                .to_string(),
            scopes: vec![
                "https://outlook.office.com/IMAP.AccessAsUser.All".to_string(),
                "https://outlook.office.com/SMTP.Send".to_string(),
                "offline_access".to_string(),
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            imap_host: "outlook.office365.com".to_string(),
            imap_port: 993,
            smtp_host: Some("smtp.office365.com".to_string()),
            smtp_port: Some(587),
        },
        OAuth2ProviderConfig {
            provider: "yahoo".to_string(),
            display_name: "Yahoo Mail".to_string(),
            authorization_endpoint: "https://api.login.yahoo.com/oauth2/request_auth".to_string(),
            token_endpoint: "https://api.login.yahoo.com/oauth2/get_token".to_string(),
            scopes: vec![
                "mail-r".to_string(),
                "mail-w".to_string(),
                "openid".to_string(),
                "email".to_string(),
            ],
            imap_host: "imap.mail.yahoo.com".to_string(),
            imap_port: 993,
            smtp_host: Some("smtp.mail.yahoo.com".to_string()),
            smtp_port: Some(587),
        },
    ]
}

/// Look up a provider config by name
pub fn get_provider_config(provider: &str) -> Option<OAuth2ProviderConfig> {
    get_supported_providers()
        .into_iter()
        .find(|p| p.provider == provider)
}

/// Build the XOAUTH2 SASL authentication string for IMAP
/// Format: user=<email>\x01auth=Bearer <access_token>\x01\x01
/// See RFC 7628 Section 3
pub fn build_xoauth2_string(email: &str, access_token: &str) -> String {
    format!("user={}\x01auth=Bearer {}\x01\x01", email, access_token)
}

/// Generate the authorization URL for a provider
pub fn build_authorization_url(
    provider: &OAuth2ProviderConfig,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    email: &str,
) -> String {
    let scopes = provider.scopes.join(" ");
    let mut params = HashMap::new();
    params.insert("client_id", client_id);
    params.insert("redirect_uri", redirect_uri);
    params.insert("response_type", "code");
    params.insert("scope", &scopes);
    params.insert("state", state);
    params.insert("access_type", "offline");
    params.insert("prompt", "consent");
    params.insert("login_hint", email);

    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();

    format!("{}?{}", provider.authorization_endpoint, query.join("&"))
}

/// Check if a token is expired given its RFC3339 expiry timestamp
pub fn is_token_expired(expires_at: &str) -> bool {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(dt) => {
            let now = chrono::Utc::now();
            let dt_utc = dt.with_timezone(&chrono::Utc);
            // Consider expired if less than 5 minutes remaining
            now >= (dt_utc - chrono::Duration::minutes(5))
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_providers() {
        let providers = get_supported_providers();
        assert_eq!(providers.len(), 3);
        assert!(providers.iter().any(|p| p.provider == "google"));
        assert!(providers.iter().any(|p| p.provider == "microsoft"));
        assert!(providers.iter().any(|p| p.provider == "yahoo"));
    }

    #[test]
    fn test_provider_config_lookup() {
        let google = get_provider_config("google");
        assert!(google.is_some());
        let g = google.unwrap();
        assert_eq!(g.imap_host, "imap.gmail.com");
        assert_eq!(g.imap_port, 993);

        let unknown = get_provider_config("nonexistent");
        assert!(unknown.is_none());
    }

    #[test]
    fn test_build_xoauth2_string() {
        let sasl = build_xoauth2_string("user@gmail.com", "ya29.token123");
        assert_eq!(sasl, "user=user@gmail.com\x01auth=Bearer ya29.token123\x01\x01");
    }

    #[test]
    fn test_build_authorization_url() {
        let provider = get_provider_config("google").unwrap();
        let url = build_authorization_url(
            &provider,
            "client123.apps.googleusercontent.com",
            "https://mail.misfits.ai/oauth/callback",
            "state-abc",
            "user@gmail.com",
        );
        assert!(url.contains("accounts.google.com/o/oauth2/v2/auth"));
        assert!(url.contains("client_id=client123.apps.googleusercontent.com"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=state-abc"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("login_hint"));
    }

    #[test]
    fn test_is_token_expired() {
        // Future token
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        assert!(!is_token_expired(&future));

        // Past token
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        assert!(is_token_expired(&past));

        // Invalid timestamp
        assert!(is_token_expired("not-a-date"));
    }

    #[test]
    fn test_stored_token_serialization() {
        let token = StoredOAuth2Token {
            account_id: "acct-1".to_string(),
            provider: "google".to_string(),
            encrypted_access_token: "enc-access".to_string(),
            encrypted_refresh_token: "enc-refresh".to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            refreshed_at: "2026-01-01T00:00:00Z".to_string(),
            key_version: 1,
        };
        let json = serde_json::to_value(&token).unwrap();
        assert_eq!(json["accountId"], "acct-1");
        assert_eq!(json["provider"], "google");
        assert_eq!(json["keyVersion"], 1);
        let parsed: StoredOAuth2Token = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.account_id, "acct-1");
    }
}
