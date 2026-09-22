//! OAuth 2.0 token management for external IMAP accounts (MW-2026-062).
//!
//! Implements:
//! - XOAUTH2 SASL string construction (RFC 7628)
//! - Token refresh via refresh_token grant
//! - Provider-specific OAuth2 endpoint configuration (Gmail, Outlook, Yahoo)

use crate::external_imap::ExternalImapAccount;
use serde::{Deserialize, Serialize};

/// OAuth2 provider configuration for token refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2ProviderConfig {
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
}

/// Result of a token refresh operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2TokenResult {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scopes: Option<Vec<String>>,
}

/// Get the OAuth2 provider config for a given provider name.
pub fn provider_config(provider: &str) -> Option<OAuth2ProviderConfig> {
    match provider.to_ascii_lowercase().as_str() {
        "gmail" | "google" => Some(OAuth2ProviderConfig {
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            client_id: std::env::var("GOOGLE_OAUTH_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").unwrap_or_default(),
            scopes: vec![
                "https://mail.google.com/".to_string(),
            ],
        }),
        "outlook" | "microsoft" | "office365" => Some(OAuth2ProviderConfig {
            token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
            client_id: std::env::var("MICROSOFT_OAUTH_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("MICROSOFT_OAUTH_CLIENT_SECRET").unwrap_or_default(),
            scopes: vec![
                "https://outlook.office.com/IMAP.AccessAsUser.All".to_string(),
                "offline_access".to_string(),
            ],
        }),
        "yahoo" => Some(OAuth2ProviderConfig {
            token_endpoint: "https://api.login.yahoo.com/oauth2/get_token".to_string(),
            client_id: std::env::var("YAHOO_OAUTH_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("YAHOO_OAUTH_CLIENT_SECRET").unwrap_or_default(),
            scopes: vec![
                "mail-r".to_string(),
            ],
        }),
        _ => None,
    }
}

/// Check if an account's OAuth2 token is expired or about to expire.
/// Returns true if the token expires within the next 5 minutes.
pub fn is_token_expired(account: &ExternalImapAccount) -> bool {
    match account.oauth_token_expires_at {
        Some(expiry) => {
            let now = chrono::Utc::now();
            let threshold = chrono::Duration::minutes(5);
            expiry <= now + threshold
        }
        None => true, // No expiry info = assume expired
    }
}

/// Build the XOAUTH2 SASL authentication string for IMAP.
/// Format (RFC 7628): user={email}\x01auth=Bearer {access_token}\x01\x01
pub fn build_xoauth2_auth_string(email: &str, access_token: &str) -> String {
    format!("user={}\x01auth=Bearer {}\x01\x01", email, access_token)
}

/// Refresh an OAuth2 access token using the refresh_token grant.
/// Returns the new token set on success.
pub async fn refresh_oauth2_token(
    account: &ExternalImapAccount,
) -> Result<OAuth2TokenResult, String> {
    let config = provider_config(&account.provider)
        .ok_or_else(|| format!("Unsupported OAuth2 provider: {}", account.provider))?;

    let refresh_token = account.oauth_refresh_token.as_ref()
        .ok_or_else(|| "No refresh token available for account".to_string())?;

    if config.client_id.is_empty() || config.client_secret.is_empty() {
        return Err(format!(
            "OAuth2 client credentials not configured for provider: {}",
            account.provider
        ));
    }

    let client = reqwest::Client::new();
    let response = client
        .post(&config.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .map_err(|e| format!("OAuth2 token refresh request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("OAuth2 token refresh failed (HTTP {status}): {body}"));
    }

    let token_data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse OAuth2 token response: {e}"))?;

    let access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| "No access_token in OAuth2 response".to_string())?
        .to_string();

    let refresh_token_new = token_data["refresh_token"].as_str().map(String::from);
    let expires_in = token_data["expires_in"].as_i64();
    let scopes = token_data["scope"].as_str().map(|s| {
        s.split_whitespace().map(String::from).collect()
    });

    Ok(OAuth2TokenResult {
        access_token,
        refresh_token: refresh_token_new,
        expires_in,
        scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn is_token_expired_with_no_expiry() {
        let acct = ExternalImapAccount {
            id: "test".into(),
            owner_user_id: "user".into(),
            provider: "gmail".into(),
            email: "a@gmail.com".into(),
            auth_type: "oauth2".into(),
            secret_ref: None,
            secret_value: None,
            oauth_access_token: Some("token".into()),
            oauth_refresh_token: Some("refresh".into()),
            oauth_token_expires_at: None,
            oauth_scopes: None,
            imap_host: "imap.gmail.com".into(),
            imap_port: 993,
            imap_tls: true,
            smtp_host: None,
            smtp_port: None,
            smtp_tls: None,
            status: "active".into(),
            last_sync_at: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(is_token_expired(&acct));
    }

    #[test]
    fn is_token_expired_with_future_expiry() {
        let mut acct = ExternalImapAccount {
            id: "test".into(),
            owner_user_id: "user".into(),
            provider: "gmail".into(),
            email: "a@gmail.com".into(),
            auth_type: "oauth2".into(),
            secret_ref: None,
            secret_value: None,
            oauth_access_token: Some("token".into()),
            oauth_refresh_token: Some("refresh".into()),
            oauth_token_expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            oauth_scopes: None,
            imap_host: "imap.gmail.com".into(),
            imap_port: 993,
            imap_tls: true,
            smtp_host: None,
            smtp_port: None,
            smtp_tls: None,
            status: "active".into(),
            last_sync_at: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(!is_token_expired(&acct));

        // Expired: past
        acct.oauth_token_expires_at = Some(Utc::now() - chrono::Duration::minutes(1));
        assert!(is_token_expired(&acct));

        // About to expire: within 5 min
        acct.oauth_token_expires_at = Some(Utc::now() + chrono::Duration::minutes(3));
        assert!(is_token_expired(&acct));
    }

    #[test]
    fn build_xoauth2_auth_string_format() {
        let result = build_xoauth2_auth_string("user@gmail.com", "ya29.token123");
        assert_eq!(result, "user=user@gmail.com\x01auth=Bearer ya29.token123\x01\x01");
    }

    #[test]
    fn provider_config_gmail() {
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-client-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-secret");
        let config = provider_config("gmail").unwrap();
        assert_eq!(config.token_endpoint, "https://oauth2.googleapis.com/token");
        assert_eq!(config.client_id, "test-client-id");
        assert!(config.scopes.contains(&"https://mail.google.com/".to_string()));
    }

    #[test]
    fn provider_config_outlook() {
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_ID", "ms-client-id");
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_SECRET", "ms-secret");
        let config = provider_config("outlook").unwrap();
        assert!(config.token_endpoint.contains("microsoftonline.com"));
        assert!(config.scopes.contains(&"offline_access".to_string()));
    }

    #[test]
    fn provider_config_unknown() {
        assert!(provider_config("unknown-provider").is_none());
    }
}
