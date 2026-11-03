use actix_web::{web, HttpResponse};
use serde::Deserialize;
use std::sync::Arc;

use crate::external_imap::ExternalImapAccount;

/// OAuth2 token endpoint response.
#[derive(Debug, Deserialize)]
pub struct OAuth2TokenResult {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scopes: Option<Vec<String>>,
}

/// Build the XOAUTH2 authentication string for IMAP/SMTP.
pub fn build_xoauth2_auth_string(account: &ExternalImapAccount) -> String {
    let email = account.email.clone();
    let token = account.access_token.clone();
    format!("user={}\x01auth=Bearer {}\x01\x01", email, token)
}

/// Exchange an OAuth2 authorization code for tokens.
async fn exchange_authorization_code(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuth2TokenResult, String> {
    let client = reqwest::Client::new();
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
    ];

    let response = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("OAuth2 token request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "OAuth2 token endpoint returned {}: {}",
            status, body
        ));
    }

    response
        .json::<OAuth2TokenResult>()
        .await
        .map_err(|e| format!("OAuth2 token response parse failed: {e}"))
}

/// Build the XOAUTH2 authentication string for IMAP/SMTP.
pub fn build_auth_string(account: &ExternalImapAccount) -> String {
    build_xoauth2_auth_string(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth2_build_auth_string_format() {
        let account = ExternalImapAccount {
            email: "user@gmail.com".to_string(),
            access_token: "ya29.test".to_string(),
            ..Default::default()
        };
        let result = build_auth_string(&account);
        assert_eq!(result, "user=user@gmail.com\x01auth=Bearer ya29.test\x01\x01");
    }
}
