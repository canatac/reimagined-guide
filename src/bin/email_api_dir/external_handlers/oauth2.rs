use crate::external_imap::oauth2::{OAuth2TokenResult, exchange_authorization_code, refresh_access_token};
use crate::external_imap::account_ops::ExternalAccount;

fn provider_config(provider: &str) -> Option<OAuth2ProviderConfig> {
    match provider {
        "gmail" | "google" => Some(OAuth2ProviderConfig {
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            client_id_env: "GOOGLE_OAUTH_CLIENT_ID",
            client_secret_env: "GOOGLE_OAUTH_CLIENT_SECRET",
            scopes: "https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email",
            access_type_offline: true,
        }),
        "outlook" | "office365" | "microsoft" => Some(OAuth2ProviderConfig {
            authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            client_id_env: "MICROSOFT_OAUTH_CLIENT_ID",
            client_secret_env: "MICROSOFT_OAUTH_CLIENT_SECRET",
            scopes: "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access",
            access_type_offline: false,
        }),
        "yahoo" => Some(OAuth2ProviderConfig {
            authorize_url: "https://api.login.yahoo.com/oauth2/request_auth",
            token_url: "https://api.login.yahoo.com/oauth2/get_token",
            client_id_env: "YAHOO_OAUTH_CLIENT_ID",
            client_secret_env: "YAHOO_OAUTH_CLIENT_SECRET",
            scopes: "openid sdpp-w",
            access_type_offline: true,
        }),
        _ => None,
    }
}

struct OAuth2ProviderConfig {
    authorize_url: &'static str,
    token_url: &'static str,
    client_id_env: &'static str,
    client_secret_env: &'static str,
    scopes: &'static str,
    access_type_offline: bool,
}

fn build_oauth2_authorize_url(provider: &str, redirect_uri: &str, state: &str) -> Option<String> {
    let config = provider_config(provider)?;
    let client_id = std::env::var(config.client_id_env).ok()?;
    let mut url = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}",
        config.authorize_url,
        urlencode(&client_id),
        urlencode(redirect_uri),
        urlencode(config.scopes),
        urlencode(state),
    );
    if config.access_type_offline {
        url.push_str("&access_type=offline");
    }
    Some(url)
}

fn urlencode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{:02X}", byte)),
        }
    }
    encoded
}

async fn exchange_authorization_code(
    account: &ExternalAccount,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuth2TokenResult, String> {
    let config = provider_config(&account.provider)
        .ok_or_else(|| format!("Unsupported OAuth2 provider: {}", account.provider))?;
    let client_id = std::env::var(config.client_id_env)
        .map_err(|_| format!("Missing env var: {}", config.client_id_env))?;
    let client_secret = std::env::var(config.client_secret_env)
        .map_err(|_| format!("Missing env var: {}", config.client_secret_env))?;
    let params = [
        ("code", code),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ];
    let response = reqwest::Client::new()
        .post(config.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("OAuth2 token exchange request failed: {}", e))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("OAuth2 token exchange failed ({}): {}", status, body));
    }
    let token: OAuth2TokenResult = response
        .json()
        .await
        .map_err(|e| format!("OAuth2 token response parse failed: {}", e))?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_oauth2_authorize_url_gmail() {
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-gmail-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-gmail-secret");
        let url = build_oauth2_authorize_url("gmail", "https://mail.misfits.ai/callback", "state-123").unwrap();
        assert!(url.contains("accounts.google.com/o/oauth2/v2/auth"));
        assert!(url.contains("client_id=test-gmail-id"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("access_type=offline"));
    }

    #[test]
    fn build_oauth2_authorize_url_outlook() {
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_ID", "test-ms-id");
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_SECRET", "test-ms-secret");
        let url = build_oauth2_authorize_url("outlook", "https://mail.misfits.ai/callback", "state-456").unwrap();
        assert!(url.contains("login.microsoftonline.com"));
        assert!(url.contains("client_id=test-ms-id"));
    }

    #[test]
    fn build_oauth2_authorize_url_unknown() {
        assert!(build_oauth2_authorize_url("unknown", "https://example.com", "state").is_none());
    }

    #[test]
    fn build_oauth2_authorize_url_yahoo() {
        std::env::set_var("YAHOO_OAUTH_CLIENT_ID", "test-yahoo-id");
        std::env::set_var("YAHOO_OAUTH_CLIENT_SECRET", "test-yahoo-secret");
        let url = build_oauth2_authorize_url("yahoo", "https://mail.misfits.ai/callback", "state-789").unwrap();
        assert!(url.contains("api.login.yahoo.com/oauth2/request_auth"));
        assert!(url.contains("client_id=test-yahoo-id"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn build_oauth2_authorize_url_office365_alias() {
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_ID", "test-ms-id");
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_SECRET", "test-ms-secret");
        let url = build_oauth2_authorize_url("office365", "https://mail.misfits.ai/callback", "state-000").unwrap();
        assert!(url.contains("login.microsoftonline.com"));
        assert!(url.contains("client_id=test-ms-id"));
    }

    #[test]
    fn build_oauth2_authorize_url_google_alias() {
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-gmail-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-gmail-secret");
        let url = build_oauth2_authorize_url("google", "https://mail.misfits.ai/callback", "state-111").unwrap();
        assert!(url.contains("accounts.google.com/o/oauth2/v2/auth"));
        assert!(url.contains("access_type=offline"));
    }

    #[test]
    fn build_oauth2_authorize_url_encodes_state() {
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-gmail-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-gmail-secret");
        let state = "state with spaces & symbols";
        let url = build_oauth2_authorize_url("gmail", "https://mail.misfits.ai/callback", state).unwrap();
        assert!(url.contains("state=state+with+spaces+%26+symbols"));
    }

    #[test]
    fn build_oauth2_authorize_url_encodes_redirect_uri() {
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-gmail-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-gmail-secret");
        let redirect = "https://mail.misfits.ai/api/external-accounts/abc/oauth2/callback";
        let url = build_oauth2_authorize_url("gmail", redirect, "state-1").unwrap();
        assert!(url.contains("redirect_uri=https%3A%2F%2Fmail.misfits.ai%2Fapi%2Fexternal-accounts%2Fabc%2Foauth2%2Fcallback"));
    }

    #[test]
    fn build_oauth2_authorize_url_includes_scopes() {
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-gmail-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-gmail-secret");
        let url = build_oauth2_authorize_url("gmail", "https://mail.misfits.ai/callback", "state-1").unwrap();
        assert!(url.contains("scope="));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn urlencode_encodes_reserved_characters() {
        assert_eq!(urlencode("a b"), "a+b");
        assert_eq!(urlencode("a&b"), "a%26b");
        assert_eq!(urlencode("a/b"), "a%2Fb");
        assert_eq!(urlencode("a:b"), "a%3Ab");
        assert_eq!(urlencode("AZaz09-_.~"), "AZaz09-_.~");
    }

    #[test]
    fn provider_config_supports_all_issue_providers() {
        assert!(provider_config("gmail").is_some());
        assert!(provider_config("google").is_some());
        assert!(provider_config("outlook").is_some());
        assert!(provider_config("office365").is_some());
        assert!(provider_config("yahoo").is_some());
        assert!(provider_config("other").is_none());
    }
}
