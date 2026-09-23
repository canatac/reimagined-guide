//! OAuth 2.0 handler for external IMAP accounts (MW-2026-062).
//!
//! Provides:
//! - Authorization URL generation (initiate OAuth2 consent flow)
//! - Authorization code exchange for tokens
//! - Token refresh
//! - Manual token update (testing)

use super::super::*;
use simple_smtp_server::external_imap::oauth2::{is_token_expired, provider_config, refresh_oauth2_token};
use simple_smtp_server::external_imap::{build_xoauth2_auth_string, ExternalImapAccount, OAuth2TokenResult};

/// Input for OAuth2 authorization code exchange.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2CallbackInput {
    pub account_id: String,
    pub authorization_code: String,
    pub redirect_uri: String,
}

/// Input for manual token update (for testing or manual token injection).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2TokenUpdateInput {
    pub account_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scopes: Option<Vec<String>>,
}

/// Handle OAuth2 authorization code callback.
/// Exchanges the authorization code for access/refresh tokens.
pub async fn api_oauth2_callback(
    req: actix_web::HttpRequest,
    payload: web::Json<OAuth2CallbackInput>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let user_id = resolve_user_id(&req);
    let input = payload.into_inner();

    // Get the account to find provider info
    let account = match svc.get_account_raw(&user_id, &input.account_id).await {
        Ok(Some(acct)) => acct,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": { "code": "OAUTH2_ACCOUNT_NOT_FOUND", "message": "External account not found" }
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "OAUTH2_ACCOUNT_FETCH_FAILED", "message": e.to_string() }
            }));
        }
    };

    // Exchange authorization code for tokens
    match exchange_authorization_code(&account, &input.authorization_code, &input.redirect_uri).await {
        Ok(token_result) => {
            // Store tokens
            match svc.update_oauth_tokens(
                &user_id,
                &input.account_id,
                &token_result.access_token,
                token_result.refresh_token.as_deref(),
                token_result.expires_in,
            ).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                    "status": "ok",
                    "message": "OAuth2 tokens stored successfully"
                })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": { "code": "OAUTH2_TOKEN_STORE_FAILED", "message": e.to_string() }
                })),
            }
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_CODE_EXCHANGE_FAILED", "message": e.to_string() }
        })),
    }
}

/// Manually update OAuth2 tokens (for testing or manual token injection).
pub async fn api_oauth2_update_tokens(
    req: actix_web::HttpRequest,
    payload: web::Json<OAuth2TokenUpdateInput>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let user_id = resolve_user_id(&req);
    let input = payload.into_inner();

    match svc.update_oauth_tokens(
        &user_id,
        &input.account_id,
        &input.access_token,
        input.refresh_token.as_deref(),
        input.expires_in,
    ).await {
        Ok(Some(_)) => HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "message": "OAuth2 tokens updated successfully"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": { "code": "OAUTH2_ACCOUNT_NOT_FOUND", "message": "External account not found" }
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_UPDATE_FAILED", "message": e.to_string() }
        })),
    }
}

/// Trigger a token refresh for an account with expired OAuth2 tokens.
pub async fn api_oauth2_refresh(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    // Get the raw account (with tokens)
    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(acct)) => acct,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": { "code": "OAUTH2_ACCOUNT_NOT_FOUND", "message": "External account not found" }
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "OAUTH2_ACCOUNT_FETCH_FAILED", "message": e.to_string() }
            }));
        }
    };

    // Check if token is actually expired
    if !is_token_expired(&account) {
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "message": "Token is still valid, no refresh needed"
        }));
    }

    // Refresh the token
    match refresh_oauth2_token(&account).await {
        Ok(token_result) => {
            match svc.update_oauth_tokens(
                &user_id,
                &account_id,
                &token_result.access_token,
                token_result.refresh_token.as_deref(),
                token_result.expires_in,
            ).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                    "status": "ok",
                    "message": "OAuth2 tokens refreshed successfully"
                })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": { "code": "OAUTH2_TOKEN_STORE_FAILED", "message": e.to_string() }
                })),
            }
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_REFRESH_FAILED", "message": e.to_string() }
        })),
    }
}

/// Exchange an OAuth2 authorization code for access/refresh tokens.
async fn exchange_authorization_code(
    account: &ExternalImapAccount,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuth2TokenResult, String> {
    // provider_config already imported at top of file (line 7)

    let config = provider_config(&account.provider)
        .ok_or_else(|| format!("Unsupported OAuth2 provider: {}", account.provider))?;

    if config.client_id.is_empty() || config.client_secret.is_empty() {
        return Err(format!(
            "OAuth2 client credentials not configured for provider: {}",
            account.provider
        ));
    }

    let client = reqwest::Client::new();
    let form_body = format!(
        "grant_type=authorization_code&client_id={}&client_secret={}&code={}&redirect_uri={}",
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&config.client_secret),
        urlencoding::encode(code),
        urlencoding::encode(redirect_uri),
    );

    let response = client
        .post(&config.token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await
        .map_err(|e| format!("OAuth2 code exchange request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("OAuth2 code exchange failed (HTTP {status}): {body}"));
    }

    let token_data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse OAuth2 token response: {e}"))?;

    let access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| "No access_token in OAuth2 response".to_string())?
        .to_string();

    let refresh_token = token_data["refresh_token"].as_str().map(String::from);
    let expires_in = token_data["expires_in"].as_i64();
    let scopes = token_data["scope"].as_str().map(|s| {
        s.split_whitespace().map(String::from).collect()
    });

    Ok(OAuth2TokenResult {
        access_token,
        refresh_token,
        expires_in,
        scopes,
    })
}

/// Generate the OAuth2 authorization URL for initiating the consent flow.
/// Returns the URL the user should be redirected to for provider consent.
pub fn build_oauth2_authorize_url(
    provider: &str,
    redirect_uri: &str,
    state: &str,
) -> Option<String> {
    let config = provider_config(provider)?;
    let scope_param = config.scopes.join(" ");
    let encoded_redirect = urlencoding::encode(redirect_uri);
    let encoded_scope = urlencoding::encode(&scope_param);
    let encoded_state = urlencoding::encode(state);

    match provider.to_ascii_lowercase().as_str() {
        "gmail" | "google" => Some(format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}",
            urlencoding::encode(&config.client_id),
            encoded_redirect,
            encoded_scope,
            encoded_state,
        )),
        "outlook" | "microsoft" | "office365" => Some(format!(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            urlencoding::encode(&config.client_id),
            encoded_redirect,
            encoded_scope,
            encoded_state,
        )),
        "yahoo" => Some(format!(
            "https://api.login.yahoo.com/oauth2/request_auth?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            urlencoding::encode(&config.client_id),
            encoded_redirect,
            encoded_scope,
            encoded_state,
        )),
        _ => None,
    }
}

/// API handler: GET /api/external-accounts/{id}/oauth2/start
/// Returns the authorization URL for the account's provider.
pub async fn api_oauth2_start(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(acct)) => acct,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": { "code": "OAUTH2_ACCOUNT_NOT_FOUND", "message": "External account not found" }
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "OAUTH2_ACCOUNT_FETCH_FAILED", "message": e.to_string() }
            }));
        }
    };

    let callback_base = std::env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let redirect_uri = format!(
        "{}/api/external-accounts/{}/oauth2/callback",
        callback_base.trim_end_matches('/'),
        account_id
    );
    let state = Uuid::new_v4().to_string();

    match build_oauth2_authorize_url(&account.provider, &redirect_uri, &state) {
        Some(url) => HttpResponse::Ok().json(serde_json::json!({
            "authorizationUrl": url,
            "state": state,
            "provider": account.provider,
        })),
        None => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_PROVIDER_NOT_SUPPORTED", "message": format!("Provider '{}' does not support OAuth2 authorization URL generation", account.provider) }
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth2_build_auth_string_format() {
        let result = build_xoauth2_auth_string("user@gmail.com", "ya29.test");
        assert_eq!(result, "user=user@gmail.com\x01auth=Bearer ya29.test\x01\x01");
    }

    #[test]
    fn build_oauth2_authorize_url_gmail() {
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-gmail-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-gmail-secret");
        let url = build_oauth2_authorize_url("gmail", "https://mail.misfits.ai/callback", "state-123").unwrap();
        assert!(url.contains("accounts.google.com/o/oauth2/v2/auth"));
        assert!(url.contains("client_id=test-gmail-id"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("state=state-123"));
    }

    #[test]
    fn build_oauth2_authorize_url_outlook() {
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_ID", "test-ms-id");
        std::env::set_var("MICROSOFT_OAUTH_CLIENT_SECRET", "test-ms-secret");
        let url = build_oauth2_authorize_url("outlook", "https://mail.misfits.ai/callback", "state-456").unwrap();
        assert!(url.contains("login.microsoftonline.com"));
        assert!(url.contains("client_id=test-ms-id"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn build_oauth2_authorize_url_unknown() {
        assert!(build_oauth2_authorize_url("unknown", "https://example.com", "state").is_none());
    }
}
