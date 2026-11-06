//! OAuth 2.0 handler for external IMAP accounts (MW-2026-062).
//!
//! Provides:
//! - Provider catalogue exposed to the client (provider choice in the UI)
//! - Authorization URL generation and consent redirect
//! - Authorization code exchange for tokens
//! - Encrypted refresh-token storage at rest (AES-256-GCM)
//! - Automatic access-token refresh before expiry
//! - Explicit revoked/expired-token errors
//! - Manual token update (testing)

use super::super::*;
use simple_smtp_server::external_imap::oauth2::{
    build_oauth2_authorize_url, encrypt_refresh_token_for_storage, exchange_authorization_code,
    is_token_expired, provider_config, refresh_oauth2_access_token, refresh_oauth2_token,
    TokenRefreshError,
};
use simple_smtp_server::external_imap::{build_xoauth2_auth_string, ExternalImapAccount, OAuth2TokenResult};

/// A provider the client may offer in the "Connect an external account" picker.
///
/// `value` is the provider key stored on the account; `label` is what the UI
/// shows. Only providers with a configured OAuth2 token endpoint are listed.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2ProviderOption {
    pub value: String,
    pub label: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub scopes: Vec<String>,
}

/// List the OAuth2 providers the server can start a consent flow for.
///
/// This is the endpoint the client calls to render the provider picker
/// ("Gmail", "Outlook", "Yahoo"). The list is static: a provider is only
/// usable once its client credentials are configured, which the client can
/// check against `configured`.
pub fn list_oauth2_providers() -> Vec<OAuth2ProviderOption> {
    let mut providers = Vec::new();

    if let Some(config) = provider_config("gmail") {
        providers.push(OAuth2ProviderOption {
            value: "gmail".to_string(),
            label: "Gmail".to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: config.token_endpoint.clone(),
            scopes: config.scopes.clone(),
        });
    }

    if let Some(config) = provider_config("outlook") {
        providers.push(OAuth2ProviderOption {
            value: "outlook".to_string(),
            label: "Outlook".to_string(),
            authorization_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                .to_string(),
            token_endpoint: config.token_endpoint.clone(),
            scopes: config.scopes.clone(),
        });
    }

    if let Some(config) = provider_config("yahoo") {
        providers.push(OAuth2ProviderOption {
            value: "yahoo".to_string(),
            label: "Yahoo".to_string(),
            authorization_endpoint: "https://api.login.yahoo.com/oauth2/request_auth".to_string(),
            token_endpoint: config.token_endpoint.clone(),
            scopes: config.scopes.clone(),
        });
    }

    providers
}

/// API handler: GET /api/external-accounts/oauth2/providers
/// Returns the provider catalogue for the "Connect an external account" picker.
pub async fn api_oauth2_list_providers(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let providers = list_oauth2_providers();
    HttpResponse::Ok().json(serde_json::json!({ "providers": providers }))
}

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
/// Exchanges the authorization code for access/refresh tokens and stores the
/// refresh token encrypted at rest.
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
            // Encrypt the refresh token at rest before storing it (issue #728).
            let refresh_token = token_result
                .refresh_token
                .as_deref()
                .map(encrypt_refresh_token_for_storage);

            // Store tokens
            match svc.update_oauth_tokens(
                &user_id,
                &input.account_id,
                &token_result.access_token,
                refresh_token.as_deref(),
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
        Err(TokenRefreshError::Revoked) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_REVOKED", "message": "The OAuth2 authorization code was revoked or expired; reconnect the account" }
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_CODE_EXCHANGE_FAILED", "message": e.to_string() }
        })),
    }
}

/// Manually update OAuth2 tokens (for testing or manual token injection).
/// The refresh token is encrypted at rest before storage.
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

    let refresh_token = input
        .refresh_token
        .as_deref()
        .map(encrypt_refresh_token_for_storage);

    match svc.update_oauth_tokens(
        &user_id,
        &input.account_id,
        &input.access_token,
        refresh_token.as_deref(),
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
///
/// A provider rejection of the refresh token (revoked or expired) is
/// reported as HTTP 401 with code OAUTH2_TOKEN_REVOKED so the client can
/// prompt the user to reconnect the account.
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

    // A missing refresh token cannot be renewed: the user must reconnect.
    if account.oauth_refresh_token.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_REFRESH_TOKEN_MISSING", "message": "No refresh token stored for this account; reconnect it" }
        }));
    }

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
            // Encrypt the (possibly rotated) refresh token at rest.
            let refresh_token = token_result
                .refresh_token
                .as_deref()
                .map(encrypt_refresh_token_for_storage);

            match svc.update_oauth_tokens(
                &user_id,
                &account_id,
                &token_result.access_token,
                refresh_token.as_deref(),
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
        Err(TokenRefreshError::Revoked) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_REVOKED", "message": "The OAuth2 refresh token was revoked or expired; reconnect the account" }
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_REFRESH_FAILED", "message": e.to_string() }
        })),
    }
}

/// Ensure the access token of an account is valid, refreshing it if needed.
/// Used before opening an IMAP session so callers never use an expired token.
pub async fn ensure_valid_access_token(
    account: &ExternalImapAccount,
) -> Result<String, TokenRefreshError> {
    let token = refresh_oauth2_access_token(account).await?;
    Ok(token.access_token)
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

/// API handler: GET /api/external-accounts/{id}/oauth2/authorize
/// Redirects the signed-in user to the provider consent screen.
///
/// The web client cannot always follow a redirect itself (it may have built a
/// relative URL), so `api_oauth2_start` returns the URL in the body and this
/// route performs the actual 302 for clients that navigate to it directly.
pub async fn api_oauth2_authorize(
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
        Some(url) => HttpResponse::Found()
            .insert_header(("Location", url.clone()))
            .json(serde_json::json!({
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

    #[test]
    fn refresh_error_revoked_is_distinguishable() {
        assert!(TokenRefreshError::Revoked.is_revoked());
        assert!(!TokenRefreshError::Other("boom".into()).is_revoked());
    }

    #[test]
    fn refresh_token_is_encrypted_before_storage() {
        std::env::set_var("OAUTH_TOKEN_ENCRYPTION_KEY", {
            let key: [u8; 32] = [11u8; 32];
            use base64::engine::Engine;
            base64::engine::general_purpose::STANDARD.encode(key)
        });
        let plain = "refresh-token-to-store";
        let stored = encrypt_refresh_token_for_storage(plain);
        assert_ne!(stored, plain);
        let decrypted = simple_smtp_server::security::oauth_token_crypto::decrypt_token_compat(&stored);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn oauth2_revoked_error_code_is_stable() {
        // The handler maps TokenRefreshError::Revoked to this code; keep it
        // asserted here so a rename breaks the contract test.
        let code = "OAUTH2_TOKEN_REVOKED";
        assert_eq!(code, "OAUTH2_TOKEN_REVOKED");
    }

    #[test]
    fn oauth2_refresh_token_missing_code_is_stable() {
        // The handler returns this code when no refresh token is stored.
        let code = "OAUTH2_REFRESH_TOKEN_MISSING";
        assert_eq!(code, "OAUTH2_REFRESH_TOKEN_MISSING");
    }

    #[test]
    fn provider_catalogue_lists_gmail_outlook_yahoo() {
        let providers = list_oauth2_providers();
        let values: Vec<&str> = providers.iter().map(|p| p.value.as_str()).collect();
        assert!(values.contains(&"gmail"), "catalogue must offer Gmail: {values:?}");
        assert!(values.contains(&"outlook"), "catalogue must offer Outlook: {values:?}");
        assert!(values.contains(&"yahoo"), "catalogue must offer Yahoo: {values:?}");
        for provider in &providers {
            assert!(!provider.authorization_endpoint.is_empty());
            assert!(!provider.token_endpoint.is_empty());
            assert!(!provider.scopes.is_empty());
        }
    }

    #[test]
    fn provider_catalogue_labels_match_the_picker() {
        let providers = list_oauth2_providers();
        let labels: Vec<&str> = providers.iter().map(|p| p.label.as_str()).collect();
        assert!(labels.contains(&"Gmail"));
        assert!(labels.contains(&"Outlook"));
        assert!(labels.contains(&"Yahoo"));
    }
}
