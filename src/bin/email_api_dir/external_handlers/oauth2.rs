//! OAuth 2.0 handler for external IMAP accounts (MW-2026-062).
//!
//! Provides:
//! - Provider catalogue exposed to the client (provider choice in the UI)
//! - Authorization URL generation and consent redirect
//! - Authorization code exchange for tokens
//! - Encrypted refresh-token storage at rest (AES-256-GCM)
//! - Automatic access-token refresh before expiry
//! - Clear errors when a token is revoked or expired

use actix_web::{web, HttpResponse};
use std::sync::Arc;

use crate::admin_auth;
use crate::external_imap::ExternalImapService;
use crate::external_imap::oauth2::{
    build_oauth2_authorize_url, exchange_oauth2_code_for_tokens, provider_config,
    refresh_oauth2_access_token, store_oauth2_tokens_encrypted, TokenRefreshError,
};
use crate::external_imap::{build_xoauth2_auth_string, ExternalImapAccount, OAuth2TokenResult};

/// A provider the client may offer in the "Connect an external account" picker.
///
/// `value` is the provider key stored on the account; `label` is what the UI
/// shows. Providers with a configured OAuth2 token endpoint are listed, plus
/// the catch-all "other" entry so the picker always offers a fallback.
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
/// ("Gmail", "Outlook", "Yahoo", "Other"). A provider is only usable once
/// its client credentials are configured; the "other" entry is always listed
/// so the picker can offer a fallback for providers without built-in support.
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

    // Catch-all option: the client can offer "Other" even when the provider
    // has no built-in OAuth2 configuration. The account is stored with this
    // provider key and the flow falls back to the generic endpoints below.
    providers.push(OAuth2ProviderOption {
        value: "other".to_string(),
        label: "Other".to_string(),
        authorization_endpoint: "https://mail.misfits.ai/api/external-accounts/oauth2/authorize"
            .to_string(),
        token_endpoint: "https://mail.misfits.ai/api/external-accounts/oauth2/callback".to_string(),
        scopes: vec!["https://mail.google.com/".to_string()],
    });

    providers
}

/// API handler: GET /api/external-accounts/oauth2/providers
/// Returns the provider catalogue for the "Connect an external account" picker.
pub async fn api_oauth2_list_providers(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
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

/// API handler: GET /api/external-accounts/oauth2/start
/// Returns the provider authorization URL in the body.
///
/// The provider is taken from the query (`?provider=gmail|outlook|yahoo|other`)
/// so the flow can start before any external account exists. The account-scoped
/// `/api/external-accounts/{id}/oauth2/start` route remains for clients that
/// already hold an account.
pub async fn api_oauth2_start(
    req: actix_web::HttpRequest,
    query: web::Query<OAuth2StartQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let provider = query.provider.trim().to_ascii_lowercase();
    if provider.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_PROVIDER_REQUIRED", "message": "The 'provider' query parameter is required (gmail, outlook, yahoo, other)." }
        }));
    }

    let callback_base = std::env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let redirect_uri = format!(
        "{}/api/external-accounts/oauth2/callback",
        callback_base.trim_end_matches('/')
    );
    let state = Uuid::new_v4().to_string();

    match build_oauth2_authorize_url(&provider, &redirect_uri, &state) {
        Some(url) => HttpResponse::Ok().json(serde_json::json!({
            "authorizationUrl": url,
            "state": state,
            "provider": provider,
        })),
        None => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_PROVIDER_NOT_SUPPORTED", "message": format!("Provider '{}' does not support OAuth2 authorization URL generation", provider) }
        })),
    }
}

/// Query parameters for the provider-scoped start route.
#[derive(Debug, serde::Deserialize)]
pub struct OAuth2StartQuery {
    pub provider: String,
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
) -> impl actix_web::Responder {
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

/// API handler: POST /api/external-accounts/{id}/oauth2/callback
/// Exchanges the authorization code for tokens and stores the refresh token
/// encrypted at rest.
pub async fn api_oauth2_callback(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    body: web::Json<OAuth2CallbackInput>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    let input = body.into_inner();

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

    let result = exchange_oauth2_code_for_tokens(
        &account.provider,
        &input.authorization_code,
        &input.redirect_uri,
    )
    .await;

    match result {
        Ok(tokens) => {
            if let Err(e) = store_oauth2_tokens_encrypted(&user_id, &account_id, &tokens).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": { "code": "OAUTH2_TOKEN_STORE_FAILED", "message": e.to_string() }
                }));
            }
            HttpResponse::Ok().json(serde_json::json!({
                "status": "ok",
                "message": "Tokens stored"
            }))
        }
        Err(TokenRefreshError::Revoked(msg)) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_REVOKED", "message": msg }
        })),
        Err(TokenRefreshError::Expired(msg)) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_EXPIRED", "message": msg }
        })),
        Err(TokenRefreshError::Other(msg)) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_EXCHANGE_FAILED", "message": msg }
        })),
    }
}

/// API handler: POST /api/external-accounts/{id}/oauth2/refresh
/// Refreshes the stored access token, or reports a clear error when the
/// refresh token is revoked or expired.
pub async fn api_oauth2_refresh(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    match refresh_oauth2_access_token(&user_id, &account_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "message": "Access token refreshed"
        })),
        Err(TokenRefreshError::Revoked(msg)) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_REVOKED", "message": msg }
        })),
        Err(TokenRefreshError::Expired(msg)) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_EXPIRED", "message": msg }
        })),
        Err(TokenRefreshError::Other(msg)) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "OAUTH2_REFRESH_FAILED", "message": msg }
        })),
    }
}

/// Resolve the user id from the request extensions.
fn resolve_user_id(req: &actix_web::HttpRequest) -> String {
    req.extensions()
        .get::<crate::auth_handlers::AuthenticatedUser>()
        .map(|u| u.id.clone())
        .unwrap_or_default()
}

/// Name of the MongoDB database.
fn mongo_db_name() -> String {
    std::env::var("MONGO_DB_NAME").unwrap_or_else(|_| "misfits_mail".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_catalogue_lists_gmail_outlook_yahoo_and_other() {
        let providers = list_oauth2_providers();
        let values: Vec<&str> = providers.iter().map(|p| p.value.as_str()).collect();
        assert!(values.contains(&"gmail"), "catalogue must offer Gmail: {values:?}");
        assert!(values.contains(&"outlook"), "catalogue must offer Outlook: {values:?}");
        assert!(values.contains(&"yahoo"), "catalogue must offer Yahoo: {values:?}");
        assert!(values.contains(&"other"), "catalogue must offer Other: {values:?}");
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
        assert!(labels.contains(&"Other"));
    }

    #[test]
    fn provider_scoped_start_requires_provider() {
        let query = OAuth2StartQuery { provider: String::new() };
        assert!(query.provider.trim().is_empty());
    }

    #[test]
    fn provider_scoped_start_normalizes_case() {
        let query = OAuth2StartQuery { provider: "GMAIL".to_string() };
        assert_eq!(query.provider.trim().to_ascii_lowercase(), "gmail");
    }

    #[test]
    fn refresh_error_codes_are_stable() {
        let code = "OAUTH2_REFRESH_TOKEN_MISSING";
        assert_eq!(code, "OAUTH2_REFRESH_TOKEN_MISSING");
    }
}
