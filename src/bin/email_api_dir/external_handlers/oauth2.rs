//! OAuth2 IMAP authentication handlers (MW-2026-062 / issue #728).
//!
//! - Authorization code flow callback
//! - Automatic access-token refresh before expiry
//! - Explicit revoked/expired-token errors
//! - Manual token update (testing)
//! - Provider catalogue for the "Connect an external account" picker

use super::super::*;
use simple_smtp_server::external_imap::oauth2::{
    build_oauth2_authorize_url, build_xoauth2_auth_string, decrypt_token_compat,
    encrypt_refresh_token_for_storage, exchange_authorization_code, is_token_expired,
    refresh_oauth2_access_token, OAuth2ProviderConfig, TokenRefreshError,
};
use simple_smtp_server::external_imap::{ExternalImapAccount, OAuth2TokenResult};

/// Input for OAuth2 authorization code exchange.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2CallbackInput {
    pub account_id: String,
    pub authorization_code: String,
    pub redirect_uri: String,
}

/// Input for the manual token update route (testing only).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2TokenUpdateInput {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scopes: Option<Vec<String>>,
}

/// Query parameters of the start-by-provider route.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2StartQuery {
    pub provider: String,
}

/// A provider offered in the "Connect an external account" picker.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2ProviderOption {
    pub value: String,
    pub label: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub scopes: Vec<String>,
}

/// Provider keys accepted by the picker and the start route.
/// `other` covers any provider not shipped as a built-in.
pub const OAUTH2_PROVIDER_KEYS: [&str; 4] = ["gmail", "outlook", "yahoo", "other"];

/// Normalize a provider key from user input (picker or query param).
/// Accepts the common aliases and rejects anything else.
pub fn normalize_oauth2_provider_key(raw: &str) -> Option<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gmail" | "google" => Some("gmail".to_string()),
        "outlook" | "microsoft" | "office365" => Some("outlook".to_string()),
        "yahoo" => Some("yahoo".to_string()),
        "other" | "autre" => Some("other".to_string()),
        _ => None,
    }
}

/// Authorization endpoint of a provider, used by the picker.
fn provider_authorization_endpoint(provider: &str) -> Option<&'static str> {
    match provider {
        "gmail" => Some("https://accounts.google.com/o/oauth2/v2/auth"),
        "outlook" => Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
        "yahoo" => Some("https://api.login.yahoo.com/oauth2/request_auth"),
        _ => None,
    }
}

/// Build the provider catalogue served to the account picker.
/// Lists Gmail, Outlook, Yahoo and the 'Other' option; 'Other' carries no
/// built-in endpoints because the operator configures the provider.
pub fn oauth2_provider_catalogue() -> Vec<OAuth2ProviderOption> {
    let mut providers = Vec::new();
    for key in OAUTH2_PROVIDER_KEYS {
        let (label, authorization_endpoint, token_endpoint, scopes) = match key {
            "gmail" => (
                "Gmail",
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                vec!["https://mail.google.com/".to_string()],
            ),
            "outlook" => (
                "Outlook",
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                vec![
                    "https://outlook.office.com/IMAP.AccessAsUser.All".to_string(),
                    "offline_access".to_string(),
                ],
            ),
            "yahoo" => (
                "Yahoo",
                "https://api.login.yahoo.com/oauth2/request_auth",
                "https://api.login.yahoo.com/oauth2/get_token",
                vec!["mail-r".to_string()],
            ),
            _ => (
                "Other",
                "",
                "",
                Vec::new(),
            ),
        };
        providers.push(OAuth2ProviderOption {
            value: key.to_string(),
            label: label.to_string(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            scopes,
        });
    }
    providers
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

/// API handler: GET /api/external-accounts/oauth2/providers
/// Returns the provider catalogue for the "Connect an external account" picker.
pub async fn api_oauth2_providers_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    HttpResponse::Ok().json(serde_json::json!({
        "providers": oauth2_provider_catalogue()
    }))
}

/// API handler: GET /api/external-accounts/oauth2/start?provider=gmail
/// Starts the consent flow from the provider chosen by the user, without an
/// already-created account.
pub async fn api_oauth2_start_by_provider(
    req: actix_web::HttpRequest,
    query: web::Query<OAuth2StartQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let provider = match normalize_oauth2_provider_key(&query.provider) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": { "code": "OAUTH2_PROVIDER_UNKNOWN", "message": "unknown provider" }
            }));
        }
    };
    let config = OAuth2ProviderConfig::for_provider(&provider);
    match build_oauth2_authorize_url(&config) {
        Ok(url) => HttpResponse::Ok().json(serde_json::json!({
            "authorizationUrl": url,
            "provider": provider,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_AUTHORIZE_URL_FAILED", "message": e.to_string() }
        })),
    }
}

/// API handler: GET /api/external-accounts/{id}/oauth2/start
/// Returns the provider consent URL in the body.
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
    let provider = account.provider.clone();
    let config = OAuth2ProviderConfig::for_provider(&provider);
    match build_oauth2_authorize_url(&config) {
        Ok(url) => HttpResponse::Ok().json(serde_json::json!({
            "authorizationUrl": url,
            "provider": provider,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_AUTHORIZE_URL_FAILED", "message": e.to_string() }
        })),
    }
}

/// API handler: GET /api/external-accounts/{id}/oauth2/authorize
/// 302 redirect to the provider consent screen.
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
    let provider = account.provider.clone();
    let config = OAuth2ProviderConfig::for_provider(&provider);
    match build_oauth2_authorize_url(&config) {
        Ok(url) => HttpResponse::Found()
            .append_header(("Location", url.clone()))
            .json(serde_json::json!({
                "authorizationUrl": url,
                "provider": provider,
            })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_AUTHORIZE_URL_FAILED", "message": e.to_string() }
        })),
    }
}

/// API handler: POST /api/external-accounts/{id}/oauth2/refresh
/// Refresh an expired access token.
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
    if account.oauth_refresh_token.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_NO_REFRESH_TOKEN", "message": "no refresh token stored" }
        }));
    }
    match refresh_oauth2_access_token(&user_id, &account_id, &account, svc.as_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "message": "OAuth2 tokens refreshed"
        })),
        Err(TokenRefreshError::Revoked) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_REVOKED", "message": "The refresh token was revoked or expired; reconnect the account" }
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_REFRESH_FAILED", "message": e.to_string() }
        })),
    }
}

/// Manually update OAuth2 tokens (for testing or manual token injection).
/// The refresh token is encrypted at rest before storage.
pub async fn api_oauth2_update_tokens(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    payload: web::Json<OAuth2TokenUpdateInput>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    let input = payload.into_inner();
    let refresh_token = input.refresh_token.as_deref().map(encrypt_refresh_token_for_storage);
    match svc.update_oauth_tokens(
        &user_id,
        &account_id,
        &input.access_token,
        refresh_token.as_deref(),
        input.expires_in,
    ).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "message": "OAuth2 tokens updated"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_STORE_FAILED", "message": e.to_string() }
        })),
    }
}
