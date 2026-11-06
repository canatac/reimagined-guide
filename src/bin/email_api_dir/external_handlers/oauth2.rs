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
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let account_id = path.into_inner();
    let code = body
        .get("authorizationCode")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let redirect_uri = body
        .get("redirectUri")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if code.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_CODE_MISSING", "message": "authorizationCode is required" }
        }));
    }

    let db = mongo.database(&mongo_db_name());
    let accounts = db.collection::<mongodb::bson::Document>("external_imap_accounts");
    let filter = mongodb::bson::doc! { "_id": &account_id };
    let account = match accounts.find_one(filter).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": { "code": "ACCOUNT_NOT_FOUND", "message": "external account not found" }
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "DB_ERROR", "message": e.to_string() }
            }));
        }
    };

    let provider = account.get_str("provider").unwrap_or("").to_string();
    let config = OAuth2ProviderConfig::for_provider(&provider);
    let token_response = match exchange_authorization_code(&config, &code, &redirect_uri).await {
        Ok(tokens) => tokens,
        Err(TokenRefreshError::Revoked) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": {
                    "code": "OAUTH2_TOKEN_REVOKED",
                    "message": "The authorization code was revoked or expired. Please reconnect the account."
                }
            }));
        }
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": { "code": "OAUTH2_CODE_EXCHANGE_FAILED", "message": e.to_string() }
            }));
        }
    };

    let refresh_token = token_response
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let access_token = token_response
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let expires_in = token_response.get("expires_in").and_then(|v| v.as_i64());

    let encrypted_refresh = refresh_token
        .as_deref()
        .map(encrypt_refresh_token_for_storage);

    let now = chrono::Utc::now();
    let expiry = expires_in.map(|secs| now + chrono::Duration::seconds(secs));

    let update = mongodb::bson::doc! {
        "$set": {
            "oauth_access_token": &access_token,
            "oauth_refresh_token": &encrypted_refresh,
            "oauth_token_expires_at": expiry,
            "oauth_connected_at": now,
            "auth_type": "oauth2",
        }
    };
    let filter = mongodb::bson::doc! { "_id": &account_id };
    if let Err(e) = accounts.update_one(filter, update).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "DB_ERROR", "message": e.to_string() }
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "connected",
        "message": "OAuth2 tokens stored; the account is connected."
    }))
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

/// API handler: GET /api/external-accounts/oauth2/start?provider=gmail|outlook|yahoo|other
///
/// Starts the consent flow from the provider chosen by the user, without
/// requiring an already-created external account. The provider is read from
/// the `provider` query parameter.
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
                "error": { "code": "OAUTH2_PROVIDER_NOT_SUPPORTED", "message": format!("Provider '{}' is not offered in the account picker", query.provider) }
            }));
        }
    };

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

/// API handler: GET /api/external-accounts/{id}/oauth2/start
/// Returns the authorization URL for the account's provider.
pub async fn api_oauth2_start(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let account_id = path.into_inner();
    let db = mongo.database(&mongo_db_name());
    let accounts = db.collection::<mongodb::bson::Document>("external_imap_accounts");
    let filter = mongodb::bson::doc! { "_id": &account_id };
    let account = match accounts.find_one(filter).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": { "code": "ACCOUNT_NOT_FOUND", "message": "external account not found" }
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "DB_ERROR", "message": e.to_string() }
            }));
        }
    };

    let provider = account.get_str("provider").unwrap_or("").to_string();
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
            "error": { "code": "OAUTH2_PROVIDER_NOT_SUPPORTED", "message": format!("Provider '{}' does not support OAuth2", provider) }
        })),
    }
}

/// API handler: GET /api/external-accounts/{id}/oauth2/authorize
/// 302 redirect to the provider consent screen.
pub async fn api_oauth2_authorize(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let account_id = path.into_inner();
    let db = mongo.database(&mongo_db_name());
    let accounts = db.collection::<mongodb::bson::Document>("external_imap_accounts");
    let filter = mongodb::bson::doc! { "_id": &account_id };
    let account = match accounts.find_one(filter).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": { "code": "ACCOUNT_NOT_FOUND", "message": "external account not found" }
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "DB_ERROR", "message": e.to_string() }
            }));
        }
    };

    let provider = account.get_str("provider").unwrap_or("").to_string();
    let callback_base = std::env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let redirect_uri = format!(
        "{}/api/external-accounts/oauth2/callback",
        callback_base.trim_end_matches('/')
    );
    let state = Uuid::new_v4().to_string();

    match build_oauth2_authorize_url(&provider, &redirect_uri, &state) {
        Some(url) => HttpResponse::Found()
            .append_header(("Location", url.clone()))
            .json(serde_json::json!({
                "authorizationUrl": url,
                "state": state,
                "provider": provider,
            })),
        None => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_PROVIDER_NOT_SUPPORTED", "message": format!("Provider '{}' does not support OAuth2", provider) }
        })),
    }
}

/// API handler: POST /api/external-accounts/{id}/oauth2/refresh
/// Refreshes an expired access token with the stored refresh token.
pub async fn api_oauth2_refresh(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let account_id = path.into_inner();
    match ensure_valid_access_token(&account_id, &mongo).await {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({
            "status": "refreshed",
            "message": "Access token is valid.",
            "accessToken": token,
        })),
        Err(TokenRefreshError::Revoked) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": {
                "code": "OAUTH2_TOKEN_REVOKED",
                "message": "The refresh token was revoked or expired. Please reconnect the account."
            }
        })),
        Err(TokenRefreshError::NoRefreshToken) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_REFRESH_TOKEN_MISSING", "message": "No refresh token stored for this account" }
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "OAUTH2_REFRESH_FAILED", "message": e.to_string() }
        })),
    }
}

/// API handler: POST /api/external-accounts/{id}/oauth2/tokens
/// Manual token update (testing only).
pub async fn api_oauth2_tokens_update(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    body: web::Json<OAuth2TokenUpdateInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }

    let account_id = path.into_inner();
    let encrypted_refresh = body
        .refresh_token
        .as_deref()
        .map(encrypt_refresh_token_for_storage);
    let expiry = body
        .expires_in
        .map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs));

    let db = mongo.database(&mongo_db_name());
    let accounts = db.collection::<mongodb::bson::Document>("external_imap_accounts");
    let update = mongodb::bson::doc! {
        "$set": {
            "oauth_access_token": &body.access_token,
            "oauth_refresh_token": &encrypted_refresh,
            "oauth_token_expires_at": expiry,
        }
    };
    let filter = mongodb::bson::doc! { "_id": &account_id };
    match accounts.update_one(filter, update).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "updated",
            "message": "Tokens updated."
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "DB_ERROR", "message": e.to_string() }
        })),
    }
}

/// Ensure the account has a valid access token, refreshing it if expired.
pub async fn ensure_valid_access_token(
    account_id: &str,
    mongo: &web::Data<Arc<mongodb::Client>>,
) -> Result<String, TokenRefreshError> {
    let db = mongo.database(&mongo_db_name());
    let accounts = db.collection::<mongodb::bson::Document>("external_imap_accounts");
    let filter = mongodb::bson::doc! { "_id": account_id };
    let account = accounts
        .find_one(filter)
        .await
        .map_err(|_| TokenRefreshError::Revoked)?
        .ok_or(TokenRefreshError::Revoked)?;

    let access_token = account
        .get_str("oauth_access_token")
        .unwrap_or("")
        .to_string();
    let expires_at = account.get_datetime("oauth_token_expires_at").ok();

    if !access_token.is_empty() {
        let expired = match expires_at {
            Some(dt) => is_token_expired(dt),
            None => false,
        };
        if !expired {
            return Ok(access_token);
        }
    }

    let encrypted_refresh = account
        .get_str("oauth_refresh_token")
        .ok()
        .ok_or(TokenRefreshError::NoRefreshToken)?;
    let refresh_token = decrypt_token_compat(encrypted_refresh);

    let provider = account.get_str("provider").unwrap_or("").to_string();
    let config = OAuth2ProviderConfig::for_provider(&provider);
    let token_response = refresh_oauth2_access_token(&config, &refresh_token).await?;

    let new_access = token_response
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let expires_in = token_response.get("expires_in").and_then(|v| v.as_i64());
    let new_refresh = token_response
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let encrypted_new_refresh = new_refresh
        .as_deref()
        .map(encrypt_refresh_token_for_storage)
        .or_else(|| Some(encrypted_refresh.to_string()));
    let expiry = expires_in.map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs));

    let update = mongodb::bson::doc! {
        "$set": {
            "oauth_access_token": &new_access,
            "oauth_refresh_token": &encrypted_new_refresh,
            "oauth_token_expires_at": expiry,
        }
    };
    let filter = mongodb::bson::doc! { "_id": account_id };
    let _ = accounts.update_one(filter, update).await;

    Ok(new_access)
}

/// Build the XOAUTH2 SASL string for an account.
pub fn xoauth2_string(account_email: &str, access_token: &str) -> String {
    build_xoauth2_auth_string(account_email, access_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_catalogue_lists_other_option() {
        let providers = oauth2_provider_catalogue();
        let values: Vec<&str> = providers.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(values, vec!["gmail", "outlook", "yahoo", "other"]);
        let other = providers.iter().find(|p| p.value == "other").unwrap();
        assert_eq!(other.label, "Other");
        assert!(other.authorization_endpoint.is_empty());
    }

    #[test]
    fn provider_keys_are_normalized() {
        assert_eq!(normalize_oauth2_provider_key("Gmail").as_deref(), Some("gmail"));
        assert_eq!(normalize_oauth2_provider_key("google").as_deref(), Some("gmail"));
        assert_eq!(normalize_oauth2_provider_key("outlook").as_deref(), Some("outlook"));
        assert_eq!(normalize_oauth2_provider_key("microsoft").as_deref(), Some("outlook"));
        assert_eq!(normalize_oauth2_provider_key("yahoo").as_deref(), Some("yahoo"));
        assert_eq!(normalize_oauth2_provider_key("autre").as_deref(), Some("other"));
        assert_eq!(normalize_oauth2_provider_key("other").as_deref(), Some("other"));
        assert_eq!(normalize_oauth2_provider_key("proton"), None);
    }

    #[test]
    fn provider_authorization_endpoints_are_known() {
        assert!(provider_authorization_endpoint("gmail").is_some());
        assert!(provider_authorization_endpoint("outlook").is_some());
        assert!(provider_authorization_endpoint("yahoo").is_some());
        assert!(provider_authorization_endpoint("other").is_none());
    }

    #[test]
    fn xoauth2_string_is_base64_of_user_and_token() {
        let s = xoauth2_string("user@example.com", "token");
        assert!(s.starts_with("dXNlcj11c2VyQGV4YW1wbGUuY29tAWF1dGg9QmVhcmVyIHRva2Vu"));
    }
}
