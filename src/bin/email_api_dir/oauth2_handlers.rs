//! OAuth2 IMAP Authentication handlers (issue #728).
//! Implements RFC 7628 (OAuth 2.0 for IMAP) with XOAUTH2 SASL mechanism.
//! Supports Google (Gmail), Microsoft (Outlook), and Yahoo providers.

use super::*;
use super::oauth2_crypto;
use super::oauth2_providers::{
    self, OAuth2CallbackInput, OAuth2CallbackResponse, OAuth2StartAuthInput,
    OAuth2StartAuthResponse, OAuth2TokenStatus, StoredOAuth2Token,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use mongodb::bson::doc;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Pending OAuth2 state → (user_id, provider, email, imap_host, imap_port, imap_tls, smtp_host, smtp_port, smtp_tls)
/// In production this would be in Redis with TTL; for now we use in-memory with short expiry.
type PendingState = (
    String,
    String,
    String,
    Option<String>,
    Option<u16>,
    Option<bool>,
    Option<String>,
    Option<u16>,
    Option<bool>,
);

lazy_static::lazy_static! {
    static ref PENDING_STATES: std::sync::Mutex<HashMap<String, (PendingState, chrono::DateTime<chrono::Utc>)>> =
        std::sync::Mutex::new(HashMap::new());
}

/// Clean up expired states (older than 10 minutes)
fn cleanup_expired_states() {
    if let Ok(mut states) = PENDING_STATES.lock() {
        let now = chrono::Utc::now();
        states.retain(|_, (_, ts)| now.signed_duration_since(*ts).num_minutes() < 10);
    }
}

/// List supported OAuth2 providers
pub(crate) async fn api_oauth2_providers_list() -> impl Responder {
    let providers = oauth2_providers::get_supported_providers()
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "provider": p.provider,
                "displayName": p.display_name,
                "scopes": p.scopes,
                "imapHost": p.imap_host,
                "imapPort": p.imap_port,
                "smtpHost": p.smtp_host,
                "smtpPort": p.smtp_port,
            })
        })
        .collect::<Vec<_>>();

    HttpResponse::Ok().json(serde_json::json!({ "providers": providers }))
}

/// Start OAuth2 authorization flow — returns the authorization URL
pub(crate) async fn api_oauth2_start(
    req: HttpRequest,
    payload: web::Json<OAuth2StartAuthInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let input = payload.into_inner();

    // Look up provider config
    let provider_config = match oauth2_providers::get_provider_config(&input.provider) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": {
                    "code": "OAUTH2_UNSUPPORTED_PROVIDER",
                    "message": format!("Provider '{}' is not supported. Use /api/oauth2/providers to list supported providers.", input.provider)
                }
            }));
        }
    };

    // Get client credentials from environment
    let client_id_env = format!("OAUTH2_CLIENT_ID_{}", input.provider.to_uppercase());
    let client_id = match std::env::var(&client_id_env) {
        Ok(id) if !id.is_empty() => id,
        _ => {
            return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": {
                    "code": "OAUTH2_NOT_CONFIGURED",
                    "message": format!("OAuth2 client ID not configured for provider '{}'. Set {} environment variable.", input.provider, client_id_env)
                }
            }));
        }
    };

    // Generate state token for CSRF protection
    let state = Uuid::new_v4().to_string();

    // Determine redirect URI
    let redirect_uri = input
        .redirect_uri
        .clone()
        .unwrap_or_else(|| {
            std::env::var("OAUTH2_REDIRECT_URI")
                .unwrap_or_else(|_| "https://mail.misfits.ai/oauth/callback".to_string())
        });

    // Store pending state
    cleanup_expired_states();
    if let Ok(mut states) = PENDING_STATES.lock() {
        let imap_host = input
            .imap_host
            .clone()
            .or_else(|| Some(provider_config.imap_host.clone()));
        let imap_port = input.imap_port.or(Some(provider_config.imap_port));
        let pending = (
            user_id,
            input.provider.clone(),
            input.email.clone(),
            imap_host,
            imap_port,
            Some(true),
            provider_config.smtp_host.clone(),
            provider_config.smtp_port,
            Some(true),
        );
        states.insert(
            state.clone(),
            (pending, chrono::Utc::now()),
        );
    }

    // Build authorization URL
    let authorization_url = oauth2_providers::build_authorization_url(
        &provider_config,
        &client_id,
        &redirect_uri,
        &state,
        &input.email,
    );

    HttpResponse::Ok().json(OAuth2StartAuthResponse {
        authorization_url,
        state,
        provider: input.provider,
    })
}

/// Handle OAuth2 callback — exchange code for tokens and create external account
pub(crate) async fn api_oauth2_callback(
    req: HttpRequest,
    payload: web::Json<OAuth2CallbackInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let input = payload.into_inner();

    // Retrieve and validate pending state
    let pending = {
        if let Ok(mut states) = PENDING_STATES.lock() {
            states.remove(&input.state)
        } else {
            None
        }
    };

    let (stored_user_id, provider, email, imap_host, imap_port, imap_tls, smtp_host, smtp_port, smtp_tls) =
        match pending {
            Some((data, ts)) => {
                // Validate state hasn't expired (10 min)
                if chrono::Utc::now().signed_duration_since(ts).num_minutes() >= 10 {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "error": {
                            "code": "OAUTH2_STATE_EXPIRED",
                            "message": "Authorization state expired. Please restart the OAuth2 flow."
                        }
                    }));
                }
                // Validate user matches
                if data.0 != user_id {
                    return HttpResponse::Forbidden().json(serde_json::json!({
                        "error": {
                            "code": "OAUTH2_USER_MISMATCH",
                            "message": "OAuth2 state was created for a different user."
                        }
                    }));
                }
                data
            }
            None => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": {
                        "code": "OAUTH2_INVALID_STATE",
                        "message": "Invalid or expired OAuth2 state. Please restart the authorization flow."
                    }
                }));
            }
        };

    // Get provider config for token endpoint
    let provider_config = match oauth2_providers::get_provider_config(&input.provider) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": { "code": "OAUTH2_UNSUPPORTED_PROVIDER", "message": "Unknown provider" }
            }));
        }
    };

    // Get client credentials
    let client_id_env = format!("OAUTH2_CLIENT_ID_{}", input.provider.to_uppercase());
    let client_secret_env = format!("OAUTH2_CLIENT_SECRET_{}", input.provider.to_uppercase());
    let client_id = std::env::var(&client_id_env).unwrap_or_default();
    let client_secret = std::env::var(&client_secret_env).unwrap_or_default();
    let redirect_uri = std::env::var("OAUTH2_REDIRECT_URI")
        .unwrap_or_else(|_| "https://mail.misfits.ai/oauth/callback".to_string());

    // Exchange authorization code for tokens
    let token_response = match exchange_code_for_tokens(
        &provider_config.token_endpoint,
        &input.code,
        &client_id,
        &client_secret,
        &redirect_uri,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(e) => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": {
                    "code": "OAUTH2_TOKEN_EXCHANGE_FAILED",
                    "message": format!("Failed to exchange authorization code: {}", e)
                }
            }));
        }
    };

    // Encrypt tokens for storage
    let encrypted_access = match oauth2_crypto::encrypt_token(&token_response.access_token) {
        Ok(enc) => enc,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "OAUTH2_ENCRYPTION_FAILED", "message": e }
            }));
        }
    };

    let encrypted_refresh = match &token_response.refresh_token {
        Some(rt) => match oauth2_crypto::encrypt_token(rt) {
            Ok(enc) => enc,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": { "code": "OAUTH2_ENCRYPTION_FAILED", "message": e }
                }));
            }
        },
        None => "".to_string(),
    };

    // Calculate expiry
    let now = chrono::Utc::now();
    let expires_at = if let Some(secs) = token_response.expires_in {
        (now + chrono::Duration::seconds(secs as i64)).to_rfc3339()
    } else {
        (now + chrono::Duration::hours(1)).to_rfc3339()
    };

    // Create the external account with OAuth2 auth type
    let account_id = Uuid::new_v4().to_string();
    let imap_host_val = imap_host.unwrap_or_else(|| provider_config.imap_host.clone());
    let imap_port_val = imap_port.unwrap_or(provider_config.imap_port);

    let create_input = CreateExternalAccountInput {
        provider: provider.clone(),
        email: email.clone(),
        auth_type: "oauth2".to_string(),
        imap: ExternalImapServerConfig {
            host: imap_host_val.clone(),
            port: imap_port_val,
            tls: imap_tls.unwrap_or(true),
        },
        smtp: Some(ExternalSmtpServerConfig {
            host: smtp_host.or(provider_config.smtp_host.clone()),
            port: smtp_port.or(provider_config.smtp_port),
            tls: smtp_tls,
        }),
        credentials: Some(ExternalAccountCredentials {
            secret_value: None, // Tokens stored separately encrypted
            secret_ref: Some(format!("oauth2:{}", account_id)),
            oauth_access_token: None,
            oauth_refresh_token: None,
            oauth_token_expires_at: None,
            oauth_scopes: None,
        }),
    };

    match svc.create_account(&stored_user_id, create_input).await {
        Ok(account) => {
            // Store encrypted tokens in a separate collection
            let token_doc = doc! {
                "accountId": &account_id,
                "provider": &provider,
                "encryptedAccessToken": encrypted_access,
                "encryptedRefreshToken": encrypted_refresh,
                "expiresAt": &expires_at,
                "refreshedAt": now.to_rfc3339(),
                "keyVersion": 1u32,
                "createdAt": now.to_rfc3339(),
                "updatedAt": now.to_rfc3339(),
            };

            let db_name = std::env::var("MONGODB_DATABASE")
                .unwrap_or_else(|_| "mailserver".to_string());
            let db = svc.client().database(&db_name);
            let token_coll = db
                .collection::<mongodb::bson::Document>("oauth2_tokens");

            if let Err(e) = token_coll.insert_one(token_doc).await {
                // Log error but don't fail the request — account is created
                eprintln!("Failed to store OAuth2 tokens: {}", e);
            }

            HttpResponse::Ok().json(OAuth2CallbackResponse {
                account_id: account.id,
                provider,
                email,
                status: "active".to_string(),
                expires_at,
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": {
                "code": "OAUTH2_ACCOUNT_CREATE_FAILED",
                "message": format!("Failed to create external account: {}", e)
            }
        })),
    }
}

/// Refresh an expired OAuth2 access token using the stored refresh token
pub(crate) async fn api_oauth2_refresh(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    // Retrieve stored tokens
    let db_name =
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = svc.client().database(&db_name);
    let token_coll = db.collection::<mongodb::bson::Document>("oauth2_tokens");

    let token_doc = match token_coll
        .find_one(doc! { "accountId": &account_id })
        .await
    {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": { "code": "OAUTH2_TOKEN_NOT_FOUND", "message": "No OAuth2 tokens found for this account" }
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "OAUTH2_DB_ERROR", "message": e.to_string() }
            }));
        }
    };

    // Decrypt refresh token
    let encrypted_refresh = token_doc
        .get_str("encryptedRefreshToken")
        .unwrap_or("");
    if encrypted_refresh.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": { "code": "OAUTH2_NO_REFRESH_TOKEN", "message": "No refresh token available. Re-authorization required." }
        }));
    }

    let refresh_token = match oauth2_crypto::decrypt_token(encrypted_refresh) {
        Ok(rt) => rt,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "OAUTH2_DECRYPT_FAILED", "message": e }
            }));
        }
    };

    // Get provider from account
    let provider = token_doc.get_str("provider").unwrap_or("google");
    let provider_config = match oauth2_providers::get_provider_config(provider) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": { "code": "OAUTH2_UNSUPPORTED_PROVIDER", "message": "Provider not found" }
            }));
        }
    };

    // Get client credentials
    let client_id_env = format!("OAUTH2_CLIENT_ID_{}", provider.to_uppercase());
    let client_secret_env = format!("OAUTH2_CLIENT_SECRET_{}", provider.to_uppercase());
    let client_id = std::env::var(&client_id_env).unwrap_or_default();
    let client_secret = std::env::var(&client_secret_env).unwrap_or_default();

    // Refresh the token
    let new_tokens = match refresh_access_token(
        &provider_config.token_endpoint,
        &refresh_token,
        &client_id,
        &client_secret,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(e) => {
            // Mark account with error
            let _ = svc
                .update_account(
                    &user_id,
                    &account_id,
                    UpdateExternalAccountInput {
                        status: Some("token_expired".to_string()),
                        last_error: Some(format!("Token refresh failed: {}", e)),
                        ..Default::default()
                    },
                )
                .await;

            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": {
                    "code": "OAUTH2_REFRESH_FAILED",
                    "message": format!("Token refresh failed: {}. Re-authorization may be required.", e)
                }
            }));
        }
    };

    // Encrypt new access token
    let encrypted_access = match oauth2_crypto::encrypt_token(&new_tokens.access_token) {
        Ok(enc) => enc,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "OAUTH2_ENCRYPTION_FAILED", "message": e }
            }));
        }
    };

    let now = chrono::Utc::now();
    let expires_at = if let Some(secs) = new_tokens.expires_in {
        (now + chrono::Duration::seconds(secs as i64)).to_rfc3339()
    } else {
        (now + chrono::Duration::hours(1)).to_rfc3339()
    };

    // Update stored tokens
    let mut update_doc = doc! {
        "encryptedAccessToken": encrypted_access,
        "expiresAt": expires_at.clone(),
        "refreshedAt": now.to_rfc3339(),
        "updatedAt": now.to_rfc3339(),
    };

    // Update refresh token if a new one was issued
    if let Some(new_rt) = &new_tokens.refresh_token {
        match oauth2_crypto::encrypt_token(new_rt) {
            Ok(enc_rt) => {
                update_doc.insert("encryptedRefreshToken", enc_rt);
            }
            Err(_) => {} // Keep old refresh token if encryption fails
        }
    }

    if let Err(e) = token_coll
        .update_one(
            doc! { "accountId": &account_id },
            doc! { "$set": update_doc },
        )
        .await
    {
        eprintln!("Failed to update OAuth2 tokens: {}", e);
    }

    // Clear any error status on the account
    let _ = svc
        .update_account(
            &user_id,
            &account_id,
            UpdateExternalAccountInput {
                status: Some("active".to_string()),
                last_error: Some("".to_string()),
                ..Default::default()
            },
        )
        .await;

    HttpResponse::Ok().json(serde_json::json!({
        "accountId": account_id,
        "status": "refreshed",
        "expiresAt": expires_at,
    }))
}

/// Check OAuth2 token status for an account
pub(crate) async fn api_oauth2_status(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let _user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    let db_name =
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = svc.client().database(&db_name);
    let token_coll = db.collection::<mongodb::bson::Document>("oauth2_tokens");

    match token_coll
        .find_one(doc! { "accountId": &account_id })
        .await
    {
        Ok(Some(doc)) => {
            let provider = doc.get_str("provider").unwrap_or("unknown");
            let expires_at = doc.get_str("expiresAt").ok();
            let is_expired = expires_at
                .map(|e| oauth2_providers::is_token_expired(e))
                .unwrap_or(true);
            let has_refresh = doc
                .get_str("encryptedRefreshToken")
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            let status = if is_expired && !has_refresh {
                "expired"
            } else if is_expired {
                "needs_refresh"
            } else {
                "active"
            };

            HttpResponse::Ok().json(OAuth2TokenStatus {
                account_id,
                provider: provider.to_string(),
                has_token: true,
                expires_at: expires_at.map(|s| s.to_string()),
                is_expired,
                status: status.to_string(),
            })
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": { "code": "OAUTH2_TOKEN_NOT_FOUND", "message": "No OAuth2 tokens found for this account" }
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "OAUTH2_DB_ERROR", "message": e.to_string() }
        })),
    }
}

/// Revoke OAuth2 tokens for an account
pub(crate) async fn api_oauth2_revoke(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    let db_name =
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = svc.client().database(&db_name);
    let token_coll = db.collection::<mongodb::bson::Document>("oauth2_tokens");

    // Delete stored tokens
    match token_coll
        .delete_one(doc! { "accountId": &account_id })
        .await
    {
        Ok(_) => {
            // Update account status
            let _ = svc
                .update_account(
                    &user_id,
                    &account_id,
                    UpdateExternalAccountInput {
                        status: Some("revoked".to_string()),
                        ..Default::default()
                    },
                )
                .await;

            HttpResponse::Ok().json(serde_json::json!({
                "accountId": account_id,
                "status": "revoked",
                "message": "OAuth2 tokens revoked successfully"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": { "code": "OAUTH2_REVOKE_FAILED", "message": e.to_string() }
        })),
    }
}

// --- HTTP helpers ---

/// Exchange authorization code for access/refresh tokens
async fn exchange_code_for_tokens(
    token_endpoint: &str,
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<oauth2_providers::OAuth2TokenResponse, String> {
    let client = reqwest::Client::new();
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("code", code);
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);
    params.insert("redirect_uri", redirect_uri);

    let response = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        return Err(format!("Token endpoint returned HTTP {}: {}", status.as_u16(), body));
    }

    let mut token_response: oauth2_providers::OAuth2TokenResponse =
        serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

    token_response.obtained_at = Some(chrono::Utc::now().to_rfc3339());
    Ok(token_response)
}

/// Refresh an access token using a refresh token
async fn refresh_access_token(
    token_endpoint: &str,
    refresh_token: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<oauth2_providers::OAuth2TokenResponse, String> {
    let client = reqwest::Client::new();
    let mut params = HashMap::new();
    params.insert("grant_type", "refresh_token");
    params.insert("refresh_token", refresh_token);
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);

    let response = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        return Err(format!("Token refresh returned HTTP {}: {}", status.as_u16(), body));
    }

    let mut token_response: oauth2_providers::OAuth2TokenResponse =
        serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

    token_response.obtained_at = Some(chrono::Utc::now().to_rfc3339());
    Ok(token_response)
}
