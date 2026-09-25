// two_factor.rs — 2FA setup, enable, disable, recovery codes (issue #1041).
#![allow(unused_imports, dead_code)]
use actix_web::{web, HttpResponse, Responder};
use bson::doc;
use data_encoding::BASE32;
use mongodb::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::login::make_session;
use super::totp::{generate_totp_secret, verify_totp};

// ── Request / Response types ──────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct TwoFactorSetupRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub(crate) struct TwoFactorEnableRequest {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize)]
pub(crate) struct TwoFactorDisableRequest {
    pub email: String,
    pub password: String,
    pub code: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RecoveryCodeLoginRequest {
    pub email: String,
    pub recovery_code: String,
}

#[derive(Serialize)]
pub(crate) struct TwoFactorSetupResponse {
    pub secret: String,
    pub otpauth_uri: String,
    pub issuer: String,
}

#[derive(Serialize)]
pub(crate) struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Get the MongoDB database name from env or default.
fn mongo_db_name() -> String {
    std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

/// Get the configured domain for issuer label.
fn domain_name() -> String {
    std::env::var("DOMAIN_NAME").unwrap_or_else(|_| "misfits.ai".to_string())
}

/// Generate a single recovery code (alphanumeric, 10 chars, hyphenated).
fn generate_recovery_code() -> String {
    let uuid1 = uuid::Uuid::new_v4();
    let uuid2 = uuid::Uuid::new_v4();
    let bytes = [&uuid1.as_bytes()[..4], &uuid2.as_bytes()[..4]].concat();
    let encoded = BASE32.encode(&bytes);
    let chunk1 = encoded.chars().take(5).collect::<String>();
    let chunk2 = encoded.chars().skip(5).take(5).collect::<String>();
    format!("{}-{}", chunk1, chunk2).to_uppercase()
}

/// Generate N unique recovery codes.
fn generate_recovery_codes(count: usize) -> Vec<String> {
    let mut codes = HashSet::new();
    while codes.len() < count {
        codes.insert(generate_recovery_code());
    }
    codes.into_iter().collect()
}

/// Look up user document by email (tries both raw and local-part).
async fn find_user_by_email(
    mongo: &Client,
    email: &str,
) -> Result<Option<bson::Document>, mongodb::error::Error> {
    let db = mongo.database(&mongo_db_name());
    let coll = db.collection::<bson::Document>("users");
    let local = email.split('@').next().unwrap_or(email);
    match coll
        .find_one(doc! { "$or": [{ "username": local }, { "username": email }] })
        .await
    {
        Ok(doc) => Ok(doc),
        Err(e) => {
            // Fallback to admin_users collection
            let admin_coll = db.collection::<bson::Document>("admin_users");
            let email_lc = email.trim().to_lowercase();
            admin_coll
                .find_one(doc! { "$or": [{ "email": &email_lc }, { "email": email }] })
                .await
        }
    }
}

/// Store pending TOTP secret (pre-enable confirmation step).
/// We store it in a `pending_totp_secret` field on the user document.
async fn store_pending_secret(
    mongo: &Client,
    email: &str,
    secret: &str,
) -> Result<(), mongodb::error::Error> {
    let db = mongo.database(&mongo_db_name());
    let coll = db.collection::<bson::Document>("users");
    let local = email.split('@').next().unwrap_or(email);
    let _ = coll
        .update_one(
            doc! { "$or": [{ "username": local }, { "username": email }] },
            doc! { "$set": { "pending_totp_secret": secret } },
        )
        .await;
    // Also try admin_users
    let admin_coll = db.collection::<bson::Document>("admin_users");
    let email_lc = email.trim().to_lowercase();
    let _ = admin_coll
        .update_one(
            doc! { "$or": [{ "email": &email_lc }, { "email": email }] },
            doc! { "$set": { "pending_totp_secret": secret } },
        )
        .await;
    Ok(())
}

/// Read pending TOTP secret from user document.
async fn get_pending_secret(
    mongo: &Client,
    email: &str,
) -> Result<Option<String>, mongodb::error::Error> {
    let user = find_user_by_email(mongo, email).await?;
    Ok(user
        .and_then(|d| d.get_str("pending_totp_secret").ok().map(String::from)))
}

// ── POST /api/auth/2fa/setup ──────────────────────────────────────────────
/// Generates a TOTP secret and returns the otpauth URI for QR code scanning.
/// The secret is stored temporarily as `pending_totp_secret` until confirmed.

pub(crate) async fn api_2fa_setup(
    body: web::Json<TwoFactorSetupRequest>,
    mongo: web::Data<Client>,
) -> impl Responder {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "email is required"
        }));
    }

    // Verify user exists
    match find_user_by_email(mongo.as_ref(), &email).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    // Check if 2FA is already enabled
    if let Ok(Some(doc)) = find_user_by_email(mongo.as_ref(), &email).await {
        if doc.get_bool("totp_enabled").unwrap_or(false) {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "2FA is already enabled. Disable first to reconfigure."
            }));
        }
    }

    // Generate new TOTP secret
    let secret = generate_totp_secret();
    let issuer = domain_name();
    let local = email.split('@').next().unwrap_or(&email);

    // otpauth URI for QR code generation
    let otpauth_uri = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, email, secret, issuer
    );

    // Store pending secret
    if let Err(e) = store_pending_secret(mongo.as_ref(), &email, &secret).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }));
    }

    HttpResponse::Ok().json(TwoFactorSetupResponse {
        secret,
        otpauth_uri,
        issuer,
    })
}

// ── POST /api/auth/2fa/enable ──────────────────────────────────────────────
/// Verifies the TOTP code against the pending secret and enables 2FA.
/// Also generates recovery codes.

pub(crate) async fn api_2fa_enable(
    body: web::Json<TwoFactorEnableRequest>,
    mongo: web::Data<Client>,
) -> impl Responder {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || body.code.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "email and code are required"
        }));
    }

    // Retrieve pending secret
    let pending_secret = match get_pending_secret(mongo.as_ref(), &email).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No pending 2FA setup. Call /api/auth/2fa/setup first."
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    // Verify TOTP code
    if !verify_totp(&pending_secret, &body.code) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "enabled": false,
            "error": "Invalid TOTP code"
        }));
    }

    // Generate recovery codes
    let codes = generate_recovery_codes(10);
    let codes_json: Vec<serde_json::Value> = codes
        .iter()
        .map(|c| serde_json::json!({ "code": c, "used": false }))
        .collect();

    // Enable 2FA on user document
    let db = mongo.database(&mongo_db_name());
    let local = email.split('@').next().unwrap_or(&email);

    let update_doc = doc! {
        "$set": {
            "totp_secret": &pending_secret,
            "totp_enabled": true,
            "recovery_codes": bson::to_bson(&codes_json).unwrap_or(bson::Bson::Null),
        },
        "$unset": { "pending_totp_secret": "" }
    };

    let coll = db.collection::<bson::Document>("users");
    let _ = coll
        .update_one(
            doc! { "$or": [{ "username": local }, { "username": &email }] },
            update_doc.clone(),
        )
        .await;

    // Also try admin_users
    let admin_coll = db.collection::<bson::Document>("admin_users");
    let _ = admin_coll
        .update_one(
            doc! { "$or": [{ "email": &email }, { "email": &email }] },
            update_doc,
        )
        .await;

    HttpResponse::Ok().json(serde_json::json!({
        "enabled": true,
        "message": "2FA enabled successfully",
        "recovery_codes": codes
    }))
}

// ── POST /api/auth/2fa/disable ─────────────────────────────────────────────
/// Disables 2FA. Requires password and optionally a TOTP code or recovery code.

pub(crate) async fn api_2fa_disable(
    body: web::Json<TwoFactorDisableRequest>,
    mongo: web::Data<Client>,
) -> impl Responder {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || body.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "email and password are required"
        }));
    }

    // Find user
    let user_doc = match find_user_by_email(mongo.as_ref(), &email).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    // Check if 2FA is enabled
    let totp_enabled = user_doc.get_bool("totp_enabled").unwrap_or(false);
    if !totp_enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "2FA is not enabled"
        }));
    }

    // Verify password (check both password_hash and password fields)
    let stored_hash = user_doc
        .get_str("password_hash")
        .or_else(|_| user_doc.get_str("password"))
        .unwrap_or("");
    let password_valid = !stored_hash.is_empty()
        && bcrypt::verify(&body.password, stored_hash).unwrap_or(false);

    // If bcrypt fails, try plaintext comparison (for env-based admin)
    let password_valid = password_valid || {
        let env_pass = std::env::var("SMTP_PASSWORD").unwrap_or_default();
        body.password == env_pass
    };

    if !password_valid {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid password"
        }));
    }

    // If a TOTP code is provided, verify it
    if let Some(code) = &body.code {
        if !code.is_empty() {
            let totp_secret = user_doc.get_str("totp_secret").unwrap_or("");
            if !totp_secret.is_empty() && !verify_totp(totp_secret, code) {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid TOTP code"
                }));
            }
        }
    }

    // Disable 2FA
    let db = mongo.database(&mongo_db_name());
    let local = email.split('@').next().unwrap_or(&email);

    let unset_doc = doc! {
        "$unset": {
            "totp_secret": "",
            "totp_enabled": "",
            "pending_totp_secret": "",
            "recovery_codes": ""
        }
    };

    let coll = db.collection::<bson::Document>("users");
    let _ = coll
        .update_one(
            doc! { "$or": [{ "username": local }, { "username": &email }] },
            unset_doc.clone(),
        )
        .await;

    let admin_coll = db.collection::<bson::Document>("admin_users");
    let _ = admin_coll
        .update_one(
            doc! { "$or": [{ "email": &email }, { "email": &email }] },
            unset_doc,
        )
        .await;

    HttpResponse::Ok().json(serde_json::json!({
        "enabled": false,
        "message": "2FA disabled successfully"
    }))
}

// ── POST /api/auth/2fa/recovery ────────────────────────────────────────────
/// Verify a recovery code and issue a session if valid.

pub(crate) async fn api_2fa_recovery(
    body: web::Json<RecoveryCodeLoginRequest>,
    mongo: web::Data<Client>,
) -> impl Responder {
    let email = body.email.trim().to_lowercase();
    let recovery_code = body.recovery_code.trim().to_uppercase();

    if email.is_empty() || recovery_code.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "email and recovery_code are required"
        }));
    }

    // Find user
    let user_doc = match find_user_by_email(mongo.as_ref(), &email).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "verified": false,
                "error": "Invalid recovery code"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    // Check if 2FA is enabled
    if !user_doc.get_bool("totp_enabled").unwrap_or(false) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "verified": false,
            "error": "2FA is not enabled"
        }));
    }

    // Get recovery codes
    let recovery_codes = user_doc.get_array("recovery_codes").ok();
    let codes: Vec<bson::Document> = recovery_codes
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_document().map(|d| d.clone()))
                .collect()
        })
        .unwrap_or_default();

    // Find matching unused code
    let mut found = false;
    let mut updated_codes = Vec::new();
    for code_doc in &codes {
        let code_val = code_doc.get_str("code").unwrap_or("").to_uppercase();
        let used = code_doc.get_bool("used").unwrap_or(false);
        if code_val == recovery_code && !used {
            found = true;
            let mut updated = code_doc.clone();
            updated.insert("used", true);
            updated_codes.push(bson::Bson::Document(updated));
        } else {
            updated_codes.push(bson::Bson::Document(code_doc.clone()));
        }
    }

    if !found {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "verified": false,
            "error": "Invalid or already used recovery code"
        }));
    }

    // Mark code as used
    let db = mongo.database(&mongo_db_name());
    let local = email.split('@').next().unwrap_or(&email);
    let coll = db.collection::<bson::Document>("users");
    let _ = coll
        .update_one(
            doc! { "$or": [{ "username": local }, { "username": &email }] },
            doc! { "$set": { "recovery_codes": updated_codes } },
        )
        .await;

    // Issue session
    let display = email.split('@').next().unwrap_or(&email).to_string();
    let session = make_session(&email, &display);

    HttpResponse::Ok().json(serde_json::json!({
        "verified": true,
        "session": session.session
    }))
}

// ── GET /api/auth/2fa/status ───────────────────────────────────────────────
/// Returns 2FA status for a user.

pub(crate) async fn api_2fa_status(
    body: web::Json<TwoFactorSetupRequest>,
    mongo: web::Data<Client>,
) -> impl Responder {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "email is required"
        }));
    }

    let user_doc = match find_user_by_email(mongo.as_ref(), &email).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    let totp_enabled = user_doc.get_bool("totp_enabled").unwrap_or(false);
    let pending = user_doc
        .get_str("pending_totp_secret")
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let recovery_codes_count = user_doc
        .get_array("recovery_codes")
        .map(|arr| {
            arr.iter()
                .filter(|v| {
                    v.as_document()
                        .map(|d| !d.get_bool("used").unwrap_or(false))
                        .unwrap_or(false)
                })
                .count() as i32
        })
        .unwrap_or(0);

    HttpResponse::Ok().json(serde_json::json!({
        "enabled": totp_enabled,
        "pending_setup": pending,
        "recovery_codes_remaining": recovery_codes_count
    }))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_recovery_code_format() {
        let code = generate_recovery_code();
        assert!(code.contains("-"));
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
    }

    #[test]
    fn generate_recovery_codes_unique() {
        let codes = generate_recovery_codes(10);
        assert_eq!(codes.len(), 10);
        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), 10);
    }

    #[test]
    fn generate_recovery_codes_count() {
        let codes = generate_recovery_codes(10);
        assert_eq!(codes.len(), 10);
    }

    #[test]
    fn domain_name_default() {
        // Should not panic
        let _ = domain_name();
    }

    #[test]
    fn mongo_db_name_default() {
        let db = mongo_db_name();
        assert!(!db.is_empty());
    }
}
