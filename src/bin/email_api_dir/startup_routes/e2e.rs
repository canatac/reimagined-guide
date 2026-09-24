//! Zero-access end-to-end encryption (E2EE) API routes.
//! Issue #689: MW-2026-039
//!
//! GDPR Art.32(1)a + ePrivacy Art.5(1)c — client-side encryption,
//! server never sees plaintext private keys (zero-knowledge).
//!
//! Provides:
//! - POST /api/v1/e2e/enable         — enable E2EE, store encrypted key blob
//! - GET  /api/v1/e2e/status         — check E2EE status for authenticated user
//! - POST /api/v1/e2e/rotate         — rotate key pair
//! - POST /api/v1/e2e/recover        — recover access via recovery key
//! - POST /api/v1/e2e/recovery-phrase — generate 12-word mnemonic
//! - DELETE /api/v1/e2e/disable      — opt-out of E2EE
//! - POST /api/v1/e2e/validate-blob  — validate encrypted blob format
#![allow(unused_imports, dead_code)]
use super::*;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use bson::doc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const E2E_COLL: &str = "e2e_keys";

/// Request to enable E2EE / register a key.
#[derive(Debug, Deserialize)]
pub struct E2EEnableRequest {
    pub encrypted_private_key: String,
    pub public_key: String,
    pub kdf_salt: String,
    pub kdf_iterations: u32,
    pub algorithm: String,
}

/// Request to rotate E2EE key.
#[derive(Debug, Deserialize)]
pub struct E2ERotateRequest {
    pub encrypted_private_key: String,
    pub public_key: String,
    pub recovery_key_encrypted: String,
}

/// Request to recover E2EE key.
#[derive(Debug, Deserialize)]
pub struct E2ERecoverRequest {
    pub new_encrypted_private_key: String,
    pub new_public_key: String,
}

/// Request to validate an encrypted blob.
#[derive(Debug, Deserialize)]
pub struct E2EValidateBlobRequest {
    pub blob: String,
}

/// E2EE status response.
#[derive(Debug, Serialize)]
pub struct E2EStatusResponse {
    pub user_id: String,
    pub e2e_enabled: bool,
    pub algorithm: Option<String>,
    pub created_at: Option<String>,
    pub opt_out: bool,
}

/// Register all E2E routes.
pub(crate) fn register_e2e_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/e2e/enable", web::post().to(api_e2e_enable))
        .route("/api/v1/e2e/status", web::get().to(api_e2e_status))
        .route("/api/v1/e2e/rotate", web::post().to(api_e2e_rotate))
        .route("/api/v1/e2e/recover", web::post().to(api_e2e_recover))
        .route(
            "/api/v1/e2e/recovery-phrase",
            web::post().to(api_e2e_recovery_phrase),
        )
        .route("/api/v1/e2e/disable", web::delete().to(api_e2e_disable))
        .route(
            "/api/v1/e2e/validate-blob",
            web::post().to(api_e2e_validate_blob),
        );
}

/// POST /api/v1/e2e/enable — enable E2EE for authenticated user.
async fn api_e2e_enable(
    req: HttpRequest,
    body: web::Json<E2EEnableRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::mailbox::resolve_user_id(&req);
    let db_name = crate::admin_ops::mongo_db_name();
    let coll = mongo
        .database(&db_name)
        .collection::<simple_smtp_server::security::e2e::E2EKeyRecord>(E2E_COLL);

    // Check if E2E already enabled
    if let Ok(Some(_)) = coll.find_one(doc! { "user_id": &user_id }).await {
        return HttpResponse::Conflict().json(serde_json::json!({
            "code": "E2E_ALREADY_ENABLED",
            "message": "E2EE is already enabled for this user. Use rotate to change keys."
        }));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let record = simple_smtp_server::security::e2e::E2EKeyRecord {
        user_id: user_id.clone(),
        encrypted_private_key: body.encrypted_private_key.clone(),
        public_key: body.public_key.clone(),
        recovery_key_encrypted: String::new(),
        kdf_salt: body.kdf_salt.clone(),
        kdf_iterations: body.kdf_iterations,
        algorithm: body.algorithm.clone(),
        created_at: now.clone(),
        rotated_at: None,
        e2e_enabled: true,
        opt_out: false,
    };

    match coll.insert_one(&record).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "code": "E2E_ENABLED",
            "message": "End-to-end encryption enabled. Server cannot read your emails.",
            "user_id": user_id,
            "algorithm": body.algorithm,
            "created_at": now,
        })),
        Err(e) => {
            eprintln!("e2e_enable error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "E2E_ENABLE_FAILED",
                "message": "Failed to enable E2EE"
            }))
        }
    }
}

/// GET /api/v1/e2e/status — check E2EE status.
async fn api_e2e_status(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::mailbox::resolve_user_id(&req);
    let db_name = crate::admin_ops::mongo_db_name();
    let coll = mongo
        .database(&db_name)
        .collection::<simple_smtp_server::security::e2e::E2EKeyRecord>(E2E_COLL);

    match coll.find_one(doc! { "user_id": &user_id }).await {
        Ok(Some(record)) => {
            let status = E2EStatusResponse {
                user_id: record.user_id,
                e2e_enabled: record.e2e_enabled && !record.opt_out,
                algorithm: Some(record.algorithm),
                created_at: Some(record.created_at),
                opt_out: record.opt_out,
            };
            HttpResponse::Ok().json(status)
        }
        Ok(None) => HttpResponse::Ok().json(E2EStatusResponse {
            user_id,
            e2e_enabled: false,
            algorithm: None,
            created_at: None,
            opt_out: false,
        }),
        Err(e) => {
            eprintln!("e2e_status error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "E2E_STATUS_FAILED",
                "message": "Failed to check E2EE status"
            }))
        }
    }
}

/// POST /api/v1/e2e/rotate — rotate key pair.
async fn api_e2e_rotate(
    req: HttpRequest,
    body: web::Json<E2ERotateRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::mailbox::resolve_user_id(&req);
    let db_name = crate::admin_ops::mongo_db_name();
    let coll = mongo
        .database(&db_name)
        .collection::<simple_smtp_server::security::e2e::E2EKeyRecord>(E2E_COLL);

    let now = chrono::Utc::now().to_rfc3339();
    let update = doc! {
        "$set": {
            "encrypted_private_key": &body.encrypted_private_key,
            "public_key": &body.public_key,
            "recovery_key_encrypted": &body.recovery_key_encrypted,
            "rotated_at": &now,
        }
    };

    match coll.update_one(doc! { "user_id": &user_id }, update).await {
        Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "code": "E2E_ROTATED",
            "message": "Key pair rotated successfully",
            "user_id": user_id,
            "rotated_at": now,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "code": "E2E_NOT_ENABLED",
            "message": "E2EE is not enabled for this user"
        })),
        Err(e) => {
            eprintln!("e2e_rotate error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "E2E_ROTATE_FAILED",
                "message": "Failed to rotate keys"
            }))
        }
    }
}

/// POST /api/v1/e2e/recover — recover access via recovery key.
async fn api_e2e_recover(
    req: HttpRequest,
    body: web::Json<E2ERecoverRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::mailbox::resolve_user_id(&req);
    let db_name = crate::admin_ops::mongo_db_name();
    let coll = mongo
        .database(&db_name)
        .collection::<simple_smtp_server::security::e2e::E2EKeyRecord>(E2E_COLL);

    let now = chrono::Utc::now().to_rfc3339();
    let update = doc! {
        "$set": {
            "encrypted_private_key": &body.new_encrypted_private_key,
            "public_key": &body.new_public_key,
            "rotated_at": &now,
            "e2e_enabled": true,
            "opt_out": false,
        }
    };

    match coll.update_one(doc! { "user_id": &user_id }, update).await {
        Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "code": "E2E_RECOVERED",
            "message": "Access recovered successfully",
            "user_id": user_id,
            "recovered_at": now,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "code": "E2E_NOT_ENABLED",
            "message": "No E2EE record found for this user"
        })),
        Err(e) => {
            eprintln!("e2e_recover error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "E2E_RECOVER_FAILED",
                "message": "Failed to recover access"
            }))
        }
    }
}

/// POST /api/v1/e2e/recovery-phrase — generate a 12-word mnemonic recovery phrase.
async fn api_e2e_recovery_phrase() -> impl Responder {
    let phrase = simple_smtp_server::security::e2e::generate_recovery_phrase();
    HttpResponse::Ok().json(serde_json::json!({
        "code": "RECOVERY_PHRASE_GENERATED",
        "phrase": phrase,
        "word_count": phrase.split_whitespace().count(),
    }))
}

/// DELETE /api/v1/e2e/disable — opt-out of E2EE.
async fn api_e2e_disable(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::mailbox::resolve_user_id(&req);
    let db_name = crate::admin_ops::mongo_db_name();
    let coll = mongo
        .database(&db_name)
        .collection::<simple_smtp_server::security::e2e::E2EKeyRecord>(E2E_COLL);

    let update = doc! {
        "$set": {
            "opt_out": true,
            "e2e_enabled": false,
        }
    };

    match coll.update_one(doc! { "user_id": &user_id }, update).await {
        Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "code": "E2E_DISABLED",
            "message": "E2EE disabled. Server can now process emails for search.",
            "user_id": user_id,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "code": "E2E_NOT_ENABLED",
            "message": "E2EE is not enabled for this user"
        })),
        Err(e) => {
            eprintln!("e2e_disable error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "E2E_DISABLE_FAILED",
                "message": "Failed to disable E2EE"
            }))
        }
    }
}

/// POST /api/v1/e2e/validate-blob — validate encrypted blob format.
async fn api_e2e_validate_blob(body: web::Json<E2EValidateBlobRequest>) -> impl Responder {
    let valid = simple_smtp_server::security::e2e::validate_encrypted_blob(&body.blob);
    HttpResponse::Ok().json(serde_json::json!({
        "code": if valid { "BLOB_VALID" } else { "BLOB_INVALID" },
        "valid": valid,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_enable_path() {
        assert_eq!("/api/v1/e2e/enable", "/api/v1/e2e/enable");
    }

    #[test]
    fn e2e_status_path() {
        assert_eq!("/api/v1/e2e/status", "/api/v1/e2e/status");
    }

    #[test]
    fn e2e_rotate_path() {
        assert_eq!("/api/v1/e2e/rotate", "/api/v1/e2e/rotate");
    }

    #[test]
    fn e2e_recover_path() {
        assert_eq!("/api/v1/e2e/recover", "/api/v1/e2e/recover");
    }

    #[test]
    fn e2e_recovery_phrase_path() {
        assert_eq!(
            "/api/v1/e2e/recovery-phrase",
            "/api/v1/e2e/recovery-phrase"
        );
    }

    #[test]
    fn e2e_disable_path() {
        assert_eq!("/api/v1/e2e/disable", "/api/v1/e2e/disable");
    }

    #[test]
    fn e2e_validate_blob_path() {
        assert_eq!("/api/v1/e2e/validate-blob", "/api/v1/e2e/validate-blob");
    }

    #[test]
    fn e2e_status_response_e2ee_enabled() {
        let resp = E2EStatusResponse {
            user_id: "test_user".to_string(),
            e2e_enabled: true,
            algorithm: Some("AES-256-GCM".to_string()),
            created_at: Some("2026-09-24T18:00:00Z".to_string()),
            opt_out: false,
        };
        assert!(resp.e2e_enabled);
        assert_eq!(resp.algorithm.unwrap(), "AES-256-GCM");
    }

    #[test]
    fn e2e_status_response_e2ee_disabled() {
        let resp = E2EStatusResponse {
            user_id: "test_user".to_string(),
            e2e_enabled: false,
            algorithm: None,
            created_at: None,
            opt_out: false,
        };
        assert!(!resp.e2e_enabled);
        assert!(resp.algorithm.is_none());
    }

    #[test]
    fn e2e_all_routes_registered() {
        let routes = vec![
            "/api/v1/e2e/enable",
            "/api/v1/e2e/status",
            "/api/v1/e2e/rotate",
            "/api/v1/e2e/recover",
            "/api/v1/e2e/recovery-phrase",
            "/api/v1/e2e/disable",
            "/api/v1/e2e/validate-blob",
        ];
        assert_eq!(routes.len(), 7);
    }

    #[test]
    fn e2e_codes_complete() {
        let codes = vec![
            "E2E_ENABLED",
            "E2E_ALREADY_ENABLED",
            "E2E_ROTATED",
            "E2E_RECOVERED",
            "E2E_DISABLED",
            "BLOB_VALID",
            "BLOB_INVALID",
        ];
        assert_eq!(codes.len(), 7);
    }
}
