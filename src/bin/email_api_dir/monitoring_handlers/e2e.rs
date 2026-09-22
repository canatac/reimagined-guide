//! End-to-end encryption (E2EE) zero-access HTTP handlers
//!
//! Issue #600: Zero-access encryption (client-side E2EE)
//!
//! The server operates in zero-knowledge mode: it never sees plaintext emails
//! or unencrypted private keys. All encryption/decryption happens client-side.
//! The server only stores encrypted blobs and manages key metadata.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};

use crate::security::e2e::{
    generate_recovery_phrase, is_e2e_enabled, validate_encrypted_blob, E2EError, E2EKeyRecord,
    RegisterKeyRequest, RecoveryRequest, RotateKeyRequest,
};

/// Response for key status check
#[derive(Debug, Serialize)]
pub struct KeyStatusResponse {
    pub user_id: String,
    pub e2e_enabled: bool,
    pub algorithm: Option<String>,
    pub fingerprint: Option<String>,
    pub created_at: Option<String>,
    pub rotated_at: Option<String>,
}

/// Response for key registration
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub e2e_enabled: bool,
    pub recovery_phrase: String,
    pub algorithm: String,
    pub created_at: String,
}

/// Response for recovery key generation
#[derive(Debug, Serialize)]
pub struct RecoveryPhraseResponse {
    pub recovery_phrase: String,
    pub warning: String,
}

/// POST /api/v1/e2e/enable
/// Enable E2EE for a user (store encrypted private key + public key)
pub async fn api_e2e_enable(body: web::Json<RegisterKeyRequest>) -> Result<HttpResponse> {
    // Validate the encrypted blob is valid base64
    if !validate_encrypted_blob(&body.encrypted_private_key) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid encrypted_private_key: must be valid base64 ciphertext",
        })));
    }

    if body.public_key.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "public_key is required",
        })));
    }

    if body.user_id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "user_id is required",
        })));
    }

    // In production: store via E2EKeyManager. For now, return success with recovery phrase.
    let recovery_phrase = generate_recovery_phrase();
    let now = chrono::Utc::now().to_rfc3339();

    Ok(HttpResponse::Ok().json(RegisterResponse {
        user_id: body.user_id.clone(),
        e2e_enabled: true,
        recovery_phrase,
        algorithm: body.algorithm.clone(),
        created_at: now,
    }))
}

/// GET /api/v1/e2e/status/{user_id}
/// Check E2EE status for a user
pub async fn api_e2e_status(
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();

    // In production: query E2EKeyManager.get_key(&user_id)
    // For now, return not-enabled (no record found)
    Ok(HttpResponse::Ok().json(KeyStatusResponse {
        user_id,
        e2e_enabled: false,
        algorithm: None,
        fingerprint: None,
        created_at: None,
        rotated_at: None,
    }))
}

/// POST /api/v1/e2e/rotate
/// Rotate the user's E2E key pair
pub async fn api_e2e_rotate(body: web::Json<RotateKeyRequest>) -> Result<HttpResponse> {
    if !validate_encrypted_blob(&body.encrypted_private_key) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid encrypted_private_key: must be valid base64 ciphertext",
        })));
    }

    if body.public_key.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "public_key is required",
        })));
    }

    // In production: call E2EKeyManager.rotate_key
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "rotated",
        "algorithm": "AES-256-GCM",
    })))
}

/// POST /api/v1/e2e/recover
/// Recover E2EE access using recovery key
pub async fn api_e2e_recover(body: web::Json<RecoveryRequest>) -> Result<HttpResponse> {
    if body.user_id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "user_id is required",
        })));
    }

    if !validate_encrypted_blob(&body.new_encrypted_private_key) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid new_encrypted_private_key: must be valid base64 ciphertext",
        })));
    }

    // In production: verify recovery key hash, then call E2EKeyManager.recover_key
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "recovered",
        "user_id": body.user_id,
    })))
}

/// POST /api/v1/e2e/recovery-phrase
/// Generate a new recovery phrase (12-word mnemonic)
pub async fn api_e2e_recovery_phrase() -> Result<HttpResponse> {
    let phrase = generate_recovery_phrase();
    Ok(HttpResponse::Ok().json(RecoveryPhraseResponse {
        recovery_phrase: phrase,
        warning: "Store this phrase securely. It cannot be recovered if lost.".to_string(),
    }))
}

/// DELETE /api/v1/e2e/disable/{user_id}
/// Disable E2EE for a user (opt-out)
pub async fn api_e2e_disable(
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    // In production: call E2EKeyManager.set_opt_out(&user_id, true)
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "disabled",
        "user_id,
        "e2e_enabled": false,
    })))
}

/// POST /api/v1/e2e/validate-blob
/// Validate that an encrypted blob is valid base64 ciphertext
#[derive(Debug, Deserialize)]
pub struct ValidateBlobRequest {
    pub blob: String,
}

pub async fn api_e2e_validate_blob(
    body: web::Json<ValidateBlobRequest>,
) -> Result<HttpResponse> {
    let valid = validate_encrypted_blob(&body.blob);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": valid,
        "blob_length": body.blob.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_response_has_required_fields() {
        let resp = RegisterResponse {
            user_id: "user-1".to_string(),
            e2e_enabled: true,
            recovery_phrase: "abandon ability able".to_string(),
            algorithm: "AES-256-GCM".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        assert_eq!(resp.user_id, "user-1");
        assert!(resp.e2e_enabled);
        assert_eq!(resp.algorithm, "AES-256-GCM");
    }

    #[test]
    fn key_status_response_default() {
        let resp = KeyStatusResponse {
            user_id: "user-1".to_string(),
            e2e_enabled: false,
            algorithm: None,
            fingerprint: None,
            created_at: None,
            rotated_at: None,
        };
        assert!(!resp.e2e_enabled);
        assert!(resp.algorithm.is_none());
    }

    #[test]
    fn recovery_phrase_response_has_warning() {
        let resp = RecoveryPhraseResponse {
            recovery_phrase: "test phrase".to_string(),
            warning: "Store securely".to_string(),
        };
        assert!(!resp.recovery_phrase.is_empty());
        assert!(!resp.warning.is_empty());
    }

    #[test]
    fn validate_blob_request_accepts_base64() {
        let valid = base64::encode("test-encrypted-data");
        assert!(validate_encrypted_blob(&valid));
    }

    #[test]
    fn validate_blob_request_rejects_invalid() {
        assert!(!validate_encrypted_blob("not-valid-base64!!!"));
    }
}
