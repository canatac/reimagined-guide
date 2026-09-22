//! Zero-access encryption mode handlers (Issue #575).
//!
//! Provides endpoints for enabling/disabling zero-access mode
//! and managing E2E encryption keys.

use actix_web::{web, HttpResponse, HttpRequest};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use simple_smtp_server::security::zero_access::{
    ZeroAccessManager, EnableZeroAccessRequest, DisableZeroAccessRequest,
    ZeroAccessStatus,
};

/// Type alias for the zero-access app state (shared across handlers).
pub type ZeroAccessAppState = Arc<Mutex<ZeroAccessManager>>;

/// Extract user ID from request (simplified — uses query param or header).
/// In production, this would extract from JWT/session.
fn extract_user_id(req: &HttpRequest) -> Option<String> {
    // Try header first
    req.headers()
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            // Fallback: query param
            let query = req.query_string();
            for pair in query.split('&') {
                let mut kv = pair.splitn(2, '=');
                if let (Some("user_id"), Some(val)) = (kv.next(), kv.next()) {
                    return Some(val.to_string());
                }
            }
            None
        })
}

/// GET /api/v1/zero-access/status
/// Returns the zero-access mode status for the authenticated user.
pub async fn api_zero_access_status(
    req: HttpRequest,
    data: web::Data<ZeroAccessAppState>,
) -> HttpResponse {
    let user_id = match extract_user_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "status": "error",
                "message": "Missing user identification (X-User-Id header or user_id query param)"
            }));
        }
    };

    let manager = data.lock().await;
    match manager.status(&user_id).await {
        Ok(status) => HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "zeroAccess": status
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

/// POST /api/v1/zero-access/enable
/// Enable zero-access mode for the authenticated user.
pub async fn api_zero_access_enable(
    req: HttpRequest,
    data: web::Data<ZeroAccessAppState>,
    body: web::Json<EnableZeroAccessRequest>,
) -> HttpResponse {
    let user_id = match extract_user_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "status": "error",
                "message": "Missing user identification (X-User-Id header or user_id query param)"
            }));
        }
    };

    let manager = data.lock().await;
    match manager.enable(&user_id, &body).await {
        Ok(status) => HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Zero-access mode enabled",
            "zeroAccess": status
        })),
        Err(e) => {
            let status_code = match e {
                simple_smtp_server::security::zero_access::ZeroAccessError::AlreadyEnabled => {
                    409
                }
                simple_smtp_server::security::zero_access::ZeroAccessError::InvalidInput(_) => {
                    400
                }
                _ => 500,
            };
            let status_code = actix_web::http::StatusCode::from_u16(status_code).unwrap_or(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            );
            HttpResponse::build(status_code).json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            }))
        }
    }
}

/// POST /api/v1/zero-access/disable
/// Disable zero-access mode for the authenticated user.
pub async fn api_zero_access_disable(
    req: HttpRequest,
    data: web::Data<ZeroAccessAppState>,
    body: web::Json<DisableZeroAccessRequest>,
) -> HttpResponse {
    let user_id = match extract_user_id(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "status": "error",
                "message": "Missing user identification (X-User-Id header or user_id query param)"
            }));
        }
    };

    let manager = data.lock().await;
    match manager.disable(&user_id, &body).await {
        Ok(status) => HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Zero-access mode disabled",
            "zeroAccess": status
        })),
        Err(e) => {
            let status_code = match e {
                simple_smtp_server::security::zero_access::ZeroAccessError::NotEnabled => 404,
                simple_smtp_server::security::zero_access::ZeroAccessError::InvalidRecovery => {
                    403
                }
                _ => 500,
            };
            let status_code = actix_web::http::StatusCode::from_u16(status_code).unwrap_or(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            );
            HttpResponse::build(status_code).json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            }))
        }
    }
}

/// POST /api/v1/zero-access/validate-blob
/// Validate that a blob looks like valid encrypted data (base64).
#[derive(Debug, Deserialize)]
pub struct ValidateBlobRequest {
    pub blob: String,
}

pub async fn api_zero_access_validate_blob(
    body: web::Json<ValidateBlobRequest>,
) -> HttpResponse {
    let valid = simple_smtp_server::security::zero_access::validate_encrypted_blob(&body.blob);
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "valid": valid
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_blob_request_deserializes() {
        let json = serde_json::json!({ "blob": "aGVsbG8=" });
        let req: ValidateBlobRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.blob, "aGVsbG8=");
    }

    #[test]
    fn enable_zero_access_request_deserializes() {
        let json = serde_json::json!({
            "public_key": "cHVibGljX2tleQ==",
            "kdf_ssalt": "c2FsdA==",
            "kdf_salt": "c2FsdA==",
            "kdf_iterations": 100000,
            "algorithm": "AES-256-GCM",
            "encrypted_private_key": "ZW5jcnlwdGVk",
            "recovery_phrase_hash": "abc123"
        });
        let req: EnableZeroAccessRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.algorithm, "AES-256-GCM");
        assert_eq!(req.kdf_iterations, 100000);
    }

    #[test]
    fn disable_zero_access_request_deserializes() {
        let json = serde_json::json!({
            "recovery_phrase_hash": "abc123"
        });
        let req: DisableZeroAccessRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.recovery_phrase_hash, "abc123");
    }

    #[test]
    fn zero_access_status_serializes() {
        let status = ZeroAccessStatus {
            enabled: true,
            has_e2e_keys: true,
            algorithm: Some("AES-256-GCM".into()),
            key_fingerprint: Some("abc123".into()),
        };
        let json = serde_json::to_value(&status).unwrap();
        assert!(json["enabled"].as_bool().unwrap());
        assert!(json["has_e2e_keys"].as_bool().unwrap());
    }
}
