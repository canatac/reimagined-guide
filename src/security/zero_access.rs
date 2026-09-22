//! Zero-access encryption mode (Issue #575).
//!
//! When enabled, the server stores only encrypted email bodies.
//! The server never sees plaintext email content — all encryption/decryption
//! happens client-side. The server manages key metadata only.

use bson::doc;
use mongodb::Collection;
use serde::{Deserialize, Serialize};

/// Zero-access mode status for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroAccessStatus {
    /// Whether zero-access mode is enabled.
    pub enabled: bool,
    /// Whether the user has registered E2E keys.
    pub has_e2e_keys: bool,
    /// Algorithm used (e.g., "AES-256-GCM").
    pub algorithm: Option<String>,
    /// Public key fingerprint (hex).
    pub key_fingerprint: Option<String>,
}

/// Request to enable zero-access mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableZeroAccessRequest {
    /// Client-generated public key (base64).
    pub public_key: String,
    /// KDF salt (base64).
    pub kdf_salt: String,
    /// KDF iterations.
    pub kdf_iterations: u32,
    /// Algorithm identifier.
    pub algorithm: String,
    /// Encrypted private key blob (base64, encrypted client-side with user password).
    pub encrypted_private_key: String,
    /// Recovery phrase hash (SHA-256 hex).
    pub recovery_phrase_hash: String,
}

/// Request to disable zero-access mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableZeroAccessRequest {
    /// Confirmation: user must provide the recovery phrase hash.
    pub recovery_phrase_hash: String,
}

/// Zero-access mode manager.
pub struct ZeroAccessManager {
    user_collection: Collection<bson::Document>,
    e2e_collection: Collection<bson::Document>,
}

/// Errors for zero-access operations.
#[derive(Debug, Clone, Serialize)]
pub enum ZeroAccessError {
    /// Zero-access mode is already enabled.
    AlreadyEnabled,
    /// Zero-access mode is not enabled.
    NotEnabled,
    /// Invalid recovery phrase.
    InvalidRecovery,
    /// Database error.
    Database(String),
    /// Invalid input.
    InvalidInput(String),
}

impl std::fmt::Display for ZeroAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZeroAccessError::AlreadyEnabled => write!(f, "Zero-access mode already enabled"),
            ZeroAccessError::NotEnabled => write!(f, "Zero-access mode not enabled"),
            ZeroAccessError::InvalidRecovery => write!(f, "Invalid recovery phrase"),
            ZeroAccessError::Database(e) => write!(f, "Database error: {}", e),
            ZeroAccessError::InvalidInput(e) => write!(f, "Invalid input: {}", e),
        }
    }
}

impl std::error::Error for ZeroAccessError {}

impl ZeroAccessManager {
    /// Create a new ZeroAccessManager.
    pub fn new(
        user_collection: Collection<bson::Document>,
        e2e_collection: Collection<bson::Document>,
    ) -> Self {
        ZeroAccessManager {
            user_collection,
            e2e_collection,
        }
    }

    /// Check if zero-access mode is enabled for a user.
    pub async fn status(&self, user_id: &str) -> Result<ZeroAccessStatus, ZeroAccessError> {
        let user = self
            .user_collection
            .find_one(doc! { "_id": user_id })
            .await
            .map_err(|e| ZeroAccessError::Database(e.to_string()))?;

        let enabled = match &user {
            Some(u) => u
                .get_bool("zero_access_enabled")
                .unwrap_or(false),
            None => false,
        };

        let e2e_record = self
            .e2e_collection
            .find_one(doc! { "user_id": user_id })
            .await
            .map_err(|e| ZeroAccessError::Database(e.to_string()))?;

        let (has_keys, algorithm, fingerprint) = match e2e_record {
            Some(rec) => {
                let algo = rec.get_str("algorithm").ok().map(|s| s.to_string());
                let pk = rec.get_str("public_key").unwrap_or("");
                // Simple fingerprint: first 16 hex chars of SHA-256 of public key
                let fingerprint = if pk.is_empty() {
                    None
                } else {
                    Some(format!("{:x}", md5::compute(pk.as_bytes())))
                };
                (true, algo, fingerprint)
            }
            None => (false, None, None),
        };

        Ok(ZeroAccessStatus {
            enabled,
            has_e2e_keys: has_keys,
            algorithm,
            key_fingerprint: fingerprint,
        })
    }

    /// Enable zero-access mode for a user.
    pub async fn enable(
        &self,
        user_id: &str,
        req: &EnableZeroAccessRequest,
    ) -> Result<ZeroAccessStatus, ZeroAccessError> {
        // Validate input
        if req.public_key.is_empty() {
            return Err(ZeroAccessError::InvalidInput(
                "public_key is required".into(),
            ));
        }
        if req.encrypted_private_key.is_empty() {
            return Err(ZeroAccessError::InvalidInput(
                "encrypted_private_key is required".into(),
            ));
        }
        if req.algorithm.is_empty() {
            return Err(ZeroAccessError::InvalidInput(
                "algorithm is required".into(),
            ));
        }
        if req.kdf_iterations < 10000 {
            return Err(ZeroAccessError::InvalidInput(
                "kdf_iterations must be >= 10000".into(),
            ));
        }

        // Check if already enabled
        let current = self.status(user_id).await?;
        if current.enabled {
            return Err(ZeroAccessError::AlreadyEnabled);
        }

        // Store E2E key record
        let e2e_doc = doc! {
            "user_id": user_id,
            "public_key": &req.public_key,
            "encrypted_private_key": &req.encrypted_private_key,
            "kdf_salt": &req.kdf_salt,
            "kdf_iterations": req.kdf_iterations as i64,
            "algorithm": &req.algorithm,
            "recovery_phrase_hash": &req.recovery_phrase_hash,
            "e2e_enabled": true,
            "opt_out": false,
            "created_at": bson::DateTime::now(),
        };

        self.e2e_collection
            .insert_one(e2e_doc)
            .await
            .map_err(|e| ZeroAccessError::Database(e.to_string()))?;

        // Update user record
        self.user_collection
            .update_one(
                doc! { "_id": user_id },
                doc! { "$set": { "zero_access_enabled": true } },
            )
            .await
            .map_err(|e| ZeroAccessError::Database(e.to_string()))?;

        self.status(user_id).await
    }

    /// Disable zero-access mode for a user.
    pub async fn disable(
        &self,
        user_id: &str,
        req: &DisableZeroAccessRequest,
    ) -> Result<ZeroAccessStatus, ZeroAccessError> {
        let current = self.status(user_id).await?;
        if !current.enabled {
            return Err(ZeroAccessError::NotEnabled);
        }

        // Verify recovery phrase hash
        let e2e_record = self
            .e2e_collection
            .find_one(doc! { "user_id": user_id })
            .await
            .map_err(|e| ZeroAccessError::Database(e.to_string()))?;

        match e2e_record {
            Some(rec) => {
                let stored_hash = rec.get_str("recovery_phrase_hash").unwrap_or("");
                if stored_hash != req.recovery_phrase_hash {
                    return Err(ZeroAccessError::InvalidRecovery);
                }
            }
            None => return Err(ZeroAccessError::NotEnabled),
        }

        // Disable on user record
        self.user_collection
            .update_one(
                doc! { "_id": user_id },
                doc! { "$set": { "zero_access_enabled": false } },
            )
            .await
            .map_err(|e| ZeroAccessError::Database(e.to_string()))?;

        // Mark E2E as disabled (keep key record for audit)
        self.e2e_collection
            .update_one(
                doc! { "user_id": user_id },
                doc! { "$set": { "e2e_enabled": false, "opt_out": true } },
            )
            .await
            .map_err(|e| ZeroAccessError::Database(e.to_string()))?;

        self.status(user_id).await
    }

    /// Check if a user has zero-access mode enabled.
    pub async fn is_zero_access_enabled(&self, user_id: &str) -> Result<bool, ZeroAccessError> {
        let status = self.status(user_id).await?;
        Ok(status.enabled)
    }
}

/// Validate that a base64 blob looks like valid encrypted data.
pub fn validate_encrypted_blob(blob: &str) -> bool {
    base64::decode(blob).is_ok()
}

/// Compute a key fingerprint from a public key.
pub fn key_fingerprint(public_key: &str) -> String {
    format!("{:x}", md5::compute(public_key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_encrypted_blob_accepts_base64() {
        let valid = base64::encode("hello world");
        assert!(validate_encrypted_blob(&valid));
    }

    #[test]
    fn validate_encrypted_blob_rejects_invalid() {
        assert!(!validate_encrypted_blob("not-valid!!!"));
    }

    #[test]
    fn validate_encrypted_blob_rejects_empty() {
        assert!(!validate_encrypted_blob(""));
    }

    #[test]
    fn key_fingerprint_is_deterministic() {
        let pk = "test-public-key-data";
        let fp1 = key_fingerprint(pk);
        let fp2 = key_fingerprint(pk);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn key_fingerprint_differs_for_different_keys() {
        let fp1 = key_fingerprint("key1");
        let fp2 = key_fingerprint("key2");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn zero_access_error_display() {
        assert_eq!(
            ZeroAccessError::AlreadyEnabled.to_string(),
            "Zero-access mode already enabled"
        );
        assert_eq!(
            ZeroAccessError::NotEnabled.to_string(),
            "Zero-access mode not enabled"
        );
        assert_eq!(
            ZeroAccessError::InvalidRecovery.to_string(),
            "Invalid recovery phrase"
        );
        assert_eq!(
            ZeroAccessError::Database("timeout".to_string()).to_string(),
            "Database error: timeout"
        );
        assert_eq!(
            ZeroAccessError::InvalidInput("bad".to_string()).to_string(),
            "Invalid input: bad"
        );
    }
}
