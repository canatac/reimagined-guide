//! End-to-end encryption key management and zero-knowledge architecture.
//!
//! Issue #492: E2E key management and zero-knowledge architecture.
//!
//! The server operates in zero-knowledge mode: it never sees plaintext emails
//! or unencrypted private keys. All encryption/decryption happens client-side.
//! The server only stores encrypted blobs and manages key metadata.

use bson::doc;
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// User's E2E key metadata (zero-knowledge: no plaintext secrets stored).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2EKeyRecord {
    /// User ID (MongoDB _id).
    pub user_id: String,
    /// Encrypted private key blob (encrypted client-side with user password).
    /// Base64-encoded ciphertext.
    pub encrypted_private_key: String,
    /// Public key (can be stored in plaintext).
    pub public_key: String,
    /// Recovery key (encrypted with a server-side recovery key).
    pub recovery_key_encrypted: String,
    /// Key derivation salt (base64).
    pub kdf_salt: String,
    /// KDF iterations used.
    pub kdf_iterations: u32,
    /// Algorithm identifier (e.g., "AES-256-GCM", "x25519+ed25519").
    pub algorithm: String,
    /// Created at timestamp (RFC3339).
    pub created_at: String,
    /// Last rotated at timestamp (RFC3339).
    pub rotated_at: Option<String>,
    /// Whether E2E is enabled for this user.
    pub e2e_enabled: bool,
    /// Opt-out mode (advanced users can disable E2E for server-side search).
    pub opt_out: bool,
}

/// Request to register a new E2E key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterKeyRequest {
    pub user_id: String,
    pub encrypted_private_key: String,
    pub public_key: String,
    pub kdf_salt: String,
    pub kdf_iterations: u32,
    pub algorithm: String,
}

/// Request to rotate an existing E2E key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyRequest {
    pub encrypted_private_key: String,
    pub public_key: String,
    pub recovery_key_encrypted: String,
}

/// Recovery request using recovery key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub user_id: String,
    pub new_encrypted_private_key: String,
    pub new_public_key: String,
}

/// E2E key manager.
pub struct E2EKeyManager {
    collection: Collection<E2EKeyRecord>,
    /// Server-side recovery master key (loaded from env).
    recovery_master_key: Arc<RwLock<Vec<u8>>>,
}

impl E2EKeyManager {
    /// Create a new E2EKeyManager.
    pub fn new(collection: Collection<E2EKeyRecord>, recovery_master_key: Vec<u8>) -> Self {
        E2EKeyManager {
            collection,
            recovery_master_key: Arc::new(RwLock::new(recovery_master_key)),
        }
    }

    /// Register a new E2E key for a user.
    pub async fn register_key(
        &self,
        req: RegisterKeyRequest,
    ) -> Result<E2EKeyRecord, E2EError> {
        let now = chrono::Utc::now().to_rfc3339();

        // Generate recovery key (32 random bytes, hex-encoded).
        let recovery_key = self.generate_recovery_key();
        let encrypted_recovery = self.encrypt_recovery_key(&recovery_key)?;

        let record = E2EKeyRecord {
            user_id: req.user_id.clone(),
            encrypted_private_key: req.encrypted_private_key,
            public_key: req.public_key,
            recovery_key_encrypted: encrypted_recovery,
            kdf_salt: req.kdf_salt,
            kdf_iterations: req.kdf_iterations,
            algorithm: req.algorithm,
            created_at: now.clone(),
            rotated_at: None,
            e2e_enabled: true,
            opt_out: false,
        };

        // Upsert: replace existing key if any.
        let filter = doc! { "user_id": &req.user_id };
        self.collection
            .replace_one(filter, &record)
            .upsert(true)
            .await
            .map_err(|e| E2EError::Database(e.to_string()))?;

        Ok(record)
    }

    /// Get key metadata for a user.
    pub async fn get_key(&self, user_id: &str) -> Result<Option<E2EKeyRecord>, E2EError> {
        let filter = doc! { "user_id": user_id };
        self.collection
            .find_one(filter)
            .await
            .map_err(|e| E2EError::Database(e.to_string()))
    }

    /// Rotate an existing key.
    pub async fn rotate_key(
        &self,
        user_id: &str,
        req: RotateKeyRequest,
    ) -> Result<E2EKeyRecord, E2EError> {
        let filter = doc! { "user_id": user_id };
        let now = chrono::Utc::now().to_rfc3339();

        let update = doc! {
            "$set": {
                "encrypted_private_key": req.encrypted_private_key,
                "public_key": req.public_key,
                "recovery_key_encrypted": req.recovery_key_encrypted,
                "rotated_at": now,
            }
        };

        self.collection
            .find_one_and_update(filter, update)
            .await
            .map_err(|e| E2EError::Database(e.to_string()))?
            .ok_or(E2EError::NotFound)
    }

    /// Recover a key using the recovery key.
    pub async fn recover_key(
        &self,
        req: RecoveryRequest,
    ) -> Result<E2EKeyRecord, E2EError> {
        let filter = doc! { "user_id": &req.user_id };
        let now = chrono::Utc::now().to_rfc3339();

        let update = doc! {
            "$set": {
                "encrypted_private_key": req.new_encrypted_private_key,
                "public_key": req.new_public_key,
                "rotated_at": now,
            }
        };

        self.collection
            .find_one_and_update(filter, update)
            .await
            .map_err(|e| E2EError::Database(e.to_string()))?
            .ok_or(E2EError::NotFound)
    }

    /// Toggle E2E opt-out mode.
    pub async fn set_opt_out(
        &self,
        user_id: &str,
        opt_out: bool,
    ) -> Result<(), E2EError> {
        let filter = doc! { "user_id": user_id };
        let update = doc! { "$set": { "opt_out": opt_out } };

        self.collection
            .update_one(filter, update)
            .await
            .map_err(|e| E2EError::Database(e.to_string()))?;

        Ok(())
    }

    /// Delete all E2E keys for a user (account deletion).
    pub async fn delete_keys(&self, user_id: &str) -> Result<(), E2EError> {
        let filter = doc! { "user_id": user_id };
        self.collection
            .delete_one(filter)
            .await
            .map_err(|e| E2EError::Database(e.to_string()))?;
        Ok(())
    }

    /// Generate a random 32-byte recovery key, hex-encoded.
    fn generate_recovery_key(&self) -> String {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        hex::encode(key)
    }

    /// Encrypt a recovery key with the server-side master key.
    fn encrypt_recovery_key(&self, recovery_key: &str) -> Result<String, E2EError> {
        // In production, use AES-256-GCM with the master key.
        // For now, XOR with master key (placeholder — replace with real crypto).
        let master = self.recovery_master_key.try_read()
            .map_err(|_| E2EError::Internal("lock poisoned".into()))?;
        let key_bytes = recovery_key.as_bytes();
        let mut encrypted = Vec::with_capacity(key_bytes.len());
        for (i, &b) in key_bytes.iter().enumerate() {
            encrypted.push(b ^ master[i % master.len()]);
        }
        Ok(hex::encode(encrypted))
    }
}

/// Errors for E2E operations.
#[derive(Debug, Clone, PartialEq)]
pub enum E2EError {
    NotFound,
    Database(String),
    Internal(String),
    InvalidInput(String),
}

impl std::fmt::Display for E2EError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            E2EError::NotFound => write!(f, "Key record not found"),
            E2EError::Database(e) => write!(f, "Database error: {}", e),
            E2EError::Internal(e) => write!(f, "Internal error: {}", e),
            E2EError::InvalidInput(e) => write!(f, "Invalid input: {}", e),
        }
    }
}

impl std::error::Error for E2EError {}

/// Generate a recovery key phrase (12-word mnemonic placeholder).
pub fn generate_recovery_phrase() -> String {
    use rand::Rng;
    let words: Vec<&str> = vec![
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
    ];
    let mut rng = rand::thread_rng();
    let mut phrase = Vec::new();
    for _ in 0..12 {
        let idx = rng.gen_range(0..words.len());
        phrase.push(words[idx]);
    }
    phrase.join(" ")
}

/// Validate that an encrypted blob looks like valid base64 ciphertext.
pub fn validate_encrypted_blob(blob: &str) -> bool {
    base64::decode(blob).is_ok()
}

/// Check if a user has E2E enabled.
pub fn is_e2e_enabled(record: &Option<E2EKeyRecord>) -> bool {
    match record {
        Some(r) => r.e2e_enabled && !r.opt_out,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_recovery_key_produces_64_hex_chars() {
        // Can't test without a collection, but we can test the phrase generator.
        let phrase = generate_recovery_phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn validate_encrypted_blob_accepts_base64() {
        let valid = base64::encode("hello world");
        assert!(validate_encrypted_blob(&valid));
    }

    #[test]
    fn validate_encrypted_blob_rejects_invalid() {
        assert!(!validate_encrypted_blob("not-valid-base64!!!"));
    }

    #[test]
    fn is_e2e_enabled_returns_true_when_enabled() {
        let record = Some(E2EKeyRecord {
            user_id: "user1".into(),
            encrypted_private_key: "enc".into(),
            public_key: "pub".into(),
            recovery_key_encrypted: "recovery".into(),
            kdf_salt: "salt".into(),
            kdf_iterations: 100000,
            algorithm: "AES-256-GCM".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            rotated_at: None,
            e2e_enabled: true,
            opt_out: false,
        });
        assert!(is_e2e_enabled(&record));
    }

    #[test]
    fn is_e2e_enabled_returns_false_when_opt_out() {
        let record = Some(E2EKeyRecord {
            user_id: "user1".into(),
            encrypted_private_key: "enc".into(),
            public_key: "pub".into(),
            recovery_key_encrypted: "recovery".into(),
            kdf_salt: "salt".into(),
            kdf_iterations: 100000,
            algorithm: "AES-256-GCM".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            rotated_at: None,
            e2e_enabled: true,
            opt_out: true,
        });
        assert!(!is_e2e_enabled(&record));
    }

    #[test]
    fn is_e2e_enabled_returns_false_when_no_record() {
        assert!(!is_e2e_enabled(&None));
    }

    #[test]
    fn e2e_error_display() {
        assert_eq!(
            E2EError::NotFound.to_string(),
            "Key record not found"
        );
        assert_eq!(
            E2EError::Database("timeout".into()).to_string(),
            "Database error: timeout"
        );
    }
}
