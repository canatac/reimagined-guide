//! E2E encryption key management and zero-knowledge architecture.
//!
//! Zero-knowledge principle: the server NEVER sees plaintext private keys.
//! Private keys are encrypted client-side with a key derived from the user's
//! password (Argon2id). The server stores only:
//! - Public keys (for encryption of outgoing emails to the user)
//! - Encrypted private key blobs (opaque to the server)
//! - Recovery key hashes (for account recovery without password)

use crate::errors::DomainResult;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// E2E key pair metadata (zero-knowledge: server never sees plaintext private key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct E2EKeyPair {
    pub id: String,
    pub user_id: String,
    /// Armored PGP public key (ASCII-armored, can be shared freely).
    pub public_key: String,
    /// Encrypted private key blob (opaque to server, encrypted client-side).
    /// Format: base64(nonce || ciphertext || tag) using AES-256-GCM or XChaCha20-Poly1305.
    pub encrypted_private_key: String,
    /// Key derivation algorithm identifier (e.g., "argon2id").
    pub kdf_algorithm: String,
    /// KDF parameters (JSON-encoded, e.g., {"memory": 65536, "iterations": 3, "parallelism": 4}).
    pub kdf_params: String,
    /// Fingerprint of the public key (hex-encoded, 40 chars for SHA-1).
    pub fingerprint: String,
    /// Whether this key is the primary (active) key for the user.
    pub is_primary: bool,
    /// Whether E2E is enabled for this user (opt-out sets this to false).
    pub e2e_enabled: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Optional: recovery key hash (SHA-256 of recovery phrase, for verification only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key_hash: Option<String>,
}

impl E2EKeyPair {
    pub fn new(user_id: &str, public_key: &str, encrypted_private_key: &str) -> Self {
        let now = Utc::now();
        E2EKeyPair {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            public_key: public_key.to_string(),
            encrypted_private_key: encrypted_private_key.to_string(),
            kdf_algorithm: "argon2id".to_string(),
            kdf_params: r#"{"memory":65536,"iterations":3,"parallelism":4}"#.to_string(),
            fingerprint: String::new(),
            is_primary: true,
            e2e_enabled: now,
            created_at: now,
            updated_at: now,
            recovery_key_hash: None,
        }
    }
}

/// Recovery key record (zero-knowledge: server stores only hash).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKeyRecord {
    pub id: String,
    pub user_id: String,
    /// SHA-256 hash of the recovery phrase (for verification only).
    pub recovery_hash: String,
    /// Whether this recovery key has been used.
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

impl RecoveryKeyRecord {
    pub fn new(user_id: &str, recovery_hash: &str) -> Self {
        RecoveryKeyRecord {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            recovery_hash: recovery_hash.to_string(),
            used: false,
            created_at: Utc::now(),
            used_at: None,
        }
    }
}

/// Zero-knowledge proof of key ownership.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ZKProof {
    pub key_id: String,
    pub user_id: String,
    /// Challenge signed with the private key (proves ownership without revealing key).
    pub proof: String,
    pub created_at: DateTime<Utc>,
}

/// Port for E2E key management operations.
#[async_trait]
pub trait E2EKeyPort: Send + Sync {
    /// Generate a new E2E key pair for a user.
    /// Returns the key pair ID and the encrypted private key blob.
    async fn generate_key_pair(
        &self,
        user_id: &str,
        public_key: &str,
        encrypted_private_key: &str,
        fingerprint: &str,
    ) -> DomainResult<E2EKeyPair>;

    /// Import an existing E2E key pair.
    async fn import_key_pair(
        &self,
        user_id: &str,
        public_key: &str,
        encrypted_private_key: &str,
        fingerprint: &str,
    ) -> DomainResult<E2EKeyPair>;

    /// Get the primary E2E key pair for a user.
    async fn get_primary_key(&self, user_id: &str) -> DomainResult<Option<E2EKeyPair>>;

    /// Get a specific E2E key pair by ID.
    async fn get_key_by_id(&self, key_id: &str) -> DomainResult<Option<E2EKeyPair>>;

    /// List all E2E key pairs for a user.
    async fn list_keys(&self, user_id: &str) -> DomainResult<Vec<E2EKeyPair>>;

    /// Rotate (replace) the primary key pair.
    async fn rotate_key(
        &self,
        user_id: &str,
        new_public_key: &str,
        new_encrypted_private_key: &str,
        new_fingerprint: &str,
    ) -> DomainResult<E2EKeyPair>;

    /// Store a recovery key hash.
    async fn store_recovery_key(
        &self,
        user_id: &str,
        recovery_hash: &str,
    ) -> DomainResult<RecoveryKeyRecord>;

    /// Verify a recovery key against stored hash.
    async fn verify_recovery_key(
        &self,
        user_id: &str,
        recovery_hash: &str,
    ) -> DomainResult<bool>;

    /// Mark a recovery key as used.
    async fn mark_recovery_key_used(&self, key_id: &str) -> DomainResult<()>;

    /// Get public key by fingerprint (for WKD - Web Key Directory).
    async fn get_public_key_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> DomainResult<Option<String>>;

    /// Delete an E2E key pair.
    async fn delete_key(&self, key_id: &str) -> DomainResult<()>;
}

/// Port for zero-knowledge proof verification.
#[async_trait]
pub trait ZKProofPort: Send + Sync {
    /// Verify a zero-knowledge proof of key ownership.
    async fn verify_proof(&self, proof: &ZKProof) -> DomainResult<bool>;

    /// Generate a challenge for ZKP.
    async fn generate_challenge(&self, key_id: &str) -> DomainResult<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_key_pair_new_sets_defaults() {
        let key = E2EKeyPair::new("user-1", "-----BEGIN PGP PUBLIC KEY BLOCK-----...", "encrypted-blob");
        assert_eq!(key.user_id, "user-1");
        assert_eq!(key.kdf_algorithm, "argon2id");
        assert!(key.is_primary);
        assert!(key.e2e_enabled.timestamp() > 0);
        assert!(key.recovery_key_hash.is_none());
    }

    #[test]
    fn recovery_key_record_new_sets_defaults() {
        let rec = RecoveryKeyRecord::new("user-1", "sha256-hash");
        assert_eq!(rec.user_id, "user-1");
        assert_eq!(rec.recovery_hash, "sha256-hash");
        assert!(!rec.used);
        assert!(rec.used_at.is_none());
    }

    #[test]
    fn e2e_key_pair_roundtrip() {
        let key = E2EKeyPair {
            id: "key-1".to_string(),
            user_id: "user-1".to_string(),
            public_key: "public-key-data".to_string(),
            encrypted_private_key: "encrypted-blob".to_string(),
            kdf_algorithm: "argon2id".to_string(),
            kdf_params: r#"{"memory":65536}"#.to_string(),
            fingerprint: "ABCD1234".to_string(),
            is_primary: true,
            e2e_enabled: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            recovery_key_hash: Some("hash".to_string()),
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["userId"], "user-1");
        assert_eq!(json["kdfAlgorithm"], "argon2id");
        assert_eq!(json["fingerprint"], "ABCD1234");
        let parsed: E2EKeyPair = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.id, "key-1");
        assert_eq!(parsed.recovery_key_hash, Some("hash".to_string()));
    }

    #[test]
    fn zk_proof_roundtrip() {
        let proof = ZKProof {
            key_id: "key-1".to_string(),
            user_id: "user-1".to_string(),
            proof: "signature-data".to_string(),
            created_at: Utc::now(),
        };
        let json = serde_json::to_value(&proof).unwrap();
        let parsed: ZKProof = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.key_id, "key-1");
        assert_eq!(parsed.proof, "signature-data");
    }
}
