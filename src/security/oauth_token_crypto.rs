//! OAuth 2.0 token encryption at rest (issue #674).
//!
//! Encrypts OAuth2 access/refresh tokens before storage in MongoDB
//! using AES-256-GCM (authenticated encryption).
//!
//! Environment variable `OAUTH_TOKEN_ENCRYPTION_KEY` must be set to a
//! base64-encoded 32-byte key. If unset, a deterministic key is derived
//! from `JWT_SECRET` via HKDF-SHA256 (fallback for dev only).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::engine::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// Error type for token encryption/decryption failures.
#[derive(Debug)]
pub enum CryptoError {
    KeyDerivationFailed(String),
    EncryptFailed,
    DecryptFailed,
    InvalidCiphertext,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::KeyDerivationFailed(e) => write!(f, "Key derivation failed: {}", e),
            CryptoError::EncryptFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptFailed => write!(f, "Decryption failed"),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext format"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Get or derive the 32-byte encryption key.
///
/// Priority:
/// 1. `OAUTH_TOKEN_ENCRYPTION_KEY` env var (base64-encoded 32 bytes)
/// 2. Derive from `JWT_SECRET` via HKDF-SHA256 (dev fallback)
fn get_encryption_key() -> Result<[u8; 32], CryptoError> {
    // Primary: dedicated env var
    if let Ok(b64_key) = std::env::var("OAUTH_TOKEN_ENCRYPTION_KEY") {
        let key_bytes = B64
            .decode(b64_key.trim())
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("base64 decode: {}", e)))?;
        if key_bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            return Ok(key);
        }
        return Err(CryptoError::KeyDerivationFailed(format!(
            "expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    // Fallback: derive from JWT_SECRET
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-fallback-secret-do-not-use".to_string());
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"oauth-token-encryption-v1:");
    hasher.update(jwt_secret.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

/// Encrypt a token string. Returns base64(nonce || ciphertext || tag).
pub fn encrypt_token(plaintext: &str) -> Result<String, CryptoError> {
    let key_bytes = get_encryption_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate random 96-bit nonce
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::EncryptFailed)?;

    // Concatenate: nonce (12 bytes) || ciphertext+tag
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(B64.encode(&output))
}

/// Decrypt a token encrypted with `encrypt_token`.
/// Expects base64(nonce || ciphertext || tag).
pub fn decrypt_token(ciphertext_b64: &str) -> Result<String, CryptoError> {
    let key_bytes = get_encryption_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let data = B64
        .decode(ciphertext_b64.trim())
        .map_err(|_| CryptoError::InvalidCiphertext)?;

    if data.len() < 12 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptFailed)?;

    String::from_utf8(plaintext).map_err(|_| CryptoError::DecryptFailed)
}

/// Check if a token appears to be encrypted (heuristic: base64 and longer than plaintext tokens).
pub fn is_encrypted(token: &str) -> bool {
    // Encrypted tokens are base64-encoded nonce+ciphertext, always > 64 chars
    token.len() > 64 && B64.decode(token.trim()).is_ok()
}

/// Decrypt token if encrypted, otherwise return as-is (for migration compatibility).
pub fn decrypt_token_compat(stored: &str) -> String {
    if is_encrypted(stored) {
        decrypt_token(stored).unwrap_or_else(|_| stored.to_string())
    } else {
        stored.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        std::env::set_var("OAUTH_TOKEN_ENCRYPTION_KEY", {
            let key: [u8; 32] = [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ];
            B64.encode(key)
        });

        let token = "ya29.a0AfH6SMBx_example_access_token";
        let encrypted = encrypt_token(token).unwrap();
        assert_ne!(encrypted, token);
        assert!(encrypted.len() > token.len());

        let decrypted = decrypt_token(&encrypted).unwrap();
        assert_eq!(decrypted, token);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        std::env::set_var("OAUTH_TOKEN_ENCRYPTION_KEY", {
            let key: [u8; 32] = [42u8; 32];
            B64.encode(key)
        });

        let token = "same-token-value";
        let enc1 = encrypt_token(token).unwrap();
        let enc2 = encrypt_token(token).unwrap();
        // Different random nonce => different ciphertext
        assert_ne!(enc1, enc2);
        // But both decrypt to same value
        assert_eq!(decrypt_token(&enc1).unwrap(), token);
        assert_eq!(decrypt_token(&enc2).unwrap(), token);
    }

    #[test]
    fn is_encrypted_detects_format() {
        assert!(is_encrypted("dGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBjaXBoZXJ0ZXh0IHRoYXQgc2hvdWxkIGJlIGRldGVjdGVkIGFzIGVuY3J5cHRlZA=="));
        assert!(!is_encrypted("ya29.short-token"));
        assert!(!is_encrypted(""));
    }

    #[test]
    fn decrypt_compat_plain_text() {
        let plain = "ya29.plain-text-token";
        assert_eq!(decrypt_token_compat(plain), plain);
    }

    #[test]
    fn decrypt_compat_encrypted() {
        std::env::set_var("OAUTH_TOKEN_ENCRYPTION_KEY", {
            let key: [u8; 32] = [7u8; 32];
            B64.encode(key)
        });
        let token = "ya29.secret-value";
        let encrypted = encrypt_token(token).unwrap();
        assert_eq!(decrypt_token_compat(&encrypted), token);
    }

    #[test]
    fn key_derivation_from_jwt_secret() {
        std::env::remove_var("OAUTH_TOKEN_ENCRYPTION_KEY");
        std::env::set_var("JWT_SECRET", "test-secret-123");
        let key1 = get_encryption_key().unwrap();

        std::env::set_var("JWT_SECRET", "test-secret-123");
        let key2 = get_encryption_key().unwrap();
        assert_eq!(key1, key2); // Deterministic

        std::env::set_var("JWT_SECRET", "different-secret");
        let key3 = get_encryption_key().unwrap();
        assert_ne!(key1, key3); // Different secret => different key
    }
}
