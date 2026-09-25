// AES-256-GCM encryption for OAuth2 tokens at rest.
// Uses a 256-bit key derived from the OAUTH_ENCRYPTION_KEY env var.
// Format: base64(nonce || ciphertext || tag)

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};

const KEY_LEN: usize = 32; // 256 bits
const NONCE_LEN: usize = 12; // 96 bits for GCM

/// Derive a 256-bit key from the environment variable.
/// The env var must contain a base64-encoded 32-byte key.
/// Panics if not set — no hardcoded fallback (CodeQL: rust/hard-coded-cryptographic-value).
fn get_encryption_key() -> [u8; KEY_LEN] {
    let key_str = std::env::var("OAUTH_ENCRYPTION_KEY")
        .expect("OAUTH_ENCRYPTION_KEY env var must be set (base64-encoded 32-byte key)");

    let decoded = STANDARD.decode(&key_str).unwrap_or_else(|_| {
        // If not valid base64, hash the string to get 32 bytes
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key_str.as_bytes());
        hasher.finalize().to_vec()
    });

    let mut key = [0u8; KEY_LEN];
    let len = decoded.len().min(KEY_LEN);
    key[..len].copy_from_slice(&decoded[..len]);
    key
}

/// Encrypt a plaintext string, returns base64(nonce || ciphertext)
pub fn encrypt_token(plaintext: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("key init failed: {}", e))?;

    let nonce_bytes = aes_gcm::aead::rand_core::RngCore::generate::<[u8; NONCE_LEN]>(&mut OsRng);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {}", e))?;

    // Concatenate nonce + ciphertext
    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(STANDARD.encode(&combined))
}

/// Decrypt a base64(nonce || ciphertext) string back to plaintext
pub fn decrypt_token(encrypted_b64: &str) -> Result<String, String> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("key init failed: {}", e))?;

    let combined = STANDARD
        .decode(encrypted_b64)
        .map_err(|e| format!("base64 decode failed: {}", e))?;

    if combined.len() < NONCE_LEN {
        return Err("ciphertext too short".to_string());
    }

    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {}", e))
}

/// Rotate key: decrypt with old key, encrypt with new key
pub fn reencrypt_token(encrypted_b64: &str, old_key: &str, new_key: &str) -> Result<String, String> {
    // Temporarily override the key for decryption
    std::env::set_var("OAUTH_ENCRYPTION_KEY", old_key);
    let plaintext = decrypt_token(encrypted_b64)?;

    std::env::set_var("OAUTH_ENCRYPTION_KEY", new_key);
    encrypt_token(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a random 32-byte key for tests (avoids hardcoded cryptographic values).
    fn set_random_test_key() {
        let random_key: [u8; KEY_LEN] = aes_gcm::aead::rand_core::RngCore::generate::<[u8; KEY_LEN]>(&mut OsRng);
        let encoded = STANDARD.encode(&random_key);
        std::env::set_var("OAUTH_ENCRYPTION_KEY", &encoded);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        set_random_test_key();
        let original = "ya29.a0test-access-token-value";
        let encrypted = encrypt_token(original).expect("encrypt");
        assert_ne!(encrypted, original);

        let decrypted = decrypt_token(&encrypted).expect("decrypt");
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        set_random_test_key();
        let token = "same-token-value";
        let enc1 = encrypt_token(token).expect("encrypt1");
        let enc2 = encrypt_token(token).expect("encrypt2");
        // Different nonce => different ciphertext
        assert_ne!(enc1, enc2);
        // But both decrypt to the same value
        assert_eq!(decrypt_token(&enc1).unwrap(), token);
        assert_eq!(decrypt_token(&enc2).unwrap(), token);
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        set_random_test_key();
        let result = decrypt_token("!!!invalid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        set_random_test_key();
        let original = "secret-token";
        let encrypted = encrypt_token(original).expect("encrypt");

        // Tamper with the ciphertext
        let mut bytes = STANDARD.decode(&encrypted).unwrap();
        if bytes.len() > NONCE_LEN + 2 {
            bytes[NONCE_LEN + 2] ^= 0xFF; // flip bits in ciphertext
        }
        let tampered = STANDARD.encode(&bytes);

        let result = decrypt_token(&tampered);
        assert!(result.is_err(), "tampered ciphertext should fail");
    }

    #[test]
    fn test_key_from_arbitrary_string() {
        // Key that's not valid base64 — should be hashed
        std::env::set_var("OAUTH_ENCRYPTION_KEY", "my-secret-passphrase-test");
        let token = "test-token-123";
        let encrypted = encrypt_token(token).expect("encrypt");
        let decrypted = decrypt_token(&encrypted).expect("decrypt");
        assert_eq!(decrypted, token);
    }
}
