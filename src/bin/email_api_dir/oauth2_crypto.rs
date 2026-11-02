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

// Domain-separation label for HKDF (not a secret).
const HKDF_INFO: &[u8] = b"oauth2-token-encryption-v1";

// Thread-local override used only by tests so we never mutate process-wide
// environment state (std::env::set_var is unsafe in Rust 2024).
thread_local! {
    static TEST_KEY: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

fn set_test_key(key: Vec<u8>) {
    TEST_KEY.with(|k| *k.borrow_mut() = Some(key));
}

fn clear_test_key() {
    TEST_KEY.with(|k| *k.borrow_mut() = None);
}

/// Derive a 256-bit key from the environment variable via HKDF-SHA256.
/// The env var must contain a base64-encoded value (any length >= 16 bytes recommended).
/// Returns None if the env var is not set - callers must handle the missing-key case.
fn get_encryption_key() -> Option<[u8; KEY_LEN]> {
    // Test override takes precedence.
    let ikm: Vec<u8> = TEST_KEY.with(|k| k.borrow().clone()).unwrap_or_else(|| {
        let key_str = std::env::var("OAUTH_ENCRYPTION_KEY").ok()?;
        STANDARD.decode(&key_str).unwrap_or_else(|_| key_str.as_bytes().to_vec())
    });

    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF expand for 32 bytes cannot fail");
    Some(okm)
}

/// Encrypt a plaintext string, returns base64(nonce || ciphertext)
pub fn encrypt_token(plaintext: &str) -> Result<String, String> {
    let key = get_encryption_key().ok_or_else(|| "OAUTH_ENCRYPTION_KEY not set".to_string())?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("key init failed: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {}", e))?;

    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(STANDARD.encode(&combined))
}

/// Decrypt a base64(nonce || ciphertext) string back to plaintext
pub fn decrypt_token(encrypted_b64: &str) -> Result<String, String> {
    let key = get_encryption_key().ok_or_else(|| "OAUTH_ENCRYPTION_KEY not set".to_string())?;
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

/// Rotate key: decrypt with old key, encrypt with new key.
/// Takes explicit key material instead of mutating env vars.
pub fn reencrypt_token(encrypted_b64: &str, old_key: &str, new_key: &str) -> Result<String, String> {
    let old_ikm = STANDARD.decode(old_key).unwrap_or_else(|_| old_key.as_bytes().to_vec());
    let new_ikm = STANDARD.decode(new_key).unwrap_or_else(|_| new_key.as_bytes().to_vec());

    let plaintext = decrypt_with_ikm(encrypted_b64, &old_ikm)?;
    encrypt_with_ikm(&plaintext, &new_ikm)
}

fn encrypt_with_ikm(plaintext: &str, ikm: &[u8]) -> Result<String, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut key)
        .expect("HKDF expand for 32 bytes cannot fail");

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("key init failed: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {}", e))?;

    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(&combined))
}

fn decrypt_with_ikm(encrypted_b64: &str, ikm: &[u8]) -> Result<String, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut key)
        .expect("HKDF expand for 32 bytes cannot fail");

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a random base64-encoded key for tests - avoids hardcoded crypto values (CodeQL).
    fn random_test_key() -> Vec<u8> {
        let mut buf = [0u8; 32];
        aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut buf);
        buf.to_vec()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        set_test_key(random_test_key());
        let original = "test-access-token-value";
        let encrypted = encrypt_token(original).expect("encrypt");
        assert_ne!(encrypted, original);

        let decrypted = decrypt_token(&encrypted).expect("decrypt");
        assert_eq!(decrypted, original);
        clear_test_key();
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        set_test_key(random_test_key());
        let token = "same-token-value";
        let enc1 = encrypt_token(token).expect("encrypt1");
        let enc2 = encrypt_token(token).expect("encrypt2");
        assert_ne!(enc1, enc2);
        assert_eq!(decrypt_token(&enc1).unwrap(), token);
        assert_eq!(decrypt_token(&enc2).unwrap(), token);
        clear_test_key();
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        set_test_key(random_test_key());
        let result = decrypt_token("!!!invalid-base64!!!");
        assert!(result.is_err());
        clear_test_key();
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        set_test_key(random_test_key());
        let original = "tampered-token-test";
        let encrypted = encrypt_token(original).expect("encrypt");

        let mut bytes = STANDARD.decode(&encrypted).unwrap();
        if bytes.len() > NONCE_LEN + 2 {
            bytes[NONCE_LEN + 2] ^= 0xFF;
        }
        let tampered = STANDARD.encode(&bytes);

        let result = decrypt_token(&tampered);
        assert!(result.is_err(), "tampered ciphertext should fail");
        clear_test_key();
    }

    #[test]
    fn test_key_from_arbitrary_string() {
        // Non-base64 input exercises the raw-bytes fallback path.
        let random_input = STANDARD.encode(random_test_key());
        let non_standard = format!("!{}", &random_input[1..]);
        let ikm = STANDARD.decode(&non_standard).unwrap_or_else(|_| non_standard.as_bytes().to_vec());
        let token = "test-token-123";
        let encrypted = encrypt_with_ikm(token, &ikm).expect("encrypt");
        let decrypted = decrypt_with_ikm(&encrypted, &ikm).expect("decrypt");
        assert_eq!(decrypted, token);
    }

    #[test]
    fn test_reencrypt_roundtrip() {
        let old_key = STANDARD.encode(random_test_key());
        let new_key = STANDARD.encode(random_test_key());
        let token = "reencrypt-token-value";

        let old_ikm = STANDARD.decode(&old_key).unwrap();
        let encrypted = encrypt_with_ikm(token, &old_ikm).expect("encrypt");
        let reencrypted = reencrypt_token(&encrypted, &old_key, &new_key).expect("reencrypt");

        let new_ikm = STANDARD.decode(&new_key).unwrap();
        let decrypted = decrypt_with_ikm(&reencrypted, &new_ikm).expect("decrypt");
        assert_eq!(decrypted, token);
    }
}
