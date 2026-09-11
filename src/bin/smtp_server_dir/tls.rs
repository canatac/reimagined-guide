//! Chargement des certificats/clés TLS pour le serveur SMTP.
//! Extrait de smtp_server.rs (refactor architecte).

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use rustls_pemfile::{certs, private_key};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub(crate) fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

// Load SSL private key
pub(crate) fn load_key(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = private_key(&mut BufReader::new(File::open(path)?))?.ok_or_else(|| {
        std::io::Error::other("no private key found")
    })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_certs_missing_file_returns_err() {
        let result = load_certs(Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn load_key_missing_file_returns_err() {
        let result = load_key(Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn load_certs_invalid_content_returns_err() {
        let dir = std::env::temp_dir();
        let path = dir.join("invalid_cert.pem");
        std::fs::write(&path, "not a valid cert").unwrap();
        let result = load_certs(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_key_invalid_content_returns_err() {
        let dir = std::env::temp_dir();
        let path = dir.join("invalid_key.pem");
        std::fs::write(&path, "not a valid key").unwrap();
        let result = load_key(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }
}
