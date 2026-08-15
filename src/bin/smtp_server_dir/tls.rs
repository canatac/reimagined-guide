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
    Ok(private_key(&mut BufReader::new(File::open(path)?))
        .unwrap()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no private key found".to_string(),
        ))?)
}

// Check user credentials
pub(crate) fn check_credentials(username: &[u8], password: &[u8]) -> bool {
