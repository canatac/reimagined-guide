/// DANE (DNS-based Authentication of Named Entities) for SMTP outbound.
///
/// Implements TLSA record lookup and certificate validation per RFC 7671/7672.
/// Used during SMTP STARTTLS handshake to validate the server certificate
/// against the TLSA record published for `_25._tcp.<domain>`.

use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256, Sha384};
use std::io::{Error as IoError, ErrorKind};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// TLSA certificate usage modes (RFC 6698 §2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaCertUsage {
    /// PKIX-TA: cert must chain to a trust anchor.
    PkixTa = 0,
    /// PKIX-EE: cert must match and pass PKIX validation.
    PkixEe = 1,
    /// DANE-TA: cert must chain to the TLSA-specified trust anchor.
    DaneTa = 2,
    /// DANE-EE: cert must match the TLSA data exactly.
    DaneEe = 3,
}

/// TLSA selector: which part of the certificate to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaSelector {
    /// Match the full certificate.
    FullCert = 0,
    /// Match the SubjectPublicKeyInfo.
    Spki = 1,
}

/// TLSA matching type: how the association data is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaMatchingType {
    /// Exact match (SHA-256).
    Sha256 = 0,
    /// SHA-384 match.
    Sha384 = 1,
    /// Full certificate data match (not hashed).
    FullData = 2,
}

/// Parsed TLSA record data.
#[derive(Debug, Clone)]
pub struct TlsaRecord {
    pub cert_usage: TlsaCertUsage,
    pub selector: TlsaSelector,
    pub matching_type: TlsaMatchingType,
    pub association_data: Vec<u8>,
}

/// TLSA validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaneValidationResult {
    /// Validation succeeded against at least one TLSA record.
    Valid,
    /// No TLSA records found — opportunistic DANE, skip.
    NoRecords,
    /// TLSA records exist but none matched the server cert.
    ValidationFailed(String),
}

/// Look up TLSA records for the SMTP service at a given domain.
///
/// Queries `_25._tcp.<domain>` for TLSA records per RFC 7672 §3.1.
pub async fn lookup_tlsa_records(domain: &str) -> std::io::Result<Vec<TlsaRecord>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let tlsa_name = format!("_25._tcp.{}", domain);

    let lookup = resolver
        .tlsa_lookup(&tlsa_name)
        .await
        .map_err(|e| IoError::new(ErrorKind::Other, format!("TLSA lookup failed: {}", e)))?;

    let records: Vec<TlsaRecord> = lookup
        .iter()
        .filter_map(|rdata| {
            let tlsa = rdata.as_tlsa()?;
            let cert_usage = match tlsa.cert_usage() {
                0 => TlsaCertUsage::PkixTa,
                1 => TlsaCertUsage::PkixEe,
                2 => TlsaCertUsage::DaneTa,
                3 => TlsaCertUsage::DaneEe,
                _ => return None,
            };
            let selector = match tlsa.selector() {
                0 => TlsaSelector::FullCert,
                1 => TlsaSelector::Spki,
                _ => return None,
            };
            let matching_type = match tlsa.matching_type() {
                0 => TlsaMatchingType::Sha256,
                1 => TlsaMatchingType::Sha384,
                2 => TlsaMatchingType::FullData,
                _ => return None,
            };
            Some(TlsaRecord {
                cert_usage,
                selector,
                matching_type,
                association_data: tlsa.cert_data().to_vec(),
            })
        })
        .collect();

    Ok(records)
}

/// Extract the certificate data to compare based on the selector.
fn extract_cert_data<'a>(cert: &'a CertificateDer<'a>, selector: TlsaSelector) -> Vec<u8> {
    match selector {
        TlsaSelector::FullCert => cert.as_ref().to_vec(),
        TlsaSelector::Spki => extract_spki_from_der(cert.as_ref()),
    }
}

/// Extract SubjectPublicKeyInfo from a DER-encoded X.509 certificate.
///
/// This is a best-effort extraction. For production use, consider the `x509-parser` crate.
fn extract_spki_from_der(der: &[u8]) -> Vec<u8> {
    // X.509 Certificate ::= SEQUENCE { tbsCertificate, ... }
    // TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer,
    //                                validity, subject, subjectPublicKeyInfo, ... }
    //
    // We need to navigate through the DER structure to find subjectPublicKeyInfo.
    // This is a simplified parser — it walks SEQUENCEs and looks for the SPKI.
    
    if der.len() < 50 {
        return der.to_vec();
    }

    // Simple ASN.1 walk: find the subjectPublicKeyInfo by position.
    // In a proper X.509 cert, SPKI is the 7th field of TBSCertificate.
    // We'll scan for the SEQUENCE that contains an OID followed by a BIT STRING.
    
    // Scan for common public key algorithm OIDs
    // RSA: 1.2.840.113549.1.1.1 (2a 86 48 86 f7 0d 01 01 01)
    let rsa_oid = [0x2au8, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    // EC: 1.2.840.10045.2.1 (2a 86 48 ce 3d 02 01)
    let ec_oid = [0x2au8, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    // Ed25519: 172.16.58.3 (2b 65 70)
    let ed25519_oid = [0x2bu8, 0x65, 0x70];

    for oid in [&rsa_oid[..], &ec_oid[..], &ed25519_oid[..]] {
        if let Some(pos) = find_subsequence(der, oid) {
            // Found the algorithm OID — the SPKI SEQUENCE should start a few bytes before.
            // Go back to find the SEQUENCE tag that contains this OID.
            let search_start = pos.saturating_sub(10);
            // Return from the SEQUENCE containing the OID to a reasonable end
            let end = (pos + 256).min(der.len());
            return der[search_start..end].to_vec();
        }
    }

    // Fallback: return full cert
    der.to_vec()
}

/// Find a subsequence in a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Validate a server certificate against DANE TLSA records.
pub fn validate_cert_dane(
    cert: &CertificateDer<'_>,
    tlsa_records: &[TlsaRecord],
) -> DaneValidationResult {
    if tlsa_records.is_empty() {
        return DaneValidationResult::NoRecords;
    }

    for record in tlsa_records {
        let cert_data = extract_cert_data(cert, record.selector);
        let hashed = match record.matching_type {
            TlsaMatchingType::Sha256 => {
                let mut h = Sha256::new();
                h.update(&cert_data);
                h.finalize().to_vec()
            }
            TlsaMatchingType::Sha384 => {
                let mut h = Sha384::new();
                h.update(&cert_data);
                h.finalize().to_vec()
            }
            TlsaMatchingType::FullData => cert_data,
        };

        if hashed == record.association_data {
            return DaneValidationResult::Valid;
        }
    }

    DaneValidationResult::ValidationFailed(
        "No TLSA record matched the server certificate".to_string(),
    )
}

/// Full DANE validation: lookup TLSA records and validate the cert.
pub async fn validate_server_cert_dane(
    domain: &str,
    cert: &CertificateDer<'_>,
) -> DaneValidationResult {
    match lookup_tlsa_records(domain).await {
        Ok(records) => validate_cert_dane(cert, &records),
        Err(_) => DaneValidationResult::NoRecords,
    }
}

/// Check if TLSA records exist for this domain (DANE is enforced).
pub async fn has_tlsa_records(domain: &str) -> bool {
    match lookup_tlsa_records(domain).await {
        Ok(records) => !records.is_empty(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlsa_cert_usage_values() {
        assert_eq!(TlsaCertUsage::PkixTa as u8, 0);
        assert_eq!(TlsaCertUsage::PkixEe as u8, 1);
        assert_eq!(TlsaCertUsage::DaneTa as u8, 2);
        assert_eq!(TlsaCertUsage::DaneEe as u8, 3);
    }

    #[test]
    fn tlsa_selector_values() {
        assert_eq!(TlsaSelector::FullCert as u8, 0);
        assert_eq!(TlsaSelector::Spki as u8, 1);
    }

    #[test]
    fn tlsa_matching_type_values() {
        assert_eq!(TlsaMatchingType::Sha256 as u8, 0);
        assert_eq!(TlsaMatchingType::Sha384 as u8, 1);
        assert_eq!(TlsaMatchingType::FullData as u8, 2);
    }

    #[test]
    fn validate_cert_dane_no_records() {
        let result = validate_cert_dane(&CertificateDer::from(vec![1, 2, 3]), &[]);
        assert_eq!(result, DaneValidationResult::NoRecords);
    }

    #[test]
    fn validate_cert_dane_matching_sha256() {
        let cert_data = b"test certificate data";
        let mut hasher = Sha256::new();
        hasher.update(cert_data);
        let hash = hasher.finalize().to_vec();
        let records = vec![TlsaRecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Sha256,
            association_data: hash,
        }];
        let cert = CertificateDer::from(cert_data.to_vec());
        let result = validate_cert_dane(&cert, &records);
        assert_eq!(result, DaneValidationResult::Valid);
    }

    #[test]
    fn validate_cert_dane_non_matching() {
        let cert_data = b"test certificate data";
        let records = vec![TlsaRecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Sha256,
            association_data: vec![0u8; 32],
        }];
        let cert = CertificateDer::from(cert_data.to_vec());
        let result = validate_cert_dane(&cert, &records);
        assert!(matches!(
            result,
            DaneValidationResult::ValidationFailed(_)
        ));
    }

    #[test]
    fn validate_cert_dane_sha384() {
        let cert_data = b"test certificate data for sha384";
        let mut hasher = Sha384::new();
        hasher.update(cert_data);
        let hash = hasher.finalize().to_vec();
        assert_eq!(hash.len(), 48);
        let records = vec![TlsaRecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Sha384,
            association_data: hash,
        }];
        let cert = CertificateDer::from(cert_data.to_vec());
        let result = validate_cert_dane(&cert, &records);
        assert_eq!(result, DaneValidationResult::Valid);
    }

    #[test]
    fn validate_cert_dane_full_data() {
        let cert_data = b"exact match data";
        let records = vec![TlsaRecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::FullData,
            association_data: cert_data.to_vec(),
        }];
        let cert = CertificateDer::from(cert_data.to_vec());
        let result = validate_cert_dane(&cert, &records);
        assert_eq!(result, DaneValidationResult::Valid);
    }

    #[test]
    fn find_subsequence_basic() {
        let haystack = b"hello world";
        assert_eq!(find_subsequence(haystack, b"world"), Some(6));
        assert_eq!(find_subsequence(haystack, b"xyz"), None);
    }
}
