//! TLS-RPT DNS record discovery (RFC 8460 § 4.1)
//!
//! Discovers TLS-RPT policies via DNS TXT lookup at `_smtp._tls.<domain>`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// TLS-RPT DNS record content (parsed from TXT record)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TlsRptDnsRecord {
    /// The domain this record applies to
    pub domain: String,
    /// Raw TXT record content (e.g., "v=TLSRPTv1; rua=mailto:reports@example.com")
    pub raw: String,
    /// Parsed key-value pairs
    pub params: HashMap<String, String>,
    /// Whether the record is valid (starts with "v=TLSRPTv1")
    pub valid: bool,
    /// Reporting URIs from the 'rua' field
    pub reporting_uris: Vec<String>,
}

/// Parse a TLS-RPT DNS TXT record
pub fn parse_txt_record(domain: &str, txt: &str) -> TlsRptDnsRecord {
    let raw = txt.trim().to_string();
    let valid = raw.starts_with("v=TLSRPTv1");

    let mut params = HashMap::new();
    let mut reporting_uris = Vec::new();

    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            if key == "rua" {
                reporting_uris.push(value.clone());
            }
            params.insert(key, value);
        }
    }

    TlsRptDnsRecord {
        domain: domain.to_string(),
        raw,
        params,
        valid,
        reporting_uris,
    }
}

/// Simulate DNS TXT lookup for `_smtp._tls.<domain>`
/// In production, this would use a DNS resolver (e.g., trust-dns)
pub fn lookup_tls_rpt_record(domain: &str) -> Option<TlsRptDnsRecord> {
    // Check environment variable for simulated records (testing/staging)
    let env_key = format!("TLS_RPT_DOMAIN_{}", domain.replace('.', "_").to_uppercase());
    if let Ok(txt) = std::env::var(&env_key) {
        return Some(parse_txt_record(domain, &txt));
    }

    // In production: perform actual DNS TXT lookup at `_smtp._tls.<domain>`
    // For now, return None to indicate no record found
    None
}

/// Generate the DNS lookup domain for TLS-RPT
pub fn tls_rpt_dns_domain(domain: &str) -> String {
    format!("_smtp._tls.{}", domain)
}

/// Validate a TLS-RPT DNS record
pub fn validate_record(record: &TlsRptDnsRecord) -> Result<(), String> {
    if !record.valid {
        return Err(format!(
            "Invalid TLS-RPT record for {}: missing 'v=TLSRPTv1' version",
            record.domain
        ));
    }

    if record.reporting_uris.is_empty() {
        return Err(format!(
            "TLS-RPT record for {} has no reporting URIs (rua field missing)",
            record.domain
        ));
    }

    Ok(())
}

/// Extract the list of domains that have TLS-RPT records from a list of destination domains
pub fn discover_tls_rpt_domains(domains: &[String]) -> Vec<TlsRptDnsRecord> {
    domains
        .iter()
        .filter_map(|d| lookup_tls_rpt_record(d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_txt_record_valid() {
        let txt = "v=TLSRPTv1; rua=mailto:reports@example.com";
        let record = parse_txt_record("example.com", txt);

        assert_eq!(record.domain, "example.com");
        assert!(record.valid);
        assert_eq!(record.reporting_uris.len(), 1);
        assert_eq!(record.reporting_uris[0], "mailto:reports@example.com");
        assert_eq!(record.params.get("v"), Some(&"TLSRPTv1".to_string()));
        assert_eq!(
            record.params.get("rua"),
            Some(&"mailto:reports@example.com".to_string())
        );
    }

    #[test]
    fn parse_txt_record_multiple_rua() {
        let txt = "v=TLSRPTv1; rua=mailto:reports@example.com,https://example.com/rpt";
        let record = parse_txt_record("example.com", txt);

        assert!(record.valid);
        assert_eq!(record.reporting_uris.len(), 2);
        assert_eq!(record.reporting_uris[0], "mailto:reports@example.com");
        assert_eq!(record.reporting_uris[1], "https://example.com/rpt");
    }

    #[test]
    fn parse_txt_record_invalid_version() {
        let txt = "v=STSv1; mode=enforce";
        let record = parse_txt_record("example.com", txt);

        assert!(!record.valid);
        assert!(record.reporting_uris.is_empty());
    }

    #[test]
    fn parse_txt_record_empty() {
        let record = parse_txt_record("example.com", "");

        assert!(!record.valid);
        assert!(record.params.is_empty());
        assert!(record.reporting_uris.is_empty());
    }

    #[test]
    fn tls_rpt_dns_domain_format() {
        assert_eq!(tls_rpt_dns_domain("example.com"), "_smtp._tls.example.com");
        assert_eq!(
            tls_rpt_dns_domain("mail.example.org"),
            "_smtp._tls.mail.example.org"
        );
    }

    #[test]
    fn validate_record_valid() {
        let txt = "v=TLSRPTv1; rua=mailto:reports@example.com";
        let record = parse_txt_record("example.com", txt);
        assert!(validate_record(&record).is_ok());
    }

    #[test]
    fn validate_record_invalid_version() {
        let txt = "v=STSv1; mode=enforce";
        let record = parse_txt_record("example.com", txt);
        assert!(validate_record(&record).is_err());
    }

    #[test]
    fn validate_record_no_rua() {
        let txt = "v=TLSRPTv1";
        let record = parse_txt_record("example.com", txt);
        assert!(validate_record(&record).is_err());
    }

    #[test]
    fn lookup_from_env() {
        std::env::set_var("TLS_RPT_DOMAIN_EXAMPLE_COM", "v=TLSRPTv1; rua=mailto:r@example.com");
        let result = lookup_tls_rpt_record("example.com");
        assert!(result.is_some());
        let record = result.unwrap();
        assert!(record.valid);
        assert_eq!(record.domain, "example.com");
        std::env::remove_var("TLS_RPT_DOMAIN_EXAMPLE_COM");
    }

    #[test]
    fn lookup_no_record() {
        let result = lookup_tls_rpt_record("no-record-domain.example");
        assert!(result.is_none());
    }

    #[test]
    fn discover_tls_rpt_domains_filters_valid() {
        std::env::set_var("TLS_RPT_DOMAIN_GOOGLE_COM", "v=TLSRPTv1; rua=mailto:r@gmail.com");
        let domains = vec!["google.com".to_string(), "no-record.example".to_string()];
        let records = discover_tls_rpt_domains(&domains);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "google.com");
        std::env::remove_var("TLS_RPT_DOMAIN_GOOGLE_COM");
    }

    #[test]
    fn parse_txt_record_with_path() {
        let txt = "v=TLSRPTv1; rua=https://reports.example.com/v1/tls-rpt";
        let record = parse_txt_record("example.com", txt);
        assert!(record.valid);
        assert_eq!(record.reporting_uris.len(), 1);
        assert!(record.reporting_uris[0].starts_with("https://"));
    }
}
