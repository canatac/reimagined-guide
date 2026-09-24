//! TLS connection logging for outbound SMTP
//!
//! Tracks TLS handshake success/failure per destination domain
//! for TLS-RPT report generation (RFC 8460).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Result of a TLS connection attempt
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsConnectionResult {
    Success,
    Failed,
    NotAttempted,
}

/// Failure types per RFC 8460 § 4.3.2
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsFailureReason {
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
    CertificateRevoked,
    TlsNegotiationFailure,
    ConnectionTimeout,
    ConnectionRefused,
    StarttlsNotSupported,
    TlsaInvalid,
    DnssecInvalid,
    stsPolicyInvalid,
    StsWebpkiInvalid,
    DaneRequired,
    Unknown(String),
}

impl std::fmt::Display for TlsFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsFailureReason::CertificateExpired => write!(f, "certificate-expired"),
            TlsFailureReason::CertificateHostnameMismatch => write!(f, "certificate-hostname-mismatch"),
            TlsFailureReason::CertificateUntrusted => write!(f, "certificate-untrusted"),
            TlsFailureReason::CertificateRevoked => write!(f, "certificate-revoked"),
            TlsFailureReason::TlsNegotiationFailure => write!(f, "tls-negotiation-failure"),
            TlsFailureReason::ConnectionTimeout => write!(f, "connection-timeout"),
            TlsFailureReason::ConnectionRefused => write!(f, "connection-refused"),
            TlsFailureReason::StarttlsNotSupported => write!(f, "starttls-not-supported"),
            TlsFailureReason::TlsaInvalid => write!(f, "tlsa-invalid"),
            TlsFailureReason::DnssecInvalid => write!(f, "dnssec-invalid"),
            TlsFailureReason::stsPolicyInvalid => write!(f, "sts-policy-invalid"),
            TlsFailureReason::StsWebpkiInvalid => write!(f, "sts-webpki-invalid"),
            TlsFailureReason::DaneRequired => write!(f, "dane-required"),
            TlsFailureReason::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// A single TLS connection attempt record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConnectionRecord {
    pub timestamp: String,
    pub destination_domain: String,
    pub mx_host: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: u16,
    pub result: TlsConnectionResult,
    pub failure_reason: Option<TlsFailureReason>,
    pub certificate_subject: Option<String>,
    pub certificate_issuer: Option<String>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
}

impl TlsConnectionRecord {
    pub fn new(destination_domain: &str, result: TlsConnectionResult) -> Self {
        TlsConnectionRecord {
            timestamp: Utc::now().to_rfc3339(),
            destination_domain: destination_domain.to_string(),
            mx_host: None,
            remote_ip: None,
            remote_port: 25,
            result,
            failure_reason: None,
            certificate_subject: None,
            certificate_issuer: None,
            tls_version: None,
            cipher_suite: None,
        }
    }

    pub fn with_failure_reason(mut self, reason: TlsFailureReason) -> Self {
        self.failure_reason = Some(reason);
        self
    }

    pub fn with_remote(mut self, ip: &str, port: u16) -> Self {
        self.remote_ip = Some(ip.to_string());
        self.remote_port = port;
        self
    }

    pub fn with_mx(mut self, mx: &str) -> Self {
        self.mx_host = Some(mx.to_string());
        self
    }

    pub fn with_certificate(mut self, subject: &str, issuer: &str) -> Self {
        self.certificate_subject = Some(subject.to_string());
        self.certificate_issuer = Some(issuer.to_string());
        self
    }

    pub fn with_tls_info(mut self, version: &str, cipher: &str) -> Self {
        self.tls_version = Some(version.to_string());
        self.cipher_suite = Some(cipher.to_string());
        self
    }
}

/// Aggregated TLS connection stats per domain
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsDomainStats {
    pub domain: String,
    pub total_attempts: u64,
    pub total_success: u64,
    pub total_failure: u64,
    pub failure_reasons: HashMap<String, u64>,
    pub last_attempt: Option<String>,
    pub last_failure: Option<String>,
}

impl TlsDomainStats {
    pub fn failure_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            0.0
        } else {
            (self.total_failure as f64 / self.total_attempts as f64) * 100.0
        }
    }

    pub fn record(&mut self, record: &TlsConnectionRecord) {
        self.domain = record.destination_domain.clone();
        self.total_attempts += 1;
        self.last_attempt = Some(record.timestamp.clone());

        match &record.result {
            TlsConnectionResult::Success => {
                self.total_success += 1;
            }
            TlsConnectionResult::Failed => {
                self.total_failure += 1;
                self.last_failure = Some(record.timestamp.clone());
                if let Some(reason) = &record.failure_reason {
                    let key = reason.to_string();
                    *self.failure_reasons.entry(key).or_insert(0) += 1;
                }
            }
            TlsConnectionResult::NotAttempted => {}
        }
    }
}

/// Global TLS connection log (in-memory, ring-buffer style)
/// In production, this would persist to MongoDB
static TLS_CONNECTION_LOG: Mutex<Option<Vec<TlsConnectionRecord>>> = Mutex::new(None);

/// Initialize the TLS connection log
pub fn init_tls_log() {
    let mut log = TLS_CONNECTION_LOG.lock().unwrap();
    if log.is_none() {
        *log = Some(Vec::with_capacity(10_000));
    }
}

/// Record a TLS connection attempt
pub fn log_tls_connection(record: TlsConnectionRecord) {
    let mut guard = TLS_CONNECTION_LOG.lock().unwrap();
    if let Some(ref mut log) = *guard {
        log.push(record);
        // Keep max 100k records in memory
        if log.len() > 100_000 {
            let excess = log.len() - 100_000;
            log.drain(0..excess);
        }
    }
}

/// Get all TLS connection records for a domain within a time range
pub fn get_tls_records(domain: &str, since: Option<&str>) -> Vec<TlsConnectionRecord> {
    let guard = TLS_CONNECTION_LOG.lock().unwrap();
    let Some(ref log) = *guard else {
        return Vec::new();
    };

    log.iter()
        .filter(|r| {
            r.destination_domain == domain
                && since.map(|s| r.timestamp.as_str() >= s).unwrap_or(true)
        })
        .cloned()
        .collect()
}

/// Get aggregated stats per domain
pub fn get_domain_stats(domains: Option<&[String]>) -> Vec<TlsDomainStats> {
    let guard = TLS_CONNECTION_LOG.lock().unwrap();
    let Some(ref log) = *guard else {
        return Vec::new();
    };

    let mut stats_map: HashMap<String, TlsDomainStats> = HashMap::new();

    for record in log.iter() {
        if let Some(ref filter) = domains {
            if !filter.contains(&record.destination_domain) {
                continue;
            }
        }

        let entry = stats_map
            .entry(record.destination_domain.clone())
            .or_insert_with(|| TlsDomainStats {
                domain: record.destination_domain.clone(),
                ..Default::default()
            });
        entry.record(record);
    }

    stats_map.into_values().collect()
}

/// Classify an error into a TLS failure reason
pub fn classify_failure(error: &str) -> TlsFailureReason {
    let lower = error.to_lowercase();
    if lower.contains("expired") || lower.contains("not_after") {
        TlsFailureReason::CertificateExpired
    } else if lower.contains("hostname") || lower.contains("cn mismatch") || lower.contains("sni") {
        TlsFailureReason::CertificateHostnameMismatch
    } else if lower.contains("untrusted") || lower.contains("root ca") || lower.contains("chain") {
        TlsFailureReason::CertificateUntrusted
    } else if lower.contains("revoked") || lower.contains("crl") {
        TlsFailureReason::CertificateRevoked
    } else if lower.contains("timeout") || lower.contains("timed out") {
        TlsFailureReason::ConnectionTimeout
    } else if lower.contains("refused") || lower.contains("reset") {
        TlsFailureReason::ConnectionRefused
    } else if lower.contains("starttls") || lower.contains("not supported") {
        TlsFailureReason::StarttlsNotSupported
    } else if lower.contains("tls negotiation") || lower.contains("handshake") {
        TlsFailureReason::TlsNegotiationFailure
    } else {
        TlsFailureReason::Unknown(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_connection_record_success() {
        let record = TlsConnectionRecord::new("example.com", TlsConnectionResult::Success);
        assert_eq!(record.destination_domain, "example.com");
        assert_eq!(record.result, TlsConnectionResult::Success);
        assert!(record.failure_reason.is_none());
        assert_eq!(record.remote_port, 25);
    }

    #[test]
    fn tls_connection_record_failure() {
        let record = TlsConnectionRecord::new("example.com", TlsConnectionResult::Failed)
            .with_failure_reason(TlsFailureReason::CertificateExpired)
            .with_remote("192.0.2.1", 587)
            .with_mx("mx.example.com");

        assert_eq!(record.result, TlsConnectionResult::Failed);
        assert_eq!(
            record.failure_reason,
            Some(TlsFailureReason::CertificateExpired)
        );
        assert_eq!(record.remote_ip, Some("192.0.2.1".to_string()));
        assert_eq!(record.remote_port, 587);
        assert_eq!(record.mx_host, Some("mx.example.com".to_string()));
    }

    #[test]
    fn tls_domain_stats_aggregation() {
        let mut stats = TlsDomainStats {
            domain: "example.com".to_string(),
            ..Default::default()
        };

        let success = TlsConnectionRecord::new("example.com", TlsConnectionResult::Success);
        let failure = TlsConnectionRecord::new("example.com", TlsConnectionResult::Failed)
            .with_failure_reason(TlsFailureReason::CertificateExpired);

        stats.record(&success);
        stats.record(&success);
        stats.record(&failure);

        assert_eq!(stats.total_attempts, 3);
        assert_eq!(stats.total_success, 2);
        assert_eq!(stats.total_failure, 1);
        assert!((stats.failure_rate() - 33.33).abs() < 0.01);
        assert_eq!(
            stats.failure_reasons.get("certificate-expired"),
            Some(&1)
        );
    }

    #[test]
    fn classify_failure_expired() {
        assert_eq!(
            classify_failure("certificate expired: not_after=2024-01-01"),
            TlsFailureReason::CertificateExpired
        );
    }

    #[test]
    fn classify_failure_hostname() {
        assert_eq!(
            classify_failure("hostname mismatch: expected mx.example.com"),
            TlsFailureReason::CertificateHostnameMismatch
        );
    }

    #[test]
    fn classify_failure_timeout() {
        assert_eq!(
            classify_failure("connection timed out"),
            TlsFailureReason::ConnectionTimeout
        );
    }

    #[test]
    fn classify_failure_unknown() {
        let result = classify_failure("something weird happened");
        assert!(matches!(result, TlsFailureReason::Unknown(_)));
    }

    #[test]
    fn log_and_retrieve() {
        init_tls_log();
        let record = TlsConnectionRecord::new("test.example", TlsConnectionResult::Success);
        log_tls_connection(record.clone());

        let records = get_tls_records("test.example", None);
        assert!(!records.is_empty());
        assert_eq!(records[0].destination_domain, "test.example");
    }

    #[test]
    fn get_domain_stats_aggregates() {
        init_tls_log();
        let record = TlsConnectionRecord::new("stats.test", TlsConnectionResult::Failed)
            .with_failure_reason(TlsFailureReason::ConnectionRefused);
        log_tls_connection(record);

        let stats = get_domain_stats(Some(&["stats.test".to_string()]));
        assert!(!stats.is_empty());
        let s = &stats[0];
        assert_eq!(s.domain, "stats.test");
        assert!(s.total_failure >= 1);
    }

    #[test]
    fn failure_rate_zero_when_no_attempts() {
        let stats = TlsDomainStats::default();
        assert_eq!(stats.failure_rate(), 0.0);
    }

    #[test]
    fn tls_failure_reason_display() {
        assert_eq!(
            TlsFailureReason::CertificateExpired.to_string(),
            "certificate-expired"
        );
        assert_eq!(
            TlsFailureReason::StarttlsNotSupported.to_string(),
            "starttls-not-supported"
        );
    }

    #[test]
    fn connection_record_with_tls_info() {
        let record = TlsConnectionRecord::new("example.com", TlsConnectionResult::Success)
            .with_tls_info("TLSv1.3", "TLS_AES_256_GCM_SHA384")
            .with_certificate("CN=mx.example.com", "CN=Let's Encrypt Authority X3");

        assert_eq!(record.tls_version, Some("TLSv1.3".to_string()));
        assert_eq!(record.cipher_suite, Some("TLS_AES_256_GCM_SHA384".to_string()));
        assert_eq!(
            record.certificate_subject,
            Some("CN=mx.example.com".to_string())
        );
        assert_eq!(
            record.certificate_issuer,
            Some("CN=Let's Encrypt Authority X3".to_string())
        );
    }
}
